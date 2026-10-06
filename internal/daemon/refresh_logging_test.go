package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/authfile"
	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/health"
	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/refresh"
)

// logBuf is a goroutine-safe log sink: checkAndRefresh logs from several
// goroutines at once.
type logBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *logBuf) count(substr string) int {
	return strings.Count(l.String(), substr)
}

// newLogDaemon builds a daemon over a temp vault whose log lines are captured.
func newLogDaemon(t *testing.T) (*Daemon, *authfile.Vault, *health.Storage, *logBuf) {
	t.Helper()
	tmpDir := t.TempDir()
	v := authfile.NewVault(tmpDir)
	hs := health.NewStorage(filepath.Join(tmpDir, "health.json"))
	d := New(v, hs, &Config{
		CheckInterval:    50 * time.Millisecond,
		RefreshThreshold: 10 * time.Minute,
	})
	logs := &logBuf{}
	d.logger = log.New(logs, "", 0)
	d.ctx, d.cancel = context.WithCancel(context.Background())
	t.Cleanup(d.cancel)
	return d, v, hs, logs
}

// testJWT builds an unsigned three-part JWT; the parsers never check signatures.
func testJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc.EncodeToString(raw) + ".sig"
}

// writeCodexAuth writes a ChatGPT-mode Codex auth.json for email whose tokens
// were issued at iat and whose access token expires at exp.
func writeCodexAuth(t *testing.T, path, email string, iat, exp time.Time) {
	t.Helper()
	claims := map[string]any{"email": email, "sub": "user-" + email, "iat": iat.Unix(), "exp": exp.Unix()}
	auth := map[string]any{
		"tokens": map[string]any{
			"id_token":      testJWT(t, claims),
			"access_token":  testJWT(t, claims),
			"refresh_token": "rt-" + iat.Format("150405"),
		},
		"last_refresh": iat.UTC().Format(time.RFC3339),
	}
	raw, err := json.Marshal(auth)
	if err != nil {
		t.Fatalf("marshal auth: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// stubCodexRefresh swaps the Codex token endpoint call and returns a counter.
// The default answer mints a new access token valid for an hour.
func stubCodexRefresh(t *testing.T, fn func(context.Context, string) (*refresh.TokenResponse, error)) *int {
	t.Helper()
	calls := new(int)
	orig := refresh.RefreshCodexToken
	refresh.RefreshCodexToken = func(ctx context.Context, rt string) (*refresh.TokenResponse, error) {
		*calls++
		return fn(ctx, rt)
	}
	t.Cleanup(func() { refresh.RefreshCodexToken = orig })
	return calls
}

func newAccessToken(t *testing.T, email string, exp time.Time) *refresh.TokenResponse {
	t.Helper()
	return &refresh.TokenResponse{
		AccessToken:  testJWT(t, map[string]any{"email": email, "exp": exp.Unix()}),
		RefreshToken: "rt-rotated",
		ExpiresIn:    3600,
	}
}

func TestCheckProfile_ClaudeNotRefreshedLoggedOnce(t *testing.T) {
	d, v, hs, logs := newLogDaemon(t)

	vaultPath := v.ProfilePath("claude", "work")
	if err := os.MkdirAll(vaultPath, 0700); err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Add(5 * time.Minute)
	creds := map[string]any{"claudeAiOauth": map[string]any{
		"accessToken":  "at",
		"refreshToken": "rt",
		"expiresAt":    expiry.UnixMilli(),
	}}
	raw, _ := json.Marshal(creds)
	if err := os.WriteFile(filepath.Join(vaultPath, ".credentials.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := hs.UpdateProfile("claude", "work", &health.ProfileHealth{TokenExpiresAt: expiry}); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		d.checkProfile("claude", "work")
	}

	if got := logs.count("claude/work: not refreshed by caam (the claude CLI renews it when it runs)"); got != 1 {
		t.Errorf("not-refreshed line logged %d times, want exactly 1\n%s", got, logs.String())
	}
	if logs.count("refreshing token") != 0 {
		t.Errorf("logged a refresh for a provider caam cannot refresh:\n%s", logs.String())
	}
	if s := d.GetStats(); s.RefreshCount != 0 || s.RefreshErrors != 0 {
		t.Errorf("stats = count %d errors %d, want 0/0 (a skip is neither)", s.RefreshCount, s.RefreshErrors)
	}
}

func TestCheckProfile_ClaudeSelfRefreshingFromVaultParse(t *testing.T) {
	// With no health-store entry the daemon parses the vault copy itself, and
	// that parse must carry SelfRefreshing through to the profile health.
	d, v, _, _ := newLogDaemon(t)

	vaultPath := v.ProfilePath("claude", "work")
	if err := os.MkdirAll(vaultPath, 0700); err != nil {
		t.Fatal(err)
	}
	creds := map[string]any{"claudeAiOauth": map[string]any{
		"accessToken":  "at",
		"refreshToken": "rt",
		"expiresAt":    time.Now().Add(5 * time.Minute).UnixMilli(),
	}}
	raw, _ := json.Marshal(creds)
	if err := os.WriteFile(filepath.Join(vaultPath, ".credentials.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}

	ph := d.getProfileHealth("claude", "work")
	if ph == nil {
		t.Fatal("getProfileHealth returned nil for a parseable claude vault profile")
	}
	if !ph.SelfRefreshing {
		t.Error("SelfRefreshing = false, want true for a claude credential with a refresh token")
	}
}

func TestCheckProfile_CodexRefreshLogsAttemptAndOutcome(t *testing.T) {
	d, v, hs, logs := newLogDaemon(t)
	t.Setenv("CODEX_HOME", t.TempDir()) // no live login to defer to

	now := time.Now()
	writeCodexAuth(t, filepath.Join(v.ProfilePath("codex", "work"), "auth.json"),
		"alice@example.com", now.Add(-time.Hour), now.Add(5*time.Minute))
	if err := hs.UpdateProfile("codex", "work", &health.ProfileHealth{TokenExpiresAt: now.Add(5 * time.Minute)}); err != nil {
		t.Fatal(err)
	}

	newExpiry := now.Add(time.Hour)
	calls := stubCodexRefresh(t, func(context.Context, string) (*refresh.TokenResponse, error) {
		return newAccessToken(t, "alice@example.com", newExpiry), nil
	})

	d.checkProfile("codex", "work")

	if *calls != 1 {
		t.Fatalf("token endpoint called %d times, want 1", *calls)
	}
	out := logs.String()
	attempt := strings.Index(out, "codex/work: refreshing token (expires in ")
	outcome := strings.Index(out, "codex/work: token refreshed successfully (new expiry "+newExpiry.UTC().Format("2006-01-02T15:04:05")[:10])
	if attempt < 0 || outcome < 0 || outcome < attempt {
		t.Errorf("want an attempt line followed by an outcome line carrying the new expiry, got:\n%s", out)
	}
	if s := d.GetStats(); s.RefreshCount != 1 || s.RefreshErrors != 0 {
		t.Errorf("stats = count %d errors %d, want 1/0", s.RefreshCount, s.RefreshErrors)
	}
}

func TestCheckProfile_CodexRefreshFailureLogsReason(t *testing.T) {
	d, v, hs, logs := newLogDaemon(t)
	t.Setenv("CODEX_HOME", t.TempDir())

	now := time.Now()
	writeCodexAuth(t, filepath.Join(v.ProfilePath("codex", "work"), "auth.json"),
		"alice@example.com", now.Add(-time.Hour), now.Add(5*time.Minute))
	if err := hs.UpdateProfile("codex", "work", &health.ProfileHealth{TokenExpiresAt: now.Add(5 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	stubCodexRefresh(t, func(context.Context, string) (*refresh.TokenResponse, error) {
		return nil, errors.New("endpoint unreachable")
	})

	d.checkProfile("codex", "work")

	out := logs.String()
	if !strings.Contains(out, "codex/work: refreshing token") || !strings.Contains(out, "codex/work: refresh failed: refresh api: endpoint unreachable") {
		t.Errorf("want attempt and failure-with-reason lines, got:\n%s", out)
	}
	if s := d.GetStats(); s.RefreshErrors != 1 || s.RefreshCount != 0 {
		t.Errorf("stats = count %d errors %d, want 0/1", s.RefreshCount, s.RefreshErrors)
	}
}

func TestCheckProfile_CodexLiveNewerSkipsSpentVaultRefresh(t *testing.T) {
	d, v, hs, logs := newLogDaemon(t)
	codexHome := t.TempDir()
	t.Setenv("CODEX_HOME", codexHome)

	now := time.Now()
	vaultAuth := filepath.Join(v.ProfilePath("codex", "work"), "auth.json")
	// The vault copy holds the refresh token the live CLI has since rotated.
	writeCodexAuth(t, vaultAuth, "alice@example.com", now.Add(-2*time.Hour), now.Add(5*time.Minute))
	writeCodexAuth(t, filepath.Join(codexHome, "auth.json"), "alice@example.com", now.Add(-time.Minute), now.Add(8*time.Hour))
	if err := hs.UpdateProfile("codex", "work", &health.ProfileHealth{TokenExpiresAt: now.Add(5 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(vaultAuth)
	if err != nil {
		t.Fatal(err)
	}

	calls := stubCodexRefresh(t, func(context.Context, string) (*refresh.TokenResponse, error) {
		return newAccessToken(t, "alice@example.com", now.Add(time.Hour)), nil
	})

	for i := 0; i < 3; i++ {
		d.checkProfile("codex", "work")
	}

	if *calls != 0 {
		t.Fatalf("spent vault refresh token was replayed %d times, want 0", *calls)
	}
	after, _ := os.ReadFile(vaultAuth)
	if !bytes.Equal(before, after) {
		t.Error("vault copy was modified although the live login is newer")
	}
	if got := logs.count("codex/work: vault refresh skipped"); got != 1 {
		t.Errorf("skip line logged %d times, want exactly 1\n%s", got, logs.String())
	}
	if !strings.Contains(logs.String(), "caam backup codex work") {
		t.Errorf("skip line should say how to bring the vault up to date:\n%s", logs.String())
	}
	if logs.count("refreshing token") != 0 {
		t.Errorf("announced a refresh that was skipped:\n%s", logs.String())
	}
	if s := d.GetStats(); s.RefreshCount != 0 || s.RefreshErrors != 0 {
		t.Errorf("stats = count %d errors %d, want 0/0", s.RefreshCount, s.RefreshErrors)
	}

	// Once the vault catches up (backup live -> vault) the skip must lift:
	// the live-newer note dedupes the log line only, never the attempt.
	live, _ := os.ReadFile(filepath.Join(codexHome, "auth.json"))
	if err := os.WriteFile(vaultAuth, live, 0600); err != nil {
		t.Fatal(err)
	}
	d.checkProfile("codex", "work")
	if *calls != 1 {
		t.Errorf("after the vault caught up, token endpoint called %d times, want 1", *calls)
	}
}

func TestCheckProfile_CodexLiveOlderOrOtherAccountStillRefreshes(t *testing.T) {
	cases := []struct {
		name      string
		liveEmail string
		liveIAT   time.Duration // relative to now
	}{
		{"live older than vault", "alice@example.com", -3 * time.Hour},
		{"live is a different account", "bob@example.com", -time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, v, hs, logs := newLogDaemon(t)
			codexHome := t.TempDir()
			t.Setenv("CODEX_HOME", codexHome)

			now := time.Now()
			writeCodexAuth(t, filepath.Join(v.ProfilePath("codex", "work"), "auth.json"),
				"alice@example.com", now.Add(-2*time.Hour), now.Add(5*time.Minute))
			writeCodexAuth(t, filepath.Join(codexHome, "auth.json"), tc.liveEmail, now.Add(tc.liveIAT), now.Add(8*time.Hour))
			if err := hs.UpdateProfile("codex", "work", &health.ProfileHealth{TokenExpiresAt: now.Add(5 * time.Minute)}); err != nil {
				t.Fatal(err)
			}
			calls := stubCodexRefresh(t, func(context.Context, string) (*refresh.TokenResponse, error) {
				return newAccessToken(t, "alice@example.com", now.Add(time.Hour)), nil
			})

			d.checkProfile("codex", "work")

			if *calls != 1 {
				t.Errorf("token endpoint called %d times, want 1\n%s", *calls, logs.String())
			}
			if logs.count("vault refresh skipped") != 0 {
				t.Errorf("skipped a refresh the live login does not make unsafe:\n%s", logs.String())
			}
		})
	}
}

func TestCheckProfile_GeminiWithoutClientCredsReportedOnceNotAsFailure(t *testing.T) {
	d, v, hs, logs := newLogDaemon(t)

	vaultPath := v.ProfilePath("gemini", "work")
	if err := os.MkdirAll(vaultPath, 0700); err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Add(5 * time.Minute)
	// A refresh token but no client_id/client_secret: caam cannot refresh it.
	creds := map[string]any{"access_token": "at", "refresh_token": "rt", "expiry_date": expiry.UnixMilli()}
	raw, _ := json.Marshal(creds)
	if err := os.WriteFile(filepath.Join(vaultPath, "oauth_creds.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := hs.UpdateProfile("gemini", "work", &health.ProfileHealth{TokenExpiresAt: expiry}); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		d.checkProfile("gemini", "work")
	}

	if got := logs.count("gemini/work: not refreshed by caam (missing oauth client credentials"); got != 1 {
		t.Errorf("unsupported outcome logged %d times, want exactly 1\n%s", got, logs.String())
	}
	if got := logs.count("refreshing token"); got != 1 {
		t.Errorf("attempt line logged %d times, want 1 (later ticks skip a profile known unsupported)\n%s", got, logs.String())
	}
	if s := d.GetStats(); s.RefreshErrors != 0 {
		t.Errorf("RefreshErrors = %d, want 0 (unsupported is not a failure)", s.RefreshErrors)
	}
}

func TestCheckAndRefresh_IgnoresProvidersWithoutExpiry(t *testing.T) {
	d, v, _, logs := newLogDaemon(t)
	for _, p := range []string{"cursor", "opencode", "grok"} {
		if err := os.MkdirAll(v.ProfilePath(p, "work"), 0700); err != nil {
			t.Fatal(err)
		}
	}

	d.checkAndRefresh()

	if s := d.GetStats(); s.ProfilesChecked != 0 {
		t.Errorf("ProfilesChecked = %d, want 0 for providers with no expiry to time", s.ProfilesChecked)
	}
	if logs.String() != "" {
		t.Errorf("unexpected log output:\n%s", logs.String())
	}
}
