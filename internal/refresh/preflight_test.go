package refresh

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/authfile"
)

func preflightJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc.EncodeToString(raw) + ".sig"
}

// writePreflightCodexAuth writes a Codex auth.json for email issued at iat.
func writePreflightCodexAuth(t *testing.T, path, email string, iat time.Time) {
	t.Helper()
	claims := map[string]any{"email": email, "sub": "user-" + email, "iat": iat.Unix(), "exp": iat.Add(time.Hour).Unix()}
	raw, err := json.Marshal(map[string]any{
		"tokens": map[string]any{
			"id_token":      preflightJWT(t, claims),
			"access_token":  preflightJWT(t, claims),
			"refresh_token": "rt-" + iat.Format("150405"),
		},
		"last_refresh": iat.UTC().Format(time.RFC3339),
	})
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

func TestPreflight_Providers(t *testing.T) {
	t.Setenv("CODEX_HOME", t.TempDir())
	vault := authfile.NewVault(t.TempDir())

	for _, p := range []string{"codex", "gemini"} {
		if err := Preflight(p, "work", vault); err != nil {
			t.Errorf("Preflight(%s) = %v, want nil: caam refreshes this provider", p, err)
		}
	}

	wantCLI := map[string]string{"claude": "claude", "opencode": "opencode", "cursor": "cursor-agent", "grok": "grok"}
	for p, cli := range wantCLI {
		err := Preflight(p, "work", vault)
		var unsup *UnsupportedError
		if !errors.As(err, &unsup) || !errors.Is(err, ErrUnsupported) {
			t.Errorf("Preflight(%s) = %v, want *UnsupportedError", p, err)
		}
		if got := ProviderCLI(p); got != cli {
			t.Errorf("ProviderCLI(%s) = %q, want %q", p, got, cli)
		}
	}

	err := Preflight("nonesuch", "work", vault)
	var unsup *UnsupportedError
	if !errors.As(err, &unsup) {
		t.Fatalf("Preflight(unknown) = %v, want *UnsupportedError", err)
	}
	if ProviderCLI("nonesuch") != "" || ProviderCLI("codex") != "" || ProviderCLI("gemini") != "" {
		t.Error("ProviderCLI must be empty for providers caam refreshes and for unknown ones")
	}
}

func TestPreflight_CodexLiveFreshness(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		liveEmail string // "" = no live file
		liveIAT   time.Time
		wantSkip  bool
	}{
		{"no live login", "", time.Time{}, false},
		{"live strictly newer, same account", "alice@example.com", base.Add(2 * time.Hour), true},
		{"live same age, same account", "alice@example.com", base, false},
		{"live older, same account", "alice@example.com", base.Add(-2 * time.Hour), false},
		{"live newer but a different account", "bob@example.com", base.Add(2 * time.Hour), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			codexHome := t.TempDir()
			t.Setenv("CODEX_HOME", codexHome)
			vault := authfile.NewVault(t.TempDir())
			writePreflightCodexAuth(t, filepath.Join(vault.ProfilePath("codex", "work"), "auth.json"), "alice@example.com", base)
			if tc.liveEmail != "" {
				writePreflightCodexAuth(t, filepath.Join(codexHome, "auth.json"), tc.liveEmail, tc.liveIAT)
			}

			err := Preflight("codex", "work", vault)

			if !tc.wantSkip {
				if err != nil {
					t.Fatalf("Preflight = %v, want nil", err)
				}
				return
			}
			var newer *LiveCredentialNewerError
			if !errors.As(err, &newer) || !errors.Is(err, ErrLiveCredentialNewer) {
				t.Fatalf("Preflight = %v, want *LiveCredentialNewerError", err)
			}
			if newer.LivePath != filepath.Join(codexHome, "auth.json") {
				t.Errorf("LivePath = %q, want the CODEX_HOME auth file", newer.LivePath)
			}
			if got := err.Error(); !containsAll(got, "codex/work", "caam backup codex work") {
				t.Errorf("error %q should name the profile and the backup command", got)
			}
		})
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

func TestPreflight_NilVaultDoesNotBlockCodex(t *testing.T) {
	t.Setenv("CODEX_HOME", t.TempDir())
	if err := Preflight("codex", "work", nil); err != nil {
		t.Errorf("Preflight(codex, nil vault) = %v, want nil", err)
	}
}

// RefreshProfile must refuse a spent vault copy before any network call: the
// guard protects every caller (daemon, pool refresher, TUI), not just the
// daemon's own pre-check.
func TestRefreshProfile_CodexLiveNewerNeverReplaysVaultToken(t *testing.T) {
	codexHome := t.TempDir()
	t.Setenv("CODEX_HOME", codexHome)
	vault := authfile.NewVault(t.TempDir())
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	vaultAuth := filepath.Join(vault.ProfilePath("codex", "work"), "auth.json")
	writePreflightCodexAuth(t, vaultAuth, "alice@example.com", base)
	writePreflightCodexAuth(t, filepath.Join(codexHome, "auth.json"), "alice@example.com", base.Add(2*time.Hour))
	before, err := os.ReadFile(vaultAuth)
	if err != nil {
		t.Fatal(err)
	}

	orig := RefreshCodexToken
	called := false
	RefreshCodexToken = func(context.Context, string) (*TokenResponse, error) {
		called = true
		return nil, errors.New("must not be reached")
	}
	t.Cleanup(func() { RefreshCodexToken = orig })

	err = RefreshProfile(context.Background(), "codex", "work", vault, nil)

	if !errors.Is(err, ErrLiveCredentialNewer) {
		t.Fatalf("RefreshProfile = %v, want ErrLiveCredentialNewer", err)
	}
	if called {
		t.Error("the token endpoint was called with a spent refresh token")
	}
	after, _ := os.ReadFile(vaultAuth)
	if string(before) != string(after) {
		t.Error("vault copy was modified")
	}
}

// opencode and cursor used to return nil, so callers logged a successful
// refresh that never happened.
func TestRefreshProfile_NoRefresherIsUnsupportedNotSuccess(t *testing.T) {
	vault := authfile.NewVault(t.TempDir())
	for _, p := range []string{"opencode", "cursor", "grok", "claude"} {
		err := RefreshProfile(context.Background(), p, "work", vault, nil)
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("RefreshProfile(%s) = %v, want an unsupported error rather than nil", p, err)
		}
	}
}
