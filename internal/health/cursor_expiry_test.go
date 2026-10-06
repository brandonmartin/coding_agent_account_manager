package health

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// cursorSessionJWT is a Cursor session token: the browser login stores the
// same ~60-day JWT as accessToken and refreshToken.
func cursorSessionJWT(t *testing.T, exp time.Time) string {
	t.Helper()
	return unsignedJWT(t, map[string]any{
		"type":  "session",
		"scope": "openid profile email offline_access",
		"exp":   exp.Unix(),
	})
}

func writeCursorAuth(t *testing.T, dir, name, body string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseCursorExpiry_SessionLogin(t *testing.T) {
	exp := time.Now().Add(11 * 24 * time.Hour).Truncate(time.Second)
	tok := cursorSessionJWT(t, exp)
	path := writeCursorAuth(t, t.TempDir(), "auth.json",
		`{"accessToken":"`+tok+`","refreshToken":"`+tok+`"}`)

	info, err := ParseCursorExpiry(path)
	if err != nil {
		t.Fatalf("ParseCursorExpiry() error = %v", err)
	}
	if !info.ExpiresAt.Equal(exp) {
		t.Errorf("ExpiresAt = %v, want %v", info.ExpiresAt, exp)
	}
	if !info.HasRefreshToken {
		t.Error("HasRefreshToken = false, want true")
	}
	// cursor-agent has no refresh grant for session logins: the stored
	// refreshToken never renews anything.
	if info.Renewable || info.SelfRefreshing {
		t.Errorf("Renewable=%v SelfRefreshing=%v, want both false for a session login", info.Renewable, info.SelfRefreshing)
	}
	if info.ReloginLead != CursorSessionReloginLead {
		t.Errorf("ReloginLead = %v, want %v", info.ReloginLead, CursorSessionReloginLead)
	}
	if info.Source != path {
		t.Errorf("Source = %q, want %q", info.Source, path)
	}
}

func TestParseCursorExpiry_APIKeyIsRenewable(t *testing.T) {
	tok := cursorSessionJWT(t, time.Now().Add(-time.Hour))
	path := writeCursorAuth(t, t.TempDir(), "auth.json",
		`{"accessToken":"`+tok+`","refreshToken":"`+tok+`","apiKey":"key_placeholder"}`)

	info, err := ParseCursorExpiry(path)
	if err != nil {
		t.Fatalf("ParseCursorExpiry() error = %v", err)
	}
	if !info.Renewable {
		t.Error("Renewable = false, want true: cursor-agent re-mints tokens from a stored apiKey")
	}
	if info.ReloginLead != 0 {
		t.Errorf("ReloginLead = %v, want 0 for an API-key login", info.ReloginLead)
	}
	ph := &ProfileHealth{TokenExpiresAt: info.ExpiresAt, TokenRenewable: info.Renewable}
	if got := CalculateStatus(ph); got != StatusHealthy {
		t.Errorf("CalculateStatus() = %v, want healthy for a lapsed API-key token", got)
	}
}

func TestParseCursorExpiry_Errors(t *testing.T) {
	dir := t.TempDir()
	if _, err := ParseCursorExpiry(filepath.Join(dir, "missing.json")); !errors.Is(err, ErrNoAuthFile) {
		t.Errorf("missing file: error = %v, want ErrNoAuthFile", err)
	}
	empty := writeCursorAuth(t, dir, "empty.json", `{}`)
	if _, err := ParseCursorExpiry(empty); !errors.Is(err, ErrNoExpiry) {
		t.Errorf("no tokens: error = %v, want ErrNoExpiry", err)
	}
	opaque := writeCursorAuth(t, dir, "opaque.json", `{"accessToken":"not-a-jwt","refreshToken":"x"}`)
	if _, err := ParseCursorExpiry(opaque); !errors.Is(err, ErrNoExpiry) {
		t.Errorf("opaque token: error = %v, want ErrNoExpiry", err)
	}
	bad := writeCursorAuth(t, dir, "bad.json", `{not json`)
	if _, err := ParseCursorExpiry(bad); err == nil {
		t.Error("malformed JSON: error = nil, want an error")
	}
}

func TestParseCursorExpiry_LiveFileFollowsXDG(t *testing.T) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		t.Skip("XDG_CONFIG_HOME resolution applies to Linux and other Unix")
	}
	home := t.TempDir()
	xdg := filepath.Join(t.TempDir(), "xdg")
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	exp := time.Now().Add(20 * 24 * time.Hour).Truncate(time.Second)
	tok := cursorSessionJWT(t, exp)
	// A stale file under ~/.cursor must not be read on Linux.
	writeCursorAuth(t, filepath.Join(home, ".cursor"), "auth.json",
		`{"accessToken":"`+cursorSessionJWT(t, time.Now().Add(-time.Hour))+`"}`)
	want := writeCursorAuth(t, filepath.Join(xdg, "cursor"), "auth.json", `{"accessToken":"`+tok+`"}`)

	info, err := ParseCursorExpiry("")
	if err != nil {
		t.Fatalf("ParseCursorExpiry(\"\") error = %v", err)
	}
	if info.Source != want || !info.ExpiresAt.Equal(exp) {
		t.Errorf("Source=%q ExpiresAt=%v, want %q %v", info.Source, info.ExpiresAt, want, exp)
	}
}

func TestParseCursorVaultExpiry_LegacyName(t *testing.T) {
	dir := t.TempDir()
	exp := time.Now().Add(5 * 24 * time.Hour).Truncate(time.Second)
	writeCursorAuth(t, dir, "xdg-auth.json", `{"accessToken":"`+cursorSessionJWT(t, exp)+`"}`)

	info, err := ParseCursorVaultExpiry(dir)
	if err != nil {
		t.Fatalf("ParseCursorVaultExpiry() error = %v", err)
	}
	if !info.ExpiresAt.Equal(exp) {
		t.Errorf("ExpiresAt = %v, want %v", info.ExpiresAt, exp)
	}

	newer := time.Now().Add(9 * 24 * time.Hour).Truncate(time.Second)
	writeCursorAuth(t, dir, "auth.json", `{"accessToken":"`+cursorSessionJWT(t, newer)+`"}`)
	info, err = ParseCursorVaultExpiry(dir)
	if err != nil || !info.ExpiresAt.Equal(newer) {
		t.Errorf("auth.json present: ExpiresAt=%v err=%v, want %v (auth.json wins)", info.ExpiresAt, err, newer)
	}
}

// TestCursorSessionHealth checks the verdict across the life of a session
// login: healthy well before expiry, a warning with a login recommendation
// inside the relogin window, critical once expired.
func TestCursorSessionHealth(t *testing.T) {
	session := func(ttl time.Duration) *ProfileHealth {
		return &ProfileHealth{
			TokenExpiresAt: time.Now().Add(ttl),
			ReloginLead:    CursorSessionReloginLead,
		}
	}

	far := session(11 * 24 * time.Hour)
	if got := CalculateStatus(far); got != StatusHealthy {
		t.Errorf("11d left: status = %v, want healthy", got)
	}
	if far.ReloginDue(time.Now()) {
		t.Error("11d left: ReloginDue = true, want false")
	}
	if r := StatusReasons(far); len(r) != 0 {
		t.Errorf("11d left: reasons = %v, want none", r)
	}
	if got := FormatHealthStatus(StatusHealthy, far, FormatOptions{NoColor: true}); got != "🟢 11d left" {
		t.Errorf("11d left: FormatHealthStatus = %q", got)
	}

	near := session(3 * 24 * time.Hour)
	if got := CalculateStatus(near); got != StatusWarning {
		t.Errorf("3d left: status = %v, want warning", got)
	}
	if !near.ReloginDue(time.Now()) {
		t.Error("3d left: ReloginDue = false, want true")
	}
	reasons := strings.Join(StatusReasons(near), "; ")
	if !strings.Contains(reasons, "Login expires in") || !strings.Contains(reasons, "cannot auto-refresh") {
		t.Errorf("3d left: reasons = %q, want a login-expiry reason", reasons)
	}
	rec := FormatRecommendation("cursor", "p", near)
	if !strings.Contains(rec, `caam login cursor p`) || strings.Contains(rec, "caam refresh") {
		t.Errorf("3d left: recommendation = %q, want caam login and no caam refresh", rec)
	}

	expired := session(-time.Hour)
	if got := CalculateStatus(expired); got != StatusCritical {
		t.Errorf("expired: status = %v, want critical", got)
	}
	if expired.ReloginDue(time.Now()) {
		t.Error("expired: ReloginDue = true, want false (past the window)")
	}

	// The lead only applies to a credential that cannot renew.
	renewable := session(3 * 24 * time.Hour)
	renewable.TokenRenewable = true
	if renewable.ReloginDue(time.Now()) {
		t.Error("renewable: ReloginDue = true, want false")
	}
}
