package warnings

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/authfile"
	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/health"
)

// cursorSessionAuth returns a Cursor session-login auth.json whose token
// expires at exp. Session logins store the same JWT in both fields.
func cursorSessionAuth(t *testing.T, exp time.Time) []byte {
	t.Helper()
	claims, err := json.Marshal(map[string]any{"type": "session", "exp": exp.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	tok := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(claims) + ".sig"
	data, err := json.Marshal(map[string]string{"accessToken": tok, "refreshToken": tok})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeCursorVaultProfile(t *testing.T, vault *authfile.Vault, name string, exp time.Time) {
	t.Helper()
	dir := vault.ProfilePath("cursor", name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "auth.json"), cursorSessionAuth(t, exp), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestCheckAll_CursorSession covers the ~60-day Cursor session cliff: a
// login that cannot be refreshed warns a week ahead and points at a login,
// never at "caam refresh".
func TestCheckAll_CursorSession(t *testing.T) {
	vault := authfile.NewVault(t.TempDir())
	writeCursorVaultProfile(t, vault, "far", time.Now().Add(20*24*time.Hour))
	writeCursorVaultProfile(t, vault, "near", time.Now().Add(3*24*time.Hour))
	writeCursorVaultProfile(t, vault, "gone", time.Now().Add(-time.Hour))

	got := map[string]Warning{}
	for _, w := range NewChecker(vault, nil, nil).CheckAll(context.Background()) {
		if w.Tool == "cursor" {
			got[w.Profile] = w
		}
	}

	if w, ok := got["far"]; ok {
		t.Errorf("20d left: unexpected warning %+v", w)
	}
	near, ok := got["near"]
	if !ok {
		t.Fatal("3d left: no warning, want one inside the relogin lead")
	}
	if near.Level != LevelWarning || !strings.Contains(near.Message, "cannot be refreshed") || near.Action != "caam login cursor near" {
		t.Errorf("3d left: warning = %+v", near)
	}
	gone, ok := got["gone"]
	if !ok {
		t.Fatal("expired: no warning")
	}
	if gone.Level != LevelCritical || gone.Action != "caam login cursor gone" {
		t.Errorf("expired: warning = %+v", gone)
	}
}

// TestCheckLiveCursor reads the live login even when no vault profile
// matches it, and labels it so the operator knows which login is meant.
func TestCheckLiveCursor(t *testing.T) {
	orig := cursorLiveExpiry
	t.Cleanup(func() { cursorLiveExpiry = orig })

	checker := NewChecker(authfile.NewVault(t.TempDir()), nil, nil)
	set := func(ttl time.Duration, renewable bool) {
		cursorLiveExpiry = func() (*health.ExpiryInfo, error) {
			info := &health.ExpiryInfo{ExpiresAt: time.Now().Add(ttl), Renewable: renewable}
			if !renewable {
				info.ReloginLead = health.CursorSessionReloginLead
			}
			return info, nil
		}
	}

	set(2*24*time.Hour, false)
	w := checker.checkLiveCursor("")
	if len(w) != 1 || w[0].Profile != "live login" || w[0].Action != "cursor-agent login" || w[0].Level != LevelWarning {
		t.Fatalf("unmatched live login: warnings = %+v", w)
	}
	w = checker.checkLiveCursor("work")
	if len(w) != 1 || w[0].Profile != "work" || w[0].Action != "caam login cursor work" {
		t.Fatalf("matched live login: warnings = %+v", w)
	}

	set(30*time.Minute, false)
	if w = checker.checkLiveCursor("work"); len(w) != 1 || w[0].Level != LevelCritical {
		t.Fatalf("30m left: warnings = %+v, want one critical", w)
	}

	set(30*24*time.Hour, false)
	if w = checker.checkLiveCursor("work"); len(w) != 0 {
		t.Fatalf("30d left: warnings = %+v, want none", w)
	}

	set(-time.Hour, true) // API-key login: re-minted on start
	if w = checker.checkLiveCursor("work"); len(w) != 0 {
		t.Fatalf("API-key login: warnings = %+v, want none", w)
	}
}
