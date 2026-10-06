package daemon

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/authfile"
	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/health"
)

func writeCursorSession(t *testing.T, v *authfile.Vault, profile string, exp time.Time) {
	t.Helper()
	claims, _ := json.Marshal(map[string]any{"type": "session", "exp": exp.Unix()})
	tok := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(claims) + ".sig"
	data, _ := json.Marshal(map[string]string{"accessToken": tok, "refreshToken": tok})
	dir := v.ProfilePath("cursor", profile)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "auth.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestDaemon_CursorSessionReloginWarning: a Cursor session login cannot be
// refreshed, so the daemon must not try; inside the relogin window it logs
// one warning per login instead of one per check.
func TestDaemon_CursorSessionReloginWarning(t *testing.T) {
	tmpDir := t.TempDir()
	v := authfile.NewVault(tmpDir)
	hs := health.NewStorage(filepath.Join(tmpDir, "health.json"))
	writeCursorSession(t, v, "p", time.Now().Add(3*24*time.Hour))

	d := New(v, hs, &Config{CheckInterval: time.Hour, RefreshThreshold: 10 * time.Minute})
	var buf bytes.Buffer
	d.logger = log.New(&buf, "", 0)

	ph := d.getProfileHealth("cursor", "p")
	if ph == nil || ph.TokenExpiresAt.IsZero() || ph.ReloginLead != health.CursorSessionReloginLead {
		t.Fatalf("getProfileHealth(cursor) = %+v, want a parsed session expiry", ph)
	}

	d.checkProfile("cursor", "p")
	d.checkProfile("cursor", "p")

	if n := strings.Count(buf.String(), "WARNING: cursor/p: login expires in"); n != 1 {
		t.Errorf("relogin warnings logged = %d, want 1; log:\n%s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "caam login cursor p") {
		t.Errorf("warning does not point at a login; log:\n%s", buf.String())
	}
	if s := d.GetStats(); s.RefreshCount != 0 || s.RefreshErrors != 0 {
		t.Errorf("refresh attempted: RefreshCount=%d RefreshErrors=%d, want 0/0", s.RefreshCount, s.RefreshErrors)
	}

	// A new login (a new expiry) is warned about again.
	writeCursorSession(t, v, "p", time.Now().Add(2*24*time.Hour))
	d.checkProfile("cursor", "p")
	if n := strings.Count(buf.String(), "WARNING: cursor/p:"); n != 2 {
		t.Errorf("after a new login: warnings = %d, want 2", n)
	}
}

func TestDaemon_CursorSessionQuietOutsideWindow(t *testing.T) {
	tmpDir := t.TempDir()
	v := authfile.NewVault(tmpDir)
	writeCursorSession(t, v, "p", time.Now().Add(30*24*time.Hour))

	d := New(v, health.NewStorage(filepath.Join(tmpDir, "health.json")), &Config{CheckInterval: time.Hour})
	var buf bytes.Buffer
	d.logger = log.New(&buf, "", 0)
	d.checkProfile("cursor", "p")
	if strings.Contains(buf.String(), "WARNING") {
		t.Errorf("30d left: unexpected warning:\n%s", buf.String())
	}
}
