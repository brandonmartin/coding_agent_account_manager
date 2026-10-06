package cmd

import (
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

func TestReloginCheck(t *testing.T) {
	session := func(ttl time.Duration) *health.ProfileHealth {
		return &health.ProfileHealth{
			TokenExpiresAt: time.Now().Add(ttl),
			ReloginLead:    health.CursorSessionReloginLead,
		}
	}

	far := reloginCheck("cursor/p token", "cursor", "p", session(11*24*time.Hour+time.Hour))
	if far.Status != "pass" || far.Message != "login valid, expires in 11 days" {
		t.Errorf("11d left: %+v", far)
	}

	near := reloginCheck("cursor/p token", "cursor", "p", session(3*24*time.Hour+time.Hour))
	if near.Status != "warn" || !strings.Contains(near.Message, "in 3 days") ||
		!strings.Contains(near.Details, "caam login cursor p") {
		t.Errorf("3d left: %+v", near)
	}
}

// TestBuildProfileHealth_CursorSession: a Cursor vault profile used to have
// no expiry parser and sat at "unknown / Warning" in `caam ls`. It now reads
// the session expiry and carries the relogin lead.
func TestBuildProfileHealth_CursorSession(t *testing.T) {
	origVault, origStore, origHealth := vault, profileStore, healthStore
	t.Cleanup(func() { vault, profileStore, healthStore = origVault, origStore, origHealth })
	vault = authfile.NewVault(filepath.Join(t.TempDir(), "vault"))
	profileStore = nil
	healthStore = nil

	exp := time.Now().Add(11 * 24 * time.Hour).Truncate(time.Second)
	claims, _ := json.Marshal(map[string]any{"type": "session", "exp": exp.Unix()})
	tok := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(claims) + ".sig"
	data, _ := json.Marshal(map[string]string{"accessToken": tok, "refreshToken": tok})
	dir := vault.ProfilePath("cursor", "p")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "auth.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	ph := buildProfileHealth("cursor", "p")
	if !ph.TokenExpiresAt.Equal(exp) || ph.ReloginLead != health.CursorSessionReloginLead || ph.CredentialRenewable() {
		t.Fatalf("buildProfileHealth(cursor) = expiry %v lead %v renewable %v", ph.TokenExpiresAt, ph.ReloginLead, ph.CredentialRenewable())
	}
	if got := health.CalculateStatus(ph); got != health.StatusHealthy {
		t.Errorf("status = %v, want healthy with 11d left", got)
	}
}
