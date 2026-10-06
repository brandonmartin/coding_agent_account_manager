package keepalive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/authfile"
	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/profile"
	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/shallow"
	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/testutil"
)

func TestMain(m *testing.M) {
	os.Exit(testutil.IsolatedMain(m))
}

var t0 = time.Date(2026, 10, 6, 3, 0, 0, 0, time.UTC)

// ---- fixtures ---------------------------------------------------------------

type account struct{ uuid, email string }

var (
	acctA = account{"aaaaaaaa-0000-0000-0000-000000000001", "alice@example.com"}
	acctB = account{"bbbbbbbb-0000-0000-0000-000000000002", "bob@example.com"}
	acctC = account{"cccccccc-0000-0000-0000-000000000003", "carol@example.com"}
)

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	if err := writeJSONFile(path, v); err != nil {
		t.Fatal(err)
	}
}

func writeJSONFile(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func claudeCred(exp time.Time, tag string) map[string]any {
	return map[string]any{"claudeAiOauth": map[string]any{
		"accessToken":  "at-" + tag,
		"refreshToken": "rt-" + tag,
		"expiresAt":    exp.UnixMilli(),
	}}
}

func claudeState(a account) map[string]any {
	return map[string]any{"oauthAccount": map[string]any{"accountUuid": a.uuid, "emailAddress": a.email}}
}

func grokAuth(exp time.Time, a account, tag string) map[string]any {
	return map[string]any{"https://auth.x.ai::client": map[string]any{
		"key":           "key-" + tag,
		"refresh_token": "rt-" + tag,
		"expires_at":    exp.UTC().Format(time.RFC3339Nano),
		"email":         a.email,
		"user_id":       a.uuid,
	}}
}

type env struct {
	t        *testing.T
	realHome string
	base     string
	dataDir  string
	vault    *authfile.Vault
	store    *profile.Store
	mgr      *shallow.Manager
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{
		t:        t,
		realHome: filepath.Join(root, "home"),
		base:     filepath.Join(root, "orch-homes"),
		dataDir:  filepath.Join(root, "data"),
	}
	if err := os.MkdirAll(filepath.Join(e.realHome, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	e.vault = authfile.NewVault(filepath.Join(e.dataDir, "vault"))
	e.store = profile.NewStore(filepath.Join(e.dataDir, "profiles"))
	mgr, err := shallow.NewManager(e.base, e.realHome)
	if err != nil {
		t.Fatal(err)
	}
	e.mgr = mgr
	return e
}

// shallowClaude creates a claude shallow profile for account a whose access
// token expires at exp.
func (e *env) shallowClaude(name string, a account, exp time.Time) string {
	e.t.Helper()
	src := filepath.Join(e.t.TempDir(), name)
	writeJSON(e.t, filepath.Join(src, ".credentials.json"), claudeCred(exp, name))
	writeJSON(e.t, filepath.Join(src, ".claude.json"), claudeState(a))
	home, err := e.mgr.Create(name, shallow.CreateOptions{
		Provider:         "claude",
		CredentialSource: filepath.Join(src, ".credentials.json"),
		SourceClaudeJSON: filepath.Join(src, ".claude.json"),
	})
	if err != nil {
		e.t.Fatalf("create shallow %s: %v", name, err)
	}
	return home
}

func (e *env) hostClaude(a account, exp time.Time) {
	writeJSON(e.t, filepath.Join(e.realHome, ".claude", ".credentials.json"), claudeCred(exp, "host"))
	writeJSON(e.t, filepath.Join(e.realHome, ".claude.json"), claudeState(a))
}

// vaultClaude stores a vault profile for account a with a credential that
// expires at exp.
func (e *env) vaultClaude(prof string, a account, exp time.Time) {
	dir := e.vault.ProfilePath("claude", prof)
	writeJSON(e.t, filepath.Join(dir, ".credentials.json"), claudeCred(exp, "vault-"+prof))
	writeJSON(e.t, filepath.Join(dir, ".claude.json"), claudeState(a))
	writeJSON(e.t, filepath.Join(dir, "meta.json"), map[string]any{"tool": "claude", "profile": prof})
}

func (e *env) hostGrok(a account, exp time.Time) {
	writeJSON(e.t, filepath.Join(e.realHome, ".grok", "auth.json"), grokAuth(exp, a, "host"))
	if err := os.WriteFile(filepath.Join(e.realHome, ".grok", "auth.json.lock"), nil, 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) vaultGrok(prof string, a account, exp time.Time) {
	dir := e.vault.ProfilePath("grok", prof)
	writeJSON(e.t, filepath.Join(dir, "auth.json"), grokAuth(exp, a, "vault-"+prof))
	writeJSON(e.t, filepath.Join(dir, "meta.json"), map[string]any{"tool": "grok", "profile": prof})
}

func (e *env) cfg(p Pinger) Config {
	return Config{
		RealHome:       e.realHome,
		ShallowBase:    e.base,
		DataDir:        e.dataDir,
		Vault:          e.vault,
		Profiles:       e.store,
		TTL:            DefaultTTL,
		MinGap:         DefaultMinGap,
		CLILockTimeout: time.Second,
		Pinger:         p,
		Now:            func() time.Time { return t0 },
		Getenv:         func(string) string { return "" },
	}
}

func credExpiry(t *testing.T, tool, path string) time.Time {
	t.Helper()
	st, err := readCred(tool, path)
	if err != nil || !st.Exists {
		t.Fatalf("read %s: exists=%v err=%v", path, st.Exists, err)
	}
	return st.ExpiresAt
}

// fakePinger simulates the provider CLI renewing (or not) the grant in its
// own HOME.
type fakePinger struct {
	renewTo map[string]time.Time // grant ID -> new expiry; absent = no rotation
	remove  map[string]bool      // grant ID -> CLI deletes the credential
	calls   []Grant
}

func (f *fakePinger) Ping(_ context.Context, g Grant) PingOutcome {
	f.calls = append(f.calls, g)
	if f.remove[g.ID()] {
		_ = os.Remove(g.CredPath)
		return PingOutcome{Detail: "You are not authenticated."}
	}
	exp, ok := f.renewTo[g.ID()]
	if !ok {
		return PingOutcome{}
	}
	switch g.Tool {
	case "claude":
		_ = writeJSONFile(g.CredPath, claudeCred(exp, "renewed"))
	case "grok":
		data, _ := os.ReadFile(g.CredPath)
		var m map[string]map[string]any
		_ = json.Unmarshal(data, &m)
		for k := range m {
			m[k]["expires_at"] = exp.UTC().Format(time.RFC3339Nano)
			m[k]["refresh_token"] = "rt-renewed"
		}
		out, _ := json.Marshal(m)
		_ = os.WriteFile(g.CredPath, out, 0o600)
	}
	return PingOutcome{}
}

func resultFor(t *testing.T, r *Report, id string) Result {
	t.Helper()
	for _, g := range r.Grants {
		if g.Grant == id {
			return g
		}
	}
	var ids []string
	for _, g := range r.Grants {
		ids = append(ids, g.Grant)
	}
	t.Fatalf("no result for %s (have %v)", id, ids)
	return Result{}
}

// ---- TTL selection ------------------------------------------------------------

func TestDecide(t *testing.T) {
	ttl, gap := 2*time.Hour, 25*time.Minute
	cases := []struct {
		name     string
		exp      time.Time
		last     time.Time
		wantPing bool
		wantSub  string
	}{
		{"fresh token is left alone", t0.Add(3 * time.Hour), time.Time{}, false, "fresh"},
		{"exactly at ttl is pinged", t0.Add(2 * time.Hour), time.Time{}, true, "<= ttl"},
		{"inside ttl is pinged", t0.Add(90 * time.Minute), time.Time{}, true, "<= ttl"},
		{"inside ttl but pinged recently is held back", t0.Add(90 * time.Minute), t0.Add(-10 * time.Minute), false, "min-gap"},
		{"inside ttl and gap elapsed is pinged", t0.Add(90 * time.Minute), t0.Add(-30 * time.Minute), true, "<= ttl"},
		{"expired is pinged", t0.Add(-5 * time.Minute), time.Time{}, true, "expired"},
		{"expired ignores min-gap", t0.Add(-5 * time.Minute), t0.Add(-1 * time.Minute), true, "expired"},
		{"unknown expiry is pinged", time.Time{}, time.Time{}, true, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ping, reason := Decide(tc.exp, t0, ttl, gap, tc.last)
			if ping != tc.wantPing || !strings.Contains(reason, tc.wantSub) {
				t.Fatalf("Decide = %v %q, want %v containing %q", ping, reason, tc.wantPing, tc.wantSub)
			}
		})
	}
}

func TestRunSelectsByTTLAndHonoursMinGap(t *testing.T) {
	e := newEnv(t)
	e.shallowClaude("A", acctA, t0.Add(30*time.Minute)) // inside ttl
	e.shallowClaude("B", acctB, t0.Add(5*time.Hour))    // fresh
	f := &fakePinger{renewTo: map[string]time.Time{"claude/shallow:A": t0.Add(8 * time.Hour)}}

	rep, err := Run(context.Background(), e.cfg(f), nil)
	if err != nil {
		t.Fatal(err)
	}
	a := resultFor(t, rep, "claude/shallow:A")
	if !a.Pinged || !a.Rotated || a.Failed {
		t.Fatalf("A: %+v", a)
	}
	if got := credExpiry(t, "claude", filepath.Join(e.base, "A", ".claude", ".credentials.json")); !got.Equal(t0.Add(8 * time.Hour)) {
		t.Fatalf("A not renewed in place: %v", got)
	}
	b := resultFor(t, rep, "claude/shallow:B")
	if b.Pinged || b.Action != ActionSkip {
		t.Fatalf("B should be skipped as fresh: %+v", b)
	}
	if len(f.calls) != 1 || f.calls[0].Home != filepath.Join(e.base, "A") {
		t.Fatalf("expected one ping in A's own HOME, got %+v", f.calls)
	}
	if f.calls[0].Env["HOME"] != filepath.Join(e.base, "A") || f.calls[0].Env["SHALLOW_PROFILE"] != "A" {
		t.Fatalf("ping must use the shallow-spawn env: %+v", f.calls[0].Env)
	}
	if !rep.OK || rep.Pinged != 1 || rep.Rotated != 1 {
		t.Fatalf("report totals: %+v", rep)
	}

	// A token that did not rotate and is still valid is held back by min-gap
	// on the next run.
	writeJSON(t, filepath.Join(e.base, "A", ".claude", ".credentials.json"), claudeCred(t0.Add(30*time.Minute), "A"))
	f2 := &fakePinger{}
	cfg := e.cfg(f2)
	cfg.Now = func() time.Time { return t0.Add(10 * time.Minute) }
	rep, err = Run(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a := resultFor(t, rep, "claude/shallow:A"); a.Pinged || !strings.Contains(a.Reason, "min-gap") {
		t.Fatalf("A should be held back by min-gap: %+v", a)
	}
}

func TestStillValidButNotRotatedIsNotAFailure(t *testing.T) {
	e := newEnv(t)
	e.shallowClaude("A", acctA, t0.Add(40*time.Minute))
	rep, err := Run(context.Background(), e.cfg(&fakePinger{}), nil)
	if err != nil {
		t.Fatal(err)
	}
	a := resultFor(t, rep, "claude/shallow:A")
	if !a.Pinged || a.Rotated || a.Failed || !rep.OK {
		t.Fatalf("still-valid unrotated grant must be ok: %+v", a)
	}
	if !strings.Contains(a.Reason, "renews only near expiry") {
		t.Fatalf("reason should explain: %q", a.Reason)
	}
}

func TestStillExpiredAfterPingFails(t *testing.T) {
	e := newEnv(t)
	e.shallowClaude("A", acctA, t0.Add(-time.Hour))
	rep, err := Run(context.Background(), e.cfg(&fakePinger{}), nil)
	if err != nil {
		t.Fatal(err)
	}
	a := resultFor(t, rep, "claude/shallow:A")
	if !a.Failed || !strings.Contains(a.Error, "still expired") {
		t.Fatalf("expected failure: %+v", a)
	}
	if rep.OK || rep.Failed != 1 || !strings.Contains(rep.FailureSummary(), "claude/shallow:A") {
		t.Fatalf("report must name the failed grant: %+v / %q", rep, rep.FailureSummary())
	}
}

func TestNoRefreshTokenFailsWithoutPinging(t *testing.T) {
	e := newEnv(t)
	home := e.shallowClaude("A", acctA, t0.Add(-time.Hour))
	writeJSON(t, filepath.Join(home, ".claude", ".credentials.json"), map[string]any{"claudeAiOauth": map[string]any{"accessToken": "x", "expiresAt": t0.Add(-time.Hour).UnixMilli()}})
	f := &fakePinger{}
	rep, err := Run(context.Background(), e.cfg(f), nil)
	if err != nil {
		t.Fatal(err)
	}
	if a := resultFor(t, rep, "claude/shallow:A"); !a.Failed || !strings.Contains(a.Error, "no refresh token") || len(f.calls) != 0 {
		t.Fatalf("expected refusal to ping: %+v calls=%d", a, len(f.calls))
	}
}

// ---- identity-matched vault backup --------------------------------------------

func TestVaultSyncIsIdentityMatched(t *testing.T) {
	e := newEnv(t)
	e.shallowClaude("A", acctA, t0.Add(-10*time.Minute))
	e.vaultClaude("alice", acctA, t0.Add(-2*time.Hour))            // same account, older
	e.vaultClaude("carol", acctC, t0.Add(-2*time.Hour))            // other account
	e.vaultClaude("_backup_20261001", acctA, t0.Add(-9*time.Hour)) // system profile
	// A vault profile with alice's email but a different account id must not
	// be treated as the same account.
	e.vaultClaude("impostor", account{"dddddddd-0000-0000-0000-000000000004", acctA.email}, t0.Add(-2*time.Hour))

	f := &fakePinger{renewTo: map[string]time.Time{"claude/shallow:A": t0.Add(8 * time.Hour)}}
	rep, err := Run(context.Background(), e.cfg(f), nil)
	if err != nil {
		t.Fatal(err)
	}
	a := resultFor(t, rep, "claude/shallow:A")
	if len(a.Vault) != 1 || a.Vault[0].Profile != "alice" || a.Vault[0].Action != VaultSynced {
		t.Fatalf("vault sync: %+v", a.Vault)
	}
	vp := func(p string) string { return filepath.Join(e.vault.ProfilePath("claude", p), ".credentials.json") }
	if got := credExpiry(t, "claude", vp("alice")); !got.Equal(t0.Add(8 * time.Hour)) {
		t.Fatalf("alice vault copy not updated: %v", got)
	}
	for _, p := range []string{"carol", "impostor"} {
		if got := credExpiry(t, "claude", vp(p)); !got.Equal(t0.Add(-2 * time.Hour)) {
			t.Fatalf("%s vault copy must not change: %v", p, got)
		}
	}
	if got := credExpiry(t, "claude", vp("_backup_20261001")); !got.Equal(t0.Add(-9 * time.Hour)) {
		t.Fatalf("system profile must not change: %v", got)
	}
	// Backup recorded the identity next to the snapshot.
	keys := e.vault.ClaudeProfileIdentityKeys("alice")
	if !sameIdentity(keys, []string{"uuid:" + acctA.uuid}) {
		t.Fatalf("alice identity keys: %v", keys)
	}
}

func TestVaultSyncSkipsCurrentCopyAndSyncsWithoutPing(t *testing.T) {
	e := newEnv(t)
	e.shallowClaude("A", acctA, t0.Add(6*time.Hour)) // fresh: no ping
	e.vaultClaude("alice", acctA, t0.Add(1*time.Hour))
	e.shallowClaude("B", acctB, t0.Add(6*time.Hour))
	e.vaultClaude("bob", acctB, t0.Add(6*time.Hour)) // already current

	f := &fakePinger{}
	rep, err := Run(context.Background(), e.cfg(f), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("fresh grants must not be pinged: %+v", f.calls)
	}
	if a := resultFor(t, rep, "claude/shallow:A"); len(a.Vault) != 1 || a.Vault[0].Action != VaultSynced {
		t.Fatalf("older vault copy should be refreshed from the live grant: %+v", a.Vault)
	}
	if b := resultFor(t, rep, "claude/shallow:B"); len(b.Vault) != 1 || b.Vault[0].Action != VaultCurrent {
		t.Fatalf("current vault copy should be left: %+v", b.Vault)
	}
}

// ---- ownership refusal ----------------------------------------------------------

func TestRefusesToPingOwnedVaultProfile(t *testing.T) {
	e := newEnv(t)
	e.shallowClaude("A", acctA, t0.Add(-time.Hour))
	e.vaultClaude("alice", acctA, t0.Add(-5*time.Hour))
	e.vaultClaude("carol", acctC, t0.Add(-5*time.Hour))
	f := &fakePinger{}

	for _, sel := range []string{"vault:claude/alice", "claude/alice", "alice"} {
		_, err := Run(context.Background(), e.cfg(f), []string{sel})
		var refusal *RefusalError
		if !errors.As(err, &refusal) {
			t.Fatalf("%s: expected refusal, got %v", sel, err)
		}
		if !strings.Contains(err.Error(), "claude/shallow:A") || !strings.Contains(err.Error(), "spent") {
			t.Fatalf("%s: refusal should name the owner and the hazard: %v", sel, err)
		}
	}
	_, err := Run(context.Background(), e.cfg(f), []string{"vault:claude/carol"})
	var refusal *RefusalError
	if !errors.As(err, &refusal) || !strings.Contains(err.Error(), "live grants only") {
		t.Fatalf("unowned vault profile must also be refused: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("nothing may be pinged on refusal: %+v", f.calls)
	}
	if got := credExpiry(t, "claude", filepath.Join(e.vault.ProfilePath("claude", "alice"), ".credentials.json")); !got.Equal(t0.Add(-5 * time.Hour)) {
		t.Fatalf("refused vault profile changed: %v", got)
	}
}

func TestHostLoginOwnedByShallowProfileIsNotPinged(t *testing.T) {
	e := newEnv(t)
	e.shallowClaude("B", acctB, t0.Add(-time.Hour))
	e.hostClaude(acctB, t0.Add(-3*time.Hour))
	f := &fakePinger{renewTo: map[string]time.Time{"claude/shallow:B": t0.Add(8 * time.Hour)}}
	rep, err := Run(context.Background(), e.cfg(f), nil)
	if err != nil {
		t.Fatal(err)
	}
	host := resultFor(t, rep, "claude/live:live")
	if host.Pinged || host.Failed || !strings.Contains(host.Reason, `shallow profile "B"`) {
		t.Fatalf("host login should be skipped as owned by B: %+v", host)
	}
	for _, c := range f.calls {
		if c.Kind == KindLive {
			t.Fatalf("host login was pinged: %+v", c)
		}
	}
	if !rep.OK {
		t.Fatalf("an owned host copy is not a failure: %+v", rep)
	}
}

func TestHostLoginOfItsOwnAccountIsPingedInPlace(t *testing.T) {
	e := newEnv(t)
	e.hostClaude(acctC, t0.Add(-time.Minute))
	f := &fakePinger{renewTo: map[string]time.Time{"claude/live:live": t0.Add(8 * time.Hour)}}
	rep, err := Run(context.Background(), e.cfg(f), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := resultFor(t, rep, "claude/live:live"); !r.Rotated {
		t.Fatalf("host login should be renewed: %+v", r)
	}
	if len(f.calls) != 1 || f.calls[0].Env["HOME"] != e.realHome {
		t.Fatalf("host ping must run in the real HOME: %+v", f.calls)
	}
}

func TestSharedFamilyBetweenShallowProfilesIsRefused(t *testing.T) {
	e := newEnv(t)
	e.shallowClaude("A", acctA, t0.Add(-time.Hour))
	e.shallowClaude("A2", acctA, t0.Add(-time.Hour))
	e.shallowClaude("B", acctB, t0.Add(-time.Hour))
	f := &fakePinger{renewTo: map[string]time.Time{"claude/shallow:B": t0.Add(8 * time.Hour)}}
	rep, err := Run(context.Background(), e.cfg(f), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"claude/shallow:A", "claude/shallow:A2"} {
		r := resultFor(t, rep, id)
		if r.Action != ActionRefused || !r.Failed || !strings.Contains(r.Error, "refresh-token family") {
			t.Fatalf("%s should be refused: %+v", id, r)
		}
	}
	if len(f.calls) != 1 || f.calls[0].Name != "B" {
		t.Fatalf("only B may be pinged: %+v", f.calls)
	}
}

// ---- dry run ----------------------------------------------------------------------

func TestDryRunTouchesNothing(t *testing.T) {
	e := newEnv(t)
	home := e.shallowClaude("A", acctA, t0.Add(-time.Hour))
	e.vaultClaude("alice", acctA, t0.Add(-5*time.Hour))
	e.hostGrok(acctB, t0.Add(-time.Minute))
	e.vaultGrok("bob", acctB, t0.Add(-6*time.Hour))
	credBefore, _ := os.ReadFile(filepath.Join(home, ".claude", ".credentials.json"))
	vaultBefore, _ := os.ReadFile(filepath.Join(e.vault.ProfilePath("claude", "alice"), ".credentials.json"))

	f := &fakePinger{renewTo: map[string]time.Time{"claude/shallow:A": t0.Add(8 * time.Hour)}}
	cfg := e.cfg(f)
	cfg.DryRun = true
	rep, err := Run(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("dry run must not ping: %+v", f.calls)
	}
	a := resultFor(t, rep, "claude/shallow:A")
	if a.Action != ActionWouldPing || a.Pinged || len(a.Vault) != 1 || a.Vault[0].Action != VaultWouldSync {
		t.Fatalf("dry-run claude result: %+v", a)
	}
	g := resultFor(t, rep, "grok/live:live")
	if g.Action != ActionWouldPing || len(g.Vault) != 1 || g.Vault[0].Action != VaultWouldSync {
		t.Fatalf("dry-run grok result: %+v", g)
	}
	credAfter, _ := os.ReadFile(filepath.Join(home, ".claude", ".credentials.json"))
	vaultAfter, _ := os.ReadFile(filepath.Join(e.vault.ProfilePath("claude", "alice"), ".credentials.json"))
	if string(credBefore) != string(credAfter) || string(vaultBefore) != string(vaultAfter) {
		t.Fatal("dry run changed a credential")
	}
	if _, err := os.Stat(filepath.Join(e.dataDir, "keepalive")); !os.IsNotExist(err) {
		t.Fatalf("dry run wrote keepalive state: %v", err)
	}
	if !rep.DryRun {
		t.Fatal("report should say dry run")
	}
}

// ---- grok -------------------------------------------------------------------------

func TestGrokLiveLoginRenewedAndSynced(t *testing.T) {
	e := newEnv(t)
	e.hostGrok(acctB, t0.Add(-30*time.Minute))
	e.vaultGrok("bob", acctB, t0.Add(-6*time.Hour))
	e.vaultGrok("carol", acctC, t0.Add(-6*time.Hour))
	f := &fakePinger{renewTo: map[string]time.Time{"grok/live:live": t0.Add(6 * time.Hour)}}
	cfg := e.cfg(f)
	cfg.Tools = []string{"grok"}
	rep, err := Run(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	g := resultFor(t, rep, "grok/live:live")
	if !g.Rotated || g.Identity != acctB.email {
		t.Fatalf("grok live: %+v", g)
	}
	if len(f.calls) != 1 || f.calls[0].CLILock == "" || f.calls[0].Env["HOME"] != e.realHome {
		t.Fatalf("grok ping: %+v", f.calls)
	}
	if len(g.Vault) != 1 || g.Vault[0].Profile != "bob" || g.Vault[0].Action != VaultSynced {
		t.Fatalf("grok vault sync: %+v", g.Vault)
	}
	if got := credExpiry(t, "grok", filepath.Join(e.vault.ProfilePath("grok", "bob"), "auth.json")); !got.Equal(t0.Add(6 * time.Hour)) {
		t.Fatalf("bob not synced: %v", got)
	}
	if got := credExpiry(t, "grok", filepath.Join(e.vault.ProfilePath("grok", "carol"), "auth.json")); !got.Equal(t0.Add(-6 * time.Hour)) {
		t.Fatalf("carol must not change: %v", got)
	}
}

func TestGrokCLIRemovingCredentialIsAFailure(t *testing.T) {
	e := newEnv(t)
	e.hostGrok(acctB, t0.Add(-30*time.Minute))
	f := &fakePinger{remove: map[string]bool{"grok/live:live": true}}
	cfg := e.cfg(f)
	cfg.Tools = []string{"grok"}
	rep, err := Run(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	g := resultFor(t, rep, "grok/live:live")
	if !g.Failed || !strings.Contains(g.Error, "removed the credential") {
		t.Fatalf("expected failure naming the removal: %+v", g)
	}
}

func TestGrokEnvPinsGrokHome(t *testing.T) {
	e := newEnv(t)
	custom := filepath.Join(t.TempDir(), "grokhome")
	writeJSON(t, filepath.Join(custom, "auth.json"), grokAuth(t0.Add(-time.Minute), acctB, "custom"))
	f := &fakePinger{}
	cfg := e.cfg(f)
	cfg.Tools = []string{"grok"}
	cfg.Getenv = func(k string) string {
		if k == "GROK_HOME" {
			return custom
		}
		return ""
	}
	if _, err := Run(context.Background(), cfg, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 1 || f.calls[0].Env["GROK_HOME"] != custom || f.calls[0].CredPath != filepath.Join(custom, "auth.json") {
		t.Fatalf("GROK_HOME not honoured: %+v", f.calls)
	}
}

// ---- selectors, env, locks ----------------------------------------------------------

func TestSelectorNarrowsRun(t *testing.T) {
	e := newEnv(t)
	e.shallowClaude("A", acctA, t0.Add(-time.Hour))
	e.shallowClaude("B", acctB, t0.Add(-time.Hour))
	f := &fakePinger{}
	rep, err := Run(context.Background(), e.cfg(f), []string{"B"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Grants) != 1 || rep.Grants[0].Grant != "claude/shallow:B" || len(f.calls) != 1 {
		t.Fatalf("selector: %+v", rep.Grants)
	}
	if _, err := Run(context.Background(), e.cfg(f), []string{"nope"}); err == nil || !strings.Contains(err.Error(), "no live grant") {
		t.Fatalf("unknown selector: %v", err)
	}
}

func TestGrantEnvScrubsTokensAndPinsHome(t *testing.T) {
	g := Grant{
		Env:   map[string]string{"HOME": "/x/A", "SHALLOW_PROFILE": "A"},
		Scrub: append([]string{"CLAUDE_CONFIG_DIR"}, alwaysScrub...),
	}
	env := GrantEnv([]string{
		"HOME=/real", "PATH=/bin", "ANTHROPIC_API_KEY=sk-secret", "CLAUDE_CODE_OAUTH_TOKEN=t",
		"CLAUDE_CONFIG_DIR=/real/.claude", "SHALLOW_PROFILE=other", "CLAUDECODE=1",
	}, g)
	got := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		if _, dup := got[k]; dup {
			t.Fatalf("duplicate %s", k)
		}
		got[k] = v
	}
	if got["HOME"] != "/x/A" || got["SHALLOW_PROFILE"] != "A" || got["PATH"] != "/bin" {
		t.Fatalf("env: %v", got)
	}
	for _, k := range []string{"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CONFIG_DIR", "CLAUDECODE"} {
		if _, ok := got[k]; ok {
			t.Fatalf("%s must be scrubbed", k)
		}
	}
}

func TestBusyGrantIsSkipped(t *testing.T) {
	e := newEnv(t)
	e.shallowClaude("A", acctA, t0.Add(-time.Hour))
	g := Grant{Tool: "claude", Kind: KindShallow, Name: "A"}
	unlock, busy, err := lockGrant(e.dataDir, g, false)
	if err != nil || busy {
		t.Fatalf("first lock: busy=%v err=%v", busy, err)
	}
	defer unlock()
	f := &fakePinger{}
	rep, err := Run(context.Background(), e.cfg(f), nil)
	if err != nil {
		t.Fatal(err)
	}
	if a := resultFor(t, rep, "claude/shallow:A"); a.Action != ActionSkip || !strings.Contains(a.Reason, "another caam keepalive") || len(f.calls) != 0 {
		t.Fatalf("busy grant: %+v", a)
	}
}

func TestCommandArgv(t *testing.T) {
	p := ExecPinger{ClaudeBin: "claude", GrokBin: "grok"}
	c, _ := p.Command("claude")
	joined := strings.Join(c, " ")
	for _, want := range []string{"-p", "--model " + DefaultClaudeModel, "--no-session-persistence", "--setting-sources project"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("claude argv %q missing %q", joined, want)
		}
	}
	g, _ := p.Command("grok")
	if strings.Join(g, " ") != "grok models" {
		t.Fatalf("grok argv: %v", g)
	}
	if _, err := p.Command("cursor"); err == nil {
		t.Fatal("cursor must not have a keepalive call")
	}
}

func TestRedact(t *testing.T) {
	in := fmt.Sprintf("error: bad token %s here", strings.Repeat("Ab3_", 12))
	if out := Redact(in); strings.Contains(out, "Ab3_Ab3_") || !strings.Contains(out, "<redacted>") {
		t.Fatalf("Redact: %q", out)
	}
}
