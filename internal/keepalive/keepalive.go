// Package keepalive keeps self-refreshing logins alive in place.
//
// Claude Code and the Grok CLI renew their own OAuth access tokens, and caam
// cannot (Claude refresh is deliberately disabled; there is no Grok
// refresher). For those providers only running the provider CLI renews a
// grant. An idle account therefore drifts into an expired access token that
// nothing ever renews: `caam limits` fails, a router marks the account stale,
// sends it no work, and so nothing ever runs the CLI that would renew it.
//
// keepalive breaks that spiral. For every LIVE grant — a Claude shallow
// profile, the real-HOME Claude login, the active Grok login, an isolated
// Grok profile — whose access token is expired or close to it, it runs the
// provider's cheapest call that triggers the CLI's own silent refresh, inside
// that grant's own HOME, so the refresh token is spent exactly where it lives.
// It then copies the renewed credential into the vault profile of the SAME
// identity, like `caam backup` would.
//
// It never pings a vault copy. Refresh tokens are single use: a vault snapshot
// of a grant that a live login or shallow profile owns holds an already-spent
// refresh token, and replaying it can revoke the whole token family.
package keepalive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/authfile"
	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/health"
	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/identity"
	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/profile"
	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/shallow"
)

// Tools lists the providers keepalive handles, in display order.
func Tools() []string { return []string{"claude", "grok"} }

// Grant kinds.
const (
	KindShallow = "shallow" // a caam shallow profile (claude)
	KindLive    = "live"    // the login in the real HOME / $GROK_HOME
	KindProfile = "profile" // a caam isolated profile (grok)
)

// Result actions.
const (
	ActionPing      = "ping"       // the CLI was run
	ActionWouldPing = "would-ping" // --dry-run: the CLI would have been run
	ActionSkip      = "skip"       // nothing to do (fresh, pinged recently, busy, not ours)
	ActionRefused   = "refused"    // unsafe to touch (shared refresh-token family)
	ActionError     = "error"      // the credential cannot be renewed as it stands
)

// Vault sync actions.
const (
	VaultSynced    = "synced"
	VaultWouldSync = "would-sync"
	VaultCurrent   = "current"
	VaultSkipped   = "skipped"
	VaultError     = "error"
)

// Defaults for the selection window and the CLI calls.
const (
	DefaultTTL            = 2 * time.Hour
	DefaultMinGap         = 25 * time.Minute
	DefaultPingTimeout    = 180 * time.Second
	DefaultCLILockTimeout = 30 * time.Second
	DefaultClaudeModel    = "claude-haiku-4-5-20251001"
)

// Grant is one live login keepalive may renew.
type Grant struct {
	Tool string
	Kind string
	Name string
	// Home is the HOME the provider CLI runs under for this grant.
	Home string
	// CredPath is the credential file the CLI reads and renews.
	CredPath string
	// CLILock is the CLI's own lock file next to the credential ("" if none).
	CLILock string
	// Env is applied after Scrub when running the CLI.
	Env   map[string]string
	Scrub []string
	// IdentityKeys are namespaced account keys ("uuid:…", "user:…", "email:…").
	IdentityKeys []string
	Identity     string
	// Files is the auth file set copied into a same-identity vault profile.
	Files authfile.AuthFileSet
}

// ID is the stable selector for a grant: <tool>/<kind>:<name>.
func (g Grant) ID() string { return g.Tool + "/" + g.Kind + ":" + g.Name }

// Config drives one keepalive run.
type Config struct {
	RealHome    string
	ShallowBase string // "" = shallow.DefaultBaseDir(RealHome)
	DataDir     string // caam data dir; locks and state live under <DataDir>/keepalive
	Vault       *authfile.Vault
	Profiles    *profile.Store // isolated profiles (grok); may be nil
	Tools       []string       // nil = all of Tools()
	TTL         time.Duration
	MinGap      time.Duration
	DryRun      bool
	// CLILockTimeout bounds the wait for the CLI's own lock before a vault copy.
	CLILockTimeout time.Duration
	Pinger         Pinger
	Now            func() time.Time
	Getenv         func(string) string
}

// Report is the machine-readable outcome of a run.
type Report struct {
	CheckedAt time.Time `json:"checked_at"`
	DryRun    bool      `json:"dry_run"`
	TTL       string    `json:"ttl"`
	MinGap    string    `json:"min_gap"`
	Grants    []Result  `json:"grants"`
	Pinged    int       `json:"pinged"`
	Rotated   int       `json:"rotated"`
	Failed    int       `json:"failed"`
	OK        bool      `json:"ok"`
}

// Result is one grant's outcome.
type Result struct {
	Grant        string      `json:"grant"`
	Tool         string      `json:"tool"`
	Kind         string      `json:"kind"`
	Name         string      `json:"name"`
	Identity     string      `json:"identity,omitempty"`
	ExpiresAt    *time.Time  `json:"expires_at,omitempty"`
	TTLSeconds   *int64      `json:"ttl_seconds,omitempty"`
	Action       string      `json:"action"`
	Reason       string      `json:"reason"`
	Pinged       bool        `json:"pinged"`
	Rotated      bool        `json:"rotated"`
	NewExpiresAt *time.Time  `json:"new_expires_at,omitempty"`
	Failed       bool        `json:"failed"`
	Error        string      `json:"error,omitempty"`
	Vault        []VaultSync `json:"vault,omitempty"`
}

// VaultSync is the outcome of copying a grant into one vault profile.
type VaultSync struct {
	Profile string `json:"profile"`
	Action  string `json:"action"`
	Reason  string `json:"reason,omitempty"`
}

// RefusalError reports a request keepalive will not carry out.
type RefusalError struct{ Msg string }

func (e *RefusalError) Error() string { return e.Msg }

func (c *Config) defaults() {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Getenv == nil {
		c.Getenv = os.Getenv
	}
	if c.TTL <= 0 {
		c.TTL = DefaultTTL
	}
	if c.MinGap < 0 {
		c.MinGap = 0
	}
	if c.CLILockTimeout <= 0 {
		c.CLILockTimeout = DefaultCLILockTimeout
	}
	if len(c.Tools) == 0 {
		c.Tools = Tools()
	}
}

func (c *Config) wants(tool string) bool {
	for _, t := range c.Tools {
		if t == tool {
			return true
		}
	}
	return false
}

// Run discovers the live grants, renews the ones that need it and syncs them
// into same-identity vault profiles. selectors (optional) narrow the run to
// named grants; a selector that names a vault profile is refused. The error is
// non-nil only for setup problems and refusals; per-grant failures are in the
// report.
func Run(ctx context.Context, cfg Config, selectors []string) (*Report, error) {
	cfg.defaults()
	if cfg.RealHome == "" {
		return nil, errors.New("keepalive: real HOME is not set")
	}
	if cfg.Vault == nil {
		return nil, errors.New("keepalive: vault is not initialized")
	}
	if cfg.Pinger == nil && !cfg.DryRun {
		return nil, errors.New("keepalive: no pinger configured")
	}

	inv, err := discover(&cfg)
	if err != nil {
		return nil, err
	}
	if len(selectors) > 0 {
		if err := inv.selectGrants(&cfg, selectors); err != nil {
			return nil, err
		}
	}

	report := &Report{
		CheckedAt: cfg.Now().UTC(),
		DryRun:    cfg.DryRun,
		TTL:       cfg.TTL.String(),
		MinGap:    cfg.MinGap.String(),
	}
	report.Grants = append(report.Grants, inv.preset...)
	for _, g := range inv.grants {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		report.Grants = append(report.Grants, renewGrant(ctx, &cfg, inv, g))
	}
	sort.SliceStable(report.Grants, func(i, j int) bool {
		a, b := report.Grants[i], report.Grants[j]
		if a.Tool != b.Tool {
			return toolRank(a.Tool) < toolRank(b.Tool)
		}
		return a.Grant < b.Grant
	})
	for _, r := range report.Grants {
		if r.Pinged {
			report.Pinged++
		}
		if r.Rotated {
			report.Rotated++
		}
		if r.Failed {
			report.Failed++
		}
	}
	report.OK = report.Failed == 0
	return report, nil
}

func toolRank(tool string) int {
	for i, t := range Tools() {
		if t == tool {
			return i
		}
	}
	return len(Tools())
}

// FailureSummary names every grant that could not be renewed and why.
func (r *Report) FailureSummary() string {
	var parts []string
	for _, g := range r.Grants {
		if g.Failed {
			parts = append(parts, fmt.Sprintf("%s: %s", g.Grant, g.Error))
		}
	}
	return strings.Join(parts, "; ")
}

// Decide is the TTL selection rule. A grant is pinged when its access token
// expires within ttl (or already has), unless it was pinged less than minGap
// ago and is still valid — an expired token is never held back by the gap.
func Decide(expiresAt, now time.Time, ttl, minGap time.Duration, lastPing time.Time) (ping bool, reason string) {
	if expiresAt.IsZero() {
		return true, "access-token expiry unknown"
	}
	left := expiresAt.Sub(now)
	if left > ttl {
		return false, fmt.Sprintf("fresh: %s left > ttl %s", fmtDur(left), ttl)
	}
	if left > 0 && !lastPing.IsZero() && now.Sub(lastPing) < minGap {
		return false, fmt.Sprintf("%s left, but pinged %s ago (< min-gap %s)", fmtDur(left), fmtDur(now.Sub(lastPing)), minGap)
	}
	if left <= 0 {
		return true, fmt.Sprintf("expired %s ago", fmtDur(-left))
	}
	return true, fmt.Sprintf("%s left <= ttl %s", fmtDur(left), ttl)
}

func fmtDur(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	d = d.Round(time.Minute)
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
	return fmt.Sprintf("%dh%02dm", int(d/time.Hour), int((d%time.Hour)/time.Minute))
}

// credState is what keepalive needs to know about a credential file.
type credState struct {
	Exists     bool
	ExpiresAt  time.Time
	HasAccess  bool
	HasRefresh bool
}

func readCred(tool, path string) (credState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return credState{}, nil
		}
		return credState{}, err
	}
	st := credState{Exists: true}
	switch tool {
	case "claude":
		var root struct {
			OAuth *struct {
				AccessToken  string  `json:"accessToken"`
				RefreshToken string  `json:"refreshToken"`
				ExpiresAt    float64 `json:"expiresAt"`
			} `json:"claudeAiOauth"`
		}
		if err := json.Unmarshal(data, &root); err != nil {
			return st, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
		}
		if root.OAuth == nil {
			return st, fmt.Errorf("%s has no claudeAiOauth block (API-key login?)", filepath.Base(path))
		}
		st.HasAccess = root.OAuth.AccessToken != ""
		st.HasRefresh = root.OAuth.RefreshToken != ""
		if root.OAuth.ExpiresAt > 0 {
			st.ExpiresAt = time.UnixMilli(int64(root.OAuth.ExpiresAt))
		}
	case "grok":
		info, err := health.ParseGrokExpiry(path)
		if err != nil {
			return st, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
		}
		st.HasAccess = true
		st.HasRefresh = info.HasRefreshToken
		st.ExpiresAt = info.ExpiresAt
	default:
		return st, fmt.Errorf("unsupported tool %q", tool)
	}
	return st, nil
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// renewGrant runs the whole per-grant pipeline: lock, select, ping, verify,
// sync to the vault.
func renewGrant(ctx context.Context, cfg *Config, inv *inventory, g Grant) Result {
	res := Result{Grant: g.ID(), Tool: g.Tool, Kind: g.Kind, Name: g.Name, Identity: g.Identity}
	fail := func(action, msg string) Result {
		res.Action = action
		res.Failed = true
		res.Error = msg
		if res.Reason == "" {
			res.Reason = msg
		}
		return res
	}

	unlock, busy, err := lockGrant(cfg.DataDir, g, cfg.DryRun)
	if err != nil {
		return fail(ActionError, fmt.Sprintf("lock grant: %v", err))
	}
	if busy {
		res.Action = ActionSkip
		res.Reason = "another caam keepalive is renewing this grant"
		return res
	}
	defer unlock()

	before, err := readCred(g.Tool, g.CredPath)
	if err != nil {
		return fail(ActionError, err.Error())
	}
	if !before.Exists {
		return fail(ActionError, fmt.Sprintf("no credential at %s: log in first", g.CredPath))
	}
	res.ExpiresAt = timePtr(before.ExpiresAt)
	now := cfg.Now()
	if !before.ExpiresAt.IsZero() {
		left := int64(before.ExpiresAt.Sub(now) / time.Second)
		res.TTLSeconds = &left
	}
	if !before.HasRefresh {
		return fail(ActionError, "credential has no refresh token: it cannot renew itself; log in again")
	}

	last := lastPing(cfg.DataDir, g)
	doPing, reason := Decide(before.ExpiresAt, now, cfg.TTL, cfg.MinGap, last)
	res.Reason = reason
	after := before

	switch {
	case !doPing:
		res.Action = ActionSkip
	case cfg.DryRun:
		res.Action = ActionWouldPing
	default:
		res.Action = ActionPing
		res.Pinged = true
		recordPing(cfg.DataDir, g, now)
		out := cfg.Pinger.Ping(ctx, g)
		after, err = readCred(g.Tool, g.CredPath)
		if err != nil {
			return fail(ActionPing, fmt.Sprintf("re-read credential after ping: %v", err))
		}
		if !after.Exists {
			return fail(ActionPing, fmt.Sprintf("the %s CLI removed the credential during its refresh (refresh token rejected?): log in again%s", g.Tool, out.suffix()))
		}
		res.NewExpiresAt = timePtr(after.ExpiresAt)
		res.Rotated = after.ExpiresAt.After(before.ExpiresAt)
		switch {
		case res.Rotated:
			res.Reason = fmt.Sprintf("%s; renewed, now %s left", reason, fmtDur(after.ExpiresAt.Sub(cfg.Now())))
		case after.ExpiresAt.After(cfg.Now()):
			// Both CLIs renew only a token that is expired or about to be,
			// so a still-valid token is routinely left as it is.
			res.Reason = fmt.Sprintf("%s; still valid, not rotated (the CLI renews only near expiry)%s", reason, out.suffix())
		default:
			return fail(ActionPing, fmt.Sprintf("still expired after running the %s CLI%s", g.Tool, out.suffix()))
		}
	}

	res.Vault = syncVault(cfg, inv, g, after)
	return res
}

// syncVault copies a live grant into every user vault profile of the same
// identity whose copy is older. It never crosses accounts and never writes
// system (_*) profiles.
func syncVault(cfg *Config, inv *inventory, g Grant, live credState) []VaultSync {
	targets := inv.vaultTargets(g)
	if len(targets) == 0 {
		return nil
	}
	var out []VaultSync
	for _, prof := range targets {
		vs := VaultSync{Profile: prof}
		snap, err := readCred(g.Tool, inv.vaultCredPath(g.Tool, prof))
		switch {
		case !live.HasAccess || !live.HasRefresh:
			vs.Action, vs.Reason = VaultSkipped, "live credential is incomplete"
		case err == nil && snap.Exists && !live.ExpiresAt.After(snap.ExpiresAt):
			vs.Action = VaultCurrent
		case cfg.DryRun:
			vs.Action, vs.Reason = VaultWouldSync, "vault copy is older than the live grant"
		default:
			vs.Action, vs.Reason = copyToVault(cfg, g, prof)
		}
		out = append(out, vs)
	}
	return out
}

func copyToVault(cfg *Config, g Grant, prof string) (string, string) {
	release, err := lockCLI(g.CLILock, cfg.CLILockTimeout)
	if err != nil {
		return VaultSkipped, fmt.Sprintf("%v; will retry next run", err)
	}
	defer release()
	// Re-check identity under the CLI lock: the CLI may have re-logged in.
	if keys := grantIdentityKeys(g); !sameIdentity(keys, g.IdentityKeys) {
		return VaultSkipped, "live identity changed during the run"
	}
	if err := cfg.Vault.Backup(g.Files, prof); err != nil {
		return VaultError, err.Error()
	}
	return VaultSynced, "copied live → vault"
}

// sameIdentity reports whether two key sets name the same account. When both
// sides know a stable account id, that id decides; otherwise any shared key
// (an email address) does.
func sameIdentity(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	for _, prefix := range []string{"uuid:", "user:"} {
		ia, ib := keyWithPrefix(a, prefix), keyWithPrefix(b, prefix)
		if ia != "" && ib != "" {
			return ia == ib
		}
	}
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func keyWithPrefix(keys []string, prefix string) string {
	for _, k := range keys {
		if strings.HasPrefix(k, prefix) {
			return k
		}
	}
	return ""
}

// grokIdentityKeys derives identity keys from a Grok auth.json.
func grokIdentityKeys(path string) []string {
	id, err := identity.ExtractFromGrokAuth(path)
	if err != nil || id == nil {
		return nil
	}
	var keys []string
	if v := strings.ToLower(strings.TrimSpace(id.AccountID)); v != "" && v != strings.ToLower(id.Email) {
		keys = append(keys, "user:"+v)
	}
	if v := strings.ToLower(strings.TrimSpace(id.Email)); v != "" && strings.Contains(v, "@") {
		keys = append(keys, "email:"+v)
	}
	return keys
}

func grantIdentityKeys(g Grant) []string {
	switch g.Tool {
	case "claude":
		return authfile.ClaudeIdentityKeysFromFile(claudeStatePath(g))
	case "grok":
		return grokIdentityKeys(g.CredPath)
	}
	return nil
}

func identityLabel(keys []string) string {
	for _, prefix := range []string{"email:", "uuid:", "user:"} {
		if k := keyWithPrefix(keys, prefix); k != "" {
			return strings.TrimPrefix(k, prefix)
		}
	}
	return ""
}

// claudeStatePath is the .claude.json that carries a Claude grant's identity.
func claudeStatePath(g Grant) string {
	return filepath.Join(g.Home, ".claude.json")
}

// shallowManager builds the shallow profile manager for cfg.
func shallowManager(cfg *Config) (*shallow.Manager, error) {
	base := cfg.ShallowBase
	if base == "" {
		base = shallow.DefaultBaseDir(cfg.RealHome)
	}
	return shallow.NewManager(base, cfg.RealHome)
}
