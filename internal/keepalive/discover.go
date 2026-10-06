package keepalive

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/authfile"
	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/shallow"
)

// Variables scrubbed from every CLI run: an API key or token in the
// environment would make the CLI authenticate with it instead of the
// credential file we are trying to renew, and the nested-session markers of
// a parent Claude Code would leak into the ping.
var alwaysScrub = []string{
	"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
	"CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_SSE_PORT",
	"GROK_AUTH", "GROK_AUTH_PATH", "XAI_API_KEY", "GROK_API_KEY",
	"SHALLOW_PROFILE",
}

// inventory is everything discovery learned: the grants to renew, results
// already decided (collisions, host logins owned by a shallow profile), and
// which vault profiles belong to which grant.
type inventory struct {
	grants []Grant
	preset []Result
	// all live grants found, including refused ones, for ownership checks.
	live []Grant
	// vault[tool] = user (non-system) vault profiles of that tool.
	vault map[string][]string
	// vaultKeys[tool][profile] = identity keys of that vault profile.
	vaultKeys map[string]map[string][]string
	v         *authfile.Vault
}

func discover(cfg *Config) (*inventory, error) {
	inv := &inventory{
		vault:     map[string][]string{},
		vaultKeys: map[string]map[string][]string{},
		v:         cfg.Vault,
	}
	for _, tool := range Tools() {
		if !cfg.wants(tool) {
			continue
		}
		if err := inv.loadVault(tool); err != nil {
			return nil, err
		}
	}
	if cfg.wants("claude") {
		if err := inv.discoverClaude(cfg); err != nil {
			return nil, err
		}
	}
	if cfg.wants("grok") {
		if err := inv.discoverGrok(cfg); err != nil {
			return nil, err
		}
	}
	inv.refuseSharedFamilies()
	return inv, nil
}

func (inv *inventory) loadVault(tool string) error {
	profiles, err := inv.v.List(tool)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("list %s vault: %w", tool, err)
	}
	keys := map[string][]string{}
	for _, p := range profiles {
		if authfile.IsSystemProfile(p) {
			continue
		}
		inv.vault[tool] = append(inv.vault[tool], p)
		switch tool {
		case "claude":
			keys[p] = inv.v.ClaudeProfileIdentityKeys(p)
		case "grok":
			keys[p] = grokIdentityKeys(inv.vaultCredPath(tool, p))
		}
	}
	sort.Strings(inv.vault[tool])
	inv.vaultKeys[tool] = keys
	return nil
}

func (inv *inventory) vaultCredPath(tool, prof string) string {
	switch tool {
	case "claude":
		return inv.v.BackupPath(tool, prof, ".credentials.json")
	default:
		return inv.v.BackupPath(tool, prof, "auth.json")
	}
}

func (inv *inventory) discoverClaude(cfg *Config) error {
	mgr, err := shallowManager(cfg)
	if err != nil {
		return fmt.Errorf("shallow profiles: %w", err)
	}
	profiles, err := mgr.List()
	if err != nil {
		return fmt.Errorf("list shallow profiles: %w", err)
	}
	var shallowGrants []Grant
	for _, p := range profiles {
		provider, err := mgr.ResolveProvider(p.Name)
		if err != nil || shallow.NormalizeProvider(provider) != "claude" {
			continue // another provider's profile, or one shallow-spawn would refuse too
		}
		set, scrub := shallow.SpawnEnv("claude", p.Path, p.Name, false, false)
		g := Grant{
			Tool:     "claude",
			Kind:     KindShallow,
			Name:     p.Name,
			Home:     p.Path,
			CredPath: filepath.Join(p.Path, ".claude", ".credentials.json"),
			CLILock:  filepath.Join(p.Path, ".claude", ".credentials.lock"),
			Env:      set,
			Scrub:    append(scrub, alwaysScrub...),
		}
		g.Files = claudeFiles(g.Home)
		g.IdentityKeys = authfile.ClaudeIdentityKeysFromFile(claudeStatePath(g))
		g.Identity = identityLabel(g.IdentityKeys)
		shallowGrants = append(shallowGrants, g)
	}
	inv.live = append(inv.live, shallowGrants...)
	inv.grants = append(inv.grants, shallowGrants...)

	// The real-HOME login. A shallow profile of the same account owns the
	// grant (the shallow profiles are the live Claude logins); the host copy
	// of that family is left alone rather than replayed.
	home := cfg.RealHome
	cred := filepath.Join(home, ".claude", ".credentials.json")
	if _, err := os.Stat(cred); err != nil {
		return nil
	}
	g := Grant{
		Tool:     "claude",
		Kind:     KindLive,
		Name:     "live",
		Home:     home,
		CredPath: cred,
		CLILock:  existingOrEmpty(filepath.Join(home, ".claude", ".credentials.lock")),
		Env:      map[string]string{"HOME": home, "CLAUDE_CODE_DISABLE_AGENT_VIEW": "1"},
		Scrub:    append([]string{"CLAUDE_CONFIG_DIR", "CAAM_HOME", "XDG_DATA_HOME"}, alwaysScrub...),
	}
	g.Files = claudeFiles(home)
	g.IdentityKeys = authfile.ClaudeIdentityKeysFromFile(claudeStatePath(g))
	g.Identity = identityLabel(g.IdentityKeys)
	if len(g.IdentityKeys) == 0 {
		inv.preset = append(inv.preset, presetResult(g, ActionSkip, false,
			"host login has no readable identity in ~/.claude.json; not pinged because its ownership cannot be checked"))
		return nil
	}
	for _, s := range shallowGrants {
		if sameIdentity(g.IdentityKeys, s.IdentityKeys) {
			inv.preset = append(inv.preset, presetResult(g, ActionSkip, false,
				fmt.Sprintf("same account as shallow profile %q, which owns this grant; the host copy shares its refresh-token family and is not replayed", s.Name)))
			return nil
		}
	}
	inv.live = append(inv.live, g)
	inv.grants = append(inv.grants, g)
	return nil
}

func claudeFiles(home string) authfile.AuthFileSet {
	return authfile.AuthFileSet{
		Tool: "claude",
		Files: []authfile.AuthFileSpec{
			{Tool: "claude", Path: filepath.Join(home, ".claude", ".credentials.json"), Description: "Claude Code OAuth credentials", Required: true},
			{Tool: "claude", Path: filepath.Join(home, ".claude.json"), Description: "Claude Code settings and session state"},
		},
	}
}

func grokFiles(grokHome string) authfile.AuthFileSet {
	return authfile.AuthFileSet{
		Tool: "grok",
		Files: []authfile.AuthFileSpec{
			{Tool: "grok", Path: filepath.Join(grokHome, "auth.json"), Description: "Grok Build CLI login credential", Required: true},
			{Tool: "grok", Path: filepath.Join(grokHome, "config.toml"), Description: "Grok Build CLI configuration"},
		},
	}
}

func existingOrEmpty(path string) string {
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return ""
}

func (inv *inventory) discoverGrok(cfg *Config) error {
	// The active login: $GROK_HOME, else ~/.grok.
	grokHome := strings.TrimSpace(cfg.Getenv("GROK_HOME"))
	env := map[string]string{"HOME": cfg.RealHome}
	if grokHome != "" {
		env["GROK_HOME"] = grokHome
	} else {
		grokHome = filepath.Join(cfg.RealHome, ".grok")
	}
	if _, err := os.Stat(filepath.Join(grokHome, "auth.json")); err == nil {
		inv.addGrok(Grant{Tool: "grok", Kind: KindLive, Name: "live", Home: cfg.RealHome, Env: env}, grokHome)
	}

	// caam isolated profiles: HOME=<profile>/home, GROK_HOME=<home>/.grok.
	if cfg.Profiles == nil {
		return nil
	}
	profs, err := cfg.Profiles.List("grok")
	if err != nil {
		return fmt.Errorf("list grok profiles: %w", err)
	}
	for _, p := range profs {
		home := p.HomePath()
		gh := filepath.Join(home, ".grok")
		if _, err := os.Stat(filepath.Join(gh, "auth.json")); err != nil {
			continue
		}
		inv.addGrok(Grant{Tool: "grok", Kind: KindProfile, Name: p.Name, Home: home,
			Env: map[string]string{"HOME": home, "GROK_HOME": gh}}, gh)
	}
	return nil
}

func (inv *inventory) addGrok(g Grant, grokHome string) {
	g.CredPath = filepath.Join(grokHome, "auth.json")
	g.CLILock = existingOrEmpty(filepath.Join(grokHome, "auth.json.lock"))
	g.Scrub = append([]string{"GROK_HOME"}, alwaysScrub...)
	g.Files = grokFiles(grokHome)
	g.IdentityKeys = grokIdentityKeys(g.CredPath)
	g.Identity = identityLabel(g.IdentityKeys)
	inv.live = append(inv.live, g)
	inv.grants = append(inv.grants, g)
}

// refuseSharedFamilies refuses every live grant that shares an account with
// another live grant of the same tool. Two homes holding one refresh-token
// family invalidate each other; pinging the stale one replays a spent refresh
// token, which can revoke the family for both.
func (inv *inventory) refuseSharedFamilies() {
	var keep []Grant
	for i, g := range inv.grants {
		var others []string
		for j, h := range inv.grants {
			if i != j && g.Tool == h.Tool && sameIdentity(g.IdentityKeys, h.IdentityKeys) {
				others = append(others, h.ID())
			}
		}
		if len(others) == 0 {
			keep = append(keep, g)
			continue
		}
		r := presetResult(g, ActionRefused, true, "")
		r.Error = fmt.Sprintf("same account as %s: two live homes share one refresh-token family and invalidate each other; log one of them in to a different account (or delete it) before keepalive will touch either", strings.Join(others, ", "))
		r.Reason = r.Error
		inv.preset = append(inv.preset, r)
	}
	inv.grants = keep
}

func presetResult(g Grant, action string, failed bool, reason string) Result {
	return Result{Grant: g.ID(), Tool: g.Tool, Kind: g.Kind, Name: g.Name, Identity: g.Identity,
		Action: action, Failed: failed, Reason: reason}
}

// vaultTargets lists the user vault profiles that hold the same account as g.
func (inv *inventory) vaultTargets(g Grant) []string {
	var out []string
	for _, p := range inv.vault[g.Tool] {
		if sameIdentity(g.IdentityKeys, inv.vaultKeys[g.Tool][p]) {
			out = append(out, p)
		}
	}
	return out
}

// vaultOwner returns the live grant that owns vault profile tool/prof, if any.
func (inv *inventory) vaultOwner(tool, prof string) (Grant, bool) {
	keys := inv.vaultKeys[tool][prof]
	if keys == nil {
		switch tool {
		case "claude":
			keys = inv.v.ClaudeProfileIdentityKeys(prof)
		case "grok":
			keys = grokIdentityKeys(inv.vaultCredPath(tool, prof))
		}
	}
	for _, g := range inv.live {
		if g.Tool == tool && sameIdentity(g.IdentityKeys, keys) {
			return g, true
		}
	}
	return Grant{}, false
}

// selectGrants narrows the run to the named grants. A selector is a grant ID
// (claude/shallow:A), <tool>/<name>, or a bare name. A selector that names a
// vault profile ("vault:<tool>/<profile>", or a name that only matches the
// vault) is refused: keepalive renews live grants only.
func (inv *inventory) selectGrants(cfg *Config, selectors []string) error {
	chosen := map[string]bool{}
	for _, raw := range selectors {
		sel := strings.TrimSpace(raw)
		if sel == "" {
			continue
		}
		if strings.HasPrefix(sel, "vault:") {
			tool, prof, ok := strings.Cut(strings.TrimPrefix(sel, "vault:"), "/")
			if !ok || tool == "" || prof == "" {
				return &RefusalError{Msg: fmt.Sprintf("keepalive: %q: want vault:<tool>/<profile>", sel)}
			}
			return inv.refuseVault(tool, prof)
		}
		matched := false
		for _, g := range append(append([]Grant{}, inv.grants...), presetGrants(inv.preset)...) {
			if selectorMatches(sel, g) {
				chosen[g.ID()] = true
				matched = true
			}
		}
		if matched {
			continue
		}
		tool, name, hasTool := strings.Cut(sel, "/")
		if !hasTool {
			tool, name = "", sel
		}
		for _, t := range Tools() {
			if tool != "" && tool != t {
				continue
			}
			for _, p := range inv.vault[t] {
				if p == name {
					return inv.refuseVault(t, p)
				}
			}
		}
		return fmt.Errorf("keepalive: no live grant matches %q (see `caam keepalive --dry-run` for the grants on this host)", sel)
	}
	var grants []Grant
	for _, g := range inv.grants {
		if chosen[g.ID()] {
			grants = append(grants, g)
		}
	}
	var preset []Result
	for _, r := range inv.preset {
		if chosen[r.Grant] {
			preset = append(preset, r)
		}
	}
	inv.grants, inv.preset = grants, preset
	return nil
}

// presetGrants turns preset results back into selector-matchable grants.
func presetGrants(rs []Result) []Grant {
	out := make([]Grant, 0, len(rs))
	for _, r := range rs {
		out = append(out, Grant{Tool: r.Tool, Kind: r.Kind, Name: r.Name})
	}
	return out
}

func selectorMatches(sel string, g Grant) bool {
	if sel == g.ID() || sel == g.Tool+"/"+g.Name || sel == g.Name || sel == g.Tool+"/"+g.Kind+":"+g.Name {
		return true
	}
	return sel == g.Kind+":"+g.Name
}

func (inv *inventory) refuseVault(tool, prof string) error {
	if owner, ok := inv.vaultOwner(tool, prof); ok {
		return &RefusalError{Msg: fmt.Sprintf(
			"keepalive: refusing to ping vault profile %s/%s: its account is owned by the live grant %s, so the vault copy holds a spent (or soon spent) single-use refresh token, and replaying it can revoke the whole token family. keepalive renews %s in place and copies it into the vault; run `caam keepalive %s` instead",
			tool, prof, owner.ID(), owner.ID(), owner.ID())}
	}
	return &RefusalError{Msg: fmt.Sprintf(
		"keepalive: refusing to ping vault profile %s/%s: keepalive renews live grants only and never replays a vault copy. To keep this account alive, give it a live home (e.g. `caam shallow-profile create <name> --from-vault %s/%s`) and keepalive will renew it there",
		tool, prof, tool, prof)}
}
