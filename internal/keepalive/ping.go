package keepalive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Pinger runs a provider CLI's cheapest call that makes it renew its own
// grant.
type Pinger interface {
	Ping(ctx context.Context, g Grant) PingOutcome
}

// PingOutcome is what the CLI call reported. Success is judged by re-reading
// the credential, not by this: the Grok CLI exits 0 even after its refresh
// was rejected and it deleted the credential.
type PingOutcome struct {
	Err    error
	Detail string // last line of CLI stderr, redacted
}

func (o PingOutcome) suffix() string {
	switch {
	case o.Err != nil && o.Detail != "":
		return fmt.Sprintf(" (CLI: %v: %s)", o.Err, o.Detail)
	case o.Err != nil:
		return fmt.Sprintf(" (CLI: %v)", o.Err)
	case o.Detail != "":
		return fmt.Sprintf(" (CLI: %s)", o.Detail)
	}
	return ""
}

// ExecPinger runs the real provider CLIs.
type ExecPinger struct {
	ClaudeBin   string
	GrokBin     string
	ClaudeModel string
	Timeout     time.Duration
	// WorkDir is the (empty, caam-owned) working directory for the call.
	WorkDir string
	// Environ is the base environment (default os.Environ()).
	Environ []string
}

// Command returns the argv keepalive runs for a tool:
//
//   - claude: a one-word headless prompt on the cheapest model, with no
//     session persistence, no MCP servers and only project settings (from an
//     empty directory), so no user hooks fire. Claude Code renews an expired
//     access token before the request.
//   - grok: `grok models` — no model turn. Verified on grok 1.0.46: its
//     startup auth path runs a PreRequest OIDC refresh when the stored access
//     token is expired ("oidc refresh enter" reason=PreRequest is_expired=true
//     in ~/.grok/logs/unified.jsonl), writes the new token under
//     auth.json.lock, and logs auth.refresh.success.
func (p ExecPinger) Command(tool string) ([]string, error) {
	switch tool {
	case "claude":
		bin := p.ClaudeBin
		if bin == "" {
			bin = "claude"
		}
		model := p.ClaudeModel
		if model == "" {
			model = DefaultClaudeModel
		}
		return []string{bin,
			"-p", "Reply with the single word pong and nothing else.",
			"--output-format", "text",
			"--model", model,
			"--effort", "low",
			"--permission-mode", "dontAsk",
			"--no-session-persistence",
			"--strict-mcp-config",
			"--setting-sources", "project",
		}, nil
	case "grok":
		bin := p.GrokBin
		if bin == "" {
			bin = "grok"
		}
		return []string{bin, "models"}, nil
	}
	return nil, fmt.Errorf("no keepalive call for tool %q", tool)
}

// Ping implements Pinger.
func (p ExecPinger) Ping(ctx context.Context, g Grant) PingOutcome {
	argv, err := p.Command(g.Tool)
	if err != nil {
		return PingOutcome{Err: err}
	}
	bin, err := exec.LookPath(argv[0])
	if err != nil {
		return PingOutcome{Err: fmt.Errorf("find %s: %w", argv[0], err)}
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = DefaultPingTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, argv[1:]...)
	cmd.Env = GrantEnv(p.Environ, g)
	if p.WorkDir != "" {
		if err := os.MkdirAll(p.WorkDir, 0o700); err == nil {
			cmd.Dir = p.WorkDir
		}
	}
	cmd.Stdin = nil
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// SIGTERM first, SIGKILL if the CLI ignores it.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 20 * time.Second

	runErr := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		runErr = fmt.Errorf("timed out after %s", timeout)
	}
	detail := lastLine(stderr.String())
	if detail == "" && runErr != nil {
		detail = lastLine(stdout.String())
	}
	return PingOutcome{Err: runErr, Detail: Redact(detail)}
}

// GrantEnv builds the CLI environment for a grant: the base environment with
// g.Scrub removed, then g.Env applied (so a pinned variable always wins).
func GrantEnv(base []string, g Grant) []string {
	if base == nil {
		base = os.Environ()
	}
	scrub := map[string]bool{}
	for _, k := range g.Scrub {
		scrub[k] = true
	}
	var env []string
	for _, kv := range base {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || scrub[k] {
			continue
		}
		if _, pinned := g.Env[k]; pinned {
			continue
		}
		env = append(env, kv)
	}
	for k, v := range g.Env {
		env = append(env, k+"="+v)
	}
	return env
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			if len(l) > 300 {
				l = l[:300] + "…"
			}
			return l
		}
	}
	return ""
}

var tokenish = regexp.MustCompile(`[A-Za-z0-9_\-\.]{32,}`)

// Redact masks long token-shaped runs so CLI output never leaks a credential
// into keepalive's report or journal.
func Redact(s string) string {
	return tokenish.ReplaceAllString(s, "<redacted>")
}

// --- per-grant state -------------------------------------------------------

func grantFileStem(g Grant) string {
	var b strings.Builder
	for _, r := range g.Tool + "-" + g.Kind + "-" + g.Name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.', r == '@', r == '+':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

func statePath(dataDir string, g Grant) string {
	return filepath.Join(dataDir, "keepalive", "grants", grantFileStem(g)+".last-ping")
}

// lastPing returns when keepalive last ran the CLI for g (zero if never).
func lastPing(dataDir string, g Grant) time.Time {
	if dataDir == "" {
		return time.Time{}
	}
	data, err := os.ReadFile(statePath(dataDir, g))
	if err != nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
	if err != nil {
		return time.Time{}
	}
	return t
}

func recordPing(dataDir string, g Grant, at time.Time) {
	if dataDir == "" {
		return
	}
	path := statePath(dataDir, g)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(at.UTC().Format(time.RFC3339)+"\n"), 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}
