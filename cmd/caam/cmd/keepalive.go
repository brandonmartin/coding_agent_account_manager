package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/config"
	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/keepalive"
	"github.com/spf13/cobra"
)

var keepaliveCmd = &cobra.Command{
	Use:   "keepalive [grant...]",
	Short: "Keep self-refreshing logins (claude, grok) alive in place",
	Long: `Renew every live Claude and Grok login whose access token is expired or about
to expire, by running the provider CLI's cheapest call inside that login's own
HOME, so the CLI renews the grant itself.

caam can refresh codex and gemini directly ('caam refresh'), but not claude or
grok: only their CLIs renew a grant. An idle account's access token therefore
expires and nothing renews it — 'caam limits' fails, routers mark the account
stale and stop using it, and nothing ever runs the CLI again. Run keepalive
from a timer (see --print-systemd) to break that loop.

Live grants:
  claude   every shallow profile (run as 'caam shallow-spawn <name>' would),
           and the real-HOME login unless a shallow profile holds the same
           account (the shallow profile owns it)
  grok     the active login ($GROK_HOME, default ~/.grok) and any isolated
           grok profiles ('caam profile add grok …')

A grant is pinged when its access token has --ttl or less left (or has
expired), at most once per --min-gap while it is still valid:
  claude   claude -p <one word> --model <--claude-model> --effort low
           --no-session-persistence --strict-mcp-config --setting-sources project
  grok     grok models   (no model turn; renews an expired token on startup)
Both CLIs renew only a token that is at or near expiry, so a ping of a
still-valid token is often a no-op; the next run after expiry renews it.

After a run the credential is re-read and reported as rotated or not. A user
vault profile of the SAME account is then brought up to date from the live
grant (like 'caam backup'); different accounts and system (_*) profiles are
never written.

keepalive never pings a vault copy: refresh tokens are single use, so the vault
copy of a live grant holds a spent one, and replaying it can revoke the whole
token family. Naming a vault profile is refused. Two live homes on the same
account are refused too: they invalidate each other.

Each grant is locked while it is renewed, so the timer and a manual run never
collide; the CLI's own lock (.claude/.credentials.lock, ~/.grok/auth.json.lock)
is taken while a credential is copied, never while the CLI runs.

Exit status is non-zero only when a grant could not be renewed (expired after
the ping, no refresh token, removed by the CLI, shared family); the message
names each one and why.

Examples:
  caam keepalive --dry-run
  caam keepalive
  caam keepalive --tool grok --json
  caam keepalive A                  # one shallow profile
  caam keepalive --print-systemd    # user service + timer
  caam keepalive --write-systemd ~/.config/systemd/user`,
	RunE: runKeepalive,
}

func init() {
	addKeepaliveFlags(keepaliveCmd)
	rootCmd.AddCommand(keepaliveCmd)
}

func addKeepaliveFlags(c *cobra.Command) {
	c.Flags().Bool("dry-run", false, "report what would be pinged and synced; run nothing, write nothing")
	c.Flags().StringSlice("tool", nil, "limit to these tools (claude, grok); repeatable or comma-separated")
	c.Flags().Duration("ttl", keepalive.DefaultTTL, "ping a grant whose access token has this much time or less left")
	c.Flags().Duration("min-gap", keepalive.DefaultMinGap, "minimum time between pings of a still-valid grant")
	c.Flags().Duration("timeout", keepalive.DefaultPingTimeout, "time limit for one CLI call (SIGTERM, then SIGKILL 20s later)")
	c.Flags().String("claude-model", keepalive.DefaultClaudeModel, "model for the claude ping")
	c.Flags().String("base", "", "shallow profiles base dir (default: $CAAM_SHALLOW_HOMES_DIR or ~/orch-homes)")
	c.Flags().Bool("json", false, "machine-readable output")
	c.Flags().Bool("print-systemd", false, "print a systemd user service and timer for keepalive and exit")
	c.Flags().String("write-systemd", "", "write caam-keepalive.service and .timer into this directory and exit")
}

func runKeepalive(cmd *cobra.Command, args []string) error {
	if p, _ := cmd.Flags().GetBool("print-systemd"); p {
		return printKeepaliveSystemd(cmd.OutOrStdout())
	}
	if dir, _ := cmd.Flags().GetString("write-systemd"); strings.TrimSpace(dir) != "" {
		return writeKeepaliveSystemd(cmd.OutOrStdout(), dir)
	}
	jsonOut, _ := cmd.Flags().GetBool("json")
	fail := func(err error) error {
		if jsonOut {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			_ = enc.Encode(map[string]any{"ok": false, "error": err.Error()})
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
		}
		return err
	}

	if sp := os.Getenv("SHALLOW_PROFILE"); sp != "" {
		return fail(fmt.Errorf("keepalive must run from your real HOME, not inside shallow profile %q (its HOME hides the vault and the other profiles)", sp))
	}
	realHome, err := os.UserHomeDir()
	if err != nil {
		return fail(fmt.Errorf("resolve HOME: %w", err))
	}
	tools, err := keepaliveTools(cmd)
	if err != nil {
		return fail(err)
	}
	if vault == nil {
		return fail(errors.New("vault not initialized"))
	}

	ttl, _ := cmd.Flags().GetDuration("ttl")
	minGap, _ := cmd.Flags().GetDuration("min-gap")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	model, _ := cmd.Flags().GetString("claude-model")
	base, _ := cmd.Flags().GetString("base")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	dataDir := config.DefaultDataPath()

	cfg := keepalive.Config{
		RealHome:    realHome,
		ShallowBase: strings.TrimSpace(base),
		DataDir:     dataDir,
		Vault:       vault,
		Profiles:    profileStore,
		Tools:       tools,
		TTL:         ttl,
		MinGap:      minGap,
		DryRun:      dryRun,
		Pinger: keepalive.ExecPinger{
			ClaudeModel: model,
			Timeout:     timeout,
			WorkDir:     filepath.Join(dataDir, "keepalive", "cwd"),
		},
	}
	report, err := keepalive.Run(cmd.Context(), cfg, args)
	if err != nil {
		return fail(err)
	}

	if jsonOut {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		renderKeepalive(cmd.OutOrStdout(), report)
	}
	if !report.OK {
		cmd.SilenceUsage = true
		if jsonOut {
			cmd.SilenceErrors = true
			fmt.Fprintf(cmd.ErrOrStderr(), "caam keepalive: %d grant(s) could not be renewed: %s\n", report.Failed, report.FailureSummary())
		}
		return fmt.Errorf("%d grant(s) could not be renewed: %s", report.Failed, report.FailureSummary())
	}
	return nil
}

func keepaliveTools(cmd *cobra.Command) ([]string, error) {
	raw, _ := cmd.Flags().GetStringSlice("tool")
	var tools []string
	for _, t := range raw {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		ok := false
		for _, known := range keepalive.Tools() {
			if t == known {
				ok = true
			}
		}
		if !ok {
			hint := ""
			switch t {
			case "codex", "gemini":
				hint = "; caam refreshes it directly: caam refresh " + t
			case "cursor":
				hint = "; cursor-agent has no refresh path for session logins"
			}
			return nil, fmt.Errorf("keepalive does not handle %q (supported: %s)%s", t, strings.Join(keepalive.Tools(), ", "), hint)
		}
		tools = append(tools, t)
	}
	return tools, nil
}

func renderKeepalive(w io.Writer, r *keepalive.Report) {
	mode := ""
	if r.DryRun {
		mode = " (dry run)"
	}
	fmt.Fprintf(w, "caam keepalive%s: ttl %s, min-gap %s\n", mode, r.TTL, r.MinGap)
	if len(r.Grants) == 0 {
		fmt.Fprintln(w, "  no live claude or grok grants found")
		return
	}
	for _, g := range r.Grants {
		left := ""
		if g.TTLSeconds != nil {
			d := (time.Duration(*g.TTLSeconds) * time.Second).Round(time.Minute)
			if d < 0 {
				left = " [expired " + strings.TrimSuffix((-d).String(), "0s") + " ago]"
			} else {
				left = " [" + strings.TrimSuffix(d.String(), "0s") + " left]"
			}
		}
		who := ""
		if g.Identity != "" {
			who = " (" + g.Identity + ")"
		}
		status := g.Action
		switch {
		case g.Failed:
			status = "FAILED"
		case g.Rotated:
			status = "renewed"
		}
		fmt.Fprintf(w, "  %-8s %s%s%s: %s\n", status, g.Grant, who, left, g.Reason)
		for _, v := range g.Vault {
			reason := ""
			if v.Reason != "" {
				reason = ": " + v.Reason
			}
			fmt.Fprintf(w, "           vault %s/%s %s%s\n", g.Tool, v.Profile, v.Action, reason)
		}
	}
	fmt.Fprintf(w, "pinged %d, renewed %d, failed %d\n", r.Pinged, r.Rotated, r.Failed)
}

const (
	keepaliveServiceName = "caam-keepalive.service"
	keepaliveTimerName   = "caam-keepalive.timer"
)

// keepaliveSystemdUnits renders the user service and timer. The timer is
// wall-clock anchored (OnCalendar + Persistent): OnBootSec/OnUnitActiveSec
// alone leave a timer with no next run after the user manager restarts.
func keepaliveSystemdUnits() (service, timer string, err error) {
	self, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	// Keep a symlinked install (~/.local/bin/caam -> …) on its stable path.
	if onPath, err := exec.LookPath("caam"); err == nil {
		if r, err := filepath.EvalSymlinks(onPath); err == nil && r == self {
			self = onPath
		}
	}
	home, _ := os.UserHomeDir()
	short := func(p string) string {
		if home != "" && strings.HasPrefix(p, home+string(filepath.Separator)) {
			return "%h" + strings.TrimPrefix(p, home)
		}
		return p
	}
	var dirs []string
	seen := map[string]bool{}
	add := func(d string) {
		if d = short(d); d != "" && !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	add(filepath.Dir(self))
	for _, bin := range []string{"claude", "grok"} {
		if p, err := exec.LookPath(bin); err == nil {
			add(filepath.Dir(p))
		}
	}
	for _, d := range []string{"/usr/local/bin", "/usr/bin", "/bin"} {
		add(d)
	}

	service = fmt.Sprintf(`[Unit]
Description=caam keepalive: renew idle claude/grok logins in place
Documentation=https://github.com/Dicklesworthstone/coding_agent_account_manager
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Nice=10
TimeoutStartSec=15min
# The provider CLIs (claude, grok) must be on PATH.
Environment=PATH=%s
ExecStart=%s keepalive
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
`, strings.Join(dirs, ":"), short(self))

	timer = `[Unit]
Description=Run caam keepalive every 30 minutes

[Timer]
# Wall-clock anchor: re-arms after a user-manager restart, and Persistent
# catches up a run missed while the machine was off. Do not use
# OnBootSec/OnUnitActiveSec alone; they can leave the timer with no next run.
OnCalendar=*:0/30
Persistent=true
AccuracySec=1min
Unit=` + keepaliveServiceName + `

[Install]
WantedBy=timers.target
`
	return service, timer, nil
}

func printKeepaliveSystemd(w io.Writer) error {
	service, timer, err := keepaliveSystemdUnits()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "# ---- ~/.config/systemd/user/%s ----\n%s\n# ---- ~/.config/systemd/user/%s ----\n%s\n", keepaliveServiceName, service, keepaliveTimerName, timer)
	fmt.Fprintf(w, "# Install with: caam keepalive --write-systemd ~/.config/systemd/user\n#   systemctl --user daemon-reload && systemctl --user enable --now %s\n", keepaliveTimerName)
	return nil
}

// writeKeepaliveSystemd writes both units into dir (atomically, 0644).
func writeKeepaliveSystemd(w io.Writer, dir string) error {
	service, timer, err := keepaliveSystemdUnits()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, body := range map[string]string{keepaliveServiceName: service, keepaliveTimerName: timer} {
		path := filepath.Join(dir, name)
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
		fmt.Fprintf(w, "wrote %s\n", path)
	}
	fmt.Fprintf(w, "next: systemctl --user daemon-reload && systemctl --user enable --now %s\n", keepaliveTimerName)
	return nil
}
