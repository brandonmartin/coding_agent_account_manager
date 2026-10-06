package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestKeepaliveSystemdUnitsAreWallClockAnchored(t *testing.T) {
	service, timer, err := keepaliveSystemdUnits()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"OnCalendar=*:0/30", "Persistent=true", "Unit=" + keepaliveServiceName, "WantedBy=timers.target"} {
		if !strings.Contains(timer, want) {
			t.Fatalf("timer missing %q:\n%s", want, timer)
		}
	}
	// OnBootSec/OnUnitActiveSec alone stranded the old timer; they must not
	// be the schedule.
	for _, bad := range []string{"\nOnBootSec=", "\nOnUnitActiveSec="} {
		if strings.Contains(timer, bad) {
			t.Fatalf("timer must not use %q:\n%s", strings.TrimSpace(bad), timer)
		}
	}
	for _, want := range []string{"Type=oneshot", " keepalive\n", "Environment=PATH="} {
		if !strings.Contains(service, want) {
			t.Fatalf("service missing %q:\n%s", want, service)
		}
	}
}

func TestKeepaliveWriteSystemd(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := writeKeepaliveSystemd(&out, dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{keepaliveServiceName, keepaliveTimerName} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s not written: %v", name, err)
		}
	}
	if !strings.Contains(out.String(), "enable --now "+keepaliveTimerName) {
		t.Fatalf("missing next step: %s", out.String())
	}
}

func newKeepaliveTestCmd() *cobra.Command {
	c := &cobra.Command{Use: "keepalive", RunE: runKeepalive}
	addKeepaliveFlags(c)
	return c
}

func TestKeepaliveRejectsUnsupportedTool(t *testing.T) {
	t.Setenv("SHALLOW_PROFILE", "")
	c := newKeepaliveTestCmd()
	if err := c.Flags().Set("tool", "cursor"); err != nil {
		t.Fatal(err)
	}
	err := runKeepalive(c, nil)
	if err == nil || !strings.Contains(err.Error(), "cursor-agent has no refresh path") {
		t.Fatalf("cursor: %v", err)
	}
}

func TestKeepaliveRefusesInsideShallowProfile(t *testing.T) {
	t.Setenv("SHALLOW_PROFILE", "A")
	err := runKeepalive(newKeepaliveTestCmd(), nil)
	if err == nil || !strings.Contains(err.Error(), "real HOME") {
		t.Fatalf("expected refusal inside a shallow profile: %v", err)
	}
}
