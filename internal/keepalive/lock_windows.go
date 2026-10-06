//go:build windows

package keepalive

import "time"

// Windows has no flock; keepalive runs unlocked there (the systemd timer it
// is built for is Linux-only).
func lockGrant(dataDir string, g Grant, dryRun bool) (func(), bool, error) {
	return func() {}, false, nil
}

func lockCLI(path string, timeout time.Duration) (func(), error) {
	return func() {}, nil
}
