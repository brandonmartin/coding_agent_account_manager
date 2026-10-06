//go:build !windows

package keepalive

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// lockGrant takes caam's own exclusive, non-blocking lock for one grant, so
// two keepalive runs (a timer and a manual run) never renew the same grant at
// once. busy is true when another run holds it. A dry run takes no lock and
// writes nothing.
func lockGrant(dataDir string, g Grant, dryRun bool) (unlock func(), busy bool, err error) {
	if dryRun || dataDir == "" {
		return func() {}, false, nil
	}
	dir := filepath.Join(dataDir, "keepalive", "grants")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, err
	}
	f, err := os.OpenFile(filepath.Join(dir, grantFileStem(g)+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, true, nil
		}
		return nil, false, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, false, nil
}

// lockCLI takes the provider CLI's own lock file (Claude's
// .claude/.credentials.lock, Grok's auth.json.lock) while keepalive reads the
// credential for a vault copy, so it never copies a half-written file or
// races a refresh the CLI is doing right now. It is never held while the CLI
// runs — the CLI takes it itself. An absent lock file is not created.
func lockCLI(path string, timeout time.Duration) (release func(), err error) {
	if path == "" {
		return func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return func() {}, nil
		}
		// flock does not need write access, so a read-only lock file works.
		if f, err = os.Open(path); err != nil {
			return nil, fmt.Errorf("open CLI lock %s: %w", path, err)
		}
	}
	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("the CLI held %s for over %s", filepath.Base(path), timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
