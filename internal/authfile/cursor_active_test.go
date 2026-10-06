package authfile

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCursorActiveProfileIgnoresConfigDrift: cursor-agent rewrites
// cli-config.json (model choice, caches) constantly. The live login must
// still match its snapshot while auth.json is unchanged, and must stop
// matching once auth.json holds a different login.
func TestCursorActiveProfileIgnoresConfigDrift(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, ".config", "cursor", "cli-config.json")
	authPath := filepath.Join(home, ".config", "cursor", "auth.json")
	fs := AuthFileSet{
		Tool: "cursor",
		Files: []AuthFileSpec{
			{Tool: "cursor", Path: configPath},
			{Tool: "cursor", Path: authPath},
		},
		AllowOptionalOnly: true,
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write(configPath, `{"authInfo":{"email":"work@example.com"},"model":"a"}`)
	write(authPath, `{"accessToken":"SYNTHETIC-WORK","refreshToken":"SYNTHETIC-WORK"}`)
	v := NewVault(t.TempDir())
	if err := v.Backup(fs, "work"); err != nil {
		t.Fatalf("Backup() error = %v", err)
	}

	write(configPath, `{"authInfo":{"email":"work@example.com"},"model":"b","modelSelectionHistory":["b"]}`)
	if got, err := v.ActiveProfile(fs); err != nil || got != "work" {
		t.Errorf("after cli-config.json drift: ActiveProfile() = %q, %v; want work", got, err)
	}

	write(authPath, `{"accessToken":"SYNTHETIC-OTHER","refreshToken":"SYNTHETIC-OTHER"}`)
	if got, _ := v.ActiveProfile(fs); got != "" {
		t.Errorf("different login: ActiveProfile() = %q, want no match", got)
	}

	// Without auth.json (macOS keeps the token in the keychain) the config
	// file is all there is, so it still decides.
	if err := os.Remove(authPath); err != nil {
		t.Fatal(err)
	}
	write(configPath, `{"authInfo":{"email":"work@example.com"},"model":"a"}`)
	if got, _ := v.ActiveProfile(fs); got != "work" {
		t.Errorf("config only, unchanged: ActiveProfile() = %q, want work", got)
	}
}
