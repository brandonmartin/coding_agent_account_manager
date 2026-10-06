package refresh

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/authfile"
)

// ErrLiveCredentialNewer indicates that the vault copy of a Codex credential
// must not be refreshed because the live CLI login holds the same identity and
// was refreshed more recently. The vault copy's refresh token is therefore
// already spent: replaying it gets refresh_token_reused and can revoke the
// whole token family.
var ErrLiveCredentialNewer = errors.New("live credential is newer than the vault copy")

// LiveCredentialNewerError is the typed form of ErrLiveCredentialNewer.
type LiveCredentialNewerError struct {
	Provider string
	Profile  string
	LivePath string
}

func (e *LiveCredentialNewerError) Error() string {
	return fmt.Sprintf(
		"%s/%s: %s holds the same identity and is newer than the vault copy, so the vault refresh token is already spent; "+
			"back the live login up into the vault instead: caam backup %s %s",
		e.Provider, e.Profile, e.LivePath, e.Provider, e.Profile)
}

func (e *LiveCredentialNewerError) Unwrap() error { return ErrLiveCredentialNewer }

// providerCLI names the CLI that renews its own credential for providers caam
// has no vault refresher for.
var providerCLI = map[string]string{
	"claude":   "claude",
	"opencode": "opencode",
	"cursor":   "cursor-agent",
	"grok":     "grok",
}

// ProviderCLI returns the name of the provider's own CLI when that CLI, and not
// caam, renews the provider's credential. It is empty for providers caam
// refreshes itself (codex, gemini) and for unknown providers.
func ProviderCLI(provider string) string {
	return providerCLI[provider]
}

func unsupportedProviderError(provider string) *UnsupportedError {
	if cli := ProviderCLI(provider); cli != "" {
		return &UnsupportedError{
			Provider: provider,
			Reason:   fmt.Sprintf("caam has no refresher for %s; the %s CLI renews it when it runs", provider, cli),
		}
	}
	return &UnsupportedError{Provider: provider, Reason: "provider not supported"}
}

// Preflight reports whether RefreshProfile would actually attempt a refresh for
// provider/profile, without any network access or writes. It returns nil when
// an attempt would be made, an *UnsupportedError when caam never refreshes the
// provider, and a *LiveCredentialNewerError when refreshing the Codex vault
// copy would replay a refresh token the live CLI has already rotated.
//
// Callers that log before refreshing (the daemon) use it to decide first, so
// they never announce a refresh that cannot happen.
func Preflight(provider, profile string, vault *authfile.Vault) error {
	switch provider {
	case "claude":
		return claudeUnsupportedError()
	case "codex":
		if vault == nil {
			return nil
		}
		livePath := authfile.CodexLiveAuthPath()
		vaultAuth := filepath.Join(vault.ProfilePath(provider, profile), "auth.json")
		if livePath != "" && authfile.CodexLiveIsNewer(livePath, vaultAuth) {
			return &LiveCredentialNewerError{Provider: provider, Profile: profile, LivePath: livePath}
		}
		return nil
	case "gemini":
		return nil
	default:
		return unsupportedProviderError(provider)
	}
}
