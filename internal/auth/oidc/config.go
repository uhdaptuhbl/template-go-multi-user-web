package oidc

import (
	"time"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/secret"
)

// DefaultClockSkew is the leeway allowed on an identity token's expiry when
// nothing overrides it.
const DefaultClockSkew = configtype.Duration(30 * time.Second)

// ProviderConfig is one identity provider's registration.
type ProviderConfig struct {
	// Key is the short name used in the callback URL and returned to clients,
	// for example "google".
	Key string `json:"key" validate:"required"`
	// Issuer is the provider's issuer URL, used to discover and verify the
	// provider. It is not the value stored in identities.provider, which
	// holds the configured provider key (for example "google") instead.
	Issuer string `json:"issuer" validate:"required"`
	// ClientID is the OAuth client identifier.
	ClientID string `json:"client_id" validate:"required"`
	// ClientSecret is the OAuth client secret.
	ClientSecret secret.String `json:"client_secret" validate:"required"`
	// Scopes are requested in addition to openid.
	Scopes []string `json:"scopes"`
	// DisplayName labels the provider in the list of login options.
	DisplayName string `json:"display_name"`
}

// Config holds every configured provider and the origin callbacks return to.
type Config struct {
	// PublicOrigin is this service's externally reachable origin, for example
	// https://service.example. The redirect URI registered with each provider
	// is this origin plus /api/v1/auth/oidc/{key}/callback.
	PublicOrigin string `json:"public_origin"`
	// Providers is every configured provider, keyed by its Key.
	Providers []ProviderConfig `json:"providers"`
	// ClockSkew is the leeway allowed when checking an identity token's expiry,
	// so a small difference between this host's clock and the provider's does
	// not reject a valid token.
	ClockSkew configtype.Duration `json:"clock_skew" validate:"gte=0"`
}

// DefaultConfig returns a Config with no providers configured and the
// default clock skew.
func DefaultConfig() Config {
	return Config{
		PublicOrigin: "",
		Providers:    nil,
		ClockSkew:    DefaultClockSkew,
	}
}
