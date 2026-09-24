package config

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/sethvargo/go-envconfig"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/oidc"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
)

// schemeHTTPS is the "https" URL scheme, named so PublicOrigin's scheme
// comparisons in this package and in config.go share one literal.
const schemeHTTPS = "https"

// schemeHTTP is the "http" URL scheme, the only other scheme
// validatePublicOriginCanonical accepts.
const schemeHTTP = "http"

// defaultOTPCodeTTL is how long an emailed one-time code stays valid when
// nothing overrides it.
const defaultOTPCodeTTL = configtype.Duration(10 * time.Minute)

// defaultOTPMaxAttempts is the number of wrong guesses that invalidates a
// code when nothing overrides it.
const defaultOTPMaxAttempts = 5

// defaultFlowTTL is how long ceremony state survives between the two
// requests of a login flow when nothing overrides it.
const defaultFlowTTL = configtype.Duration(10 * time.Minute)

// defaultRateLimitPerMinute bounds authentication requests per client
// address when nothing overrides it.
const defaultRateLimitPerMinute = 10

// defaultRateLimitBurst is how far a client address may exceed the steady
// authentication rate when nothing overrides it.
const defaultRateLimitBurst = 20

// defaultInviteTokenBytes is how much entropy an invite token carries before
// base64url encoding, when nothing overrides it.
const defaultInviteTokenBytes = 32

// defaultInviteRetainAfterExpiry is how long an expired invite is kept
// before the sweeper removes it, when nothing overrides it.
const defaultInviteRetainAfterExpiry = configtype.Duration(2160 * time.Hour)

// defaultInviteMaxTTL is the longest lifetime an invite may be issued with,
// and the ceiling the default invite lifetime setting may not exceed, when
// nothing overrides it.
const defaultInviteMaxTTL = configtype.Duration(336 * time.Hour)

// defaultInviteDefaultMaxUses is the redemption limit an invite gets when its
// issuer names none, when nothing overrides it.
const defaultInviteDefaultMaxUses = 1

// defaultDeletedGracePeriod is how long a soft-deleted account remains
// recoverable before the sweeper purges it, when nothing overrides it. The
// unit's own step-by-step defaults enumeration is silent on this field, but
// leaving it at the zero value would make every deployment that never sets
// SERVICE_AUTH_DELETED_GRACE_PERIOD purge a deleted account on the very next
// sweep, which is the escape hatch documented on the field, not the ordinary
// case. Thirty days matches the value the operator-facing configuration
// table gives this variable elsewhere in the plan.
const defaultDeletedGracePeriod = configtype.Duration(720 * time.Hour)

// defaultProviderScopes are the scopes requested for an OIDC provider that
// sets none of its own.
var defaultProviderScopes = []string{"openid", "email", "profile"}

// errPublicOriginRequiredForMethod reports that an authentication method
// that needs a static, pre-registered callback address is enabled while
// PublicOrigin is empty.
var errPublicOriginRequiredForMethod = errors.New("SERVICE_AUTH_PUBLIC_ORIGIN is required: SERVICE_AUTH_OTP_ENABLED or SERVICE_AUTH_OIDC_PROVIDERS is set")

// errPublicOriginNotCanonical reports that PublicOrigin is not exactly
// scheme://host[:port]: a browser sends the Origin header in precisely that
// form, and the cross-site request middleware compares it byte-for-byte, so
// anything else -- a path, a query, a fragment, userinfo, a default port, or
// a non-lowercase scheme or host -- can never match a real request.
var errPublicOriginNotCanonical = errors.New("SERVICE_AUTH_PUBLIC_ORIGIN must be exactly scheme://host[:port], with scheme http or https, no path, query, fragment, userinfo, default port, or upper-case characters")

// errDeletedGracePeriodNegative reports a negative DeletedGracePeriod. Zero
// is valid and means immediate purge on the next sweep.
var errDeletedGracePeriodNegative = errors.New("SERVICE_AUTH_DELETED_GRACE_PERIOD must not be negative")

// errInviteRetainAfterExpiryNegative reports a negative
// InviteRetainAfterExpiry.
var errInviteRetainAfterExpiryNegative = errors.New("SERVICE_AUTH_INVITE_RETAIN_AFTER_EXPIRY must not be negative")

// errProviderVariableMissing reports that a key listed in OIDCProviders is
// missing one of its required per-provider variables.
var errProviderVariableMissing = errors.New("missing required environment variable")

// errNoAuthenticationMethod reports that every authentication method is disabled, which would
// start a service nobody can sign in to.
var errNoAuthenticationMethod = errors.New("no authentication method is enabled: set SERVICE_AUTH_OIDC_PROVIDERS, SERVICE_AUTH_WEBAUTHN_ENABLED=true, or SERVICE_AUTH_OTP_ENABLED=true")

// AuthConfig holds the settings shared across authentication methods and the
// per-method switches.
type AuthConfig struct {
	// PublicOrigin is this service's externally reachable origin, used to build
	// provider redirect URIs, to scope WebAuthn credentials, and to recognise
	// a same-origin request.
	PublicOrigin string `env:"PUBLIC_ORIGIN, overwrite" json:"public_origin"`
	// OIDCProviders lists the configured provider keys. Each key K expands to
	// SERVICE_AUTH_OIDC_<K>_ISSUER, _CLIENT_ID, _CLIENT_SECRET, _SCOPES, and
	// _DISPLAY_NAME.
	// The delimiter is not spelled out in the tag: it defaults to ",", and an
	// explicit `delimiter=,` is misparsed by go-envconfig's tag splitter,
	// which treats the unescaped comma inside the option's own value as the
	// start of a second, empty option.
	OIDCProviders []string `env:"OIDC_PROVIDERS, overwrite" json:"oidc_providers"`
	// WebAuthnEnabled registers the passkey routes.
	WebAuthnEnabled bool `env:"WEBAUTHN_ENABLED, overwrite" json:"webauthn_enabled"`
	// WebAuthnRPID is the relying party identifier. Empty means the host of
	// PublicOrigin.
	WebAuthnRPID string `env:"WEBAUTHN_RP_ID, overwrite" json:"webauthn_rp_id"`
	// WebAuthnRPDisplayName is what an authenticator shows the user.
	WebAuthnRPDisplayName string `env:"WEBAUTHN_RP_DISPLAY_NAME, overwrite" json:"webauthn_rp_display_name"`
	// OTPEnabled registers the email code routes.
	OTPEnabled bool `env:"OTP_ENABLED, overwrite" json:"otp_enabled"`
	// OTPCodeTTL is how long an emailed code stays valid.
	OTPCodeTTL configtype.Duration `env:"OTP_CODE_TTL, overwrite" json:"otp_code_ttl" validate:"gt=0"`
	// OTPMaxAttempts is the number of wrong guesses that invalidates a code.
	OTPMaxAttempts int `env:"OTP_MAX_ATTEMPTS, overwrite" json:"otp_max_attempts" validate:"gt=0"`
	// FlowTTL is how long ceremony state survives between its two requests.
	FlowTTL configtype.Duration `env:"FLOW_TTL, overwrite" json:"flow_ttl" validate:"gt=0"`
	// RateLimitPerMinute bounds authentication requests per client address.
	RateLimitPerMinute int `env:"RATE_LIMIT_PER_MINUTE, overwrite" json:"rate_limit_per_minute" validate:"gt=0"`
	// RateLimitBurst is how far a client address may exceed the steady rate.
	RateLimitBurst int `env:"RATE_LIMIT_BURST, overwrite" json:"rate_limit_burst" validate:"gt=0"`
	// BootstrapAdminEmails are addresses granted the administrator role on
	// their first authentication with a verified address. They are also exempt
	// from the signup admission rules, which is what allows a deployment that
	// starts with signup closed to ever create its first account.
	// See OIDCProviders above for why the delimiter option is left implicit.
	BootstrapAdminEmails []string `env:"BOOTSTRAP_ADMIN_EMAILS, overwrite" json:"bootstrap_admin_emails"`
	// SignupEnabled is the break-glass override of the runtime setting of the
	// same name. It is a pointer because "unset" and "set to false" are
	// different states: unset means the database decides, and false means the
	// database is overruled and the key is locked against the admin endpoint.
	// ADR 0015 records why this is the only setting with an override.
	// noinit keeps the unset case nil: go-envconfig otherwise materializes an
	// overwrite-tagged pointer field to a pointer to its zero value even when
	// the variable is not set, which would collapse "unset" and "false" into
	// the same state -- exactly what this field exists to keep apart.
	SignupEnabled *bool `env:"SIGNUP_ENABLED, overwrite, noinit" json:"signup_enabled"`
	// InviteTokenBytes is how much entropy an invite token carries before
	// base64url encoding.
	InviteTokenBytes int `env:"INVITE_TOKEN_BYTES, overwrite" json:"invite_token_bytes" validate:"gte=16"`
	// InviteRetainAfterExpiry is how long an expired invite is kept before the
	// sweeper removes it, so that the redemption rows pointing at it stay
	// readable for a while.
	InviteRetainAfterExpiry configtype.Duration `env:"INVITE_RETAIN_AFTER_EXPIRY, overwrite" json:"invite_retain_after_expiry" validate:"gte=0"`
	// InviteMaxTTL is the longest lifetime an invite may be issued with, and the ceiling the
	// default invite lifetime setting may not exceed.
	InviteMaxTTL configtype.Duration `env:"INVITE_MAX_TTL, overwrite" json:"invite_max_ttl" validate:"gt=0"`
	// InviteDefaultMaxUses is the redemption limit an invite gets when its issuer names none.
	InviteDefaultMaxUses int `env:"INVITE_DEFAULT_MAX_USES, overwrite" json:"invite_default_max_uses" validate:"gte=1"`
	// DeletedGracePeriod is how long a soft-deleted account remains
	// recoverable before the sweeper purges it. Zero means the next sweep
	// purges it, which is the escape hatch for an erasure request that has to
	// be honoured immediately.
	DeletedGracePeriod configtype.Duration `env:"DELETED_GRACE_PERIOD, overwrite" json:"deleted_grace_period"`
	// Providers is filled by LoadProviders from the per-provider variables. It
	// carries client secrets, so it is excluded from the JSON representation.
	// It has no env tag at all, rather than go-envconfig's encoding/json-style
	// env:"-": for a non-struct field, go-envconfig treats an absent tag as
	// "leave alone" but validates "-" as a literal (invalid) variable name and
	// fails Decode with it.
	Providers []oidc.ProviderConfig `json:"-"`
}

// DefaultAuthConfig returns the authentication settings used when nothing
// overrides them.
func DefaultAuthConfig() AuthConfig {
	return AuthConfig{
		PublicOrigin:            "",
		OIDCProviders:           nil,
		WebAuthnEnabled:         true,
		WebAuthnRPID:            "",
		WebAuthnRPDisplayName:   "service",
		OTPEnabled:              false,
		OTPCodeTTL:              defaultOTPCodeTTL,
		OTPMaxAttempts:          defaultOTPMaxAttempts,
		FlowTTL:                 defaultFlowTTL,
		RateLimitPerMinute:      defaultRateLimitPerMinute,
		RateLimitBurst:          defaultRateLimitBurst,
		BootstrapAdminEmails:    nil,
		SignupEnabled:           nil,
		InviteTokenBytes:        defaultInviteTokenBytes,
		InviteRetainAfterExpiry: defaultInviteRetainAfterExpiry,
		InviteMaxTTL:            defaultInviteMaxTTL,
		InviteDefaultMaxUses:    defaultInviteDefaultMaxUses,
		DeletedGracePeriod:      defaultDeletedGracePeriod,
		Providers:               nil,
	}
}

// LoadProviders fills Providers by reading the per-provider variables for each
// key in OIDCProviders, using lookuper so tests need not mutate process state.
// It returns an error naming the first key that is missing a required
// variable.
func (c *AuthConfig) LoadProviders(_ context.Context, lookuper envconfig.Lookuper) error {
	// No cancellation check: every read here is from memory, and refusing one
	// on a cancelled context would turn a clean shutdown into a startup error,
	// the same rule Decode follows.
	if len(c.OIDCProviders) == 0 {
		c.Providers = nil

		return nil
	}

	providers := make([]oidc.ProviderConfig, 0, len(c.OIDCProviders))

	for _, key := range c.OIDCProviders {
		provider, err := loadProviderConfig(lookuper, key)
		if err != nil {
			return fmt.Errorf("loading oidc providers: %w", err)
		}

		providers = append(providers, provider)
	}

	c.Providers = providers

	return nil
}

// loadProviderConfig reads one provider's variables, applying the default
// scopes and title-cased display name when their variables are unset.
func loadProviderConfig(lookuper envconfig.Lookuper, key string) (oidc.ProviderConfig, error) {
	prefix := "SERVICE_AUTH_OIDC_" + strings.ToUpper(key) + "_"

	issuer, ok := lookuper.Lookup(prefix + "ISSUER")
	if !ok || issuer == "" {
		return oidc.ProviderConfig{}, fmt.Errorf("provider %q: %w: %sISSUER", key, errProviderVariableMissing, prefix)
	}

	clientID, ok := lookuper.Lookup(prefix + "CLIENT_ID")
	if !ok || clientID == "" {
		return oidc.ProviderConfig{}, fmt.Errorf("provider %q: %w: %sCLIENT_ID", key, errProviderVariableMissing, prefix)
	}

	clientSecret, ok := lookuper.Lookup(prefix + "CLIENT_SECRET")
	if !ok || clientSecret == "" {
		return oidc.ProviderConfig{}, fmt.Errorf("provider %q: %w: %sCLIENT_SECRET", key, errProviderVariableMissing, prefix)
	}

	scopes := defaultProviderScopes
	if raw, set := lookuper.Lookup(prefix + "SCOPES"); set && raw != "" {
		scopes = splitAndTrim(raw)
	}

	displayName := titleCase(key)
	if raw, set := lookuper.Lookup(prefix + "DISPLAY_NAME"); set && raw != "" {
		displayName = raw
	}

	return oidc.ProviderConfig{
		Key:          key,
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: SecretString(clientSecret),
		Scopes:       scopes,
		DisplayName:  displayName,
	}, nil
}

// splitAndTrim splits a comma-delimited value into its non-empty, trimmed
// parts.
func splitAndTrim(raw string) []string {
	parts := strings.Split(raw, ",")
	trimmed := make([]string, 0, len(parts))

	for _, part := range parts {
		if p := strings.TrimSpace(part); p != "" {
			trimmed = append(trimmed, p)
		}
	}

	return trimmed
}

// titleCase upper-cases the first byte of key and leaves the rest untouched,
// which is the "title-cased" default display name a provider key such as
// "google" renders as: "Google".
func titleCase(key string) string {
	if key == "" {
		return key
	}

	return strings.ToUpper(key[:1]) + key[1:]
}

// Validate reports the problems inside these settings that the struct tags
// cannot express. It is the CustomValidator hook Decode calls on this field;
// rules that span two settings groups belong on Config instead, which is the
// only place that can see both.
func (c *AuthConfig) Validate(_ context.Context) error {
	errs := make([]error, 0, 4)

	// OTP and OIDC both need a stable, pre-registered address: an emailed
	// code links back to it, and a provider's redirect URI is registered with
	// the provider ahead of time. WebAuthn is not checked here: process wiring
	// derives its relying party ID and origin from PublicOrigin and refuses to
	// start WebAuthn without one, naming this variable in the error.
	methodNeedsPublicOrigin := c.OTPEnabled || len(c.OIDCProviders) > 0

	switch {
	case methodNeedsPublicOrigin && c.PublicOrigin == "":
		errs = append(errs, errPublicOriginRequiredForMethod)
	case c.PublicOrigin != "":
		if err := validatePublicOriginCanonical(c.PublicOrigin); err != nil {
			errs = append(errs, err)
		}
	}

	if c.DeletedGracePeriod.Duration() < 0 {
		errs = append(errs, errDeletedGracePeriodNegative)
	}

	if c.InviteRetainAfterExpiry.Duration() < 0 {
		errs = append(errs, errInviteRetainAfterExpiryNegative)
	}

	if !c.OTPEnabled && len(c.OIDCProviders) == 0 && !c.WebAuthnEnabled {
		errs = append(errs, errNoAuthenticationMethod)
	}

	return errors.Join(errs...)
}

// validatePublicOriginCanonical reports whether origin is exactly
// scheme://host[:port]: http or https, no userinfo, no path (not even a
// trailing "/"), no query, no fragment, no default port, and equal to its
// own lowercase form.
//
// This is stricter than "parses as an absolute URL" because a browser sends
// the Origin header in precisely this canonical form, and the cross-site
// request middleware that reads PublicOrigin back compares it byte-for-byte.
func validatePublicOriginCanonical(origin string) error {
	parsed, err := url.Parse(origin)
	if err != nil {
		return errPublicOriginNotCanonical
	}

	if parsed.Scheme != schemeHTTP && parsed.Scheme != schemeHTTPS {
		return errPublicOriginNotCanonical
	}

	if parsed.User != nil || parsed.Host == "" {
		return errPublicOriginNotCanonical
	}

	if parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errPublicOriginNotCanonical
	}

	if parsed.Scheme+"://"+parsed.Host != origin {
		return errPublicOriginNotCanonical
	}

	if origin != strings.ToLower(origin) {
		return errPublicOriginNotCanonical
	}

	if (parsed.Scheme == schemeHTTPS && strings.HasSuffix(parsed.Host, ":443")) ||
		(parsed.Scheme == schemeHTTP && strings.HasSuffix(parsed.Host, ":80")) {
		return errPublicOriginNotCanonical
	}

	return nil
}
