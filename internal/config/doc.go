// Package config resolves the settings the process runs with.
//
// Config is the single composed structure: it embeds the configuration each
// package defines for itself rather than redeclaring those fields, so a package
// owns the meaning and defaults of its own settings and this package owns only
// how they are assembled and where the values come from.
//
// Values are layered. Defaults come from each package's own DefaultConfig, and
// environment variables override them. That ordering depends on every
// env-loadable field carrying the overwrite option: without it go-envconfig
// leaves an already-populated field alone and silently ignores the variable.
//
// Validation is layered the same way. Struct tags are checked first and gate
// what follows, then the hook each composed package may implement over its own
// settings, then the hook over the whole configuration, which is where a rule
// that spans two packages belongs. Those two hook layers do not gate each
// other: both run, and their failures are reported together, so one startup
// names every settings group that is wrong. Variable names are written once,
// in the struct tags: the names that appear in failure messages are read back
// off them rather than restated here.
//
// Telemetry is the one part that does not carry this project's variable prefix.
// The OpenTelemetry specification fixes those names, so they are absolute.
//
// SecretString is the type any credential-bearing setting is declared with.
// It is an alias for internal/secret's String. The database DSN, the SMTP
// password, and each OIDC provider's client secret use it, so rendering the
// whole configuration, as LogEffective does, redacts them. A package this one
// composes declares its fields with secret.String directly, because it cannot
// import this package without a cycle.
//
// See docs/adr/0006-configuration-loading.md.
package config
