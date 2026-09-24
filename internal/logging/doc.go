// Package logging constructs the application's zap logger and bridges records
// emitted through the standard library's log/slog into that same logger.
//
// It is the only package permitted to import log/slog. Application code logs
// through *zap.Logger directly; the bridge exists so that dependencies which
// emit slog records reach the same output stream rather than disappearing. See
// docs/adr/0003-use-uber-zap-for-logging.md.
package logging
