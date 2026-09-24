// Package mail delivers outbound plain-text mail over SMTP, such as an
// email one-time code sent during authentication.
//
// It is deliberately inert when disabled: a deployment with no mail server
// configured gets a Sender that rejects every message with ErrDisabled rather
// than a package that fails unpredictably or cannot be constructed at all.
// That makes "no mail server" a supported configuration rather than a broken
// one.
package mail
