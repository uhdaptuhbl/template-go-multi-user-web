// Package auth orchestrates login across every authentication method. It owns
// the session middleware and the HTTP surface for authentication, and the
// account-linking rules it enforces are recorded in
// docs/adr/0012-authentication-model.md. It also owns the refusals that keep
// an account reachable and the administrator set non-empty, and the
// two-stage deletion that makes an account unusable at once and destroys it
// later.
package auth
