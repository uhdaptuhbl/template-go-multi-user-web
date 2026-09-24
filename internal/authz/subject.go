package authz

import (
	"context"
	"slices"

	"github.com/google/uuid"
)

// subjectContextKey is the context key a Subject is stored under. It is an
// unexported empty struct type, which is what makes collision with another
// package's key impossible, per revive's context-keys-type rule.
type subjectContextKey struct{}

// Subject is the authenticated caller attached to a request's context.
type Subject struct {
	// UserID is the authenticated account's identifier.
	UserID uuid.UUID `json:"user_id"`
	// SessionPublicID identifies the session that authenticated the request.
	// It is the session's public handle, not its digest: nothing above the
	// session package needs the digest, so nothing above it is given one.
	SessionPublicID uuid.UUID `json:"session_public_id"`
	// Permissions is every permission the account holds, resolved once when
	// the session was validated so a route check costs no query.
	Permissions []string `json:"permissions"`
}

// WithSubject returns a context carrying s.
func WithSubject(ctx context.Context, s Subject) context.Context {
	return context.WithValue(ctx, subjectContextKey{}, s)
}

// SubjectFromContext returns the authenticated caller and whether one is
// present.
func SubjectFromContext(ctx context.Context) (Subject, bool) {
	s, ok := ctx.Value(subjectContextKey{}).(Subject)

	return s, ok
}

// HasPermission reports whether the subject holds the named permission.
func (s Subject) HasPermission(permission string) bool {
	return slices.Contains(s.Permissions, permission)
}
