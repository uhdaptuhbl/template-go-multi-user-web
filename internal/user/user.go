package user

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Status is the lifecycle state of an account.
type Status string

// StatusPending is an account created while signup_require_approval was true.
// It exists and owns its identity row, and it may not authenticate until an
// administrator approves it. Signup admission rule 7 (design.md's "Signup
// admission path") is what creates one, and the approval routes are the
// only thing that moves it to StatusActive.
const StatusPending Status = "pending"

// StatusActive is an account that may authenticate.
const StatusActive Status = "active"

// StatusSuspended is an account that exists but may not authenticate.
const StatusSuspended Status = "suspended"

// StatusDeleted is an account the owner has deleted. It may not authenticate
// and appears in no listing, but its row survives until the grace period
// elapses and the sweeper purges it, so a deletion made in error is
// recoverable.
const StatusDeleted Status = "deleted"

// User is an account. Its identity is ID; the email address is contact
// information and display data, never a credential and never a lookup key for
// authentication.
type User struct {
	ID              uuid.UUID  `db:"id"`
	DisplayName     string     `db:"display_name"`
	Email           *string    `db:"email"`
	EmailVerifiedAt *time.Time `db:"email_verified_at"`
	Status          Status     `db:"status"`
	DeletedAt       *time.Time `db:"deleted_at"`
	CreatedAt       time.Time  `db:"created_at"`
	UpdatedAt       time.Time  `db:"updated_at"`
	// RejectedAt is when the account was rejected from the approval queue, or nil. A rejected
	// account is deleted and can never be restored.
	RejectedAt *time.Time `db:"rejected_at" json:"-"`
	// BootstrapAdminGrantedAt is when the bootstrap administrator list granted this account the
	// admin role, or nil if it never has.
	BootstrapAdminGrantedAt *time.Time `db:"bootstrap_admin_granted_at" json:"-"`
}

// Identity is a credential-issuing authority's stable reference to a User.
// Provider holds the configured provider key (for example "google") for an
// OpenID Connect provider and the literal "email" for the one-time code
// path; the issuer URL itself is used only to discover and verify the
// provider, not stored here. Subject is that provider's stable subject for
// the account. The pair is unique across the service.
type Identity struct {
	ID         uuid.UUID  `db:"id"`
	UserID     uuid.UUID  `db:"user_id"`
	Provider   string     `db:"provider"`
	Subject    string     `db:"subject"`
	Email      *string    `db:"email"`
	CreatedAt  time.Time  `db:"created_at"`
	LastUsedAt *time.Time `db:"last_used_at"`
}

// ErrNotFound reports that no account matched the lookup.
var ErrNotFound = errors.New("user not found")

// ErrEmailTaken reports that another account already claims the address.
var ErrEmailTaken = errors.New("email already in use")

// ErrIdentityLinked reports that the provider and subject pair is already
// linked to a different account.
var ErrIdentityLinked = errors.New("identity already linked to another account")
