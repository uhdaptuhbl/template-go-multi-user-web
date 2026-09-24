package authflow

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
)

// Kind names which ceremony a stored flow belongs to.
type Kind string

// KindOIDC is an OpenID Connect authorization code exchange in progress for a
// login.
const KindOIDC Kind = "oidc"

// KindOIDCLink is an OpenID Connect exchange started by a signed-in account to
// attach an additional identity to itself. It is a separate kind so a link
// flow can never be consumed as a login, and its UserID is always set.
const KindOIDCLink Kind = "oidc_link"

// KindWebAuthnRegister is a passkey registration ceremony in progress.
const KindWebAuthnRegister Kind = "webauthn_register"

// KindWebAuthnLogin is a passkey assertion ceremony in progress.
const KindWebAuthnLogin Kind = "webauthn_login"

// Flow is one ceremony's server-side state, held between the request that
// starts it and the request that finishes it.
type Flow struct {
	// ID is the raw ceremony identifier and Data holds live ceremony secrets:
	// the OIDC state and nonce, the PKCE verifier, or the WebAuthn challenge.
	// Neither may reach a response or a log.
	ID        []byte          `db:"id"         json:"-"`
	Kind      Kind            `db:"kind"`
	UserID    *uuid.UUID      `db:"user_id"`
	Data      json.RawMessage `db:"data"       json:"-"`
	CreatedAt time.Time       `db:"created_at"`
	ExpiresAt time.Time       `db:"expires_at"`
}

// MarshalJSON always fails. Flow is a persistence row carrying live ceremony
// secrets, never a response body; this turns an accidental serialization into
// a loud error instead of handing out a PKCE verifier.
func (Flow) MarshalJSON() ([]byte, error) {
	return nil, errors.New("authflow: Flow must never be serialized to JSON")
}

// ErrNotFound reports that no live flow matched, whether because the
// identifier is unknown, has expired, or has already been consumed. The three
// are deliberately indistinguishable to a caller.
var ErrNotFound = errors.New("flow not found")

// Store persists ceremony state.
type Store struct {
	handle *store.Handle
	ttl    time.Duration
	now    func() time.Time
}

// NewStore returns a store backed by h, expiring flows after ttl and using now
// as its clock.
func NewStore(h *store.Handle, ttl time.Duration, now func() time.Time) *Store {
	return &Store{handle: h, ttl: ttl, now: now}
}

// Begin persists data for a ceremony and returns the opaque identifier the
// caller round-trips through the user agent. The identifier is 32 bytes from
// crypto/rand rendered with base64.RawURLEncoding, so it is URL-safe,
// unguessable, and doubles as the OpenID Connect state value. The stored
// flows.id is the raw 32 bytes, not the encoded text.
func (s *Store) Begin(ctx context.Context, kind Kind, userID *uuid.UUID, data json.RawMessage) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("authflow: generating flow identifier: %w", err)
	}

	createdAt := s.now()
	expiresAt := createdAt.Add(s.ttl)

	const query = `
		INSERT INTO auth_flows (id, kind, user_id, data, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	if _, err := s.handle.Pool().Exec(ctx, query, raw, kind, userID, data, createdAt, expiresAt); err != nil {
		return "", fmt.Errorf("authflow: persisting flow: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Consume atomically deletes the flow with the given identifier and kind and
// returns its data, so a replayed identifier finds nothing. It returns
// ErrNotFound when no live flow matches.
func (s *Store) Consume(ctx context.Context, kind Kind, id string) (Flow, error) {
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return Flow{}, ErrNotFound
	}

	const query = `
		DELETE FROM auth_flows
		WHERE id = $1 AND kind = $2 AND expires_at > $3
		RETURNING id, kind, user_id, data, created_at, expires_at
	`

	rows, err := s.handle.Pool().Query(ctx, query, raw, kind, s.now())
	if err != nil {
		return Flow{}, fmt.Errorf("authflow: consuming flow: %w", err)
	}

	flow, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[Flow])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Flow{}, ErrNotFound
		}

		return Flow{}, fmt.Errorf("authflow: consuming flow: %w", err)
	}

	return flow, nil
}

// DeleteExpired removes flows past their expiry, returning how many it removed.
func (s *Store) DeleteExpired(ctx context.Context) (int64, error) {
	const query = `DELETE FROM auth_flows WHERE expires_at <= $1`

	tag, err := s.handle.Pool().Exec(ctx, query, s.now())
	if err != nil {
		return 0, fmt.Errorf("authflow: deleting expired flows: %w", err)
	}

	return tag.RowsAffected(), nil
}
