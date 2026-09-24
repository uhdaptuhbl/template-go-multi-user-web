package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
)

// MethodOIDC records that a session was established through an identity provider.
const MethodOIDC = "oidc"

// MethodWebAuthn records that a session was established with a passkey.
const MethodWebAuthn = "webauthn"

// MethodOTP records that a session was established with an emailed code.
const MethodOTP = "otp"

// tokenBytes is the number of random bytes a session token is generated
// from. Encoded with base64.RawURLEncoding this produces a 43 character
// token.
const tokenBytes = 32

// ErrNotFound reports that no live session matched the presented token.
var ErrNotFound = errors.New("session not found")

// errSessionNotSerializable is returned unconditionally by
// Session.MarshalJSON.
var errSessionNotSerializable = errors.New("session: must not be marshaled directly")

// Session is a server-side record of an authenticated browser. ID is a digest
// of the token the browser holds, not the token itself.
type Session struct {
	// ID is the SHA-256 digest of the session token. It is stored credential
	// material and must never reach a response, a URL, or a log.
	ID []byte `db:"id" json:"-"`
	// PublicID is the meaningless handle the API exposes in its place.
	PublicID          uuid.UUID   `db:"public_id"`
	UserID            uuid.UUID   `db:"user_id"`
	CreatedAt         time.Time   `db:"created_at"`
	LastSeenAt        time.Time   `db:"last_seen_at"`
	IdleExpiresAt     time.Time   `db:"idle_expires_at"`
	AbsoluteExpiresAt time.Time   `db:"absolute_expires_at"`
	ClientIP          *netip.Addr `db:"client_ip"`
	UserAgent         string      `db:"user_agent"`
	Methods           []string    `db:"methods"`
	// CookieIssuedAt is when the session cookie was last sent to the browser.
	CookieIssuedAt time.Time `db:"cookie_issued_at"`
}

// MarshalJSON always fails. Session is a persistence row holding the session
// digest, never a response body; this turns an accidental serialization into a
// loud error at the call site instead of a silent credential leak. Handlers
// build their own response types from PublicID and the timestamps.
func (Session) MarshalJSON() ([]byte, error) {
	return nil, errSessionNotSerializable
}

// Digest returns the stored identifier for a session token: the raw 32 bytes
// of its SHA-256 hash. The token itself is never persisted, so a database dump
// does not hand an attacker live sessions.
func Digest(token string) []byte {
	sum := sha256.Sum256([]byte(token))

	return sum[:]
}

// Store issues, resolves, refreshes, and revokes sessions.
type Store struct {
	handle *store.Handle
	cfg    Config
	now    func() time.Time
}

// NewStore returns a store backed by h, using cfg's expiries and now as its
// clock.
func NewStore(h *store.Handle, cfg Config, now func() time.Time) *Store {
	return &Store{handle: h, cfg: cfg, now: now}
}

// Issue creates a session for userID and returns it together with the raw
// token the browser must present. The raw token is returned exactly once and
// is never retrievable afterwards.
func (s *Store) Issue(ctx context.Context, userID uuid.UUID, clientIP, userAgent string, methods []string) (Session, string, error) {
	var raw [tokenBytes]byte

	if _, err := rand.Read(raw[:]); err != nil {
		return Session{}, "", fmt.Errorf("session: generating token: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(raw[:])

	publicID, err := uuid.NewV7()
	if err != nil {
		return Session{}, "", fmt.Errorf("session: generating public id: %w", err)
	}

	now := s.now()

	// methods is bound to a JSONB NOT NULL column. An empty slice encodes as
	// the empty JSON array; a nil slice has no encoding this column accepts,
	// so a caller passing nil would fail the NOT NULL constraint at runtime
	// rather than at compile time.
	if methods == nil {
		methods = []string{}
	}

	// cookie_issued_at is compared against later by ReissueCookie's
	// compare-and-set, which sends whatever Session it was given straight
	// back as a query parameter. Truncating to microsecond precision here
	// keeps the in-memory value bit-identical to what Postgres actually
	// stores (a TIMESTAMPTZ column has microsecond resolution), so a caller
	// that holds on to this returned Session, rather than re-reading it from
	// the database, still presents a value the CAS can match.
	cookieIssuedAt := now.Truncate(time.Microsecond)

	sess := Session{
		ID:                Digest(token),
		PublicID:          publicID,
		UserID:            userID,
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(s.cfg.IdleTimeout.Duration()),
		AbsoluteExpiresAt: now.Add(s.cfg.AbsoluteTimeout.Duration()),
		ClientIP:          parseClientIP(clientIP),
		UserAgent:         userAgent,
		Methods:           methods,
		CookieIssuedAt:    cookieIssuedAt,
	}

	const insertSessionQuery = `
INSERT INTO sessions (id, public_id, user_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at, client_ip, user_agent, methods, cookie_issued_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
`

	if _, execErr := s.handle.Pool().Exec(ctx, insertSessionQuery,
		sess.ID, sess.PublicID, sess.UserID, sess.CreatedAt, sess.LastSeenAt,
		sess.IdleExpiresAt, sess.AbsoluteExpiresAt, sess.ClientIP, sess.UserAgent, sess.Methods,
		sess.CookieIssuedAt,
	); execErr != nil {
		return Session{}, "", fmt.Errorf("session: inserting session: %w", execErr)
	}

	return sess, token, nil
}

// parseClientIP returns raw parsed as a netip.Addr, or nil when it does not
// parse. Storing nil rather than a string that merely looks like an address
// keeps the client_ip column an INET a caller can query, never free text.
func parseClientIP(raw string) *netip.Addr {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return nil
	}

	return &addr
}

// Lookup resolves a presented token to a live session, advancing its
// last_seen_at and idle expiry. The idle expiry advances by the configured
// idle timeout but never past the absolute expiry, so the stored value never
// names a time the session cannot reach. It returns ErrNotFound when the
// token is unknown, when either expiry has passed, or when the owning account
// is suspended, so a caller cannot distinguish the three.
func (s *Store) Lookup(ctx context.Context, token string) (Session, error) {
	digest := Digest(token)
	now := s.now()
	newIdleExpiresAt := now.Add(s.cfg.IdleTimeout.Duration())

	const lookupQuery = `
UPDATE sessions
SET last_seen_at = $2, idle_expires_at = LEAST($3, sessions.absolute_expires_at)
FROM users
WHERE sessions.id = $1
  AND sessions.user_id = users.id
  AND users.status = 'active'
  AND sessions.idle_expires_at > $2
  AND sessions.absolute_expires_at > $2
RETURNING sessions.id, sessions.public_id, sessions.user_id, sessions.created_at,
  sessions.last_seen_at, sessions.idle_expires_at, sessions.absolute_expires_at,
  sessions.client_ip, sessions.user_agent, sessions.methods, sessions.cookie_issued_at
`

	rows, err := s.handle.Pool().Query(ctx, lookupQuery, digest, now, newIdleExpiresAt)
	if err != nil {
		return Session{}, fmt.Errorf("session: looking up session: %w", err)
	}

	sess, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[Session])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrNotFound
		}

		return Session{}, fmt.Errorf("session: scanning session: %w", err)
	}

	return sess, nil
}

// Revoke deletes the session with the given public identifier, scoped to
// userID so a caller cannot revoke a session it does not own. It takes the
// public identifier rather than the digest, so no caller above this package
// ever holds one.
//
// It reports whether a row was deleted. The bool exists for the ownership
// isolation test (design.md's "Authorization path"), which must assert
// that a cross-account call affected nothing; the route ignores it and
// answers 204 either way, so the caller still cannot use the response to
// learn whether someone else's session exists.
func (s *Store) Revoke(ctx context.Context, userID, publicID uuid.UUID) (bool, error) {
	const revokeQuery = `DELETE FROM sessions WHERE public_id = $1 AND user_id = $2`

	tag, err := s.handle.Pool().Exec(ctx, revokeQuery, publicID, userID)
	if err != nil {
		return false, fmt.Errorf("session: revoking session: %w", err)
	}

	return tag.RowsAffected() > 0, nil
}

// RevokeToken deletes the session a raw token resolves to, which is what
// logout does.
func (s *Store) RevokeToken(ctx context.Context, token string) error {
	const deleteByDigestQuery = `DELETE FROM sessions WHERE id = $1`

	if _, err := s.handle.Pool().Exec(ctx, deleteByDigestQuery, Digest(token)); err != nil {
		return fmt.Errorf("session: revoking session by token: %w", err)
	}

	return nil
}

// RevokeAllFor deletes every session belonging to an account, returning how
// many it deleted, for the same reason Revoke returns a bool.
func (s *Store) RevokeAllFor(ctx context.Context, userID uuid.UUID) (int64, error) {
	const revokeAllQuery = `DELETE FROM sessions WHERE user_id = $1`

	tag, err := s.handle.Pool().Exec(ctx, revokeAllQuery, userID)
	if err != nil {
		return 0, fmt.Errorf("session: revoking all sessions: %w", err)
	}

	return tag.RowsAffected(), nil
}

// RevokeAllForTx is RevokeAllFor against the caller-supplied transaction tx
// instead of the pool, so a suspension or deletion can revoke every session
// in the same transaction that applies the status change: a suspension or
// deletion that leaves live sessions is not one. It takes no receiver-held
// state: it is a Store method, rather than a package function, only so it
// sits alongside RevokeAllFor as the pair ByEmail and ByEmailTx in
// internal/user already establish the pattern for.
//
//nolint:revive // Deliberately receiver-less: see the doc comment above.
func (s *Store) RevokeAllForTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (int64, error) {
	const revokeAllQuery = `DELETE FROM sessions WHERE user_id = $1`

	tag, err := tx.Exec(ctx, revokeAllQuery, userID)
	if err != nil {
		return 0, fmt.Errorf("session: revoking all sessions in transaction: %w", err)
	}

	return tag.RowsAffected(), nil
}

// ListFor returns every live session belonging to an account, most recently
// seen first.
func (s *Store) ListFor(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	const listQuery = `
SELECT id, public_id, user_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at, client_ip, user_agent, methods, cookie_issued_at
FROM sessions
WHERE user_id = $1
  AND idle_expires_at > $2
  AND absolute_expires_at > $2
ORDER BY last_seen_at DESC
`

	rows, err := s.handle.Pool().Query(ctx, listQuery, userID, s.now())
	if err != nil {
		return nil, fmt.Errorf("session: listing sessions: %w", err)
	}

	sessions, err := pgx.CollectRows(rows, pgx.RowToStructByName[Session])
	if err != nil {
		return nil, fmt.Errorf("session: scanning sessions: %w", err)
	}

	return sessions, nil
}

// DeleteExpired removes sessions past either expiry, returning how many rows
// it removed. It removes nothing else: expired ceremony state and expired
// one-time codes belong to internal/authflow and internal/auth/otp, each of
// which has its own DeleteExpired, and the background sweep (design.md's
// "Session lifecycle") calls all of them. A session store that reached into
// two other packages' tables would put three packages' schema knowledge in
// one statement.
func (s *Store) DeleteExpired(ctx context.Context) (int64, error) {
	const deleteExpiredQuery = `DELETE FROM sessions WHERE idle_expires_at <= $1 OR absolute_expires_at <= $1`

	tag, err := s.handle.Pool().Exec(ctx, deleteExpiredQuery, s.now())
	if err != nil {
		return 0, fmt.Errorf("session: deleting expired sessions: %w", err)
	}

	return tag.RowsAffected(), nil
}
