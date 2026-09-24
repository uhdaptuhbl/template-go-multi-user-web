package invite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/settings"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
)

// inviteColumns names the columns selected from the invites table, in the
// order Invite's db tags expect them. email is coalesced to the empty string
// so Invite's Email field, which is a plain string rather than a pointer, can
// scan a NULL column.
const inviteColumns = "id, created_by, created_by_ref, COALESCE(email, '') AS email, note, max_uses, uses, created_at, expires_at, revoked_at"

// stateLive, stateRevoked, stateExpired, and stateSpent are the values State
// returns.
const stateLive = "live"
const stateRevoked = "revoked"
const stateExpired = "expired"
const stateSpent = "spent"

// Invite is an issued invitation to create an account. It never carries its
// token: only the digest is stored, so nothing can reconstruct the link.
type Invite struct {
	// ID is the invite's public identifier, used in administrative routes.
	ID uuid.UUID `db:"id" json:"-"`
	// CreatedBy is the issuing account while it exists.
	CreatedBy uuid.NullUUID `db:"created_by" json:"-"`
	// CreatedByRef identifies the issuer in the audit package's
	// "<kind>:<value>" subject grammar (see internal/audit.ErrMalformedSubject)
	// and survives that account's purge.
	CreatedByRef string `db:"created_by_ref" json:"-"`
	// Email, when non-empty, binds the invite to one lowercased address that
	// the redeeming authentication must have verifiably asserted.
	Email string `db:"email" json:"-"`
	// Note is a free-text reminder for the issuer. It is never shown to the
	// redeemer.
	Note string `db:"note" json:"-"`
	// MaxUses is how many accounts this invite may create.
	MaxUses int `db:"max_uses" json:"-"`
	// Uses is how many it has created.
	Uses int `db:"uses" json:"-"`
	// CreatedAt is when it was issued.
	CreatedAt time.Time `db:"created_at" json:"-"`
	// ExpiresAt is when it stops being redeemable regardless of Uses.
	ExpiresAt time.Time `db:"expires_at" json:"-"`
	// RevokedAt is when it was revoked, if it was.
	RevokedAt *time.Time `db:"revoked_at" json:"-"`
}

// State reports whether the invite is live at t, and which of revoked,
// expired, or spent it is otherwise. It is derived, never stored.
func (i Invite) State(t time.Time) string {
	switch {
	case i.RevokedAt != nil:
		return stateRevoked
	case !i.ExpiresAt.After(t):
		return stateExpired
	case i.Uses >= i.MaxUses:
		return stateSpent
	default:
		return stateLive
	}
}

// Issued is a newly created invite together with the only copy of its token
// that will ever exist outside the recipient's hands. Token carries the sole
// plaintext copy of the invite's bearer credential: it must never be logged,
// passed to zap, or serialised except in the single creation response that
// discloses it once.
type Issued struct {
	Invite Invite
	Token  string
}

// Params are the caller-supplied fields of a new invite. A zero MaxUses or
// TTL takes the configured default.
type Params struct {
	Email   string
	Note    string
	MaxUses int
	TTL     time.Duration
}

// Service issues, looks up, redeems, and revokes invites.
type Service struct {
	handle     *store.Handle
	policy     *settings.Store
	tokenBytes int
	logger     *zap.Logger
	now        func() time.Time
}

// ErrInvalid reports an invite that is unknown, expired, spent, or revoked.
// It does not distinguish them, because the holder of a dead token learns
// nothing useful from the difference and an attacker learns which tokens
// exist.
var ErrInvalid = errors.New("invite invalid")

// ErrEmailMismatch reports a bound invite presented by an authentication that
// did not verifiably assert its address.
var ErrEmailMismatch = errors.New("invite address mismatch")

// ErrQuotaExhausted reports an issuer that already holds as many live invites
// as its quota allows.
var ErrQuotaExhausted = errors.New("invite quota exhausted")

// ErrMaxUsesTooHigh reports a requested redemption limit above the configured
// ceiling.
var ErrMaxUsesTooHigh = errors.New("redemption limit too high")

// ErrTTLTooLong reports a requested invite lifetime above the configured maximum. A caller
// should answer 400 invalid_request.
var ErrTTLTooLong = errors.New("invite: lifetime too long")

// ErrTokenBytesTooShort reports a NewService call whose tokenBytes is below
// minTokenBytes.
var ErrTokenBytesTooShort = errors.New("invite token length too short")

// ErrInvalidCursor is returned by List when cursor is not one List issued.
// A caller matching this with errors.Is should answer the request as
// malformed rather than as a server failure.
var ErrInvalidCursor = errors.New("invite: invalid list cursor")

// minTokenBytes is the fewest bytes NewService accepts for tokenBytes. Below
// this, the token space is small enough that collisions become plausible
// rather than merely theoretical, and at 0 every invite would share the same
// empty token and therefore the same digest. That failure mode is caught by
// the token_hash unique index at insert time regardless, but this guard
// catches it at wiring time instead of at the first concurrent Create.
const minTokenBytes = 16

// NewService returns a service persisting through h, reading its limits from
// policy, and drawing tokens of tokenBytes from crypto/rand. policy supplies
// only the invite defaults and invite_max_uses_limit. It is never read for an
// issuer's quota: that number depends on the caller's roles, so Create takes
// it as an argument and the route is its single source. It returns
// ErrTokenBytesTooShort when tokenBytes is below minTokenBytes.
func NewService(h *store.Handle, policy *settings.Store, tokenBytes int, logger *zap.Logger, now func() time.Time) (*Service, error) {
	if tokenBytes < minTokenBytes {
		return nil, fmt.Errorf("invite: NewService: %w", ErrTokenBytesTooShort)
	}

	return &Service{
		handle:     h,
		policy:     policy,
		tokenBytes: tokenBytes,
		logger:     logger,
		now:        now,
	}, nil
}

// Create issues an invite on behalf of an account. unlimitedQuota lifts the outstanding-invite
// quota for issuers who hold the invite-management permission; otherwise the quota is the
// settings row's invite_default_quota, read inside the same transaction as the insert. The
// returned token is the only copy; it is not recoverable afterwards.
func (s *Service) Create(ctx context.Context, issuer uuid.UUID, issuerRef string, unlimitedQuota bool, in Params) (Issued, error) {
	tx, err := s.handle.Pool().Begin(ctx)
	if err != nil {
		return Issued{}, fmt.Errorf("invite: beginning create transaction: %w", err)
	}

	// This transaction-scoped advisory lock is the first statement in the
	// transaction, before outstandingTx's count, so that two concurrent
	// Create calls for the same issuer cannot both read the same
	// outstanding count and both pass the quota check: Postgres' default
	// READ COMMITTED isolation makes a concurrent uncommitted insert
	// invisible to that count, so without this lock an issuer with quota k
	// firing m concurrent requests could end up with k+m-1 live invites. The
	// lock is released automatically at commit or rollback. A future reader
	// who sees no visible contention on this line should not remove it: the
	// race it prevents only ever shows up under concurrent load against a
	// non-zero quota.
	if _, lockErr := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, issuer); lockErr != nil {
		return Issued{}, errors.Join(fmt.Errorf("invite: locking issuer quota: %w", lockErr), wrapRollbackErr(tx.Rollback(ctx)))
	}

	policy, err := s.policy.LoadTx(ctx, tx)
	if err != nil {
		return Issued{}, errors.Join(fmt.Errorf("invite: loading policy: %w", err), wrapRollbackErr(tx.Rollback(ctx)))
	}

	maxUses, maxUsesErr := resolveMaxUses(in.MaxUses, policy)
	if maxUsesErr != nil {
		return Issued{}, errors.Join(maxUsesErr, wrapRollbackErr(tx.Rollback(ctx)))
	}

	ttl, ttlErr := resolveTTL(in.TTL, policy)
	if ttlErr != nil {
		return Issued{}, errors.Join(ttlErr, wrapRollbackErr(tx.Rollback(ctx)))
	}

	if !unlimitedQuota {
		outstanding, outstandingErr := outstandingTx(ctx, tx, issuer, s.now())
		if outstandingErr != nil {
			return Issued{}, errors.Join(outstandingErr, wrapRollbackErr(tx.Rollback(ctx)))
		}

		if outstanding >= policy.InviteDefaultQuota {
			return Issued{}, errors.Join(ErrQuotaExhausted, wrapRollbackErr(tx.Rollback(ctx)))
		}
	}

	raw := make([]byte, s.tokenBytes)

	if _, readErr := rand.Read(raw); readErr != nil {
		return Issued{}, errors.Join(fmt.Errorf("invite: generating token: %w", readErr), wrapRollbackErr(tx.Rollback(ctx)))
	}

	token := base64.RawURLEncoding.EncodeToString(raw)
	digest := digestToken(token)

	id, err := uuid.NewV7()
	if err != nil {
		return Issued{}, errors.Join(fmt.Errorf("invite: generating id: %w", err), wrapRollbackErr(tx.Rollback(ctx)))
	}

	now := s.now()

	invite := Invite{
		ID:           id,
		CreatedBy:    uuid.NullUUID{UUID: issuer, Valid: true},
		CreatedByRef: issuerRef,
		Email:        strings.ToLower(strings.TrimSpace(in.Email)),
		Note:         in.Note,
		MaxUses:      maxUses,
		Uses:         0,
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
		RevokedAt:    nil,
	}

	var emailArg *string

	if invite.Email != "" {
		emailArg = &invite.Email
	}

	const insertQuery = `
INSERT INTO invites (id, token_hash, created_by, created_by_ref, email, note, max_uses, uses, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
`

	if _, execErr := tx.Exec(ctx, insertQuery,
		invite.ID, digest, invite.CreatedBy, invite.CreatedByRef, emailArg, invite.Note,
		invite.MaxUses, invite.Uses, invite.CreatedAt, invite.ExpiresAt,
	); execErr != nil {
		return Issued{}, errors.Join(fmt.Errorf("invite: inserting invite: %w", execErr), wrapRollbackErr(tx.Rollback(ctx)))
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return Issued{}, fmt.Errorf("invite: committing create transaction: %w", commitErr)
	}

	s.logger.Info("invite: issued",
		zap.String("invite_id", invite.ID.String()),
		zap.String("issuer_ref", invite.CreatedByRef),
		zap.Int("max_uses", invite.MaxUses),
	)

	return Issued{Invite: invite, Token: token}, nil
}

// lookupRow is the scan target for Lookup, which alone among this package's
// reads needs the stored digest to compare against the presented token.
type lookupRow struct {
	Invite
	TokenHash []byte `db:"token_hash"`
}

// Lookup resolves a raw token to its invite without redeeming it, which is
// what the ceremony start routes and the redemption landing route use. It
// returns ErrInvalid for an unknown, expired, spent, or revoked token without
// distinguishing them.
func (s *Service) Lookup(ctx context.Context, token string) (Invite, error) {
	digest := digestToken(token)

	const query = "SELECT " + inviteColumns + ", token_hash FROM invites WHERE token_hash = $1"

	rows, err := s.handle.Pool().Query(ctx, query, digest)
	if err != nil {
		return Invite{}, fmt.Errorf("invite: querying invite by token: %w", err)
	}

	row, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[lookupRow])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Invite{}, ErrInvalid
		}

		return Invite{}, fmt.Errorf("invite: collecting invite by token: %w", err)
	}

	// The index lookup above already narrowed to the one row whose digest
	// equals the presented token's, so this comparison can never disagree
	// with it. It runs anyway in constant time, rather than trusting the
	// index equality alone, so nothing about this package's guarantee that a
	// dead token costs exactly one indexed lookup and nothing more depends on
	// how Postgres implements that equality.
	if subtle.ConstantTimeCompare(row.TokenHash, digest) != 1 {
		return Invite{}, ErrInvalid
	}

	if row.State(s.now()) != stateLive {
		return Invite{}, ErrInvalid
	}

	return row.Invite, nil
}

// ValidateTx re-reads an invite FOR UPDATE inside an open transaction and
// reports whether it is still redeemable, which is what signup admission
// rule 5 (design.md's "Signup admission path") calls before it creates an
// account. The lock it takes is held for the rest
// of the transaction, so the conditional increment RedeemTx issues later
// cannot be interleaved with another redemption of the same invite.
//
// It returns ErrInvalid when the invite is revoked, expired, or spent, and
// ErrEmailMismatch when the invite is bound to an address verifiedEmail does
// not match. An empty verifiedEmail never satisfies a binding, so the caller
// passes an empty string rather than an unverified address.
func (s *Service) ValidateTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, verifiedEmail string) (Invite, error) {
	const query = "SELECT " + inviteColumns + " FROM invites WHERE id = $1 FOR UPDATE"

	rows, err := tx.Query(ctx, query, id)
	if err != nil {
		return Invite{}, fmt.Errorf("invite: querying invite for update: %w", err)
	}

	invite, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[Invite])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Invite{}, ErrInvalid
		}

		return Invite{}, fmt.Errorf("invite: collecting invite for update: %w", err)
	}

	if invite.State(s.now()) != stateLive {
		return Invite{}, ErrInvalid
	}

	if !emailMatches(invite.Email, verifiedEmail) {
		return Invite{}, ErrEmailMismatch
	}

	return invite, nil
}

// RedeemTx spends one use of an invite inside an open transaction and records
// the redemption against the new account. It re-validates rather than trusting
// an earlier Lookup, because minutes may have passed. It returns ErrInvalid
// when the invite is no longer live and ErrEmailMismatch when the invite is
// bound to an address the authentication did not verifiably assert.
func (s *Service) RedeemTx(ctx context.Context, tx pgx.Tx, id, userID uuid.UUID, userRef, verifiedEmail string) error {
	var boundEmail string

	err := tx.QueryRow(ctx, `SELECT COALESCE(email, '') FROM invites WHERE id = $1`, id).Scan(&boundEmail)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalid
		}

		return fmt.Errorf("invite: reading invite email binding: %w", err)
	}

	if !emailMatches(boundEmail, verifiedEmail) {
		return ErrEmailMismatch
	}

	now := s.now()

	// The email predicate here is a backstop, not the primary check: the
	// pre-read above already produces the distinct ErrEmailMismatch that
	// signup admission rule 6 (design.md's "Signup admission path") needs,
	// and is currently safe only because no code anywhere
	// writes invites.email after insert, an invariant enforced by the
	// absence of code rather than by this statement. Folding the same
	// predicate into the conditional UPDATE makes the safety property
	// independent of a future migration or admin tool that might add such a
	// write between the pre-read and the update.
	const spendQuery = `
UPDATE invites
SET uses = uses + 1
WHERE id = $1 AND revoked_at IS NULL AND expires_at > $2 AND uses < max_uses
  AND (email IS NULL OR lower(email) = lower($3))
`

	tag, err := tx.Exec(ctx, spendQuery, id, now, verifiedEmail)
	if err != nil {
		return fmt.Errorf("invite: spending invite use: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return ErrInvalid
	}

	redemptionID, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("invite: generating redemption id: %w", err)
	}

	const insertRedemptionQuery = `
INSERT INTO invite_redemptions (id, invite_id, user_id, user_ref, redeemed_at)
VALUES ($1, $2, $3, $4, $5)
`

	if _, execErr := tx.Exec(ctx, insertRedemptionQuery, redemptionID, id, userID, userRef, now); execErr != nil {
		return fmt.Errorf("invite: recording redemption: %w", execErr)
	}

	return nil
}

// listFirstPageAllQuery is List's query for the first page across every
// issuer.
const listFirstPageAllQuery = "SELECT " + inviteColumns + " FROM invites ORDER BY created_at DESC, id DESC LIMIT $1"

// listFirstPageOwnQuery is List's query for the first page scoped to one
// issuer.
const listFirstPageOwnQuery = "SELECT " + inviteColumns + " FROM invites WHERE created_by = $1 ORDER BY created_at DESC, id DESC LIMIT $2"

// listNextPageAllQuery is List's query for a later page across every issuer,
// continuing after the invite named by cursor.
const listNextPageAllQuery = `
SELECT ` + inviteColumns + `
FROM invites
WHERE (created_at, id) < (SELECT created_at, id FROM invites WHERE id = $1)
ORDER BY created_at DESC, id DESC
LIMIT $2
`

// listNextPageOwnQuery is List's query for a later page scoped to one issuer,
// continuing after the invite named by cursor.
const listNextPageOwnQuery = `
SELECT ` + inviteColumns + `
FROM invites
WHERE created_by = $1
  AND (created_at, id) < (SELECT created_at, id FROM invites WHERE id = $2 AND created_by = $1)
ORDER BY created_at DESC, id DESC
LIMIT $3
`

// defaultPageSize is the page size List uses when the caller asks for a limit
// below 1.
const defaultPageSize = 20

// maxPageSize is the largest page List will return in one call, regardless of
// what the caller asks for, so a caller cannot request an unbounded page.
const maxPageSize = 100

// List returns invites most recent first. When all is false it returns only
// those the named account issued, which is the ownership predicate; when true
// it returns every invite, which requires PermissionInviteManage at the route.
// limit is clamped to the range 1 to maxPageSize before use: a limit below 1
// takes defaultPageSize instead of reaching listQueryAndArgs, which computes
// LIMIT as limit+1 with no floor of its own and would otherwise let a caller
// index an empty page.
func (s *Service) List(ctx context.Context, viewer uuid.UUID, all bool, cursor string, limit int) ([]Invite, string, error) {
	clampedLimit := limit

	if clampedLimit < 1 {
		clampedLimit = defaultPageSize
	}

	if clampedLimit > maxPageSize {
		clampedLimit = maxPageSize
	}

	query, args, err := listQueryAndArgs(viewer, all, cursor, clampedLimit)
	if err != nil {
		return nil, "", err
	}

	rows, err := s.handle.Pool().Query(ctx, query, args...)
	if err != nil {
		return nil, "", fmt.Errorf("invite: querying invite list: %w", err)
	}

	invites, err := pgx.CollectRows(rows, pgx.RowToStructByName[Invite])
	if err != nil {
		return nil, "", fmt.Errorf("invite: collecting invite list: %w", err)
	}

	if len(invites) <= clampedLimit {
		return invites, "", nil
	}

	page := invites[:clampedLimit]

	return page, page[len(page)-1].ID.String(), nil
}

// Get returns one invite by identifier, scoped to the viewer unless all is
// true, for the same reason List is.
func (s *Service) Get(ctx context.Context, id, viewer uuid.UUID, all bool) (Invite, error) {
	var rows pgx.Rows

	var err error

	if all {
		const query = "SELECT " + inviteColumns + " FROM invites WHERE id = $1"

		rows, err = s.handle.Pool().Query(ctx, query, id)
	} else {
		const query = "SELECT " + inviteColumns + " FROM invites WHERE id = $1 AND created_by = $2"

		rows, err = s.handle.Pool().Query(ctx, query, id, viewer)
	}

	if err != nil {
		return Invite{}, fmt.Errorf("invite: querying invite: %w", err)
	}

	invite, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[Invite])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Invite{}, ErrInvalid
		}

		return Invite{}, fmt.Errorf("invite: collecting invite: %w", err)
	}

	return invite, nil
}

// Revoke marks an invite unusable. It is idempotent, and is scoped to the
// viewer unless all is true. It reports whether it changed a row, which is
// false for an invite that was already revoked and false for one belonging to
// another issuer; the ownership isolation test (design.md's "Authorization
// path") needs that distinction. The route never reaches it for another
// issuer's invite: it loads the invite first under the same scope and answers
// 404 when that fails, so only an already-revoked invite answers 204 with
// nothing changed.
func (s *Service) Revoke(ctx context.Context, id, viewer uuid.UUID, all bool) (bool, error) {
	now := s.now()

	var tag pgconn.CommandTag

	var err error

	if all {
		tag, err = s.handle.Pool().Exec(ctx, `UPDATE invites SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL`, now, id)
	} else {
		tag, err = s.handle.Pool().Exec(ctx, `UPDATE invites SET revoked_at = $1 WHERE id = $2 AND created_by = $3 AND revoked_at IS NULL`, now, id, viewer)
	}

	if err != nil {
		return false, fmt.Errorf("invite: revoking invite: %w", err)
	}

	changed := tag.RowsAffected() > 0

	if changed {
		s.logger.Info("invite: revoked", zap.String("invite_id", id.String()))
	}

	return changed, nil
}

// Outstanding counts the live invites an account currently holds, which is
// what the quota is measured against.
func (s *Service) Outstanding(ctx context.Context, issuer uuid.UUID) (int, error) {
	const query = `SELECT COUNT(*) FROM invites WHERE created_by = $1 AND revoked_at IS NULL AND expires_at > $2 AND uses < max_uses`

	var count int

	if err := s.handle.Pool().QueryRow(ctx, query, issuer, s.now()).Scan(&count); err != nil {
		return 0, fmt.Errorf("invite: counting outstanding invites: %w", err)
	}

	return count, nil
}

// DeleteExpired removes invites that expired more than retain ago and were
// neither revoked nor fully spent, returning how many it removed. Revoked
// and spent invites are kept indefinitely, regardless of age, because each
// one records an admission decision that already happened, and deleting a
// spent invite would also delete its invite_redemptions rows through
// ON DELETE CASCADE. The retain window gives an issuer or administrator time
// to review a recently dead invite before it disappears. A negative retain
// is clamped to zero, so this can never compute a cutoff in the future and
// delete an invite that is still live.
func (s *Service) DeleteExpired(ctx context.Context, retain time.Duration) (int64, error) {
	if retain < 0 {
		retain = 0
	}

	const query = `DELETE FROM invites WHERE expires_at <= $1 AND revoked_at IS NULL AND uses < max_uses`

	tag, err := s.handle.Pool().Exec(ctx, query, s.now().Add(-retain))
	if err != nil {
		return 0, fmt.Errorf("invite: deleting expired invites: %w", err)
	}

	return tag.RowsAffected(), nil
}

// queryArgs is the positional argument list a query executes with. It is a
// named type, rather than a bare []any, only so listQueryAndArgs's two
// non-error results (a string and an argument list) are not seen as the same
// shape by gocritic's unnamedResult check.
type queryArgs []any

// listQueryAndArgs picks the query and argument list List issues for the
// requested page, which depends on whether the caller is scoped to one
// issuer and whether a cursor continues an earlier page.
func listQueryAndArgs(viewer uuid.UUID, all bool, cursor string, limit int) (string, queryArgs, error) {
	if cursor == "" {
		if all {
			return listFirstPageAllQuery, queryArgs{limit + 1}, nil
		}

		return listFirstPageOwnQuery, queryArgs{viewer, limit + 1}, nil
	}

	after, err := uuid.Parse(cursor)
	if err != nil {
		return "", nil, fmt.Errorf("invite: parsing list cursor: %w: %w", ErrInvalidCursor, err)
	}

	if all {
		return listNextPageAllQuery, queryArgs{after, limit + 1}, nil
	}

	return listNextPageOwnQuery, queryArgs{viewer, after, limit + 1}, nil
}

// resolveMaxUses picks the redemption limit Create writes: requested when
// positive, otherwise policy's configured default. A zero or negative
// requested value is not a distinct caller intent worth its own sentinel: it
// takes the default rather than reaching the insert, where the max_uses > 0
// CHECK constraint would reject it as a wrapped PgError, giving the caller a
// 500-shaped error instead of a sentinel and leaking a constraint name. It
// returns ErrMaxUsesTooHigh when the resolved value exceeds policy's
// configured ceiling.
func resolveMaxUses(requested int, policy settings.Settings) (int, error) {
	maxUses := requested
	if maxUses <= 0 {
		maxUses = policy.InviteDefaultMaxUses
	}

	if maxUses > policy.InviteMaxUsesLimit {
		return 0, ErrMaxUsesTooHigh
	}

	return maxUses, nil
}

// resolveTTL picks the lifetime Create writes. An unrequested TTL (zero or
// negative) takes policy's configured default, capped at policy's configured
// maximum when one is set: AC-008.80 requires the ceiling to bind on the
// default just as it binds an explicit request, rather than letting a
// default that outgrew the ceiling slip through uncapped. An explicit
// request above a configured maximum returns ErrTTLTooLong instead of being
// capped, so the caller learns their request was rejected rather than
// silently shortened.
func resolveTTL(requested time.Duration, policy settings.Settings) (time.Duration, error) {
	if requested <= 0 {
		ttl := time.Duration(policy.InviteDefaultTTLSecs) * time.Second
		if policy.InviteMaxTTL > 0 && ttl > policy.InviteMaxTTL {
			ttl = policy.InviteMaxTTL
		}

		return ttl, nil
	}

	if policy.InviteMaxTTL > 0 && requested > policy.InviteMaxTTL {
		return 0, ErrTTLTooLong
	}

	return requested, nil
}

// outstandingTx counts issuer's live invites within tx, which is what Create
// uses to enforce the caller's quota atomically with the insert it performs
// next.
func outstandingTx(ctx context.Context, tx pgx.Tx, issuer uuid.UUID, now time.Time) (int, error) {
	const query = `SELECT COUNT(*) FROM invites WHERE created_by = $1 AND revoked_at IS NULL AND expires_at > $2 AND uses < max_uses`

	var count int

	if err := tx.QueryRow(ctx, query, issuer, now).Scan(&count); err != nil {
		return 0, fmt.Errorf("invite: counting outstanding invites: %w", err)
	}

	return count, nil
}

// emailMatches reports whether verifiedEmail satisfies the binding an invite
// carries in boundEmail. An unbound invite (an empty boundEmail) is always
// satisfied. A bound invite is never satisfied by an empty verifiedEmail,
// even though an empty string trivially case-folds to itself, so an
// unverified address cannot claim a bound invite. The comparison uses
// strings.ToLower rather than strings.EqualFold, which is Unicode simple case
// folding and diverges from ToLower on some characters, so this agrees with
// Create's own strings.ToLower storage and with the database's
// lower(email) unique index on the users table.
func emailMatches(boundEmail, verifiedEmail string) bool {
	if boundEmail == "" {
		return true
	}

	if verifiedEmail == "" {
		return false
	}

	// gocritic's equalFold check and staticcheck's SA6005 both want
	// strings.EqualFold here, which is exactly the function this comparison
	// deliberately avoids: EqualFold is Unicode simple case folding, which
	// diverges from strings.ToLower on some characters, and this must agree
	// with Create's own ToLower storage and the database's lower(email)
	// unique index rather than with case-fold equality in general.
	//nolint:gocritic,staticcheck // ToLower, not EqualFold, is the deliberate choice; see the comment above.
	return strings.ToLower(boundEmail) == strings.ToLower(verifiedEmail)
}

// digestToken returns the SHA-256 digest of a raw invite token, the only form
// ever persisted.
func digestToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))

	return sum[:]
}

// wrapRollbackErr wraps a transaction rollback failure with context, or
// returns nil when the rollback succeeded.
func wrapRollbackErr(err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("invite: rolling back create transaction: %w", err)
}
