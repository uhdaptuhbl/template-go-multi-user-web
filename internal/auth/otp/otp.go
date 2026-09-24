package otp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/mail"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
)

// Provider is the identity provider name every email code identity carries,
// so that an account created this way is keyed on (Provider, lowercased
// address) like any other identity rather than on the address alone.
const Provider = "email"

// codeDigits is the number of decimal digits an emailed code carries.
const codeDigits = 8

// emailSubject is the subject line of every code email. A code requested
// with an invite and a code requested without one produce the identical
// subject, body, and response, so that neither can be told apart from the
// other by anyone observing the mail.
const emailSubject = "Your service sign-in code"

// ErrVerification reports a code that did not verify, for any reason.
var ErrVerification = errors.New("code verification failed")

// errEmptyBinding is returned by Request when binding is empty. It is not
// exported because every caller controls its own binding value and an empty
// one is always this package's own caller's bug, never a routine outcome a
// caller needs to distinguish and handle.
var errEmptyBinding = errors.New("otp: binding must not be empty")

// codeRow is the subset of an otp_codes row Verify needs to decide whether a
// presented code matches.
type codeRow struct {
	id       uuid.UUID
	codeHash []byte
	inviteID uuid.NullUUID
}

// Service issues and verifies single-use codes delivered by email.
type Service struct {
	cfg    Config
	handle *store.Handle
	sender mail.Sender
	logger *zap.Logger
	now    func() time.Time
}

// NewService returns a service that persists codes in h, sends through
// sender, and uses now as its clock.
func NewService(cfg Config, h *store.Handle, sender mail.Sender, logger *zap.Logger, now func() time.Time) *Service {
	return &Service{
		cfg:    cfg,
		handle: h,
		sender: sender,
		logger: logger,
		now:    now,
	}
}

// Request issues a code for an address, bound to binding, and mails it. It
// returns nil whether or not the address belongs to an existing account,
// whether or not delivery succeeded, and whether or not inviteID names a live
// invite, because any difference the caller could observe would turn this
// endpoint into an account-existence oracle or an invite oracle. A delivery
// failure is logged instead. It returns a wrapped error for an empty binding:
// the caller is expected to always supply one, so an empty value signals a
// caller bug rather than a routine refusal.
func (s *Service) Request(ctx context.Context, email, binding string, inviteID uuid.NullUUID) error {
	if binding == "" {
		return fmt.Errorf("otp: request: %w", errEmptyBinding)
	}

	normalized := normalizeEmail(email)
	now := s.now()
	bindingHash := sha256.Sum256([]byte(binding))

	carriedInvite, err := s.invalidateOutstanding(ctx, normalized, bindingHash[:], now)
	if err != nil {
		return err
	}

	if !inviteID.Valid && carriedInvite.Valid {
		inviteID = carriedInvite
	}

	code, err := generateCode()
	if err != nil {
		return fmt.Errorf("otp: generating code: %w", err)
	}

	hash := sha256.Sum256([]byte(code))

	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("otp: generating id: %w", err)
	}

	const insertQuery = `
INSERT INTO otp_codes (id, email, code_hash, attempts, invite_id, created_at, expires_at, consumed_at, binding_hash)
VALUES ($1, $2, $3, 0, $4, $5, $6, NULL, $7)
`

	if _, execErr := s.handle.Pool().Exec(ctx, insertQuery,
		id, normalized, hash[:], inviteID, now, now.Add(s.cfg.CodeTTL.Duration()), bindingHash[:],
	); execErr != nil {
		return fmt.Errorf("otp: inserting code: %w", execErr)
	}

	msg := mail.Message{
		To:      normalized,
		Subject: emailSubject,
		Body:    codeEmailBody(code, s.cfg.CodeTTL.Duration()),
	}

	// The address is deliberately not logged (AC-008.91).
	if sendErr := s.sender.Send(ctx, msg); sendErr != nil {
		s.logger.Error("otp: sending code failed",
			zap.Error(sendErr),
		)
	}

	return nil
}

// Verify consumes a code for an address that was requested with binding,
// returning the normalised address and the invite the code was requested
// with. It returns ErrVerification for an unknown address, a wrong code, an
// expired code, a consumed code, and a code that has exhausted its attempts,
// without distinguishing them. A code requested by another binding is never
// found, so it also returns ErrVerification without counting an attempt
// against it, and an empty binding always returns ErrVerification.
func (s *Service) Verify(ctx context.Context, email, code, binding string) (string, uuid.NullUUID, error) {
	if binding == "" {
		return "", uuid.NullUUID{}, ErrVerification
	}

	normalized := normalizeEmail(email)
	now := s.now()
	bindingHash := sha256.Sum256([]byte(binding))

	row, err := s.currentCode(ctx, normalized, bindingHash[:], now)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", uuid.NullUUID{}, ErrVerification
		}

		return "", uuid.NullUUID{}, err
	}

	providedHash := sha256.Sum256([]byte(code))

	if subtle.ConstantTimeCompare(providedHash[:], row.codeHash) != 1 {
		if recordErr := s.recordFailedAttempt(ctx, row.id, now); recordErr != nil {
			return "", uuid.NullUUID{}, recordErr
		}

		return "", uuid.NullUUID{}, ErrVerification
	}

	consumed, err := s.consume(ctx, row.id, row.codeHash, now)
	if err != nil {
		return "", uuid.NullUUID{}, err
	}

	if !consumed {
		return "", uuid.NullUUID{}, ErrVerification
	}

	return normalized, row.inviteID, nil
}

// CodeTTL returns how long an issued code stays valid, which is also the
// binding cookie's lifetime.
func (s *Service) CodeTTL() time.Duration {
	return s.cfg.CodeTTL.Duration()
}

// DeleteExpired removes codes past their expiry, returning how many it
// removed.
func (s *Service) DeleteExpired(ctx context.Context) (int64, error) {
	const deleteExpiredQuery = `DELETE FROM otp_codes WHERE expires_at <= $1`

	tag, err := s.handle.Pool().Exec(ctx, deleteExpiredQuery, s.now())
	if err != nil {
		return 0, fmt.Errorf("otp: deleting expired codes: %w", err)
	}

	return tag.RowsAffected(), nil
}

// invalidateOutstanding marks any unconsumed code for address requested with
// bindingHash as consumed, so that an earlier code from the same binding
// stops working as soon as a replacement is requested. A code outstanding
// under a different binding is left untouched, since AC-008.82 confines each
// binding to invalidating only its own codes. This runs outside a
// transaction with the insert that follows it, so two Request calls racing
// on the same address and binding can both leave a row unconsumed. That is
// harmless because currentCode only ever offers the newest live row for
// verification: a stranded older row is unreachable, not a second guessable
// code. It returns the invite_id of the newest row it invalidated, if any,
// so a caller can carry an outstanding invite forward onto a new code
// requested without one.
func (s *Service) invalidateOutstanding(ctx context.Context, address string, bindingHash []byte, now time.Time) (uuid.NullUUID, error) {
	const invalidateQuery = `
UPDATE otp_codes SET consumed_at = $3
WHERE email = $1 AND binding_hash = $2 AND consumed_at IS NULL
RETURNING invite_id
`

	rows, err := s.handle.Pool().Query(ctx, invalidateQuery, address, bindingHash, now)
	if err != nil {
		return uuid.NullUUID{}, fmt.Errorf("otp: invalidating outstanding code: %w", err)
	}
	defer rows.Close()

	carried := uuid.NullUUID{}

	for rows.Next() {
		var inviteID uuid.NullUUID

		if scanErr := rows.Scan(&inviteID); scanErr != nil {
			return uuid.NullUUID{}, fmt.Errorf("otp: scanning invalidated code: %w", scanErr)
		}

		if inviteID.Valid {
			carried = inviteID
		}
	}

	if rowsErr := rows.Err(); rowsErr != nil {
		return uuid.NullUUID{}, fmt.Errorf("otp: reading invalidated codes: %w", rowsErr)
	}

	return carried, nil
}

// currentCode returns the live, unconsumed, unexpired code row for address
// requested with bindingHash, or pgx.ErrNoRows when there is none.
func (s *Service) currentCode(ctx context.Context, address string, bindingHash []byte, now time.Time) (codeRow, error) {
	const selectQuery = `
SELECT id, code_hash, invite_id
FROM otp_codes
WHERE email = $1 AND binding_hash = $3 AND consumed_at IS NULL AND expires_at > $2
ORDER BY created_at DESC
LIMIT 1
`

	var row codeRow

	if err := s.handle.Pool().QueryRow(ctx, selectQuery, address, now, bindingHash).Scan(&row.id, &row.codeHash, &row.inviteID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return codeRow{}, pgx.ErrNoRows
		}

		return codeRow{}, fmt.Errorf("otp: selecting current code: %w", err)
	}

	return row, nil
}

// recordFailedAttempt increments a row's attempt count and, once that count
// reaches the configured limit, marks the row consumed so a later correct
// guess still fails.
func (s *Service) recordFailedAttempt(ctx context.Context, id uuid.UUID, now time.Time) error {
	const failQuery = `
UPDATE otp_codes
SET attempts = attempts + 1,
    consumed_at = CASE WHEN attempts + 1 >= $2 THEN $3 ELSE consumed_at END
WHERE id = $1 AND consumed_at IS NULL
`

	if _, err := s.handle.Pool().Exec(ctx, failQuery, id, s.cfg.MaxAttempts, now); err != nil {
		return fmt.Errorf("otp: recording failed attempt: %w", err)
	}

	return nil
}

// consume marks a matched row consumed in the same statement that matches its
// digest, so the code is single-use even under a concurrent replay. It
// reports whether this call was the one that consumed it.
func (s *Service) consume(ctx context.Context, id uuid.UUID, codeHash []byte, now time.Time) (bool, error) {
	const consumeQuery = `
UPDATE otp_codes SET consumed_at = $3
WHERE id = $1 AND code_hash = $2 AND consumed_at IS NULL
`

	tag, err := s.handle.Pool().Exec(ctx, consumeQuery, id, codeHash, now)
	if err != nil {
		return false, fmt.Errorf("otp: consuming code: %w", err)
	}

	return tag.RowsAffected() > 0, nil
}

// normalizeEmail trims whitespace and lowercases an address, so the same
// address always maps to the same stored and compared value.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// generateCode returns a code of codeDigits decimal digits drawn from
// crypto/rand. Each digit is drawn independently with math/big's Int, which
// performs rejection sampling internally rather than reducing a random value
// modulo ten, so no digit is biased toward the low end of its range.
func generateCode() (string, error) {
	digits := make([]byte, codeDigits)

	// tenDigits bounds each single-digit draw. It is built per call rather than
	// held at package scope because a *big.Int is mutable and a package-level
	// one would be shared mutable state.
	var tenDigits = big.NewInt(10)

	for i := range digits {
		n, err := rand.Int(rand.Reader, tenDigits)
		if err != nil {
			return "", fmt.Errorf("otp: drawing random digit: %w", err)
		}

		digits[i] = '0' + byte(n.Int64())
	}

	return string(digits), nil
}

// codeEmailBody renders the body of a code email, naming the code, its
// expiry in minutes, and a note to ignore the message if it was not
// requested.
func codeEmailBody(code string, ttl time.Duration) string {
	return fmt.Sprintf(
		"Your service sign-in code is %s. It expires in %d minutes. If you did not request this code, you can ignore this message.",
		code, int(ttl.Minutes()),
	)
}
