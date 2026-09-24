package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
)

// Outcome is whether the audited action succeeded.
type Outcome string

// OutcomeSuccess records an action that completed.
const OutcomeSuccess Outcome = "success"

// OutcomeFailure records an action that was attempted and refused.
const OutcomeFailure Outcome = "failure"

// ErrMalformedSubject reports that an Event's Subject does not match the
// "<kind>:<value>" grammar. A log that mixes reference formats cannot be
// queried and the mistake is invisible once the rows are written, so Record
// rejects it before it reaches the database. The literal "anonymous" is not a
// legal Subject.
var ErrMalformedSubject = errors.New(`audit: subject does not match the "<kind>:<value>" grammar`)

// ErrInvalidCursor reports a malformed audit list cursor. A caller should
// answer 400 invalid_request.
var ErrInvalidCursor = errors.New("audit: invalid list cursor")

// credentialMarkers are the lowercased substrings that mark a Detail field as
// credential material to be dropped rather than logged.
var credentialMarkers = []string{"token", "secret", "password", "code", "credential", "assertion"}

// permittedSubjectKinds are the subject kinds validateSubject accepts, the
// text before the first ":" in a Subject.
var permittedSubjectKinds = map[string]struct{}{
	"user":       {},
	"email":      {},
	"provider":   {},
	"settings":   {},
	"invite":     {},
	"session":    {},
	"credential": {},
	"identity":   {},
	"anonymous":  {},
}

// Event is one append-only record of something security-relevant happening.
type Event struct {
	ID         uuid.UUID       `db:"id"`
	OccurredAt time.Time       `db:"occurred_at"`
	ActorID    *uuid.UUID      `db:"actor_id"`
	ActorRef   string          `db:"actor_ref"`
	Subject    string          `db:"subject"`
	Action     string          `db:"action"`
	Outcome    Outcome         `db:"outcome"`
	ClientIP   *netip.Addr     `db:"client_ip"`
	RequestID  string          `db:"request_id"`
	Detail     json.RawMessage `db:"detail"`
}

// pgxExecutor is the subset of the pgx executor surface Record and RecordTx
// need to append a row. Both *pgxpool.Pool and pgx.Tx satisfy it, so the
// insert path is identical whether it runs against the pool directly or
// against a caller's transaction.
type pgxExecutor interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Recorder appends audit events.
type Recorder struct {
	pool   *pgxpool.Pool
	logger *zap.Logger
	now    func() time.Time
}

// Cursor is a position in the audit log, most recent first. The zero Cursor
// means the first page.
type Cursor struct {
	OccurredAt time.Time
	ID         uuid.UUID
}

// String encodes c as "<occurred_at in RFC 3339 with nanoseconds,
// UTC>_<id>", the form ParseCursor reads and the audit list endpoint returns
// as next_cursor.
func (c Cursor) String() string {
	return c.OccurredAt.UTC().Format(time.RFC3339Nano) + "_" + c.ID.String()
}

// isZero reports whether c is the zero Cursor, meaning the first page.
func (c Cursor) isZero() bool {
	return c == Cursor{}
}

// ParseCursor decodes a String-encoded cursor, returning ErrInvalidCursor
// when s is not one.
func ParseCursor(s string) (Cursor, error) {
	timestamp, id, ok := strings.Cut(s, "_")
	if !ok {
		return Cursor{}, fmt.Errorf("%w: %q", ErrInvalidCursor, s)
	}

	occurredAt, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return Cursor{}, fmt.Errorf("%w: %q", ErrInvalidCursor, s)
	}

	parsedID, err := uuid.Parse(id)
	if err != nil {
		return Cursor{}, fmt.Errorf("%w: %q", ErrInvalidCursor, s)
	}

	return Cursor{OccurredAt: occurredAt, ID: parsedID}, nil
}

// NewRecorder returns a recorder backed by h, using now as its clock and
// logger for the case where the append itself fails.
func NewRecorder(h *store.Handle, logger *zap.Logger, now func() time.Time) *Recorder {
	return &Recorder{
		pool:   h.Pool(),
		logger: logger,
		now:    now,
	}
}

// Record appends e, filling its identifier, its timestamp, and ActorRef from
// ActorID. A failure to append is logged at error level and returned; the
// caller decides whether it is fatal, and for an authentication path it is
// not, because refusing to authenticate a valid user because the audit table
// is full is a worse outcome than a missing record.
func (r *Recorder) Record(ctx context.Context, e Event) error {
	if err := validateSubject(e.Subject); err != nil {
		return err
	}

	prepared, err := prepareEvent(e, r.now)
	if err != nil {
		return err
	}

	if insertEventErr := insertEvent(ctx, r.pool, prepared); insertEventErr != nil {
		r.logger.Error("audit: failed to append event",
			zap.String("action", prepared.Action),
			zap.String("subject", prepared.Subject),
			zap.Error(insertEventErr),
		)

		return insertEventErr
	}

	return nil
}

// RecordTx is Record against the caller's transaction, so the event commits
// or rolls back with the change it describes.
func (r *Recorder) RecordTx(ctx context.Context, tx pgx.Tx, e Event) error {
	if err := validateSubject(e.Subject); err != nil {
		return err
	}

	prepared, err := prepareEvent(e, r.now)
	if err != nil {
		return err
	}

	return insertEvent(ctx, tx, prepared)
}

// prepareEvent fills e's identifier, timestamp, ActorRef, and default Detail
// ahead of an insert.
func prepareEvent(e Event, now func() time.Time) (Event, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return Event{}, fmt.Errorf("audit: generating event id: %w", err)
	}

	e.ID = id
	e.OccurredAt = now()

	if e.ActorID != nil {
		e.ActorRef = "user:" + e.ActorID.String()
	} else {
		e.ActorRef = "anonymous"
	}

	if e.Detail == nil {
		e.Detail = json.RawMessage("{}")
	}

	return e, nil
}

// insertEvent appends e through exec, the shared insert path for Record and
// RecordTx.
func insertEvent(ctx context.Context, exec pgxExecutor, e Event) error {
	const query = `
		INSERT INTO audit_events
			(id, occurred_at, actor_id, actor_ref, subject, action, outcome, client_ip, request_id, detail)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err := exec.Exec(ctx, query,
		e.ID, e.OccurredAt, e.ActorID, e.ActorRef, e.Subject, e.Action, e.Outcome, e.ClientIP, e.RequestID, e.Detail,
	)
	if err != nil {
		return fmt.Errorf("audit: appending event: %w", err)
	}

	return nil
}

// List returns up to limit events most recent first, strictly after (older
// than) before when before is non-zero, ordered by occurred_at then id, both
// descending.
func (r *Recorder) List(ctx context.Context, limit int, before Cursor) ([]Event, error) {
	const query = `
		SELECT id, occurred_at, actor_id, actor_ref, subject, action, outcome, client_ip, request_id, detail
		FROM audit_events
		WHERE $1::timestamptz IS NULL OR (occurred_at, id) < ($1, $2)
		ORDER BY occurred_at DESC, id DESC
		LIMIT $3
	`

	var occurredAt *time.Time

	var id *uuid.UUID

	if !before.isZero() {
		occurredAt = &before.OccurredAt
		id = &before.ID
	}

	rows, err := r.pool.Query(ctx, query, occurredAt, id, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: listing events: %w", err)
	}

	events, err := pgx.CollectRows(rows, pgx.RowToStructByName[Event])
	if err != nil {
		return nil, fmt.Errorf("audit: scanning events: %w", err)
	}

	return events, nil
}

// Detail encodes fields as the JSONB value an Event carries, dropping any key
// whose name indicates a credential. Dropping rather than redacting is
// deliberate: a redacted placeholder still records that a credential was
// present and invites someone to log the real one "just this once". It
// returns an error when a value cannot be encoded as JSON, which is a
// programming mistake in the caller rather than a runtime condition.
func Detail(fields map[string]any) (json.RawMessage, error) {
	cleaned := make(map[string]any, len(fields))

	var dropped []string

	for key, value := range fields {
		if isCredentialKey(key) {
			dropped = append(dropped, key)

			continue
		}

		cleaned[key] = value
	}

	if len(dropped) > 0 {
		sort.Strings(dropped)
		cleaned["dropped"] = dropped
	}

	data, err := json.Marshal(cleaned)
	if err != nil {
		return nil, fmt.Errorf("audit: encoding detail: %w", err)
	}

	return data, nil
}

// validateSubject rejects a Subject that does not match the "<kind>:<value>"
// grammar, or whose kind is not in permittedSubjectKinds.
func validateSubject(subject string) error {
	kind, value, ok := strings.Cut(subject, ":")
	if !ok || value == "" {
		return fmt.Errorf("%w: %q", ErrMalformedSubject, subject)
	}

	if _, permitted := permittedSubjectKinds[kind]; !permitted {
		return fmt.Errorf("%w: %q", ErrMalformedSubject, subject)
	}

	return nil
}

// isCredentialKey reports whether key's lowercased name contains a substring
// that marks it as credential material.
func isCredentialKey(key string) bool {
	lower := strings.ToLower(key)

	for _, marker := range credentialMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}

	return false
}
