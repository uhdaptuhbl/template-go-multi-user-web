package settings

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
)

// selectSettingsQuery reads the single settings row's fields, naming only the
// columns Settings declares so pgx.RowToStructByName has a matching count.
const selectSettingsQuery = `
SELECT
	signup_enabled, signup_require_invite, signup_require_approval,
	invite_default_quota, invite_default_ttl_secs, invite_max_uses_limit,
	updated_at, updated_by_ref
FROM settings
WHERE id
`

// selectSettingsForShareQuery is selectSettingsQuery with FOR SHARE, so
// LoadTx's caller holds a shared lock on the row until its transaction ends,
// which is what makes a concurrent Apply wait rather than race the read.
const selectSettingsForShareQuery = `
SELECT
	signup_enabled, signup_require_invite, signup_require_approval,
	invite_default_quota, invite_default_ttl_secs, invite_max_uses_limit,
	updated_at, updated_by_ref
FROM settings
WHERE id
FOR SHARE
`

// applySettingsQuery writes a partial update, expressing "leave it alone" as
// a NULL argument via COALESCE rather than as assembled SQL, and returns the
// row as it now stands.
const applySettingsQuery = `
UPDATE settings
SET
	signup_enabled = COALESCE($1, signup_enabled),
	signup_require_invite = COALESCE($2, signup_require_invite),
	signup_require_approval = COALESCE($3, signup_require_approval),
	invite_default_quota = COALESCE($4, invite_default_quota),
	invite_default_ttl_secs = COALESCE($5, invite_default_ttl_secs),
	invite_max_uses_limit = COALESCE($6, invite_max_uses_limit),
	updated_at = $7,
	updated_by = $8,
	updated_by_ref = $9
WHERE id
RETURNING
	signup_enabled, signup_require_invite, signup_require_approval,
	invite_default_quota, invite_default_ttl_secs, invite_max_uses_limit,
	updated_at, updated_by_ref
`

// Settings is the runtime policy that governs who may create an account and
// how many invites an account may hold. It is the whole of the settings table,
// which holds exactly one row.
//
// Every field is json:"-" because this is a persistence row, and Definition of
// Done item 14 forbids a row struct from being serialisable. The admin
// endpoint builds its own response shape in internal/auth rather than
// returning this type, which is the same rule every other table in this plan
// follows.
type Settings struct {
	// SignupEnabled is whether an authentication that matches no existing
	// identity may create an account at all. It is the outermost gate and the
	// only one with an environment override.
	SignupEnabled bool `db:"signup_enabled" json:"-"`
	// SignupRequireInvite is whether a signup must present a live invite.
	SignupRequireInvite bool `db:"signup_require_invite" json:"-"`
	// SignupRequireApproval is whether an admitted account is created unable
	// to authenticate until an administrator approves it.
	SignupRequireApproval bool `db:"signup_require_approval" json:"-"`
	// InviteDefaultQuota is how many live invites an account holding
	// PermissionInviteCreate may have outstanding. Zero means the permission
	// is inert, which is the shipped default.
	InviteDefaultQuota int `db:"invite_default_quota" json:"-"`
	// InviteDefaultTTLSecs is the lifetime an invite receives when its issuer
	// names none.
	InviteDefaultTTLSecs int `db:"invite_default_ttl_secs" json:"-"`
	// InviteMaxUsesLimit caps the redemption limit any single invite may be
	// given, so a multi-use link cannot become an open door by accident.
	InviteMaxUsesLimit int `db:"invite_max_uses_limit" json:"-"`
	// UpdatedAt is when the row last changed.
	UpdatedAt time.Time `db:"updated_at" json:"-"`
	// UpdatedByRef identifies who last changed it, in the audit package's
	// "<kind>:<value>" subject grammar (see internal/audit.ErrMalformedSubject),
	// and survives that account's purge.
	UpdatedByRef string `db:"updated_by_ref" json:"-"`
	// InviteMaxTTL is Options.InviteMaxTTL, carried so readers of one Settings value see every
	// invite limit together. It is not stored in the settings row.
	InviteMaxTTL time.Duration `db:"-" json:"-"`
	// InviteDefaultMaxUses is Options.InviteDefaultMaxUses with zero replaced by 1. It is not
	// stored in the settings row.
	InviteDefaultMaxUses int `db:"-" json:"-"`
}

// Update names the fields a caller wants changed. A nil field is left alone,
// which is what makes a partial PATCH expressible without a second type.
type Update struct {
	SignupEnabled         *bool `json:"signup_enabled"`
	SignupRequireInvite   *bool `json:"signup_require_invite"`
	SignupRequireApproval *bool `json:"signup_require_approval"`
	InviteDefaultQuota    *int  `json:"invite_default_quota"`
	InviteDefaultTTLSecs  *int  `json:"invite_default_ttl_secs"`
	InviteMaxUsesLimit    *int  `json:"invite_max_uses_limit"`
}

// Options carries the environment-sourced values a Store applies on top of the settings row.
type Options struct {
	// SignupEnabledOverride, when non-nil, replaces signup_enabled and locks it.
	SignupEnabledOverride *bool
	// InviteMaxTTL is the longest lifetime an invite may have. Zero means no ceiling.
	InviteMaxTTL time.Duration
	// InviteDefaultMaxUses is the redemption limit an invite gets when its issuer names none.
	// Zero means 1.
	InviteDefaultMaxUses int
}

// Store reads and writes the single settings row.
type Store struct {
	handle *store.Handle
	opts   Options
	logger *zap.Logger
	now    func() time.Time
}

// ErrMissing reports a settings table with no row in it.
var ErrMissing = errors.New("settings row missing")

// ErrLocked reports an update naming a setting the environment has overridden.
var ErrLocked = errors.New("setting locked by environment")

// ErrInvalidValue reports that Apply was asked to write a value that fails
// validation on its own terms, independent of any database state: a negative
// quota, a non-positive TTL, or a non-positive redemption ceiling. A caller
// mapping this error to an HTTP response should answer a client error (400
// invalid_request) rather than a 500, because the request itself is
// malformed and no infrastructure failure occurred.
var ErrInvalidValue = errors.New("settings: invalid value")

// NewStore returns a store reading through h. opts.SignupEnabledOverride, when
// non-nil, is the value SERVICE_AUTH_SIGNUP_ENABLED was set to; it replaces
// the column on every read and cannot be written. opts.InviteMaxTTL and
// opts.InviteDefaultMaxUses are carried on every Settings value Load, LoadTx,
// and Apply return, and Apply rejects a write that would violate
// opts.InviteMaxTTL.
func NewStore(h *store.Handle, opts Options, logger *zap.Logger, now func() time.Time) *Store {
	return &Store{
		handle: h,
		opts:   opts,
		logger: logger,
		now:    now,
	}
}

// Load reads the row, applying the environment override if one is set. It
// returns ErrMissing when no row exists, which means the seed migration did
// not run and is not a condition to paper over with a default.
func (s *Store) Load(ctx context.Context) (Settings, error) {
	rows, err := s.handle.Pool().Query(ctx, selectSettingsQuery)
	if err != nil {
		return Settings{}, fmt.Errorf("settings: loading row: %w", err)
	}

	row, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[Settings])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Settings{}, ErrMissing
		}

		return Settings{}, fmt.Errorf("settings: loading row: %w", err)
	}

	return s.withOptions(row), nil
}

// LoadTx is Load against an open transaction, which is how the signup
// admission rules read the policy without racing a change that lands
// mid-ceremony. It reads with FOR SHARE, so a concurrent Apply blocks until
// tx commits or rolls back rather than racing this read.
func (s *Store) LoadTx(ctx context.Context, tx pgx.Tx) (Settings, error) {
	rows, err := tx.Query(ctx, selectSettingsForShareQuery)
	if err != nil {
		return Settings{}, fmt.Errorf("settings: loading row in transaction: %w", err)
	}

	row, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[Settings])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Settings{}, ErrMissing
		}

		return Settings{}, fmt.Errorf("settings: loading row in transaction: %w", err)
	}

	return s.withOptions(row), nil
}

// Apply writes the named fields and returns the row as it now stands. It
// returns ErrLocked naming the field when an update names a key the
// environment has overridden.
func (s *Store) Apply(ctx context.Context, in Update, actorID uuid.NullUUID, actorRef string) (Settings, error) {
	if err := s.validateApply(in); err != nil {
		return Settings{}, err
	}

	rows, err := s.handle.Pool().Query(ctx, applySettingsQuery,
		in.SignupEnabled,
		in.SignupRequireInvite,
		in.SignupRequireApproval,
		in.InviteDefaultQuota,
		in.InviteDefaultTTLSecs,
		in.InviteMaxUsesLimit,
		s.now(),
		actorID,
		actorRef,
	)
	if err != nil {
		return Settings{}, fmt.Errorf("settings: applying update: %w", err)
	}

	row, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[Settings])
	if err != nil {
		return Settings{}, fmt.Errorf("settings: applying update: %w", err)
	}

	return s.withOptions(row), nil
}

// validateApply reports why in cannot be written, independent of any
// database state: a field the environment has locked, or a value that fails
// validation on its own terms. It returns nil when in is safe to write.
func (s *Store) validateApply(in Update) error {
	if in.SignupEnabled != nil && s.opts.SignupEnabledOverride != nil {
		return fmt.Errorf("settings: signup_enabled: %w", ErrLocked)
	}

	if in.InviteDefaultQuota != nil && *in.InviteDefaultQuota < 0 {
		return fmt.Errorf("settings: invite_default_quota must be at least 0: %w", ErrInvalidValue)
	}

	if in.InviteDefaultQuota != nil && *in.InviteDefaultQuota > math.MaxInt32 {
		return fmt.Errorf("settings: invite_default_quota must not exceed %d: %w", math.MaxInt32, ErrInvalidValue)
	}

	if in.InviteMaxUsesLimit != nil && *in.InviteMaxUsesLimit <= 0 {
		return fmt.Errorf("settings: invite_max_uses_limit must be greater than 0: %w", ErrInvalidValue)
	}

	if in.InviteMaxUsesLimit != nil && *in.InviteMaxUsesLimit > math.MaxInt32 {
		return fmt.Errorf("settings: invite_max_uses_limit must not exceed %d: %w", math.MaxInt32, ErrInvalidValue)
	}

	return s.validateApplyInviteDefaultTTLSecs(in.InviteDefaultTTLSecs)
}

// validateApplyInviteDefaultTTLSecs reports the reason ttlSecs cannot be
// written: nil is always valid, since a nil field means "leave alone".
// Otherwise it must be positive, fit the settings table's INTEGER column,
// and not exceed the configured invite max ttl.
func (s *Store) validateApplyInviteDefaultTTLSecs(ttlSecs *int) error {
	if ttlSecs == nil {
		return nil
	}

	if *ttlSecs <= 0 {
		return fmt.Errorf("settings: invite_default_ttl_secs must be greater than 0: %w", ErrInvalidValue)
	}

	if *ttlSecs > math.MaxInt32 {
		return fmt.Errorf("settings: invite_default_ttl_secs must not exceed %d: %w", math.MaxInt32, ErrInvalidValue)
	}

	if s.opts.InviteMaxTTL > 0 {
		maxSecs := int(s.opts.InviteMaxTTL / time.Second)
		if *ttlSecs > maxSecs {
			return fmt.Errorf(
				"settings: invite_default_ttl_secs must not exceed the configured invite max ttl of %d seconds: %w",
				maxSecs, ErrInvalidValue,
			)
		}
	}

	return nil
}

// Locked returns the names of the settings the environment has overridden, in
// the JSON form the admin endpoint reports them.
func (s *Store) Locked() []string {
	locked := []string{}

	if s.opts.SignupEnabledOverride != nil {
		locked = append(locked, "signup_enabled")
	}

	return locked
}

// withOptions applies the environment options on top of a row already read
// from the database, so UpdatedAt and UpdatedByRef still describe the row
// rather than the options. SignupEnabled is replaced only when
// SignupEnabledOverride is set; InviteMaxTTL and InviteDefaultMaxUses are
// always carried, since neither is stored in the row, with
// InviteDefaultMaxUses defaulting to 1 when unset.
func (s *Store) withOptions(row Settings) Settings {
	if s.opts.SignupEnabledOverride != nil {
		row.SignupEnabled = *s.opts.SignupEnabledOverride
	}

	row.InviteMaxTTL = s.opts.InviteMaxTTL

	row.InviteDefaultMaxUses = s.opts.InviteDefaultMaxUses
	if row.InviteDefaultMaxUses == 0 {
		row.InviteDefaultMaxUses = 1
	}

	return row
}
