package auth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/audit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/oidc"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/passkey"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/invite"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/settings"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/user"
)

// ErrSuspended reports an account that exists but may not authenticate.
var ErrSuspended = errors.New("account suspended")

// ErrLinkFlowMismatch reports an identity-link ceremony finished by a session
// other than the one that started it.
var ErrLinkFlowMismatch = errors.New("link flow does not belong to this session")

// Service turns a verified authentication into a session, creating the
// account on first sight and applying the account-linking rules.
type Service struct {
	handle          *store.Handle
	users           *user.Repository
	sessions        *session.Store
	roles           *authz.Repository
	checker         *authz.Checker
	recorder        *audit.Recorder
	inviteService   *invite.Service
	policy          *settings.Store
	bootstrapAdmins []string
	logger          *zap.Logger
	now             func() time.Time
	accounts        AccountDeps
}

// AccountDeps bundles the collaborators and policy values this service's
// account management methods need, beyond what Service already holds for
// login.
type AccountDeps struct {
	// Credentials reads and writes registered passkeys, for the last-factor
	// rule and for RemoveCredential.
	Credentials *passkey.Repository
	// Providers resolves an identity-link ceremony's provider. It may be nil
	// when no OpenID Connect provider is configured, in which case
	// StartIdentityLink refuses with oidc.ErrUnknownProvider.
	Providers *oidc.Registry
	// OTPEnabled reports whether an account's email-code identities count as
	// usable authentication factors: an emailed code reaches an account only
	// through such an identity, and only while the method is enabled.
	OTPEnabled bool
	// DeletedGracePeriod is how long a soft-deleted account stays
	// restorable before the sweeper's PurgeExpired call removes it for
	// good.
	DeletedGracePeriod time.Duration
}

// NewService wires the collaborators every login path shares. h is the
// database handle the signup admission transaction (design.md's "Signup
// admission path") is Begun against; every other collaborator reaches the
// same database through its own repository or service type. bootstrapAdmins
// is compared case-insensitively and is normalized once here.
func NewService(
	h *store.Handle,
	users *user.Repository,
	sessions *session.Store,
	roles *authz.Repository,
	checker *authz.Checker,
	recorder *audit.Recorder,
	invites *invite.Service,
	policy *settings.Store,
	bootstrapAdmins []string,
	logger *zap.Logger,
	now func() time.Time,
	accounts AccountDeps,
) *Service {
	normalized := make([]string, 0, len(bootstrapAdmins))

	for _, addr := range bootstrapAdmins {
		trimmed := strings.ToLower(strings.TrimSpace(addr))
		if trimmed != "" {
			normalized = append(normalized, trimmed)
		}
	}

	return &Service{
		handle:          h,
		users:           users,
		sessions:        sessions,
		roles:           roles,
		checker:         checker,
		recorder:        recorder,
		inviteService:   invites,
		policy:          policy,
		bootstrapAdmins: normalized,
		logger:          logger,
		now:             now,
		accounts:        accounts,
	}
}

// Authenticated describes a verified authentication before it becomes a
// session. Provider and Subject are the identity key; Email and
// EmailVerified are what the issuer asserted, not what this service
// believes.
type Authenticated struct {
	Provider      string   `json:"provider"`
	Subject       string   `json:"subject"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	DisplayName   string   `json:"display_name"`
	Methods       []string `json:"methods"`
	// InviteID is the invite the ceremony carried, resolved from the token
	// by the start route and held in server-side flow state since. It is
	// zero when the ceremony carried none, and it is ignored entirely when
	// the identity already resolves to an account.
	InviteID uuid.NullUUID `json:"-"`
}

// LogIn resolves a verified authentication to an account, creating one when
// the identity is new, and issues a session. It returns the account, the
// issued session (so the caller can size the cookie), and the raw session
// token the caller must set as a cookie. priorToken, when non-empty, is the
// session the request already carried; it is revoked before the new one is
// issued, unconditionally, which is what closes session fixation. LogIn
// grants no role to an account that already exists: the bootstrap
// administrator list grants admin only when admission creates the account
// (see createBootstrapAccount), never at a later login.
//
// It returns ErrSuspended when the resolved account may not authenticate.
// When the identity is new, admission runs through the signup admission
// rules (design.md's "Signup admission path") and LogIn returns whichever of
// that gate's sentinels applies: ErrSignupDisabled,
// ErrInviteRequired, ErrInviteInvalid, ErrInviteEmailMismatch, or
// ErrApprovalPending for an account created but not yet approved.
func (s *Service) LogIn(ctx context.Context, in Authenticated, clientIP, userAgent, requestID, priorToken string) (user.User, session.Session, string, error) {
	// Normalized once so isBootstrapAdmin, settlement, the verifiedEmail
	// passed to ValidateTx/RedeemTx, the stored address, and audit subjects
	// all agree on the same value.
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))

	action := completionAction(in.Methods)

	account, identity, err := s.users.ByIdentity(ctx, in.Provider, in.Subject)

	switch {
	case err == nil:
		if account.Status != user.StatusActive {
			// The identity resolved to an existing account, so the refusal is
			// about that account, not about a not-yet-existing signup: the
			// subject is "user:<id>", not signupSubject's email/provider
			// form, which fits only the ErrNotFound branch below, where no
			// account exists yet.
			s.recordAudit(ctx, action, nil, "user:"+account.ID.String(), audit.OutcomeFailure, clientIP, requestID, nil)

			return user.User{}, session.Session{}, "", ErrSuspended
		}

		// A failure here is logged and does not fail the login: the
		// account was already found active, and refusing a valid sign-in
		// because a courtesy timestamp could not be written is a worse
		// outcome than a stale last_used_at.
		if touchErr := s.users.TouchIdentity(ctx, identity.ID); touchErr != nil {
			s.logger.Error("auth: touching identity", zap.Error(touchErr))
		}
	case errors.Is(err, user.ErrNotFound):
		admitted, admitErr := s.admitAccount(ctx, in, clientIP, requestID)
		if admitErr != nil {
			return user.User{}, session.Session{}, "", admitErr
		}

		account = admitted
	default:
		return user.User{}, session.Session{}, "", fmt.Errorf("auth: looking up identity: %w", err)
	}

	if priorToken != "" {
		if revokeErr := s.sessions.RevokeToken(ctx, priorToken); revokeErr != nil {
			return user.User{}, session.Session{}, "", fmt.Errorf("auth: revoking prior session: %w", revokeErr)
		}
	}

	sess, token, err := s.sessions.Issue(ctx, account.ID, clientIP, userAgent, in.Methods)
	if err != nil {
		return user.User{}, session.Session{}, "", fmt.Errorf("auth: issuing session: %w", err)
	}

	s.recordAudit(ctx, action, &account.ID, "user:"+account.ID.String(), audit.OutcomeSuccess, clientIP, requestID, nil)

	return account, sess, token, nil
}

// LogInExistingUser issues a session for an account whose identity is
// already known, which is the passkey path: the assertion names the account
// rather than an external identity. It returns the account, the issued
// session (so the caller can size the cookie), and the raw session token.
func (s *Service) LogInExistingUser(ctx context.Context, userID uuid.UUID, methods []string, clientIP, userAgent, requestID, priorToken string) (user.User, session.Session, string, error) {
	// ByIDAnyStatus, not ByID: a deleted account must be reported as
	// suspended, not as though it never existed.
	account, err := s.users.ByIDAnyStatus(ctx, userID)
	if err != nil {
		return user.User{}, session.Session{}, "", fmt.Errorf("auth: loading account: %w", err)
	}

	if account.Status != user.StatusActive {
		// The actor is the account attempting to authenticate, not yet an
		// authenticated actor: the refusal row carries no actor_id.
		s.recordAudit(ctx, audit.ActionPasskeyCompleted, nil, "user:"+account.ID.String(), audit.OutcomeFailure, clientIP, requestID, nil)

		return user.User{}, session.Session{}, "", ErrSuspended
	}

	if priorToken != "" {
		if revokeErr := s.sessions.RevokeToken(ctx, priorToken); revokeErr != nil {
			return user.User{}, session.Session{}, "", fmt.Errorf("auth: revoking prior session: %w", revokeErr)
		}
	}

	sess, token, err := s.sessions.Issue(ctx, account.ID, clientIP, userAgent, methods)
	if err != nil {
		return user.User{}, session.Session{}, "", fmt.Errorf("auth: issuing session: %w", err)
	}

	s.recordAudit(ctx, audit.ActionPasskeyCompleted, &account.ID, "user:"+account.ID.String(), audit.OutcomeSuccess, clientIP, requestID, nil)

	return account, sess, token, nil
}

// LinkIdentity attaches a verified external identity to an already
// authenticated account. flowUserID is the user the link ceremony was
// started for; the HTTP layer must pass the finishing session's user as
// userID, so a session swap mid-ceremony is caught rather than silently
// linking the wrong account. A mismatch between the two, or either being
// uuid.Nil, returns ErrLinkFlowMismatch without touching any row.
func (s *Service) LinkIdentity(ctx context.Context, userID, flowUserID uuid.UUID, in Authenticated, clientIP, requestID string) error {
	// Normalized once, so the stored identity email agrees with every other
	// use of the asserted address.
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))

	if userID == uuid.Nil || flowUserID == uuid.Nil || userID != flowUserID {
		s.recordLinkFlowMismatch(ctx, userID, clientIP, requestID)

		return ErrLinkFlowMismatch
	}

	account, err := s.users.ByIDAnyStatus(ctx, userID)
	if err != nil {
		return fmt.Errorf("auth: loading account: %w", err)
	}

	if account.Status != user.StatusActive {
		return ErrSuspended
	}

	identityID, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("auth: generating identity id: %w", err)
	}

	now := s.now().UTC()

	var identityEmail *string

	if in.EmailVerified && in.Email != "" {
		email := in.Email
		identityEmail = &email
	}

	identity := user.Identity{
		ID:         identityID,
		UserID:     userID,
		Provider:   in.Provider,
		Subject:    in.Subject,
		Email:      identityEmail,
		LastUsedAt: &now,
	}

	if linkIdentityErr := s.users.LinkIdentity(ctx, identity); linkIdentityErr != nil {
		s.recordAudit(ctx, audit.ActionIdentityLinked, &userID, "user:"+userID.String(), audit.OutcomeFailure, clientIP, requestID, nil)

		return fmt.Errorf("auth: linking identity: %w", linkIdentityErr)
	}

	s.recordAudit(ctx, audit.ActionIdentityLinked, &userID, "user:"+userID.String(), audit.OutcomeSuccess, clientIP, requestID, nil)

	return nil
}

// recordLinkFlowMismatch appends identity.linked with outcome failure for a
// link ceremony refused before any row was touched. The actor is nil when
// userID itself is uuid.Nil, since nothing identifies who attempted the call.
func (s *Service) recordLinkFlowMismatch(ctx context.Context, userID uuid.UUID, clientIP, requestID string) {
	var actorID *uuid.UUID
	if userID != uuid.Nil {
		actorID = &userID
	}

	s.recordAudit(ctx, audit.ActionIdentityLinked, actorID, "user:"+userID.String(), audit.OutcomeFailure, clientIP, requestID, nil)
}

// Subject resolves an account to the context value protected routes read,
// including its permissions.
func (s *Service) Subject(ctx context.Context, userID, sessionPublicID uuid.UUID) (authz.Subject, error) {
	permissions, err := s.checker.Permissions(ctx, userID)
	if err != nil {
		return authz.Subject{}, fmt.Errorf("auth: resolving subject permissions: %w", err)
	}

	return authz.Subject{
		UserID:          userID,
		SessionPublicID: sessionPublicID,
		Permissions:     permissions,
	}, nil
}

// isBootstrapAdmin reports whether email, compared case-insensitively,
// appears in the configured bootstrap administrator list.
func (s *Service) isBootstrapAdmin(email string) bool {
	lower := strings.ToLower(strings.TrimSpace(email))
	if lower == "" {
		return false
	}

	return slices.Contains(s.bootstrapAdmins, lower)
}

// recordAudit appends an audit event on the best-effort path: it logs rather
// than failing the caller when the append itself fails, since refusing to
// authenticate a valid user because the audit table is unavailable is a
// worse outcome than a missing record. Signup's own events do not use this
// path; they commit or roll back with the signup through RecordTx instead,
// via recordAuditTx in signup.go.
func (s *Service) recordAudit(ctx context.Context, action string, actorID *uuid.UUID, subject string, outcome audit.Outcome, clientIP, requestID string, detail []byte) {
	if err := s.recorder.Record(ctx, audit.Event{
		ActorID:   actorID,
		Subject:   subject,
		Action:    action,
		Outcome:   outcome,
		ClientIP:  parseClientIP(clientIP),
		RequestID: requestID,
		Detail:    detail,
	}); err != nil {
		s.logger.Error("auth: recording audit event", zap.String("action", action), zap.Error(err))
	}
}

// auditDetail encodes fields with audit.Detail. An encoding failure is logged
// and yields no detail, so the event itself is still recorded; every caller
// builds its fields from fixed keys and string values, so the failure is a
// programming mistake rather than a runtime condition.
func (s *Service) auditDetail(fields map[string]any) []byte {
	detail, err := audit.Detail(fields)
	if err != nil {
		s.logger.Error("auth: encoding audit detail", zap.Error(err))

		return nil
	}

	return detail
}

// signupSubject reports the audit subject (the package's "<kind>:<value>"
// grammar, see internal/audit.ErrMalformedSubject) an audit event about a
// not-yet-existing account carries: the lowercased verified address when the
// issuer asserted one, and the provider key otherwise.
func signupSubject(in Authenticated) string {
	if in.EmailVerified && in.Email != "" {
		return "email:" + strings.ToLower(in.Email)
	}

	return "provider:" + in.Provider
}

// completionAction reports the audit action string LogIn records on
// completion, drawn from the first entry of methods.
func completionAction(methods []string) string {
	if len(methods) == 0 {
		return audit.ActionOIDCCompleted
	}

	switch methods[0] {
	case session.MethodOTP:
		return audit.ActionOTPCompleted
	case session.MethodWebAuthn:
		return audit.ActionPasskeyCompleted
	default:
		return audit.ActionOIDCCompleted
	}
}

// parseClientIP returns raw parsed as a netip.Addr, or nil when it does not
// parse.
func parseClientIP(raw string) *netip.Addr {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return nil
	}

	return &addr
}
