package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authflow"
)

// ErrVerification reports an assertion or attestation that did not verify. It
// is returned for every failure cause, so a caller cannot tell them apart.
var ErrVerification = errors.New("webauthn verification failed")

// errEmptyRPID reports that a Config was given no relying party identifier.
var errEmptyRPID = errors.New("passkey: RPID must not be empty")

// Service runs the WebAuthn registration and assertion ceremonies.
type Service struct {
	webAuthn *webauthn.WebAuthn
	repo     *Repository
	flows    *authflow.Store
	logger   *zap.Logger
}

// NewService builds a service from cfg, persisting ceremony state in flows and
// credentials in repo.
func NewService(cfg Config, repo *Repository, flows *authflow.Store, logger *zap.Logger) (*Service, error) {
	if cfg.RPID == "" {
		return nil, errEmptyRPID
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
		// AuthenticatorSelection is set once here rather than per-ceremony:
		// webauthn.WebAuthn.BeginRegistration seeds
		// creation.Response.AuthenticatorSelection from this same
		// webauthn.Config.AuthenticatorSelection field (registration.go), and
		// webauthn.WebAuthn.BeginLogin/BeginDiscoverableLogin seeds
		// assertion.Response.UserVerification from
		// webauthn.Config.AuthenticatorSelection.UserVerification (login.go),
		// so both ceremonies genuinely inherit these defaults. UserVerification
		// required closes the possession-only login gap: without it the
		// authenticator data's UV bit is advisory and an authenticator may
		// ignore "preferred". ResidentKey/RequireResidentKey required makes
		// every registered credential discoverable, matching BeginLogin's use
		// of BeginDiscoverableLogin with no allowCredentials fallback -- a
		// credential registered as non-resident could never be used to log in.
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: building relying party: %w", err)
	}

	return &Service{webAuthn: wa, repo: repo, flows: flows, logger: logger}, nil
}

// webauthnUser adapts an account and its existing credentials to the
// webauthn.User interface the library ceremonies require. The account's own
// UUID doubles as the WebAuthn user handle: it is stable for the life of the
// account, but it is not empty of meaning. Accounts are created with
// uuid.NewV7, so the handle's leading bits encode the account's creation
// time to millisecond precision, and this handle is sent to the client and
// to any authenticator involved in a ceremony. A random handle dedicated to
// WebAuthn alone would need its own column and therefore a migration this
// unit does not own.
type webauthnUser struct {
	id          uuid.UUID
	displayName string
	credentials []Credential
}

// WebAuthnID returns the account's UUID as the opaque WebAuthn user handle.
func (u webauthnUser) WebAuthnID() []byte {
	id := u.id

	return id[:]
}

// WebAuthnName returns the account's display name, since this package has no
// separate username to offer an authenticator.
func (u webauthnUser) WebAuthnName() string {
	return u.displayName
}

// WebAuthnDisplayName returns the account's display name.
func (u webauthnUser) WebAuthnDisplayName() string {
	return u.displayName
}

// WebAuthnCredentials returns the account's existing credentials, converted
// to the shape the library ceremonies operate on.
func (u webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	creds := make([]webauthn.Credential, 0, len(u.credentials))
	for _, c := range u.credentials {
		creds = append(creds, toWebAuthnCredential(c))
	}

	return creds
}

// toWebAuthnCredential converts a stored Credential to the library's
// in-ceremony representation.
func toWebAuthnCredential(c Credential) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
	for _, t := range c.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}

	return webauthn.Credential{
		ID:              c.CredentialID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       transports,
		Flags: webauthn.CredentialFlags{
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:       c.AAGUID,
			SignCount:    uint32(c.SignCount),
			CloneWarning: c.CloneWarning,
		},
		// AttestationFormat is deliberately left unset: this repo's schema has
		// no column for it, and populating it needs a migration this unit does
		// not own. Leaving it empty only degrades the library's handling of
		// the legacy FIDO U2F appid extension; it plays no part in the
		// clone-detection or signature checks this package relies on.
	}
}

// credentialDescriptors returns the credential descriptors the library uses
// to exclude an account's existing credentials from a new registration.
func credentialDescriptors(creds []Credential) []protocol.CredentialDescriptor {
	descriptors := make([]protocol.CredentialDescriptor, 0, len(creds))
	for _, c := range creds {
		descriptors = append(descriptors, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: c.CredentialID,
		})
	}

	return descriptors
}

// BeginRegistration starts registering a new credential for an authenticated
// account, returning the creation options to hand to the browser and the flow
// identifier that finishes the ceremony.
func (s *Service) BeginRegistration(ctx context.Context, userID uuid.UUID, displayName string, existing []Credential) ([]byte, string, error) {
	user := webauthnUser{id: userID, displayName: displayName, credentials: existing}

	creation, session, err := s.webAuthn.BeginRegistration(user, webauthn.WithExclusions(credentialDescriptors(existing)))
	if err != nil {
		return nil, "", fmt.Errorf("passkey: beginning registration: %w", err)
	}

	sessionData, err := json.Marshal(session)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: encoding registration session: %w", err)
	}

	flowID, err := s.flows.Begin(ctx, authflow.KindWebAuthnRegister, &userID, sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: persisting registration flow: %w", err)
	}

	options, err := json.Marshal(creation)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: encoding registration options: %w", err)
	}

	return options, flowID, nil
}

// FinishRegistration consumes the ceremony state and stores the credential the
// authenticator produced. It binds the ceremony to userID -- the caller's
// authenticated account -- rather than trusting the flow's own recorded
// owner alone: flowID is a 32-byte random handed to the browser, and if it
// ever leaked through a URL, a Referer header, a log, a proxy, or an XSS
// read, trusting it unchecked would let an attacker register their own
// authenticator onto the victim's account.
func (s *Service) FinishRegistration(ctx context.Context, userID uuid.UUID, flowID, name string, body []byte) (Credential, error) {
	flow, err := s.flows.Consume(ctx, authflow.KindWebAuthnRegister, flowID)
	if err != nil {
		if errors.Is(err, authflow.ErrNotFound) {
			return Credential{}, ErrVerification
		}

		return Credential{}, fmt.Errorf("passkey: consuming registration flow: %w", err)
	}

	if flow.UserID == nil {
		return Credential{}, ErrVerification
	}

	if *flow.UserID != userID {
		return Credential{}, ErrVerification
	}

	var session webauthn.SessionData
	if unmarshalErr := json.Unmarshal(flow.Data, &session); unmarshalErr != nil {
		return Credential{}, fmt.Errorf("passkey: decoding registration session: %w", unmarshalErr)
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return Credential{}, ErrVerification
	}

	user := webauthnUser{id: *flow.UserID}

	created, err := s.webAuthn.CreateCredential(user, session, parsed)
	if err != nil {
		return Credential{}, ErrVerification
	}

	id, err := uuid.NewV7()
	if err != nil {
		return Credential{}, fmt.Errorf("passkey: generating credential id: %w", err)
	}

	transports := make([]string, 0, len(created.Transport))
	for _, t := range created.Transport {
		transports = append(transports, string(t))
	}

	stored := Credential{
		ID:              id,
		UserID:          *flow.UserID,
		CredentialID:    created.ID,
		PublicKey:       created.PublicKey,
		AttestationType: created.AttestationType,
		Transports:      transports,
		AAGUID:          created.Authenticator.AAGUID,
		SignCount:       int64(created.Authenticator.SignCount),
		CloneWarning:    created.Authenticator.CloneWarning,
		BackupEligible:  created.Flags.BackupEligible,
		BackupState:     created.Flags.BackupState,
		Name:            name,
		CreatedAt:       s.repo.now(),
	}

	if createErr := s.repo.Create(ctx, stored); createErr != nil {
		return Credential{}, fmt.Errorf("passkey: storing credential: %w", createErr)
	}

	return stored, nil
}

// BeginLogin starts a discoverable-credential assertion, returning the request
// options and the flow identifier that finishes it. It takes no account
// identifier, so an unauthenticated caller learns nothing about which accounts
// exist.
func (s *Service) BeginLogin(ctx context.Context) ([]byte, string, error) {
	assertion, session, err := s.webAuthn.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", fmt.Errorf("passkey: beginning login: %w", err)
	}

	sessionData, err := json.Marshal(session)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: encoding login session: %w", err)
	}

	flowID, err := s.flows.Begin(ctx, authflow.KindWebAuthnLogin, nil, sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: persisting login flow: %w", err)
	}

	options, err := json.Marshal(assertion)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: encoding login options: %w", err)
	}

	return options, flowID, nil
}

// FinishLogin consumes the ceremony state, verifies the assertion, and returns
// the identifier of the account that owns the credential.
//
// On success it returns the owning account's ID with a nil error. On
// ErrVerification it returns uuid.UUID{} when no credential was ever
// resolved -- an unknown flow, an unparseable body, or a credential ID the
// repository does not recognise -- and the resolved credential's UserID when
// the failure occurred after the credential handler identified one, so a
// caller can attribute the failed attempt in an audit record. Either way,
// the returned ID on ErrVerification is for audit attribution only: it must
// never be treated as authenticated and must never be used to issue a
// session.
//
// A credential whose stored CloneWarning is already true is refused
// unconditionally, before its signature is even considered: the flag is
// load-bearing, not advisory. Without this, an attacker who clones an
// authenticator and logs in first advances the stored sign count past the
// legitimate authenticator's; the legitimate user's next login then reports
// a lower count than the one on file, gets flagged as the clone, and is
// locked out while the attacker keeps working. Once set, the flag makes the
// credential permanently unusable until an administrator or the owner
// removes it.
func (s *Service) FinishLogin(ctx context.Context, flowID string, body []byte) (uuid.UUID, error) {
	flow, err := s.flows.Consume(ctx, authflow.KindWebAuthnLogin, flowID)
	if err != nil {
		if errors.Is(err, authflow.ErrNotFound) {
			return uuid.UUID{}, ErrVerification
		}

		return uuid.UUID{}, fmt.Errorf("passkey: consuming login flow: %w", err)
	}

	var session webauthn.SessionData
	if unmarshalErr := json.Unmarshal(flow.Data, &session); unmarshalErr != nil {
		return uuid.UUID{}, fmt.Errorf("passkey: decoding login session: %w", unmarshalErr)
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return uuid.UUID{}, ErrVerification
	}

	var resolved Credential

	handler := func(rawID, _ []byte) (webauthn.User, error) {
		cred, credErr := s.repo.ByCredentialID(ctx, rawID)
		if credErr != nil {
			return nil, fmt.Errorf("passkey: resolving credential: %w", credErr)
		}

		resolved = cred

		return webauthnUser{id: cred.UserID, credentials: []Credential{cred}}, nil
	}

	if _, _, validatePasskeyLoginErr := s.webAuthn.ValidatePasskeyLogin(handler, session, parsed); validatePasskeyLoginErr != nil {
		return resolved.UserID, ErrVerification
	}

	if resolved.CloneWarning {
		return resolved.UserID, ErrVerification
	}

	reportedCount := int64(parsed.Response.AuthenticatorData.Counter)
	cloneWarning := evaluateSignCount(resolved.SignCount, reportedCount)

	signCount := reportedCount
	if cloneWarning {
		signCount = resolved.SignCount
	}

	if recordUseErr := s.repo.RecordUse(ctx, resolved.ID, signCount, cloneWarning); recordUseErr != nil {
		return uuid.UUID{}, fmt.Errorf("passkey: recording credential use: %w", recordUseErr)
	}

	if cloneWarning {
		s.logger.Warn("passkey: possible cloned authenticator",
			zap.String("credential_id", resolved.ID.String()),
			zap.Int64("stored_sign_count", resolved.SignCount),
			zap.Int64("reported_sign_count", reportedCount),
		)

		return resolved.UserID, ErrVerification
	}

	return resolved.UserID, nil
}

// evaluateSignCount reports whether a reported sign count from an assertion
// signals a possible cloned authenticator when compared against a
// credential's stored sign count. A reported count less than or equal to a
// non-zero stored count -- which covers both an unchanged and a regressed
// counter -- is a clone warning. A stored count of zero with a reported count
// of zero is normal for authenticators that do not implement counters and is
// not a warning.
func evaluateSignCount(stored, reported int64) bool {
	return reported <= stored && (reported != 0 || stored != 0)
}
