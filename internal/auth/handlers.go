package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/audit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/oidc"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/otp"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/passkey"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/invite"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/user"
)

// oidcBindingCookieNameHost is the OIDC binding cookie's name when
// deps.CookieSecure is true, carrying the __Host- prefix that makes a browser
// refuse it unless it is Secure, has Path=/, and carries no Domain.
const oidcBindingCookieNameHost = "__Host-service_oidc_binding"

// oidcBindingCookieNamePlain is the OIDC binding cookie's name when
// deps.CookieSecure is false, which is local development over plain HTTP
// only: the __Host- prefix requires Secure and a browser would silently
// refuse to store it otherwise.
const oidcBindingCookieNamePlain = "service_oidc_binding"

// adminUsersPageSize is the page size GET /api/v1/admin/users reads with.
const adminUsersPageSize = 50

// unauthenticatedError returns the ClientError every authentication failure
// answers with, per design.md's "Interfaces" section: 401 unauthenticated,
// whatever the cause.
func unauthenticatedError() *server.ClientError {
	return &server.ClientError{
		Status:  http.StatusUnauthorized,
		Code:    server.ErrorCodeUnauthenticated,
		Message: "authentication required",
	}
}

// invalidRequestError returns the fixed 400 invalid_request ClientError a
// decode failure or an unrecognised query value answers with. It discards
// whatever detail or pointer server.DecodeJSON's own ClientError may have
// carried, because design.md's "Interfaces" section fixes this response's
// body exactly.
func invalidRequestError() *server.ClientError {
	return &server.ClientError{
		Status:  http.StatusBadRequest,
		Code:    server.ErrorCodeInvalidRequest,
		Message: "invalid request",
	}
}

// notFoundError returns the fixed 404 not_found ClientError a route answers
// with when a path parameter names no resource.
func notFoundError() *server.ClientError {
	return &server.ClientError{
		Status:  http.StatusNotFound,
		Code:    server.ErrorCodeNotFound,
		Message: "not found",
	}
}

// rateLimitedError returns the fixed 429 rate_limited ClientError every rate
// limit refusal answers with, whether the limiter keyed the refusal by client
// IP or by the normalized address a route also limits per-address.
func rateLimitedError() *server.ClientError {
	return &server.ClientError{
		Status:  http.StatusTooManyRequests,
		Code:    server.ErrorCodeRateLimited,
		Message: "too many requests",
	}
}

// decodeBody decodes r's JSON body into dst, logging any decode failure and
// writing the fixed 400 invalid_request body in its place. It reports
// whether decoding succeeded, so a handler can return immediately when it did
// not.
func decodeBody(w http.ResponseWriter, r *http.Request, logger *zap.Logger, dst any) bool {
	if err := server.DecodeJSON(r, dst); err != nil {
		logger.Debug("auth: decoding request body", zap.Error(err))
		server.WriteError(w, r, logger, invalidRequestError())

		return false
	}

	return true
}

// mapLoginError maps a LogIn or LogInExistingUser failure to the ClientError
// an API route answers with, per the error mapping in design.md's
// "Interfaces" section: each admission refusal keeps its own 403 code,
// ErrSuspended answers 401 unauthenticated
// exactly like any other authentication failure, and anything else is
// returned unchanged so server.WriteError renders its own 5xx rather than
// disguising an infrastructure failure as a rejected login.
func mapLoginError(err error) error {
	switch {
	case errors.Is(err, ErrSignupDisabled):
		return &server.ClientError{Status: http.StatusForbidden, Code: server.ErrorCodeSignupDisabled, Message: "signup disabled", Err: err}
	case errors.Is(err, ErrInviteRequired):
		return &server.ClientError{Status: http.StatusForbidden, Code: server.ErrorCodeInviteRequired, Message: "invite required", Err: err}
	case errors.Is(err, ErrInviteInvalid):
		return &server.ClientError{Status: http.StatusForbidden, Code: server.ErrorCodeInviteInvalid, Message: "invite invalid", Err: err}
	case errors.Is(err, ErrInviteEmailMismatch):
		return &server.ClientError{Status: http.StatusForbidden, Code: server.ErrorCodeInviteEmailMismatch, Message: "invite address mismatch", Err: err}
	case errors.Is(err, ErrApprovalPending):
		return &server.ClientError{Status: http.StatusForbidden, Code: server.ErrorCodeApprovalPending, Message: "account awaiting approval", Err: err}
	case errors.Is(err, ErrSuspended):
		return unauthenticatedError()
	default:
		return err
	}
}

// oidcCallbackErrorCode maps a LogIn or LogInExistingUser failure to the
// query parameter value the OIDC callback's redirect carries, and reports
// whether err matched one of the named admission or authentication
// failures in design.md's "Interfaces" section. An unmatched error is
// infrastructure, not a refusal: the caller
// answers with server.WriteError's own 5xx instead of a redirect.
func oidcCallbackErrorCode(err error) (string, bool) {
	switch {
	case errors.Is(err, ErrSignupDisabled):
		return server.ErrorCodeSignupDisabled, true
	case errors.Is(err, ErrInviteRequired):
		return server.ErrorCodeInviteRequired, true
	case errors.Is(err, ErrInviteInvalid):
		return server.ErrorCodeInviteInvalid, true
	case errors.Is(err, ErrInviteEmailMismatch):
		return server.ErrorCodeInviteEmailMismatch, true
	case errors.Is(err, ErrApprovalPending):
		return server.ErrorCodeApprovalPending, true
	case errors.Is(err, ErrSuspended):
		return server.ErrorCodeUnauthenticated, true
	default:
		return "", false
	}
}

// resolveInviteForOIDCStart resolves an optional invite token for the
// GET /api/v1/auth/oidc/{provider}/start route. An empty token, or one that
// names a dead invite, resolves to no invite rather than refusing the
// ceremony: this route has not yet revealed anything about an address, so a
// dead invite is no reason to stop the caller from continuing to the
// provider (AC-008.86). The returned error is for an infrastructure failure
// only.
func (s *Service) resolveInviteForOIDCStart(r *http.Request, token string) (uuid.NullUUID, error) {
	if token == "" {
		return uuid.NullUUID{}, nil
	}

	inv, err := s.inviteService.Lookup(r.Context(), token)
	if err != nil {
		if errors.Is(err, invite.ErrInvalid) {
			return uuid.NullUUID{}, nil
		}

		return uuid.NullUUID{}, fmt.Errorf("looking up invite for oidc start: %w", err)
	}

	return uuid.NullUUID{UUID: inv.ID, Valid: true}, nil
}

// resolveInviteForOTPStart resolves an optional invite token for the
// POST /api/v1/auth/otp/start route, which must never reveal whether token
// names a live invite: a dead, unknown, or absent token all resolve to no
// invite rather than an error. A Lookup failure that is not invite.ErrInvalid
// is an infrastructure problem rather than a routine "this token is dead"
// outcome, so it is logged at Error even though the route still answers 202
// identically either way.
func (s *Service) resolveInviteForOTPStart(r *http.Request, logger *zap.Logger, token string) uuid.NullUUID {
	if token == "" {
		return uuid.NullUUID{}
	}

	inv, err := s.inviteService.Lookup(r.Context(), token)
	if err != nil {
		if !errors.Is(err, invite.ErrInvalid) {
			logger.Error("auth: looking up invite for otp start", zap.Error(err))
		}

		return uuid.NullUUID{}
	}

	return uuid.NullUUID{UUID: inv.ID, Valid: true}
}

// oidcBindingCookieName returns the OIDC binding cookie's name for the given
// CookieSecure setting.
func oidcBindingCookieName(secure bool) string {
	if secure {
		return oidcBindingCookieNameHost
	}

	return oidcBindingCookieNamePlain
}

// setOIDCBindingCookie sets the OIDC binding cookie carrying binding, valid
// for ttl (RouteDeps.FlowTTL), whose whole seconds become the cookie's
// MaxAge.
func setOIDCBindingCookie(w http.ResponseWriter, secure bool, binding string, ttl time.Duration) {
	// G124: Secure is a parameter load (deps.CookieSecure controls it), not a
	// literal, which is exactly the false positive already documented and
	// excluded by path for internal/session/cookie.go; that exclusion cannot
	// reach this file, so the same reasoning is recorded here as a targeted
	// line directive instead.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure carries a parameter, not a literal; HttpOnly, SameSite, and Path are all set
		Name:     oidcBindingCookieName(secure),
		Value:    binding,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

// clearOIDCBindingCookie overwrites the OIDC binding cookie with an empty
// value and a negative MaxAge, so a browser drops it. It is called on every
// callback outcome, success or failure.
func clearOIDCBindingCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure carries a parameter, not a literal; HttpOnly, SameSite, and Path are all set
		Name:     oidcBindingCookieName(secure),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// oidcBindingFromRequest returns the OIDC binding cookie's value, or the
// empty string when the request carries none.
func oidcBindingFromRequest(r *http.Request, secure bool) string {
	cookie, err := r.Cookie(oidcBindingCookieName(secure))
	if err != nil {
		return ""
	}

	return cookie.Value
}

// otpBindingCookieNameHost is the email-code binding cookie's name when
// cookies are Secure, carrying the __Host- prefix that makes a browser refuse
// it unless it is Secure, has Path=/, and carries no Domain.
const otpBindingCookieNameHost = "__Host-service_otp_binding"

// otpBindingCookieNamePlain is the email-code binding cookie's name over
// plain HTTP, local development only: the __Host- prefix requires Secure and
// a browser would silently refuse to store it otherwise.
const otpBindingCookieNamePlain = "service_otp_binding"

// otpBindingBytes is how many bytes of crypto/rand a generated binding value
// carries.
const otpBindingBytes = 32

// otpBindingLength is the exact length, in characters, a base64.RawURLEncoding
// rendering of otpBindingBytes carries. A presented cookie value of any other
// length is treated as absent rather than trusted, since it cannot be one
// this handler generated.
const otpBindingLength = 43

// otpBindingCookieName returns the email-code binding cookie's name for the
// given CookieSecure setting.
func otpBindingCookieName(secure bool) string {
	if secure {
		return otpBindingCookieNameHost
	}

	return otpBindingCookieNamePlain
}

// generateOTPBinding returns a fresh binding value: otpBindingBytes drawn
// from crypto/rand, encoded with base64.RawURLEncoding.
func generateOTPBinding() (string, error) {
	raw := make([]byte, otpBindingBytes)

	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("auth: generating otp binding: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// otpBindingFromRequest returns the email-code binding cookie's value, or the
// empty string when the request carries none or carries a value that is not
// otpBindingLength characters, which cannot be one this handler generated.
func otpBindingFromRequest(r *http.Request, secure bool) string {
	cookie, err := r.Cookie(otpBindingCookieName(secure))
	if err != nil {
		return ""
	}

	if len(cookie.Value) != otpBindingLength {
		return ""
	}

	return cookie.Value
}

// setOTPBindingCookie sets the email-code binding cookie carrying binding,
// valid for maxAgeSeconds.
func setOTPBindingCookie(w http.ResponseWriter, secure bool, binding string, maxAgeSeconds int) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure carries a parameter, not a literal; HttpOnly, SameSite, and Path are all set
		Name:     otpBindingCookieName(secure),
		Value:    binding,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAgeSeconds,
	})
}

// clearOTPBindingCookie overwrites the email-code binding cookie with an
// empty value and a negative MaxAge, so a browser drops it.
func clearOTPBindingCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure carries a parameter, not a literal; HttpOnly, SameSite, and Path are all set
		Name:     otpBindingCookieName(secure),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// providerEntry is one entry of GET /api/v1/auth/providers' response.
type providerEntry struct {
	Kind        string `json:"kind"`
	Key         string `json:"key,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

// providersResponse is GET /api/v1/auth/providers' response shape.
type providersResponse struct {
	Providers []providerEntry `json:"providers"`
}

// handleProviders answers GET /api/v1/auth/providers, listing only the
// authentication methods this deployment has enabled.
func (*Service) handleProviders(w http.ResponseWriter, _ *http.Request, deps RouteDeps) {
	entries := make([]providerEntry, 0)

	if deps.Providers != nil {
		for _, key := range deps.Providers.Keys() {
			entries = append(entries, providerEntry{Kind: "oidc", Key: key, DisplayName: deps.Providers.DisplayName(key)})
		}
	}

	if deps.Passkeys != nil {
		entries = append(entries, providerEntry{Kind: "webauthn"})
	}

	if deps.Codes != nil {
		entries = append(entries, providerEntry{Kind: "otp"})
	}

	server.WriteJSON(w, deps.Logger, http.StatusOK, providersResponse{Providers: entries})
}

// handleOIDCStart answers GET /api/v1/auth/oidc/{provider}/start, beginning a
// login ceremony and redirecting the browser to the provider.
func (s *Service) handleOIDCStart(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	key := r.PathValue("provider")

	inviteID, err := s.resolveInviteForOIDCStart(r, r.URL.Query().Get("invite"))
	if err != nil {
		deps.Logger.Error("auth: resolving invite for oidc start", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	authURL, binding, err := deps.Providers.Start(r.Context(), key, inviteID)
	if err != nil {
		if errors.Is(err, oidc.ErrUnknownProvider) {
			server.WriteError(w, r, deps.Logger, &server.ClientError{Status: http.StatusNotFound, Code: server.ErrorCodeNotFound, Message: "not found", Err: err})

			return
		}

		deps.Logger.Error("auth: starting oidc ceremony", zap.String("provider", key), zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	setOIDCBindingCookie(w, deps.CookieSecure, binding, deps.FlowTTL)

	s.recordAudit(r.Context(), audit.ActionOIDCStarted, nil, "provider:"+key, audit.OutcomeSuccess,
		deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()), nil)

	http.Redirect(w, r, authURL, http.StatusSeeOther) //nolint:gosec // G710: authURL is built by deps.Providers.Start from this deployment's own configured provider issuer, never from request-controlled input
}

// oidcLinkCallbackErrorCode maps a FinishIdentityLink failure, once it is
// known not to be oidc.ErrInvalidState, to the query parameter value the
// callback's redirect carries for a link ceremony rather than a login one.
// It reports whether err matched one of the named link failures; an
// unmatched error is infrastructure, not a refusal, so the caller answers
// with server.WriteError's own 5xx instead of a redirect.
func oidcLinkCallbackErrorCode(err error) (string, bool) {
	switch {
	case errors.Is(err, ErrLinkFlowMismatch):
		return server.ErrorCodeUnauthenticated, true
	case errors.Is(err, ErrSuspended):
		return server.ErrorCodeUnauthenticated, true
	case errors.Is(err, user.ErrIdentityLinked):
		return server.ErrorCodeConflict, true
	default:
		return "", false
	}
}

// handleOIDCCallback answers GET /api/v1/auth/oidc/{provider}/callback,
// completing either an identity-link ceremony or a login ceremony, whichever
// the presented state names. A link ceremony is tried first, through
// FinishIdentityLink; oidc.ErrInvalidState from that attempt means the
// consumed state was never a link flow (FinishIdentityLink's underlying
// Consume matches on kind and leaves a non-matching row untouched), so login
// is tried next against the same state, exchanging it for a session exactly
// as this handler always has. oidc.ErrUnknownProvider from FinishIdentityLink
// falls through the same way: it means this Service's own AccountDeps.
// Providers has no link-capable registry configured at all (nil or missing
// key), in which case StartIdentityLink could never have issued the
// presented state as a link flow either, so it can only be a login one. A
// successful link redirects to "/" without ever setting a session cookie,
// since linking is not a login.
func (s *Service) handleOIDCCallback(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	key := r.PathValue("provider")
	binding := oidcBindingFromRequest(r, deps.CookieSecure)
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	clearOIDCBindingCookie(w, deps.CookieSecure)

	sessionUserID := uuid.Nil
	if subject, ok := authz.SubjectFromContext(r.Context()); ok {
		sessionUserID = subject.UserID
	}

	clientIP := deps.Proxies.ClientIP(r)
	requestID := server.RequestIDFromContext(r.Context())

	linkErr := s.FinishIdentityLink(r.Context(), sessionUserID, key, state, code, binding, clientIP, requestID)
	if linkErr == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)

		return
	}

	if !errors.Is(linkErr, oidc.ErrInvalidState) && !errors.Is(linkErr, oidc.ErrUnknownProvider) {
		linkErrCode, matched := oidcLinkCallbackErrorCode(linkErr)
		if !matched {
			deps.Logger.Error("auth: completing oidc identity link", zap.Error(linkErr))
			server.WriteError(w, r, deps.Logger, linkErr)

			return
		}

		http.Redirect(w, r, "/?error="+linkErrCode, http.StatusSeeOther)

		return
	}

	claims, inviteID, err := deps.Providers.Finish(r.Context(), key, state, code, binding)
	if err != nil {
		deps.Logger.Warn("auth: finishing oidc ceremony", zap.String("provider", key), zap.Error(err))
		s.recordAudit(r.Context(), audit.ActionOIDCCompleted, nil, "provider:"+key, audit.OutcomeFailure,
			clientIP, requestID, nil)
		http.Redirect(w, r, "/?error="+server.ErrorCodeUnauthenticated, http.StatusSeeOther)

		return
	}

	in := Authenticated{
		Provider:      key,
		Subject:       claims.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		DisplayName:   claims.Name,
		Methods:       []string{session.MethodOIDC},
		InviteID:      inviteID,
	}

	priorToken := deps.Sessions.TokenFromRequest(r)

	_, sess, token, err := s.LogIn(r.Context(), in, clientIP, r.UserAgent(), requestID, priorToken)
	if err != nil {
		loginErrCode, matched := oidcCallbackErrorCode(err)
		if !matched {
			deps.Logger.Error("auth: completing oidc login", zap.Error(err))
			server.WriteError(w, r, deps.Logger, err)

			return
		}

		http.Redirect(w, r, "/?error="+loginErrCode, http.StatusSeeOther)

		return
	}

	deps.Sessions.SetCookie(w, token, sess)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// webauthnStartResponse is the shared response shape of the two WebAuthn
// ceremony start routes.
type webauthnStartResponse struct {
	FlowID  string          `json:"flow_id"`
	Options json.RawMessage `json:"options"`
}

// handleWebAuthnRegisterStart answers POST /api/v1/auth/webauthn/register/start,
// beginning a new credential registration for the authenticated caller.
func (*Service) handleWebAuthnRegisterStart(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	subject, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		server.WriteError(w, r, deps.Logger, unauthenticatedError())

		return
	}

	existing, err := deps.Credentials.ListFor(r.Context(), subject.UserID)
	if err != nil {
		deps.Logger.Error("auth: listing credentials for registration start", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	account, err := deps.Users.ByID(r.Context(), subject.UserID)
	if err != nil {
		deps.Logger.Error("auth: loading account for registration start", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	options, flowID, err := deps.Passkeys.BeginRegistration(r.Context(), subject.UserID, account.DisplayName, existing)
	if err != nil {
		deps.Logger.Error("auth: beginning webauthn registration", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	server.WriteJSON(w, deps.Logger, http.StatusOK, webauthnStartResponse{FlowID: flowID, Options: options})
}

// webauthnRegisterFinishRequest is POST
// /api/v1/auth/webauthn/register/finish's request body.
type webauthnRegisterFinishRequest struct {
	FlowID     string          `json:"flow_id"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

// handleWebAuthnRegisterFinish answers POST
// /api/v1/auth/webauthn/register/finish, completing a credential registration
// for the authenticated caller.
func (s *Service) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	subject, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		server.WriteError(w, r, deps.Logger, unauthenticatedError())

		return
	}

	var req webauthnRegisterFinishRequest
	if !decodeBody(w, r, deps.Logger, &req) {
		return
	}

	cred, err := deps.Passkeys.FinishRegistration(r.Context(), subject.UserID, req.FlowID, req.Name, req.Credential)
	if err != nil {
		if errors.Is(err, passkey.ErrVerification) {
			server.WriteError(w, r, deps.Logger, unauthenticatedError())

			return
		}

		deps.Logger.Error("auth: finishing webauthn registration", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	s.recordAudit(r.Context(), audit.ActionPasskeyRegistered, &subject.UserID, "credential:"+cred.ID.String(), audit.OutcomeSuccess,
		deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()), nil)

	w.WriteHeader(http.StatusNoContent)
}

// handleWebAuthnLoginStart answers POST /api/v1/auth/webauthn/login/start,
// beginning a discoverable-credential assertion.
func (*Service) handleWebAuthnLoginStart(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	options, flowID, err := deps.Passkeys.BeginLogin(r.Context())
	if err != nil {
		deps.Logger.Error("auth: beginning webauthn login", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	server.WriteJSON(w, deps.Logger, http.StatusOK, webauthnStartResponse{FlowID: flowID, Options: options})
}

// webauthnLoginFinishRequest is POST /api/v1/auth/webauthn/login/finish's
// request body.
type webauthnLoginFinishRequest struct {
	FlowID     string          `json:"flow_id"`
	Credential json.RawMessage `json:"credential"`
}

// handleWebAuthnLoginFinish answers POST /api/v1/auth/webauthn/login/finish,
// completing an assertion and issuing a session for the credential's owner.
func (s *Service) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	var req webauthnLoginFinishRequest
	if !decodeBody(w, r, deps.Logger, &req) {
		return
	}

	userID, err := deps.Passkeys.FinishLogin(r.Context(), req.FlowID, req.Credential)
	if err != nil {
		if errors.Is(err, passkey.ErrVerification) {
			// userID is for audit attribution only (see passkey.Service.FinishLogin's
			// doc comment) and is never used to authenticate this request: the
			// response below is the same 401 either way. "webauthn" is a
			// method, not a provider, so an unresolved credential audits as
			// anonymous:webauthn rather than provider:webauthn.
			subject := "anonymous:webauthn"
			if userID != uuid.Nil {
				subject = "user:" + userID.String()
			}

			s.recordAudit(r.Context(), audit.ActionPasskeyCompleted, nil, subject, audit.OutcomeFailure,
				deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()), nil)
			server.WriteError(w, r, deps.Logger, unauthenticatedError())

			return
		}

		deps.Logger.Error("auth: finishing webauthn login", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	priorToken := deps.Sessions.TokenFromRequest(r)

	_, sess, token, err := s.LogInExistingUser(r.Context(), userID, []string{session.MethodWebAuthn},
		deps.Proxies.ClientIP(r), r.UserAgent(), server.RequestIDFromContext(r.Context()), priorToken)
	if err != nil {
		server.WriteError(w, r, deps.Logger, mapLoginError(err))

		return
	}

	deps.Sessions.SetCookie(w, token, sess)
	w.WriteHeader(http.StatusNoContent)
}

// otpStartRequest is POST /api/v1/auth/otp/start's request body.
type otpStartRequest struct {
	Email  string `json:"email"`
	Invite string `json:"invite"`
}

// otpStartResponse is POST /api/v1/auth/otp/start's response shape.
type otpStartResponse struct {
	Status string `json:"status"`
}

// handleOTPStart answers POST /api/v1/auth/otp/start, always with 202,
// whether or not the address is known and whether or not an invite it
// carried is live.
func (s *Service) handleOTPStart(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	var req otpStartRequest
	if !decodeBody(w, r, deps.Logger, &req) {
		return
	}

	normalized := strings.ToLower(strings.TrimSpace(req.Email))

	startDecision := deps.Limiter.Decide("otp-start:" + normalized)
	if !startDecision.Allowed {
		if startDecision.FirstRefusal && normalized != "" {
			s.recordAudit(r.Context(), audit.ActionRateLimited, nil, "email:"+normalized, audit.OutcomeFailure,
				deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()), s.auditDetail(map[string]any{auditDetailRouteKey: r.Pattern}))
		}

		server.WriteError(w, r, deps.Logger, rateLimitedError())

		return
	}

	binding := otpBindingFromRequest(r, deps.CookieSecure)
	if binding == "" {
		generated, err := generateOTPBinding()
		if err != nil {
			deps.Logger.Error("auth: generating otp binding", zap.Error(err))
			server.WriteError(w, r, deps.Logger, err)

			return
		}

		binding = generated
	}

	setOTPBindingCookie(w, deps.CookieSecure, binding, int(deps.Codes.CodeTTL().Seconds()))

	inviteID := s.resolveInviteForOTPStart(r, deps.Logger, req.Invite)

	if err := deps.Codes.Request(r.Context(), req.Email, binding, inviteID); err != nil {
		deps.Logger.Error("auth: requesting otp code", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	if normalized != "" {
		s.recordAudit(r.Context(), audit.ActionOTPRequested, nil, "email:"+normalized, audit.OutcomeSuccess,
			deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()), nil)
	}

	server.WriteJSON(w, deps.Logger, http.StatusAccepted, otpStartResponse{Status: "sent"})
}

// otpVerifyRequest is POST /api/v1/auth/otp/verify's request body.
type otpVerifyRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// otpDisplayName is the fixed display name every account created through the
// OTP signup path receives. The submitted address must not become a display
// name other users may see, so it is never used here even though it is the
// only identifying detail the OTP ceremony carries.
const otpDisplayName = "New user"

// handleOTPVerify answers POST /api/v1/auth/otp/verify, completing a code
// verification and issuing a session for the address it names.
func (s *Service) handleOTPVerify(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	var req otpVerifyRequest
	if !decodeBody(w, r, deps.Logger, &req) {
		return
	}

	normalized := strings.ToLower(strings.TrimSpace(req.Email))
	binding := otpBindingFromRequest(r, deps.CookieSecure)
	bindingDigest := sha256.Sum256([]byte(binding))

	verifyDecision := deps.Limiter.Decide("otp-verify:" + normalized + ":" + hex.EncodeToString(bindingDigest[:8]))
	if !verifyDecision.Allowed {
		if verifyDecision.FirstRefusal {
			s.recordAudit(r.Context(), audit.ActionRateLimited, nil, "email:"+normalized, audit.OutcomeFailure,
				deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()), s.auditDetail(map[string]any{auditDetailRouteKey: r.Pattern}))
		}

		server.WriteError(w, r, deps.Logger, rateLimitedError())

		return
	}

	verifiedAddress, inviteID, err := deps.Codes.Verify(r.Context(), req.Email, req.Code, binding)
	if err != nil {
		if errors.Is(err, otp.ErrVerification) {
			s.recordAudit(r.Context(), audit.ActionOTPCompleted, nil, "email:"+normalized, audit.OutcomeFailure,
				deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()), nil)
			server.WriteError(w, r, deps.Logger, unauthenticatedError())

			return
		}

		deps.Logger.Error("auth: verifying otp code", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	clearOTPBindingCookie(w, deps.CookieSecure)

	priorToken := deps.Sessions.TokenFromRequest(r)

	in := Authenticated{
		Provider:      otp.Provider,
		Subject:       verifiedAddress,
		Email:         verifiedAddress,
		EmailVerified: true,
		DisplayName:   otpDisplayName,
		Methods:       []string{session.MethodOTP},
		InviteID:      inviteID,
	}

	_, sess, token, err := s.LogIn(r.Context(), in, deps.Proxies.ClientIP(r), r.UserAgent(), server.RequestIDFromContext(r.Context()), priorToken)
	if err != nil {
		server.WriteError(w, r, deps.Logger, mapLoginError(err))

		return
	}

	deps.Sessions.SetCookie(w, token, sess)
	w.WriteHeader(http.StatusNoContent)
}

// handleLogout answers POST /api/v1/auth/logout, revoking the current
// session and clearing its cookie whether or not it still resolved to
// anything. A RevokeToken failure still clears the cookie, since a browser
// that keeps presenting a token the server could not confirm revoking is a
// worse outcome than one that drops it and tries again, but it is answered as
// the 5xx it is rather than papered over as an ordinary 204: a caller must be
// able to tell "you are signed out" from "we don't know whether you are".
func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	token := deps.Sessions.TokenFromRequest(r)

	if token != "" {
		if err := deps.Sessions.RevokeToken(r.Context(), token); err != nil {
			deps.Logger.Error("auth: revoking session at logout", zap.Error(err))
			deps.Sessions.ClearCookie(w)
			server.WriteError(w, r, deps.Logger, err)

			return
		}
	}

	deps.Sessions.ClearCookie(w)

	if subject, ok := authz.SubjectFromContext(r.Context()); ok {
		userID := subject.UserID
		s.recordAudit(r.Context(), audit.ActionLogout, &userID, "session:"+subject.SessionPublicID.String(), audit.OutcomeSuccess,
			deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()), nil)
	}

	w.WriteHeader(http.StatusNoContent)
}

// meResponse is GET /api/v1/me's response shape.
type meResponse struct {
	ID            uuid.UUID `json:"id"`
	DisplayName   string    `json:"display_name"`
	Email         *string   `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Status        string    `json:"status"`
	Roles         []string  `json:"roles"`
	Permissions   []string  `json:"permissions"`
	CreatedAt     time.Time `json:"created_at"`
}

// accountResponse is the GET /api/v1/me shape minus permissions, which
// PATCH /api/v1/admin/users/{id}/roles answers with.
type accountResponse struct {
	ID            uuid.UUID `json:"id"`
	DisplayName   string    `json:"display_name"`
	Email         *string   `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Status        string    `json:"status"`
	Roles         []string  `json:"roles"`
	CreatedAt     time.Time `json:"created_at"`
}

// handleMe answers GET /api/v1/me with the authenticated caller's own
// account.
func (*Service) handleMe(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	subject, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		server.WriteError(w, r, deps.Logger, unauthenticatedError())

		return
	}

	account, err := deps.Users.ByID(r.Context(), subject.UserID)
	if err != nil {
		deps.Logger.Error("auth: loading account for me", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	roles, err := deps.Roles.RolesFor(r.Context(), subject.UserID)
	if err != nil {
		deps.Logger.Error("auth: loading roles for me", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	permissions := subject.Permissions
	if permissions == nil {
		permissions = []string{}
	}

	server.WriteJSON(w, deps.Logger, http.StatusOK, meResponse{
		ID:            account.ID,
		DisplayName:   account.DisplayName,
		Email:         account.Email,
		EmailVerified: account.EmailVerifiedAt != nil,
		Status:        string(account.Status),
		Roles:         roles,
		Permissions:   permissions,
		CreatedAt:     account.CreatedAt,
	})
}

// sessionResponse is one entry of GET /api/v1/me/sessions' response.
type sessionResponse struct {
	ID                uuid.UUID `json:"id"`
	Current           bool      `json:"current"`
	CreatedAt         time.Time `json:"created_at"`
	LastSeenAt        time.Time `json:"last_seen_at"`
	AbsoluteExpiresAt time.Time `json:"absolute_expires_at"`
	ClientIP          *string   `json:"client_ip"`
	UserAgent         string    `json:"user_agent"`
	Methods           []string  `json:"methods"`
}

// sessionsResponse is GET /api/v1/me/sessions' response shape.
type sessionsResponse struct {
	Sessions []sessionResponse `json:"sessions"`
}

// handleMeSessions answers GET /api/v1/me/sessions with the authenticated
// caller's own live sessions, built from each session's PublicID rather than
// its digest.
func (*Service) handleMeSessions(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	subject, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		server.WriteError(w, r, deps.Logger, unauthenticatedError())

		return
	}

	sessions, err := deps.Sessions.ListFor(r.Context(), subject.UserID)
	if err != nil {
		deps.Logger.Error("auth: listing sessions", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	entries := make([]sessionResponse, 0, len(sessions))

	for _, sess := range sessions {
		var clientIP *string

		if sess.ClientIP != nil {
			ip := sess.ClientIP.String()
			clientIP = &ip
		}

		entries = append(entries, sessionResponse{
			ID:                sess.PublicID,
			Current:           sess.PublicID == subject.SessionPublicID,
			CreatedAt:         sess.CreatedAt,
			LastSeenAt:        sess.LastSeenAt,
			AbsoluteExpiresAt: sess.AbsoluteExpiresAt,
			ClientIP:          clientIP,
			UserAgent:         sess.UserAgent,
			Methods:           sess.Methods,
		})
	}

	server.WriteJSON(w, deps.Logger, http.StatusOK, sessionsResponse{Sessions: entries})
}

// handleMeSessionsDelete answers DELETE /api/v1/me/sessions/{id}, revoking
// the named session when it belongs to the authenticated caller. It answers
// 204 whether the identifier failed to parse, named nobody's session, or
// named another account's session, so a caller cannot use the response to
// probe for a session's existence.
func (s *Service) handleMeSessionsDelete(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	subject, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		server.WriteError(w, r, deps.Logger, unauthenticatedError())

		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		w.WriteHeader(http.StatusNoContent)

		return
	}

	deleted, revokeErr := deps.Sessions.Revoke(r.Context(), subject.UserID, id)
	if revokeErr != nil {
		deps.Logger.Error("auth: revoking session", zap.Error(revokeErr))
		server.WriteError(w, r, deps.Logger, revokeErr)

		return
	}

	if deleted {
		s.recordAudit(r.Context(), audit.ActionSessionRevoked, &subject.UserID, "session:"+id.String(), audit.OutcomeSuccess,
			deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()), nil)
	}

	w.WriteHeader(http.StatusNoContent)
}

// credentialResponse is one entry of GET /api/v1/me/credentials' response.
type credentialResponse struct {
	ID           uuid.UUID  `json:"id"`
	Name         string     `json:"name"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at"`
	CloneWarning bool       `json:"clone_warning"`
}

// credentialsResponse is GET /api/v1/me/credentials' response shape.
type credentialsResponse struct {
	Credentials []credentialResponse `json:"credentials"`
}

// handleMeCredentials answers GET /api/v1/me/credentials with the
// authenticated caller's own registered credentials.
func (*Service) handleMeCredentials(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	subject, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		server.WriteError(w, r, deps.Logger, unauthenticatedError())

		return
	}

	creds, err := deps.Credentials.ListFor(r.Context(), subject.UserID)
	if err != nil {
		deps.Logger.Error("auth: listing credentials", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	entries := make([]credentialResponse, 0, len(creds))

	for _, c := range creds {
		entries = append(entries, credentialResponse{
			ID:           c.ID,
			Name:         c.Name,
			CreatedAt:    c.CreatedAt,
			LastUsedAt:   c.LastUsedAt,
			CloneWarning: c.CloneWarning,
		})
	}

	server.WriteJSON(w, deps.Logger, http.StatusOK, credentialsResponse{Credentials: entries})
}

// handleMeCredentialsDelete answers DELETE /api/v1/me/credentials/{id},
// removing the named credential when it belongs to the authenticated caller,
// through Service.RemoveCredential so the last-sign-in-method rule applies
// and the removal audits itself; this handler records no audit event of its
// own. It answers 204 whether the identifier failed to parse, named nobody's
// credential, or named another account's credential, for the same reason
// handleMeSessionsDelete does. ErrLastFactor, refusing a removal that would
// leave the account unable to sign in, answers 409 conflict and leaves the
// credential registered.
func (s *Service) handleMeCredentialsDelete(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	subject, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		server.WriteError(w, r, deps.Logger, unauthenticatedError())

		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		w.WriteHeader(http.StatusNoContent)

		return
	}

	removeErr := s.RemoveCredential(r.Context(), subject.UserID, id, deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()))
	if removeErr != nil {
		if errors.Is(removeErr, ErrLastFactor) {
			server.WriteError(w, r, deps.Logger, conflictError())

			return
		}

		deps.Logger.Error("auth: removing credential", zap.Error(removeErr))
		server.WriteError(w, r, deps.Logger, removeErr)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// validUserStatuses names the status values GET /api/v1/admin/users accepts
// as its status query parameter.
var validUserStatuses = map[string]bool{
	string(user.StatusPending):   true,
	string(user.StatusActive):    true,
	string(user.StatusSuspended): true,
	string(user.StatusDeleted):   true,
}

// adminUserResponse is one entry of GET /api/v1/admin/users' response.
type adminUserResponse struct {
	ID          uuid.UUID `json:"id"`
	DisplayName string    `json:"display_name"`
	Email       *string   `json:"email"`
	Status      string    `json:"status"`
	Roles       []string  `json:"roles"`
	CreatedAt   time.Time `json:"created_at"`
}

// adminUsersResponse is GET /api/v1/admin/users' response shape.
type adminUsersResponse struct {
	Users      []adminUserResponse `json:"users"`
	NextCursor *string             `json:"next_cursor"`
}

// handleAdminUsers answers GET /api/v1/admin/users, optionally filtered by
// status. An unrecognised status value, or a cursor that does not parse as a
// UUID, answers 400 before the repository is ever reached.
func (*Service) handleAdminUsers(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	status := r.URL.Query().Get("status")
	if status != "" && !validUserStatuses[status] {
		server.WriteError(w, r, deps.Logger, invalidRequestError())

		return
	}

	cursor := r.URL.Query().Get("cursor")
	if cursor != "" {
		if _, err := uuid.Parse(cursor); err != nil {
			server.WriteError(w, r, deps.Logger, invalidRequestError())

			return
		}
	}

	users, nextCursor, err := deps.Users.List(r.Context(), status, cursor, adminUsersPageSize)
	if err != nil {
		deps.Logger.Error("auth: listing users", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	userIDs := make([]uuid.UUID, 0, len(users))

	for _, u := range users {
		userIDs = append(userIDs, u.ID)
	}

	// One read for the whole page rather than one per account.
	rolesByUser, err := deps.Roles.RolesForEach(r.Context(), userIDs)
	if err != nil {
		deps.Logger.Error("auth: loading roles for admin user listing", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	entries := make([]adminUserResponse, 0, len(users))

	for _, u := range users {
		entries = append(entries, adminUserResponse{
			ID:          u.ID,
			DisplayName: u.DisplayName,
			Email:       u.Email,
			Status:      string(u.Status),
			Roles:       rolesByUser[u.ID],
			CreatedAt:   u.CreatedAt,
		})
	}

	var nextCursorPtr *string
	if nextCursor != "" {
		nextCursorPtr = &nextCursor
	}

	server.WriteJSON(w, deps.Logger, http.StatusOK, adminUsersResponse{Users: entries, NextCursor: nextCursorPtr})
}

// rolesUpdateRequest is PATCH /api/v1/admin/users/{id}/roles' request body.
type rolesUpdateRequest struct {
	Roles []string `json:"roles"`
}

// addedRoles returns the names in next that are not in current.
func addedRoles(current, next []string) []string {
	added := make([]string, 0, len(next))

	for _, name := range next {
		if !slices.Contains(current, name) {
			added = append(added, name)
		}
	}

	return added
}

// removedRoles returns the names in current that are not in next.
func removedRoles(current, next []string) []string {
	removed := make([]string, 0, len(current))

	for _, name := range current {
		if !slices.Contains(next, name) {
			removed = append(removed, name)
		}
	}

	return removed
}

// handleAdminUsersRoles answers PATCH /api/v1/admin/users/{id}/roles,
// replacing the target account's roles through Service.ReplaceRoles. It
// refuses, with 409, a change that would leave zero active accounts holding
// admin; ReplaceRoles checks that rule and writes the roles in one
// transaction under the last-admin advisory lock, so concurrent demotions
// cannot remove every administrator.
func (s *Service) handleAdminUsersRoles(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	subject, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		server.WriteError(w, r, deps.Logger, unauthenticatedError())

		return
	}

	targetID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		server.WriteError(w, r, deps.Logger, invalidRequestError())

		return
	}

	// The target is loaded first, and before any decoding or write, so a
	// request naming an account that does not exist (including one that is
	// soft-deleted, which ByID excludes) answers 404 before anything about
	// the request body is even inspected.
	if _, byIDErr := deps.Users.ByID(r.Context(), targetID); byIDErr != nil {
		if errors.Is(byIDErr, user.ErrNotFound) {
			server.WriteError(w, r, deps.Logger, notFoundError())

			return
		}

		deps.Logger.Error("auth: loading target account for role update", zap.Error(byIDErr))
		server.WriteError(w, r, deps.Logger, byIDErr)

		return
	}

	var req rolesUpdateRequest
	if !decodeBody(w, r, deps.Logger, &req) {
		return
	}

	// A body whose roles key is absent or explicitly null decodes to a nil
	// slice, which is refused outright; an explicit empty array decodes to a
	// non-nil empty slice and remains a legal (if unusual) request, still
	// subject to the last-admin rule below.
	if req.Roles == nil {
		server.WriteError(w, r, deps.Logger, invalidRequestError())

		return
	}

	// Duplicate names are deduplicated before they ever reach SetRolesTx: that
	// method issues one INSERT per name with no ON CONFLICT clause, so a
	// duplicate would otherwise fail as a 500 rather than being accepted the
	// way a caller sending ["member","member"] would reasonably expect.
	nextRoles := slices.Clone(req.Roles)
	slices.Sort(nextRoles)
	nextRoles = slices.Compact(nextRoles)

	currentRoles, err := s.ReplaceRoles(r.Context(), subject.UserID, targetID, nextRoles)

	switch {
	case err == nil:
	case errors.Is(err, ErrLastAdmin):
		deps.Logger.Warn("auth: refusing to remove the last active admin", zap.String("user_id", targetID.String()))
		server.WriteError(w, r, deps.Logger, &server.ClientError{
			Status:  http.StatusConflict,
			Code:    server.ErrorCodeConflict,
			Message: "request conflicts with current state",
		})

		return
	case errors.Is(err, authz.ErrUnknownRole):
		server.WriteError(w, r, deps.Logger, invalidRequestError())

		return
	default:
		deps.Logger.Error("auth: replacing roles", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	s.recordRoleChanges(r.Context(), r, deps, subject.UserID, targetID, currentRoles, nextRoles)

	updatedAccount, err := deps.Users.ByID(r.Context(), targetID)
	if err != nil {
		deps.Logger.Error("auth: loading account after role update", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	updatedRoles, err := deps.Roles.RolesFor(r.Context(), targetID)
	if err != nil {
		deps.Logger.Error("auth: loading roles after role update", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	server.WriteJSON(w, deps.Logger, http.StatusOK, accountResponse{
		ID:            updatedAccount.ID,
		DisplayName:   updatedAccount.DisplayName,
		Email:         updatedAccount.Email,
		EmailVerified: updatedAccount.EmailVerifiedAt != nil,
		Status:        string(updatedAccount.Status),
		Roles:         updatedRoles,
		CreatedAt:     updatedAccount.CreatedAt,
	})
}

// recordRoleChanges appends one audit event per role added and per role
// removed between current and next.
func (s *Service) recordRoleChanges(ctx context.Context, r *http.Request, deps RouteDeps, actorID, targetID uuid.UUID, current, next []string) {
	clientIP := deps.Proxies.ClientIP(r)
	requestID := server.RequestIDFromContext(ctx)

	for _, role := range addedRoles(current, next) {
		detail, err := json.Marshal(map[string]string{"role": role})
		if err != nil {
			deps.Logger.Error("auth: encoding role-granted audit detail", zap.Error(err))

			detail = nil
		}

		s.recordAudit(ctx, audit.ActionRoleGranted, &actorID, "user:"+targetID.String(), audit.OutcomeSuccess, clientIP, requestID, detail)
	}

	for _, role := range removedRoles(current, next) {
		detail, err := json.Marshal(map[string]string{"role": role})
		if err != nil {
			deps.Logger.Error("auth: encoding role-revoked audit detail", zap.Error(err))

			detail = nil
		}

		s.recordAudit(ctx, audit.ActionRoleRevoked, &actorID, "user:"+targetID.String(), audit.OutcomeSuccess, clientIP, requestID, detail)
	}
}
