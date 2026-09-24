package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/audit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/oidc"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/user"
)

// auditListDefaultLimit is how many rows GET /api/v1/admin/audit returns when
// the caller supplies no limit query parameter.
const auditListDefaultLimit = 50

// auditListMinLimit is the smallest limit GET /api/v1/admin/audit clamps
// down to, rather than rejecting a caller-supplied value below it.
const auditListMinLimit = 1

// auditListMaxLimit is the largest limit GET /api/v1/admin/audit clamps up
// to, rather than rejecting a caller-supplied value above it.
const auditListMaxLimit = 200

// conflictError returns the fixed 409 conflict ClientError every account
// management refusal that is not is_pending answers with: ErrLastFactor,
// ErrLastAdmin, ErrSelfAction, and user.ErrIsDeleted all render identically,
// per design.md's "Interfaces" section, because the distinction between
// them goes to the log and the audit detail, not to the client.
func conflictError() *server.ClientError {
	return &server.ClientError{
		Status:  http.StatusConflict,
		Code:    server.ErrorCodeConflict,
		Message: "request conflicts with current state",
	}
}

// isPendingError returns the fixed 409 is_pending ClientError
// PATCH /api/v1/admin/users/{id}/status answers with whenever the target
// account's current status is pending, whatever status was requested.
func isPendingError() *server.ClientError {
	return &server.ClientError{
		Status:  http.StatusConflict,
		Code:    server.ErrorCodeIsPending,
		Message: "account is awaiting approval",
	}
}

// updateDisplayNameRequest is PATCH /api/v1/me's request body.
type updateDisplayNameRequest struct {
	DisplayName string `json:"display_name"`
}

// handleMePatch answers PATCH /api/v1/me, changing the authenticated
// caller's own display name and answering with the GET /api/v1/me shape. An
// empty name is refused with 400 invalid_request, from
// user.ErrInvalidDisplayName.
func (s *Service) handleMePatch(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	subject, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		server.WriteError(w, r, deps.Logger, unauthenticatedError())

		return
	}

	var req updateDisplayNameRequest
	if !decodeBody(w, r, deps.Logger, &req) {
		return
	}

	updated, err := s.UpdateDisplayName(r.Context(), subject.UserID, req.DisplayName,
		deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()))
	if err != nil {
		if errors.Is(err, user.ErrInvalidDisplayName) {
			server.WriteError(w, r, deps.Logger, invalidRequestError())

			return
		}

		deps.Logger.Error("auth: updating display name", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	roles, err := deps.Roles.RolesFor(r.Context(), subject.UserID)
	if err != nil {
		deps.Logger.Error("auth: loading roles after display name update", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	permissions := subject.Permissions
	if permissions == nil {
		permissions = []string{}
	}

	server.WriteJSON(w, deps.Logger, http.StatusOK, meResponse{
		ID:            updated.ID,
		DisplayName:   updated.DisplayName,
		Email:         updated.Email,
		EmailVerified: updated.EmailVerifiedAt != nil,
		Status:        string(updated.Status),
		Roles:         roles,
		Permissions:   permissions,
		CreatedAt:     updated.CreatedAt,
	})
}

// handleMeDelete answers DELETE /api/v1/me, soft-deleting the authenticated
// caller's own account, revoking every session it holds, and clearing the
// session cookie after the account is gone. ErrLastAdmin answers 409
// conflict and leaves the account untouched.
func (s *Service) handleMeDelete(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	subject, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		server.WriteError(w, r, deps.Logger, unauthenticatedError())

		return
	}

	err := s.DeleteAccount(r.Context(), subject.UserID, deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()))
	if err != nil {
		if errors.Is(err, ErrLastAdmin) {
			server.WriteError(w, r, deps.Logger, conflictError())

			return
		}

		deps.Logger.Error("auth: deleting account", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	deps.Sessions.ClearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// handleMeSessionsDeleteAll answers DELETE /api/v1/me/sessions, revoking
// every session the authenticated caller's account holds, including the one
// the request itself carries, then clearing the cookie. It answers 204
// rather than a count, which is not useful and would reveal how many devices
// the account had to anyone who holds the cookie. Per AC-008.38, a
// revocation that actually revoked at least one session is recorded as an
// audit.ActionSessionRevoked event, exactly as handleAdminUsersSessions
// records one for its own target.
func (s *Service) handleMeSessionsDeleteAll(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	subject, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		server.WriteError(w, r, deps.Logger, unauthenticatedError())

		return
	}

	revoked, err := deps.Sessions.RevokeAllFor(r.Context(), subject.UserID)
	if err != nil {
		deps.Logger.Error("auth: revoking all own sessions", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	if revoked > 0 {
		s.recordAudit(r.Context(), audit.ActionSessionRevoked, &subject.UserID, "user:"+subject.UserID.String(), audit.OutcomeSuccess,
			deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()), nil)
	}

	deps.Sessions.ClearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// identityResponse is one entry of GET /api/v1/me/identities' response.
type identityResponse struct {
	ID         uuid.UUID  `json:"id"`
	Provider   string     `json:"provider"`
	Email      *string    `json:"email"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// identitiesResponse is GET /api/v1/me/identities' response shape.
type identitiesResponse struct {
	Identities []identityResponse `json:"identities"`
}

// handleMeIdentities answers GET /api/v1/me/identities with the
// authenticated caller's own linked external identities.
func (*Service) handleMeIdentities(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	subject, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		server.WriteError(w, r, deps.Logger, unauthenticatedError())

		return
	}

	identities, err := deps.Users.IdentitiesFor(r.Context(), subject.UserID)
	if err != nil {
		deps.Logger.Error("auth: listing identities", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	entries := make([]identityResponse, 0, len(identities))

	for _, id := range identities {
		entries = append(entries, identityResponse{
			ID:         id.ID,
			Provider:   id.Provider,
			Email:      id.Email,
			CreatedAt:  id.CreatedAt,
			LastUsedAt: id.LastUsedAt,
		})
	}

	server.WriteJSON(w, deps.Logger, http.StatusOK, identitiesResponse{Identities: entries})
}

// handleMeIdentitiesLinkStart answers
// GET /api/v1/me/identities/{provider}/link/start, beginning an identity-link
// ceremony for the authenticated caller and redirecting to the provider. It
// answers 404 for an unconfigured provider, exactly as the login start route
// does, so the two never disagree about which providers exist.
func (s *Service) handleMeIdentitiesLinkStart(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	subject, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		server.WriteError(w, r, deps.Logger, unauthenticatedError())

		return
	}

	provider := r.PathValue("provider")

	authURL, binding, err := s.StartIdentityLink(r.Context(), subject.UserID, provider)
	if err != nil {
		if errors.Is(err, oidc.ErrUnknownProvider) {
			server.WriteError(w, r, deps.Logger, notFoundError())

			return
		}

		deps.Logger.Error("auth: starting identity link", zap.String("provider", provider), zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	setOIDCBindingCookie(w, deps.CookieSecure, binding, deps.FlowTTL)

	http.Redirect(w, r, authURL, http.StatusSeeOther) //nolint:gosec // G710: authURL is built by StartIdentityLink from this deployment's own configured provider issuer, never from request-controlled input
}

// handleMeIdentitiesDelete answers DELETE /api/v1/me/identities/{id},
// detaching the named identity when it belongs to the authenticated caller.
// It answers 204 whether the identifier failed to parse, named nobody's
// identity, or named another account's identity, for the same reason
// handleMeSessionsDelete does. ErrLastFactor, refusing a removal that would
// leave the account unable to sign in, answers 409 conflict and leaves the
// identity attached.
func (s *Service) handleMeIdentitiesDelete(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
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

	removeErr := s.RemoveIdentity(r.Context(), subject.UserID, id, deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()))
	if removeErr != nil {
		if errors.Is(removeErr, ErrLastFactor) {
			server.WriteError(w, r, deps.Logger, conflictError())

			return
		}

		deps.Logger.Error("auth: removing identity", zap.Error(removeErr))
		server.WriteError(w, r, deps.Logger, removeErr)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// statusUpdateRequest is PATCH /api/v1/admin/users/{id}/status's request
// body.
type statusUpdateRequest struct {
	Status string `json:"status"`
}

// handleAdminUsersStatus answers PATCH /api/v1/admin/users/{id}/status,
// suspending, reactivating, or restoring the target account. A body naming
// "active" is routed to RestoreAccount when the target is currently deleted
// and to SetStatus otherwise, so an administrator has one verb for making an
// account usable again. A body naming "deleted", or anything other than
// "active" or "suspended", is refused as invalid_request: deletion is the
// account holder's own action through DELETE /api/v1/me. Whatever status is
// requested, a target whose current status is pending is refused outright
// with 409 is_pending, so this route can never be used to approve an
// account.
func (s *Service) handleAdminUsersStatus(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
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

	var req statusUpdateRequest
	if !decodeBody(w, r, deps.Logger, &req) {
		return
	}

	if req.Status != string(user.StatusActive) && req.Status != string(user.StatusSuspended) {
		server.WriteError(w, r, deps.Logger, invalidRequestError())

		return
	}

	target, err := deps.Users.ByIDAnyStatus(r.Context(), targetID)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			server.WriteError(w, r, deps.Logger, notFoundError())

			return
		}

		deps.Logger.Error("auth: loading target account for status update", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	if target.Status == user.StatusPending {
		server.WriteError(w, r, deps.Logger, isPendingError())

		return
	}

	clientIP := deps.Proxies.ClientIP(r)
	requestID := server.RequestIDFromContext(r.Context())

	updated, statusErr := s.applyStatusChange(r.Context(), subject.UserID, targetID, target.Status, user.Status(req.Status), clientIP, requestID)
	if statusErr != nil {
		writeAccountStatusError(w, r, deps, statusErr)

		return
	}

	roles, err := deps.Roles.RolesFor(r.Context(), targetID)
	if err != nil {
		deps.Logger.Error("auth: loading roles after status update", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	server.WriteJSON(w, deps.Logger, http.StatusOK, accountResponse{
		ID:            updated.ID,
		DisplayName:   updated.DisplayName,
		Email:         updated.Email,
		EmailVerified: updated.EmailVerifiedAt != nil,
		Status:        string(updated.Status),
		Roles:         roles,
		CreatedAt:     updated.CreatedAt,
	})
}

// applyStatusChange routes a status write to RestoreAccount when the target
// is deleted and the requested status is active, and to SetStatus otherwise.
// A deleted target with "suspended" requested therefore reaches SetStatus,
// which refuses it with user.ErrIsDeleted rather than reviving it: the only
// way to make a deleted account usable again is to request "active" while it
// is still within its restore grace window.
func (s *Service) applyStatusChange(
	ctx context.Context, actorID, targetID uuid.UUID, currentStatus, requestedStatus user.Status, clientIP, requestID string,
) (user.User, error) {
	if requestedStatus == user.StatusActive && currentStatus == user.StatusDeleted {
		return s.RestoreAccount(ctx, actorID, targetID, clientIP, requestID)
	}

	return s.SetStatus(ctx, actorID, targetID, requestedStatus, clientIP, requestID)
}

// writeAccountStatusError maps a RestoreAccount or SetStatus failure to the
// exact response design.md's "Interfaces" section fixes for it:
// ErrGraceExpired answers 404 not_found, indistinguishable from an unknown
// account id, and ErrLastAdmin,
// ErrSelfAction, user.ErrIsDeleted, and user.ErrIsRejected all answer 409
// conflict. user.ErrIsRejected reaches here from RestoreAccount per
// AC-008.78: a rejected account is final and answers the same conflict a
// self-deleted account past its grace window would, never a revival.
func writeAccountStatusError(w http.ResponseWriter, r *http.Request, deps RouteDeps, err error) {
	switch {
	case errors.Is(err, ErrGraceExpired):
		server.WriteError(w, r, deps.Logger, notFoundError())
	case errors.Is(err, ErrLastAdmin), errors.Is(err, ErrSelfAction), errors.Is(err, user.ErrIsDeleted), errors.Is(err, user.ErrIsRejected):
		server.WriteError(w, r, deps.Logger, conflictError())
	default:
		deps.Logger.Error("auth: applying account status change", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)
	}
}

// handleAdminUsersSessions answers DELETE /api/v1/admin/users/{id}/sessions,
// revoking every session the target account holds. It leaves the acting
// administrator's own session untouched, since that session belongs to a
// different account. An id naming no account answers 404, so a mistyped id
// is not reported as a successful revocation.
func (s *Service) handleAdminUsersSessions(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
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

	if _, lookupErr := deps.Users.ByIDAnyStatus(r.Context(), targetID); lookupErr != nil {
		if errors.Is(lookupErr, user.ErrNotFound) {
			server.WriteError(w, r, deps.Logger, notFoundError())

			return
		}

		deps.Logger.Error("auth: loading target account for session revocation", zap.Error(lookupErr))
		server.WriteError(w, r, deps.Logger, lookupErr)

		return
	}

	revoked, err := deps.Sessions.RevokeAllFor(r.Context(), targetID)
	if err != nil {
		deps.Logger.Error("auth: revoking target account sessions", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	if revoked > 0 {
		s.recordAudit(r.Context(), audit.ActionSessionRevoked, &subject.UserID, "user:"+targetID.String(), audit.OutcomeSuccess,
			deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()), nil)
	}

	w.WriteHeader(http.StatusNoContent)
}

// auditEventResponse is one entry of GET /api/v1/admin/audit's response. It
// is built entirely from typed fields rather than serializing audit.Event
// directly, so a future field added to that row cannot leak into the
// response by accident.
type auditEventResponse struct {
	ID         uuid.UUID       `json:"id"`
	OccurredAt time.Time       `json:"occurred_at"`
	ActorID    *uuid.UUID      `json:"actor_id"`
	ActorRef   string          `json:"actor_ref"`
	Subject    string          `json:"subject"`
	Action     string          `json:"action"`
	Outcome    string          `json:"outcome"`
	ClientIP   *string         `json:"client_ip"`
	RequestID  string          `json:"request_id"`
	Detail     json.RawMessage `json:"detail"`
}

// auditEventsResponse is GET /api/v1/admin/audit's response shape.
type auditEventsResponse struct {
	Events     []auditEventResponse `json:"events"`
	NextCursor *string              `json:"next_cursor"`
}

// clampAuditLimit clamps limit to [auditListMinLimit, auditListMaxLimit]:
// an out-of-range limit is adjusted rather than rejected.
func clampAuditLimit(limit int) int {
	if limit < auditListMinLimit {
		return auditListMinLimit
	}

	if limit > auditListMaxLimit {
		return auditListMaxLimit
	}

	return limit
}

// handleAdminAudit answers GET /api/v1/admin/audit, listing events newest
// first. limit is clamped rather than rejected; an absent or unparseable
// limit falls back to auditListDefaultLimit. before, when present, must
// parse as an audit.Cursor (the exact string a previous call returned as
// next_cursor) or the request is refused as invalid_request. It fetches
// limit+1 rows so it can tell whether another page follows: when it does,
// next_cursor names the last of the limit rows returned; otherwise
// next_cursor is JSON null. A NULL client_ip renders as JSON null.
func (s *Service) handleAdminAudit(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	limit := auditListDefaultLimit

	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, parseErr := strconv.Atoi(raw); parseErr == nil {
			limit = parsed
		}
	}

	limit = clampAuditLimit(limit)

	var before audit.Cursor

	if raw := r.URL.Query().Get("before"); raw != "" {
		parsed, parseErr := audit.ParseCursor(raw)
		if parseErr != nil {
			server.WriteError(w, r, deps.Logger, invalidRequestError())

			return
		}

		before = parsed
	}

	events, err := s.recorder.List(r.Context(), limit+1, before)
	if err != nil {
		deps.Logger.Error("auth: listing audit events", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	var nextCursor *string

	if len(events) > limit {
		last := events[limit-1]
		cursor := audit.Cursor{OccurredAt: last.OccurredAt, ID: last.ID}.String()
		nextCursor = &cursor
		events = events[:limit]
	}

	entries := make([]auditEventResponse, 0, len(events))

	for _, e := range events {
		var clientIP *string
		if e.ClientIP != nil {
			ip := e.ClientIP.String()
			clientIP = &ip
		}

		entries = append(entries, auditEventResponse{
			ID:         e.ID,
			OccurredAt: e.OccurredAt,
			ActorID:    e.ActorID,
			ActorRef:   e.ActorRef,
			Subject:    e.Subject,
			Action:     e.Action,
			Outcome:    string(e.Outcome),
			ClientIP:   clientIP,
			RequestID:  e.RequestID,
			Detail:     e.Detail,
		})
	}

	server.WriteJSON(w, deps.Logger, http.StatusOK, auditEventsResponse{Events: entries, NextCursor: nextCursor})
}
