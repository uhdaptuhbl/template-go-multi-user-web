package auth

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/audit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/invite"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
)

// defaultQRScale is the pixel scale GET /i/{file} renders a QR code at when
// the caller's scale query parameter is absent or unparseable. invite.QR
// clamps whatever value reaches it, so this default does not itself need to
// be validated.
const defaultQRScale = 8

// inviteQuotaExhaustedError returns the fixed 409 invite_quota_exhausted
// ClientError POST /api/v1/invites answers with when the issuer already
// holds as many live invites as its quota allows.
func inviteQuotaExhaustedError() *server.ClientError {
	return &server.ClientError{
		Status:  http.StatusConflict,
		Code:    server.ErrorCodeInviteQuotaExhausted,
		Message: "invite quota exhausted",
	}
}

// createInviteRequest is POST /api/v1/invites' request body. Every field is
// optional: an absent Email issues an unbound invite, an absent or
// non-positive MaxUses takes invite.Service's single-use default, and an
// absent or non-positive TTLSecs takes the configured default TTL.
type createInviteRequest struct {
	Email   string `json:"email"`
	Note    string `json:"note"`
	MaxUses int    `json:"max_uses"`
	TTLSecs int    `json:"ttl_secs"`
}

// inviteResponse is the shape every invite route answers with. URL, Token,
// and QRURL are populated only by the create route's 201 response, per
// AC-008.63: they are the only place an invite's token or the URLs built
// from it ever appear, and every other route omits them via their omitempty
// tags rather than sending them as null or empty.
type inviteResponse struct {
	ID           uuid.UUID  `json:"id"`
	URL          string     `json:"url,omitempty"`
	Token        string     `json:"token,omitempty"`
	QRURL        string     `json:"qr_url,omitempty"`
	CreatedBy    *uuid.UUID `json:"created_by"`
	CreatedByRef string     `json:"created_by_ref"`
	Email        *string    `json:"email"`
	Note         string     `json:"note"`
	MaxUses      int        `json:"max_uses"`
	Uses         int        `json:"uses"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	RevokedAt    *time.Time `json:"revoked_at"`
	State        string     `json:"state"`
}

// invitesResponse is GET /api/v1/invites' response shape.
type invitesResponse struct {
	Invites    []inviteResponse `json:"invites"`
	NextCursor *string          `json:"next_cursor"`
}

// inviteToResponse builds the shared invite shape, leaving URL, Token, and
// QRURL empty; the create handler fills those in afterward, since they are
// derivable only at the moment of issue.
func inviteToResponse(inv invite.Invite, now time.Time) inviteResponse {
	var createdBy *uuid.UUID
	if inv.CreatedBy.Valid {
		id := inv.CreatedBy.UUID
		createdBy = &id
	}

	var email *string
	if inv.Email != "" {
		e := inv.Email
		email = &e
	}

	return inviteResponse{
		ID:           inv.ID,
		CreatedBy:    createdBy,
		CreatedByRef: inv.CreatedByRef,
		Email:        email,
		Note:         inv.Note,
		MaxUses:      inv.MaxUses,
		Uses:         inv.Uses,
		CreatedAt:    inv.CreatedAt,
		ExpiresAt:    inv.ExpiresAt,
		RevokedAt:    inv.RevokedAt,
		State:        inv.State(now),
	}
}

// handleInvitesCreate answers POST /api/v1/invites, issuing an invite on the
// authenticated caller's behalf. It is the only response that ever carries
// token, url, or qr_url; url and qr_url are built from deps.PublicOrigin,
// never from the request's Host header, which an attacker controls.
func (s *Service) handleInvitesCreate(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	subject, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		server.WriteError(w, r, deps.Logger, unauthenticatedError())

		return
	}

	var req createInviteRequest
	if !decodeBody(w, r, deps.Logger, &req) {
		return
	}

	unlimitedQuota := subject.HasPermission(authz.PermissionInviteManage)
	issuerRef := "user:" + subject.UserID.String()

	issued, err := s.inviteService.Create(r.Context(), subject.UserID, issuerRef, unlimitedQuota, invite.Params{
		Email:   req.Email,
		Note:    req.Note,
		MaxUses: req.MaxUses,
		TTL:     time.Duration(req.TTLSecs) * time.Second,
	})
	if err != nil {
		switch {
		case errors.Is(err, invite.ErrQuotaExhausted):
			server.WriteError(w, r, deps.Logger, inviteQuotaExhaustedError())
		case errors.Is(err, invite.ErrMaxUsesTooHigh):
			server.WriteError(w, r, deps.Logger, invalidRequestError())
		case errors.Is(err, invite.ErrTTLTooLong):
			server.WriteError(w, r, deps.Logger, invalidRequestError())
		default:
			deps.Logger.Error("auth: creating invite", zap.Error(err))
			server.WriteError(w, r, deps.Logger, err)
		}

		return
	}

	resp := inviteToResponse(issued.Invite, s.now())
	resp.URL = deps.PublicOrigin + "/i/" + issued.Token
	resp.Token = issued.Token
	resp.QRURL = deps.PublicOrigin + "/i/" + issued.Token + ".png"

	// detail is nil: the token, url, and qr_url must never reach an audit
	// row, and the invite's identifier alone (already in subject) is enough
	// to correlate this event with the invite it created.
	s.recordAudit(r.Context(), audit.ActionInviteCreated, &subject.UserID, "invite:"+issued.Invite.ID.String(), audit.OutcomeSuccess,
		deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()), nil)

	server.WriteJSON(w, deps.Logger, http.StatusCreated, resp)
}

// handleInvitesList answers GET /api/v1/invites, listing the authenticated
// caller's own invites, or every invite when the caller holds
// PermissionInviteManage. The ownership predicate (design.md's
// "Authorization path") lives in invite.Service's SQL, not in this
// handler. A cursor invite.Service did not itself issue answers 400
// invalid_request per design.md's "Interfaces" section, matching the
// malformed-cursor response GET /api/v1/admin/audit gives.
func (s *Service) handleInvitesList(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	subject, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		server.WriteError(w, r, deps.Logger, unauthenticatedError())

		return
	}

	all := subject.HasPermission(authz.PermissionInviteManage)
	cursor := r.URL.Query().Get("cursor")

	invites, nextCursor, err := s.inviteService.List(r.Context(), subject.UserID, all, cursor, 0)
	if err != nil {
		if errors.Is(err, invite.ErrInvalidCursor) {
			server.WriteError(w, r, deps.Logger, invalidRequestError())

			return
		}

		deps.Logger.Error("auth: listing invites", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	now := s.now()
	entries := make([]inviteResponse, 0, len(invites))

	for _, inv := range invites {
		entries = append(entries, inviteToResponse(inv, now))
	}

	var nextCursorPtr *string
	if nextCursor != "" {
		nextCursorPtr = &nextCursor
	}

	server.WriteJSON(w, deps.Logger, http.StatusOK, invitesResponse{Invites: entries, NextCursor: nextCursorPtr})
}

// handleInvitesGet answers GET /api/v1/invites/{id}, returning one invite
// scoped to the caller unless they hold PermissionInviteManage. An
// unparseable id, and another account's invite when the caller lacks that
// permission, both answer 404, so the route never confirms that an invite
// exists.
func (s *Service) handleInvitesGet(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	subject, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		server.WriteError(w, r, deps.Logger, unauthenticatedError())

		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		server.WriteError(w, r, deps.Logger, notFoundError())

		return
	}

	all := subject.HasPermission(authz.PermissionInviteManage)

	inv, err := s.inviteService.Get(r.Context(), id, subject.UserID, all)
	if err != nil {
		if errors.Is(err, invite.ErrInvalid) {
			server.WriteError(w, r, deps.Logger, notFoundError())

			return
		}

		deps.Logger.Error("auth: loading invite", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	server.WriteJSON(w, deps.Logger, http.StatusOK, inviteToResponse(inv, s.now()))
}

// handleInvitesDelete answers DELETE /api/v1/invites/{id}, revoking the named
// invite. It looks the invite up with the
// same ownership predicate first: Revoke's own bool return cannot
// distinguish "already revoked" from "not yours", so a Get failure answers
// 404 and leaves another account's invite untouched, while any outcome for
// the caller's own invite, revoked now or already revoked earlier, answers
// 204. An unparseable id also answers 404.
func (s *Service) handleInvitesDelete(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	subject, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		server.WriteError(w, r, deps.Logger, unauthenticatedError())

		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		server.WriteError(w, r, deps.Logger, notFoundError())

		return
	}

	all := subject.HasPermission(authz.PermissionInviteManage)

	if _, getErr := s.inviteService.Get(r.Context(), id, subject.UserID, all); getErr != nil {
		if errors.Is(getErr, invite.ErrInvalid) {
			server.WriteError(w, r, deps.Logger, notFoundError())

			return
		}

		deps.Logger.Error("auth: loading invite for revocation", zap.Error(getErr))
		server.WriteError(w, r, deps.Logger, getErr)

		return
	}

	revoked, err := s.inviteService.Revoke(r.Context(), id, subject.UserID, all)
	if err != nil {
		deps.Logger.Error("auth: revoking invite", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	if revoked {
		s.recordAudit(r.Context(), audit.ActionInviteRevoked, &subject.UserID, "invite:"+id.String(), audit.OutcomeSuccess,
			deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()), nil)
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleInviteRedeem answers the merged GET /i/{file} route. Go's ServeMux
// requires a wildcard to occupy an entire path segment, so the two documented
// literal patterns, "GET /i/{token}" and "GET /i/{token}.png", cannot both
// be registered: the second panics at registration ("bad wildcard segment"),
// and registering "GET /i/{token}" alongside a second wildcard pattern over
// the same segment ("GET /i/{file}") panics as a conflicting pattern. This
// single route dispatches on a ".png" suffix instead, which is the smallest
// change that preserves both documented behaviors.
func (s *Service) handleInviteRedeem(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	file := r.PathValue("file")

	if token, isPNG := strings.CutSuffix(file, ".png"); isPNG {
		s.handleInviteQR(w, r, deps, token)

		return
	}

	s.handleInviteLanding(w, r, deps, file)
}

// handleInviteQR answers the QR-image half of GET /i/{file}: it performs no
// lookup and no validation whatsoever, per design.md's "Interfaces"
// section, so it is neither an oracle for which tokens exist nor a way to
// spend database work without a session.
func (*Service) handleInviteQR(w http.ResponseWriter, r *http.Request, deps RouteDeps, token string) {
	scale := defaultQRScale

	if raw := r.URL.Query().Get("scale"); raw != "" {
		if parsed, parseErr := strconv.Atoi(raw); parseErr == nil {
			scale = parsed
		}
	}

	png, err := invite.QR(deps.PublicOrigin+"/i/"+token, scale)
	if err != nil {
		deps.Logger.Error("auth: encoding invite qr code", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Type", "image/png")
	w.WriteHeader(http.StatusOK)

	if _, writeErr := w.Write(png); writeErr != nil { //nolint:gosec // G705: png is bytes invite.QR rendered from a path segment, not attacker-controlled HTML or script; Content-Type is set to image/png above
		deps.Logger.Error("auth: writing invite qr response", zap.Error(writeErr))
	}
}

// handleInviteLanding answers the redemption half of GET /i/{file}: a live
// invite redirects to the landing page with the token carried as a query
// parameter, and anything else, unknown, expired, spent, or revoked,
// redirects to the same page with a generic error, never distinguishing
// which.
func (s *Service) handleInviteLanding(w http.ResponseWriter, r *http.Request, deps RouteDeps, token string) {
	if _, err := s.inviteService.Lookup(r.Context(), token); err != nil {
		if errors.Is(err, invite.ErrInvalid) {
			http.Redirect(w, r, "/?error="+server.ErrorCodeInviteInvalid, http.StatusSeeOther)

			return
		}

		// This route answers plain text, never JSON, on an infrastructure
		// failure: it is reached from a browser navigation rather than an
		// API client, so a JSON error document here would be shown to a
		// person instead of parsed by code. server.WriteError always writes
		// application/json, which is why this branch calls http.Error
		// directly rather than going through it.
		deps.Logger.Error("auth: looking up invite for redemption landing", zap.Error(err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

	http.Redirect(w, r, "/?invite="+url.QueryEscape(token), http.StatusSeeOther)
}
