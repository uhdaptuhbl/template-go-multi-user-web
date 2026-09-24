package auth

import (
	"net/http"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/audit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
)

// notPendingError returns the fixed 409 not_pending ClientError the approve
// and reject routes answer with when the target account's current status is
// not pending.
func notPendingError() *server.ClientError {
	return &server.ClientError{
		Status:  http.StatusConflict,
		Code:    server.ErrorCodeNotPending,
		Message: "account is not awaiting approval",
	}
}

// handleAdminUsersApprove answers POST /api/v1/admin/users/{id}/approve,
// moving a pending account to active through user.Repository.Approve, which
// matches only rows still pending. A false return means the row was not
// pending, including one another administrator approved a moment earlier,
// which this handler answers as 409 not_pending rather than distinguishing
// the two.
func (s *Service) handleAdminUsersApprove(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
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

	approved, err := deps.Users.Approve(r.Context(), targetID)
	if err != nil {
		deps.Logger.Error("auth: approving account", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	if !approved {
		server.WriteError(w, r, deps.Logger, notPendingError())

		return
	}

	s.recordAudit(r.Context(), audit.ActionUserApproved, &subject.UserID, "user:"+targetID.String(), audit.OutcomeSuccess,
		deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()), nil)

	writeApprovalOutcome(w, r, deps, targetID)
}

// handleAdminUsersReject answers POST /api/v1/admin/users/{id}/reject,
// moving a pending account to deleted through user.Repository.Reject, which
// matches only rows still pending: SoftDelete carries no such predicate and
// would otherwise let this route delete an account of any status, so Reject
// exists specifically to keep rejection pending-only. A false return means
// the row was not pending and this handler answers 409 not_pending, changing
// nothing.
func (s *Service) handleAdminUsersReject(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
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

	rejected, err := deps.Users.Reject(r.Context(), targetID)
	if err != nil {
		deps.Logger.Error("auth: rejecting account", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	if !rejected {
		server.WriteError(w, r, deps.Logger, notPendingError())

		return
	}

	s.recordAudit(r.Context(), audit.ActionUserRejected, &subject.UserID, "user:"+targetID.String(), audit.OutcomeSuccess,
		deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()), nil)

	writeApprovalOutcome(w, r, deps, targetID)
}

// writeApprovalOutcome loads targetID's account by ByIDAnyStatus, since a
// rejection has just moved it to deleted status which the ordinary ByID
// excludes, and answers 200 with the GET /api/v1/me shape minus permissions,
// exactly as approve and reject both do per design.md's "Interfaces"
// section.
func writeApprovalOutcome(w http.ResponseWriter, r *http.Request, deps RouteDeps, targetID uuid.UUID) {
	account, err := deps.Users.ByIDAnyStatus(r.Context(), targetID)
	if err != nil {
		deps.Logger.Error("auth: loading account after approval decision", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	roles, err := deps.Roles.RolesFor(r.Context(), targetID)
	if err != nil {
		deps.Logger.Error("auth: loading roles after approval decision", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	server.WriteJSON(w, deps.Logger, http.StatusOK, accountResponse{
		ID:            account.ID,
		DisplayName:   account.DisplayName,
		Email:         account.Email,
		EmailVerified: account.EmailVerifiedAt != nil,
		Status:        string(account.Status),
		Roles:         roles,
		CreatedAt:     account.CreatedAt,
	})
}
