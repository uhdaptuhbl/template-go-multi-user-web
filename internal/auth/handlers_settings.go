package auth

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/audit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/settings"
)

// settingLockedError returns the fixed 409 setting_locked ClientError
// PATCH /api/v1/admin/settings answers with when the update names a setting
// the environment has overridden.
func settingLockedError() *server.ClientError {
	return &server.ClientError{
		Status:  http.StatusConflict,
		Code:    server.ErrorCodeSettingLocked,
		Message: "setting locked by the environment",
	}
}

// settingsResponse is GET and PATCH /api/v1/admin/settings' response shape.
// Locked is always present as an array, never null, so a client need not
// special-case an empty one.
type settingsResponse struct {
	SignupEnabled         bool      `json:"signup_enabled"`
	SignupRequireInvite   bool      `json:"signup_require_invite"`
	SignupRequireApproval bool      `json:"signup_require_approval"`
	InviteDefaultQuota    int       `json:"invite_default_quota"`
	InviteDefaultTTLSecs  int       `json:"invite_default_ttl_secs"`
	InviteMaxUsesLimit    int       `json:"invite_max_uses_limit"`
	UpdatedAt             time.Time `json:"updated_at"`
	UpdatedByRef          string    `json:"updated_by_ref"`
	Locked                []string  `json:"locked"`
}

// settingsToResponse builds the response shape from a settings.Settings row
// and the store's own locked list.
func settingsToResponse(pol settings.Settings, locked []string) settingsResponse {
	return settingsResponse{
		SignupEnabled:         pol.SignupEnabled,
		SignupRequireInvite:   pol.SignupRequireInvite,
		SignupRequireApproval: pol.SignupRequireApproval,
		InviteDefaultQuota:    pol.InviteDefaultQuota,
		InviteDefaultTTLSecs:  pol.InviteDefaultTTLSecs,
		InviteMaxUsesLimit:    pol.InviteMaxUsesLimit,
		UpdatedAt:             pol.UpdatedAt,
		UpdatedByRef:          pol.UpdatedByRef,
		Locked:                locked,
	}
}

// settingsUpdateIsEmpty reports whether every field of u is nil, which means
// the request body named no key this type recognises: an absent key is
// ordinarily "leave it alone", but a PATCH that leaves every field alone
// changed nothing and is refused as invalid_request rather than silently
// answered as a no-op 200.
func settingsUpdateIsEmpty(u settings.Update) bool {
	return u.SignupEnabled == nil &&
		u.SignupRequireInvite == nil &&
		u.SignupRequireApproval == nil &&
		u.InviteDefaultQuota == nil &&
		u.InviteDefaultTTLSecs == nil &&
		u.InviteMaxUsesLimit == nil
}

// changedSettingsDetail builds the audit detail settings.updated carries,
// naming only the keys u actually changed and their new values. It carries
// no old values: an audit log is not a diff store, and the previous value is
// the previous audit row.
func changedSettingsDetail(u settings.Update) map[string]any {
	detail := map[string]any{}

	if u.SignupEnabled != nil {
		detail["signup_enabled"] = *u.SignupEnabled
	}

	if u.SignupRequireInvite != nil {
		detail["signup_require_invite"] = *u.SignupRequireInvite
	}

	if u.SignupRequireApproval != nil {
		detail["signup_require_approval"] = *u.SignupRequireApproval
	}

	if u.InviteDefaultQuota != nil {
		detail["invite_default_quota"] = *u.InviteDefaultQuota
	}

	if u.InviteDefaultTTLSecs != nil {
		detail["invite_default_ttl_secs"] = *u.InviteDefaultTTLSecs
	}

	if u.InviteMaxUsesLimit != nil {
		detail["invite_max_uses_limit"] = *u.InviteMaxUsesLimit
	}

	return detail
}

// handleAdminSettingsGet answers GET /api/v1/admin/settings with the current
// runtime policy and the environment's locked settings.
func (s *Service) handleAdminSettingsGet(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	pol, err := s.policy.Load(r.Context())
	if err != nil {
		deps.Logger.Error("auth: loading settings", zap.Error(err))
		server.WriteError(w, r, deps.Logger, err)

		return
	}

	server.WriteJSON(w, deps.Logger, http.StatusOK, settingsToResponse(pol, s.policy.Locked()))
}

// handleAdminSettingsPatch answers PATCH /api/v1/admin/settings, decoding
// into settings.Update so an absent key means "leave it alone" and an
// explicit false is distinguishable from absence. ErrLocked answers 409
// setting_locked and ErrInvalidValue answers 400 invalid_request; on success
// it records settings.updated naming the changed keys and their new values.
func (s *Service) handleAdminSettingsPatch(w http.ResponseWriter, r *http.Request, deps RouteDeps) {
	subject, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		server.WriteError(w, r, deps.Logger, unauthenticatedError())

		return
	}

	var req settings.Update
	if !decodeBody(w, r, deps.Logger, &req) {
		return
	}

	if settingsUpdateIsEmpty(req) {
		server.WriteError(w, r, deps.Logger, invalidRequestError())

		return
	}

	actorRef := "user:" + subject.UserID.String()

	updated, err := s.policy.Apply(r.Context(), req, uuid.NullUUID{UUID: subject.UserID, Valid: true}, actorRef)
	if err != nil {
		switch {
		case errors.Is(err, settings.ErrLocked):
			server.WriteError(w, r, deps.Logger, settingLockedError())
		case errors.Is(err, settings.ErrInvalidValue):
			server.WriteError(w, r, deps.Logger, invalidRequestError())
		default:
			deps.Logger.Error("auth: applying settings update", zap.Error(err))
			server.WriteError(w, r, deps.Logger, err)
		}

		return
	}

	s.recordAudit(r.Context(), audit.ActionSettingsUpdated, &subject.UserID, "settings:global", audit.OutcomeSuccess,
		deps.Proxies.ClientIP(r), server.RequestIDFromContext(r.Context()), s.auditDetail(changedSettingsDetail(req)))

	server.WriteJSON(w, deps.Logger, http.StatusOK, settingsToResponse(updated, s.policy.Locked()))
}
