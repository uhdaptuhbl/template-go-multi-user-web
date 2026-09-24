package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
)

// TestWriteJSONError covers AC-002.1, AC-002.4, and AC-002.21.
func TestWriteJSONError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   int
		code     string
		message  string
		wantBody string
	}{
		{
			name:     "internal error",
			status:   http.StatusInternalServerError,
			code:     errorCodeInternal,
			message:  "",
			wantBody: `{"errors":[{"status":"500","code":"internal","title":"Internal server error"}]}`,
		},
		{
			name:     "payload too large",
			status:   http.StatusRequestEntityTooLarge,
			code:     errorCodePayloadTooLarge,
			message:  "",
			wantBody: `{"errors":[{"status":"413","code":"payload_too_large","title":"Request body too large"}]}`,
		},
		{
			name:     "overloaded",
			status:   http.StatusServiceUnavailable,
			code:     errorCodeOverloaded,
			message:  "",
			wantBody: `{"errors":[{"status":"503","code":"overloaded","title":"Server overloaded"}]}`,
		},
		{
			// A detail that says more than the title survives; the title
			// names the kind of failure and the detail names this one.
			name:     "detail that adds something",
			status:   http.StatusBadRequest,
			code:     errorCodeInvalidBody,
			message:  `field "age" must be a JSON number`,
			wantBody: `{"errors":[{"status":"400","code":"invalid_body","title":"Invalid request body","detail":"field \"age\" must be a JSON number"}]}`,
		},
		{
			// A detail that only restates the title is dropped rather than
			// sent twice under two member names.
			name:     "detail that restates the title",
			status:   http.StatusServiceUnavailable,
			code:     errorCodeOverloaded,
			message:  "Server Overloaded",
			wantBody: `{"errors":[{"status":"503","code":"overloaded","title":"Server overloaded"}]}`,
		},
		{
			// A code nobody gave a title to still produces a well-formed
			// document, with the code standing in.
			name:     "code with no title",
			status:   http.StatusTeapot,
			code:     "no_such_code",
			message:  "",
			wantBody: `{"errors":[{"status":"418","code":"no_such_code","title":"no_such_code"}]}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()

			writeJSONError(recorder, zap.NewNop(), test.status, test.code, test.message)

			if got := recorder.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("got Content-Type %q, want %q", got, "application/json")
			}

			got := strings.TrimSpace(recorder.Body.String())
			if diff := cmp.Diff(test.wantBody, got); diff != "" {
				t.Errorf("body mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestWriteJSONErrorAuthCodes covers AC-008.33, AC-008.34, and AC-008.42.
func TestWriteJSONErrorAuthCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   int
		code     string
		message  string
		wantBody string
	}{
		{
			name:     "invalid request",
			status:   http.StatusBadRequest,
			code:     ErrorCodeInvalidRequest,
			message:  "",
			wantBody: `{"errors":[{"status":"400","code":"invalid_request","title":"Invalid request"}]}`,
		},
		{
			name:     "unauthenticated",
			status:   http.StatusUnauthorized,
			code:     ErrorCodeUnauthenticated,
			message:  "",
			wantBody: `{"errors":[{"status":"401","code":"unauthenticated","title":"Authentication required"}]}`,
		},
		{
			// The detail restates the title case-insensitively and is
			// dropped rather than sent twice under two member names.
			name:     "forbidden with detail that restates the title",
			status:   http.StatusForbidden,
			code:     ErrorCodeForbidden,
			message:  "permission denied",
			wantBody: `{"errors":[{"status":"403","code":"forbidden","title":"Permission denied"}]}`,
		},
		{
			name:     "cross site",
			status:   http.StatusForbidden,
			code:     ErrorCodeCrossSite,
			message:  "",
			wantBody: `{"errors":[{"status":"403","code":"cross_site","title":"Cross-site request rejected"}]}`,
		},
		{
			name:     "not found",
			status:   http.StatusNotFound,
			code:     ErrorCodeNotFound,
			message:  "",
			wantBody: `{"errors":[{"status":"404","code":"not_found","title":"Not found"}]}`,
		},
		{
			name:     "conflict",
			status:   http.StatusConflict,
			code:     ErrorCodeConflict,
			message:  "",
			wantBody: `{"errors":[{"status":"409","code":"conflict","title":"Request conflicts with current state"}]}`,
		},
		{
			name:     "rate limited",
			status:   http.StatusTooManyRequests,
			code:     ErrorCodeRateLimited,
			message:  "",
			wantBody: `{"errors":[{"status":"429","code":"rate_limited","title":"Too many requests"}]}`,
		},
		{
			name:     "unavailable",
			status:   http.StatusServiceUnavailable,
			code:     ErrorCodeUnavailable,
			message:  "",
			wantBody: `{"errors":[{"status":"503","code":"unavailable","title":"Service unavailable"}]}`,
		},
		{
			name:     "signup disabled",
			status:   http.StatusForbidden,
			code:     ErrorCodeSignupDisabled,
			message:  "",
			wantBody: `{"errors":[{"status":"403","code":"signup_disabled","title":"Signup disabled"}]}`,
		},
		{
			name:     "invite required",
			status:   http.StatusForbidden,
			code:     ErrorCodeInviteRequired,
			message:  "",
			wantBody: `{"errors":[{"status":"403","code":"invite_required","title":"Invite required"}]}`,
		},
		{
			name:     "invite invalid",
			status:   http.StatusForbidden,
			code:     ErrorCodeInviteInvalid,
			message:  "",
			wantBody: `{"errors":[{"status":"403","code":"invite_invalid","title":"Invite invalid"}]}`,
		},
		{
			name:     "invite email mismatch",
			status:   http.StatusForbidden,
			code:     ErrorCodeInviteEmailMismatch,
			message:  "",
			wantBody: `{"errors":[{"status":"403","code":"invite_email_mismatch","title":"Invite address mismatch"}]}`,
		},
		{
			name:     "approval pending",
			status:   http.StatusForbidden,
			code:     ErrorCodeApprovalPending,
			message:  "",
			wantBody: `{"errors":[{"status":"403","code":"approval_pending","title":"Account awaiting approval"}]}`,
		},
		{
			name:     "invite quota exhausted",
			status:   http.StatusConflict,
			code:     ErrorCodeInviteQuotaExhausted,
			message:  "",
			wantBody: `{"errors":[{"status":"409","code":"invite_quota_exhausted","title":"Invite quota exhausted"}]}`,
		},
		{
			name:     "setting locked",
			status:   http.StatusConflict,
			code:     ErrorCodeSettingLocked,
			message:  "",
			wantBody: `{"errors":[{"status":"409","code":"setting_locked","title":"Setting locked by the environment"}]}`,
		},
		{
			name:     "not pending",
			status:   http.StatusConflict,
			code:     ErrorCodeNotPending,
			message:  "",
			wantBody: `{"errors":[{"status":"409","code":"not_pending","title":"Account is not awaiting approval"}]}`,
		},
		{
			name:     "is pending",
			status:   http.StatusConflict,
			code:     ErrorCodeIsPending,
			message:  "",
			wantBody: `{"errors":[{"status":"409","code":"is_pending","title":"Account is awaiting approval"}]}`,
		},
		{
			// A detail that adds something beyond the title survives.
			name:     "forbidden with detail that adds something",
			status:   http.StatusForbidden,
			code:     ErrorCodeForbidden,
			message:  "route requires the admin role",
			wantBody: `{"errors":[{"status":"403","code":"forbidden","title":"Permission denied","detail":"route requires the admin role"}]}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()

			writeJSONError(recorder, zap.NewNop(), test.status, test.code, test.message)

			if got := recorder.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("got Content-Type %q, want %q", got, "application/json")
			}

			got := strings.TrimSpace(recorder.Body.String())
			if diff := cmp.Diff(test.wantBody, got); diff != "" {
				t.Errorf("body mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
