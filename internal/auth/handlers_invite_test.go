//go:build integration

package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/audit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/invite"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/ratelimit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/settings"
)

// newInviteMember logs a fresh account in through the real signup path,
// returning its id and session token, exactly as issueSession does; it
// exists as a named wrapper only so this file's tests read as "a member",
// matching the vocabulary the rest of this file uses.
func newInviteMember(t *testing.T, deps testDeps, subject string) (string, string) {
	t.Helper()

	id, token := issueSession(t, deps, subject)

	return id.String(), token
}

// stripRoles removes every role from userID, so a test can exercise a caller
// that holds none of the permissions RoleMember would otherwise carry.
func stripRoles(t *testing.T, deps testDeps, userID string) {
	t.Helper()

	id := mustParseUUID(t, userID)

	if err := deps.roles.SetRoles(t.Context(), id, []string{}, id); err != nil {
		t.Fatalf("SetRoles() error = %v", err)
	}
}

// mustParseUUID parses s as a UUID, failing the test on error.
func mustParseUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()

	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("uuid.Parse(%q) error = %v", s, err)
	}

	return id
}

// TestInviteAndAdminRoutes_Unauthenticated_Return401 covers AC-008.34: every
// route this unit adds under /api/v1/ answers 401 unauthenticated without a
// session cookie.
func TestInviteAndAdminRoutes_Unauthenticated_Return401(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{name: "create invite", method: http.MethodPost, path: "/api/v1/invites"},
		{name: "list invites", method: http.MethodGet, path: "/api/v1/invites"},
		{name: "get invite", method: http.MethodGet, path: "/api/v1/invites/00000000-0000-0000-0000-000000000000"},
		{name: "delete invite", method: http.MethodDelete, path: "/api/v1/invites/00000000-0000-0000-0000-000000000000"},
		{name: "approve", method: http.MethodPost, path: "/api/v1/admin/users/00000000-0000-0000-0000-000000000000/approve"},
		{name: "reject", method: http.MethodPost, path: "/api/v1/admin/users/00000000-0000-0000-0000-000000000000/reject"},
		{name: "get settings", method: http.MethodGet, path: "/api/v1/admin/settings"},
		{name: "patch settings", method: http.MethodPatch, path: "/api/v1/admin/settings"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(tt.method, "https://service.example"+tt.path, http.NoBody)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestHandleInvitesCreate_Forbidden_WithoutInviteCreatePermission covers
// AC-008.62: a caller whose roles carry no permission at all is refused 403
// rather than reaching the quota check.
func TestHandleInvitesCreate_Forbidden_WithoutInviteCreatePermission(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	memberID, token := newInviteMember(t, deps, "sub-invite-forbidden")
	stripRoles(t, deps, memberID)

	req := acctReqBody(t, http.MethodPost, "/api/v1/invites", token, `{}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

// TestHandleInvitesCreate_QuotaExhausted_ReturnsConflict covers AC-008.66: a
// member at the seeded default quota of zero cannot create any invite.
func TestHandleInvitesCreate_QuotaExhausted_ReturnsConflict(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	_, token := newInviteMember(t, deps, "sub-invite-quota")

	req := acctReqBody(t, http.MethodPost, "/api/v1/invites", token, `{}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}

	wantBody := `{"errors":[{"status":"409","code":"invite_quota_exhausted","title":"Invite quota exhausted"}]}`
	if got := exactErrorBody(rec); got != wantBody {
		t.Fatalf("body = %s, want %s", got, wantBody)
	}
}

// TestHandleInvitesCreate_AdminHoldingInviteManage_BypassesQuota covers AC-008.66:
// a caller holding invite.manage is exempt from
// the configured default quota, while an ordinary member at the same
// (zero) quota is still refused, checked side by side against the same
// zero-quota policy so the difference is attributable to the permission
// alone.
func TestHandleInvitesCreate_AdminHoldingInviteManage_BypassesQuota(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin-invite-quota@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	_, memberToken := newInviteMember(t, deps, "sub-invite-quota-member")

	adminIn := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-invite-quota-admin",
		Email:         "admin-invite-quota@example.com",
		EmailVerified: true,
		DisplayName:   "Admin",
		Methods:       []string{session.MethodOIDC},
	}
	_, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-invite-quota-admin", "")
	if err != nil {
		t.Fatalf("LogIn() admin error = %v", err)
	}

	memberRec := httptest.NewRecorder()
	handler.ServeHTTP(memberRec, acctReqBody(t, http.MethodPost, "/api/v1/invites", memberToken, `{}`))

	if memberRec.Code != http.StatusConflict {
		t.Fatalf("member status = %d, want 409, body = %s", memberRec.Code, memberRec.Body.String())
	}

	adminRec := httptest.NewRecorder()
	handler.ServeHTTP(adminRec, acctReqBody(t, http.MethodPost, "/api/v1/invites", adminToken, `{}`))

	if adminRec.Code != http.StatusCreated {
		t.Fatalf("admin status = %d, want 201, body = %s", adminRec.Code, adminRec.Body.String())
	}
}

// TestHandleInvitesCreate_Success_ReturnsTokenURLAndQRURL covers AC-008.62
// and AC-008.63: once the quota is raised, creating an invite answers 201
// and the body carries token, url, and qr_url built from the configured
// public origin. The request's Host header is deliberately set to something
// other than testPublicOriginForRoutes's host, so a handler that built the
// URL from r.Host instead of deps.PublicOrigin would be caught here rather
// than passing by coincidence.
func TestHandleInvitesCreate_Success_ReturnsTokenURLAndQRURL(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{InviteDefaultQuota: new(5)})

	_, token := newInviteMember(t, deps, "sub-invite-success")

	req := acctReqBody(t, http.MethodPost, "/api/v1/invites", token, `{"note":"cousin","max_uses":3}`)
	req.Host = "attacker.example"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}

	var body inviteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	if body.Token == "" {
		t.Fatal("body.Token is empty, want the issued token")
	}

	wantURL := testPublicOriginForRoutes + "/i/" + body.Token
	if body.URL != wantURL {
		t.Fatalf("body.URL = %q, want %q", body.URL, wantURL)
	}

	wantQRURL := testPublicOriginForRoutes + "/i/" + body.Token + ".png"
	if body.QRURL != wantQRURL {
		t.Fatalf("body.QRURL = %q, want %q", body.QRURL, wantQRURL)
	}

	if body.MaxUses != 3 {
		t.Fatalf("body.MaxUses = %d, want 3", body.MaxUses)
	}

	if body.State != "live" {
		t.Fatalf("body.State = %q, want %q", body.State, "live")
	}
}

// TestHandleInvitesGet_BodyExcludesTokenURLAndQRURL covers AC-008.63: once
// an invite is created, reading it back never carries its token, url, or
// qr_url, checked by searching the raw response bytes for the token value
// rather than trusting the JSON decoder to catch an accidental field.
func TestHandleInvitesGet_BodyExcludesTokenURLAndQRURL(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{InviteDefaultQuota: new(5)})

	_, token := newInviteMember(t, deps, "sub-invite-get")

	created := createInviteViaHTTP(t, handler, token, `{}`)

	getReq := acctReq(t, http.MethodGet, "/api/v1/invites/"+created.ID.String(), token)
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", getRec.Code, getRec.Body.String())
	}

	if bytes.Contains(getRec.Body.Bytes(), []byte(created.Token)) {
		t.Fatalf("GET response contains the invite token: %s", getRec.Body.String())
	}

	if bytes.Contains(getRec.Body.Bytes(), []byte(`"url"`)) || bytes.Contains(getRec.Body.Bytes(), []byte(`"qr_url"`)) {
		t.Fatalf("GET response carries url or qr_url: %s", getRec.Body.String())
	}
}

// createInviteViaHTTP issues a POST /api/v1/invites request as token's
// caller and returns the decoded response, failing the test on anything
// other than 201.
func createInviteViaHTTP(t *testing.T, handler http.Handler, token, body string) inviteResponse {
	t.Helper()

	req := acctReqBody(t, http.MethodPost, "/api/v1/invites", token, body)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create invite status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}

	var resp inviteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding create response: %v", err)
	}

	return resp
}

// TestHandleInvitesList_MemberSeesOwnAdminSeesAll covers AC-008.67 and the
// ownership predicate (design.md's "Authorization path"): a member's
// listing carries only their own invites, while an admin holding
// invite.manage sees every issuer's.
func TestHandleInvitesList_MemberSeesOwnAdminSeesAll(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin-invite-list@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{InviteDefaultQuota: new(5), SignupEnabled: new(true), SignupRequireInvite: new(false)})

	_, tokenA := newInviteMember(t, deps, "sub-invite-list-a")
	_, tokenB := newInviteMember(t, deps, "sub-invite-list-b")

	invA := createInviteViaHTTP(t, handler, tokenA, `{}`)
	invB := createInviteViaHTTP(t, handler, tokenB, `{}`)

	adminIn := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-invite-list-admin",
		Email:         "admin-invite-list@example.com",
		EmailVerified: true,
		DisplayName:   "Admin",
		Methods:       []string{session.MethodOIDC},
	}
	_, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-invite-list-admin", "")
	if err != nil {
		t.Fatalf("LogIn() admin error = %v", err)
	}

	memberListRec := httptest.NewRecorder()
	handler.ServeHTTP(memberListRec, acctReq(t, http.MethodGet, "/api/v1/invites", tokenA))

	var memberList invitesResponse
	if unmarshalErr := json.Unmarshal(memberListRec.Body.Bytes(), &memberList); unmarshalErr != nil {
		t.Fatalf("decoding member list: %v", unmarshalErr)
	}

	if len(memberList.Invites) != 1 || memberList.Invites[0].ID != invA.ID {
		t.Fatalf("member list = %+v, want exactly [%s]", memberList.Invites, invA.ID)
	}

	adminListRec := httptest.NewRecorder()
	handler.ServeHTTP(adminListRec, acctReq(t, http.MethodGet, "/api/v1/invites", adminToken))

	var adminList invitesResponse
	if unmarshalErr := json.Unmarshal(adminListRec.Body.Bytes(), &adminList); unmarshalErr != nil {
		t.Fatalf("decoding admin list: %v", unmarshalErr)
	}

	if len(adminList.Invites) != 2 {
		t.Fatalf("admin list length = %d, want 2 (both %s and %s)", len(adminList.Invites), invA.ID, invB.ID)
	}
}

// TestHandleInvitesList_MalformedCursor_ReturnsExact400Body covers AC-008.67
// and design.md's "Interfaces" section: a cursor that is not a UUID answers
// 400 invalid_request, with the same body GET /api/v1/admin/audit gives
// its own malformed cursor, rather than 500.
func TestHandleInvitesList_MalformedCursor_ReturnsExact400Body(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{InviteDefaultQuota: new(5), SignupEnabled: new(true), SignupRequireInvite: new(false)})

	_, token := newInviteMember(t, deps, "sub-invite-list-malformed-cursor")

	req := acctReq(t, http.MethodGet, "/api/v1/invites", token)
	req.URL.RawQuery = "cursor=not-a-uuid"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}

	want := `{"errors":[{"status":"400","code":"invalid_request","title":"Invalid request"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

// TestHandleInvitesGet_AnotherMembersInvite_Returns404AndOwnerSucceeds
// covers the ownership predicate (design.md's "Authorization path"): a
// member requesting another member's invite by id gets 404, and the
// invite's own owner can still read it, which is the "both halves"
// isolation check the ownership predicate requires rather than a bare
// "returns not found".
// Covers AC-008.35 and AC-008.67.
func TestHandleInvitesGet_AnotherMembersInvite_Returns404AndOwnerSucceeds(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{InviteDefaultQuota: new(5)})

	_, ownerToken := newInviteMember(t, deps, "sub-invite-isolation-owner")
	_, otherToken := newInviteMember(t, deps, "sub-invite-isolation-other")

	owned := createInviteViaHTTP(t, handler, ownerToken, `{}`)

	otherRec := httptest.NewRecorder()
	handler.ServeHTTP(otherRec, acctReq(t, http.MethodGet, "/api/v1/invites/"+owned.ID.String(), otherToken))

	if otherRec.Code != http.StatusNotFound {
		t.Fatalf("other member status = %d, want 404, body = %s", otherRec.Code, otherRec.Body.String())
	}

	ownerRec := httptest.NewRecorder()
	handler.ServeHTTP(ownerRec, acctReq(t, http.MethodGet, "/api/v1/invites/"+owned.ID.String(), ownerToken))

	if ownerRec.Code != http.StatusOK {
		t.Fatalf("owner status = %d, want 200, body = %s", ownerRec.Code, ownerRec.Body.String())
	}
}

// TestHandleInvitesDelete_AnotherMembersInvite_Returns404AndLeavesLive
// covers AC-008.67: revoking another member's invite by id
// answers 404 and leaves it live, and the owner can revoke it afterward,
// which is the "both halves" check.
func TestHandleInvitesDelete_AnotherMembersInvite_Returns404AndLeavesLive(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{InviteDefaultQuota: new(5)})

	_, ownerToken := newInviteMember(t, deps, "sub-invite-delete-owner")
	_, otherToken := newInviteMember(t, deps, "sub-invite-delete-other")

	owned := createInviteViaHTTP(t, handler, ownerToken, `{}`)

	otherRec := httptest.NewRecorder()
	handler.ServeHTTP(otherRec, acctReq(t, http.MethodDelete, "/api/v1/invites/"+owned.ID.String(), otherToken))

	if otherRec.Code != http.StatusNotFound {
		t.Fatalf("other member status = %d, want 404, body = %s", otherRec.Code, otherRec.Body.String())
	}

	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, acctReq(t, http.MethodGet, "/api/v1/invites/"+owned.ID.String(), ownerToken))

	var stillLive inviteResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &stillLive); err != nil {
		t.Fatalf("decoding get after other's delete attempt: %v", err)
	}

	if stillLive.State != "live" {
		t.Fatalf("invite state after other member's failed delete = %q, want %q", stillLive.State, "live")
	}

	ownerRec := httptest.NewRecorder()
	handler.ServeHTTP(ownerRec, acctReq(t, http.MethodDelete, "/api/v1/invites/"+owned.ID.String(), ownerToken))

	if ownerRec.Code != http.StatusNoContent {
		t.Fatalf("owner delete status = %d, want 204, body = %s", ownerRec.Code, ownerRec.Body.String())
	}
}

// TestHandleInvitesDelete_OwnInvite_TwiceBothReturn204 covers AC-008.67:
// revoking an invite is idempotent, so a second delete of the same invite
// also answers 204 rather than 404 or 409.
func TestHandleInvitesDelete_OwnInvite_TwiceBothReturn204(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{InviteDefaultQuota: new(5)})

	_, token := newInviteMember(t, deps, "sub-invite-delete-twice")
	owned := createInviteViaHTTP(t, handler, token, `{}`)

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, acctReq(t, http.MethodDelete, "/api/v1/invites/"+owned.ID.String(), token))

	if first.Code != http.StatusNoContent {
		t.Fatalf("first delete status = %d, want 204, body = %s", first.Code, first.Body.String())
	}

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, acctReq(t, http.MethodDelete, "/api/v1/invites/"+owned.ID.String(), token))

	if second.Code != http.StatusNoContent {
		t.Fatalf("second delete status = %d, want 204, body = %s", second.Code, second.Body.String())
	}
}

// TestHandleInviteRedeem_LiveToken_Redirects303WithInviteParam covers
// AC-008.68: GET /i/{token} for a live invite redirects to /?invite=<token>.
func TestHandleInviteRedeem_LiveToken_Redirects303WithInviteParam(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	issuerID, _ := newInviteMember(t, deps, "sub-invite-redeem-live")
	issuer := mustParseUUID(t, issuerID)

	issued, err := deps.invites.Create(t.Context(), issuer, "user:"+issuerID, true, invite.Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("invites.Create() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://service.example/i/"+issued.Token, http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303, body = %s", rec.Code, rec.Body.String())
	}

	wantLocation := "/?invite=" + issued.Token
	if got := rec.Header().Get("Location"); got != wantLocation {
		t.Fatalf("Location = %q, want %q", got, wantLocation)
	}
}

// TestHandleInviteRedeem_ThroughNewMux_NeverLogsTheToken cites AC-008.40 (the
// system SHALL NOT write a session token, an email code, a provider client
// secret, or any other secret to a log): GET /i/{token} carries its bearer
// token in the request path itself, so it has to go through server.NewMux
// rather than the bare mux newAuthedMux builds, to prove the redaction this
// unit's route registration applies actually keeps the token out of every
// log field an observed logger sees.
func TestHandleInviteRedeem_ThroughNewMux_NeverLogsTheToken(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	routeDeps := newTestRouteDeps(t, deps, false)

	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)
	routeDeps.Logger = logger

	issuerID, _ := newInviteMember(t, deps, "sub-invite-redact")
	issuer := mustParseUUID(t, issuerID)

	issued, err := deps.invites.Create(t.Context(), issuer, "user:"+issuerID, true, invite.Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("invites.Create() error = %v", err)
	}

	api := func(mux *http.ServeMux) {
		deps.service.Routes(mux, routeDeps)
	}

	mux := server.NewMux(server.DefaultConfig(), routeDeps.Proxies, server.NewReadiness(), logger, server.Telemetry{}, http.NotFoundHandler(), api)

	req := httptest.NewRequest(http.MethodGet, "https://service.example/i/"+issued.Token, http.NoBody)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303, body = %s", rec.Code, rec.Body.String())
	}

	entries := logs.All()
	if len(entries) == 0 {
		t.Fatal("got 0 log entries, want at least the access log entry")
	}

	for _, entry := range entries {
		if strings.Contains(entry.Message, issued.Token) {
			t.Errorf("log message %q contains the invite token", entry.Message)
		}

		for key, value := range entry.ContextMap() {
			if s, ok := value.(string); ok && strings.Contains(s, issued.Token) {
				t.Errorf("log field %q = %q contains the invite token", key, s)
			}
		}
	}
}

// TestHandleInviteRedeem_RateLimited_NeverLogsTheToken cites AC-008.40 (the
// system SHALL NOT write a session token, an email code, a provider client
// secret, or any other secret to a log): a GET /i/{token} refused by the
// per-IP rate limiter must still redact the token from the 429's log entries.
// server.NewMux redacts every /i/ path before any middleware runs, so the
// redaction applies before the limiter, not only on the path that reaches
// the handler.
func TestHandleInviteRedeem_RateLimited_NeverLogsTheToken(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	routeDeps := newTestRouteDeps(t, deps, false)
	routeDeps.Limiter = ratelimit.New(1, 1, deps.clock.Now)

	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)
	routeDeps.Logger = logger

	issuerID, _ := newInviteMember(t, deps, "sub-invite-redact-429")
	issuer := mustParseUUID(t, issuerID)

	issued, err := deps.invites.Create(t.Context(), issuer, "user:"+issuerID, true, invite.Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("invites.Create() error = %v", err)
	}

	api := func(mux *http.ServeMux) {
		deps.service.Routes(mux, routeDeps)
	}

	mux := server.NewMux(server.DefaultConfig(), routeDeps.Proxies, server.NewReadiness(), logger, server.Telemetry{}, http.NotFoundHandler(), api)

	first := httptest.NewRequest(http.MethodGet, "https://service.example/i/"+issued.Token, http.NoBody)
	firstRec := httptest.NewRecorder()
	mux.ServeHTTP(firstRec, first)

	if firstRec.Code != http.StatusSeeOther {
		t.Fatalf("first request status = %d, want 303, body = %s", firstRec.Code, firstRec.Body.String())
	}

	second := httptest.NewRequest(http.MethodGet, "https://service.example/i/"+issued.Token, http.NoBody)
	secondRec := httptest.NewRecorder()
	mux.ServeHTTP(secondRec, second)

	if secondRec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429, body = %s", secondRec.Code, secondRec.Body.String())
	}

	entries := logs.All()
	if len(entries) == 0 {
		t.Fatal("got 0 log entries, want at least the two access-log entries")
	}

	for _, entry := range entries {
		if strings.Contains(entry.Message, issued.Token) {
			t.Errorf("log message %q contains the invite token", entry.Message)
		}

		for key, value := range entry.ContextMap() {
			if s, ok := value.(string); ok && strings.Contains(s, issued.Token) {
				t.Errorf("log field %q = %q contains the invite token", key, s)
			}
		}
	}
}

// TestHandleInviteRedeem_DeadTokens_Redirect303WithErrorInviteInvalid covers
// AC-008.57: an unknown, an expired, a revoked, and a spent token all
// redirect to /?error=invite_invalid, with no distinction between them.
func TestHandleInviteRedeem_DeadTokens_Redirect303WithErrorInviteInvalid(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	issuerID, _ := newInviteMember(t, deps, "sub-invite-redeem-dead")
	issuer := mustParseUUID(t, issuerID)

	expired, err := deps.invites.Create(t.Context(), issuer, "user:"+issuerID, true, invite.Params{MaxUses: 1, TTL: time.Minute})
	if err != nil {
		t.Fatalf("invites.Create(expired) error = %v", err)
	}

	deps.clock.Advance(2 * time.Minute)

	revoked, err := deps.invites.Create(t.Context(), issuer, "user:"+issuerID, true, invite.Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("invites.Create(revoked) error = %v", err)
	}

	if _, revokeErr := deps.invites.Revoke(t.Context(), revoked.Invite.ID, issuer, false); revokeErr != nil {
		t.Fatalf("Revoke() error = %v", revokeErr)
	}

	spent, err := deps.invites.Create(t.Context(), issuer, "user:"+issuerID, true, invite.Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("invites.Create(spent) error = %v", err)
	}

	if _, execErr := deps.handle.Pool().Exec(t.Context(), `UPDATE invites SET uses = max_uses WHERE id = $1`, spent.Invite.ID); execErr != nil {
		t.Fatalf("marking invite spent: %v", execErr)
	}

	tests := []struct {
		name  string
		token string
	}{
		{name: "unknown", token: "does-not-exist-at-all"},
		{name: "expired", token: expired.Token},
		{name: "revoked", token: revoked.Token},
		{name: "spent", token: spent.Token},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "https://service.example/i/"+tt.token, http.NoBody)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303, body = %s", rec.Code, rec.Body.String())
			}

			wantLocation := "/?error=" + server.ErrorCodeInviteInvalid
			if got := rec.Header().Get("Location"); got != wantLocation {
				t.Fatalf("Location = %q, want %q", got, wantLocation)
			}
		})
	}
}

// TestHandleInviteQR_MadeUpToken_Returns200ImagePNG covers AC-008.68: the QR
// route performs no lookup at all, proven by a token that names no invite
// still answering 200 image/png.
func TestHandleInviteQR_MadeUpToken_Returns200ImagePNG(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	req := httptest.NewRequest(http.MethodGet, "https://service.example/i/totally-made-up-token.png", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	if got := rec.Header().Get("Content-Type"); got != "image/png" {
		t.Fatalf("Content-Type = %q, want %q", got, "image/png")
	}

	if got := rec.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q, want %q", got, "private, no-store")
	}

	if rec.Body.Len() == 0 {
		t.Fatal("body is empty, want PNG bytes")
	}
}

// TestHandleInvitesCreate_AuditDetailNeverContainsToken covers AC-008.63:
// the invite.created audit row's raw detail
// bytes never contain the token, even though the token is known to this test
// from the same request's own response body.
func TestHandleInvitesCreate_AuditDetailNeverContainsToken(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{InviteDefaultQuota: new(5)})

	_, token := newInviteMember(t, deps, "sub-invite-audit")
	created := createInviteViaHTTP(t, handler, token, `{}`)

	events, err := deps.recorder.List(t.Context(), 50, audit.Cursor{})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	found := false

	for _, e := range events {
		if e.Action != "invite.created" {
			continue
		}

		found = true

		if bytes.Contains(e.Detail, []byte(created.Token)) {
			t.Fatalf("invite.created detail contains the token: %s", e.Detail)
		}
	}

	if !found {
		t.Fatal("no invite.created audit row was recorded")
	}
}

// settingsRouteDepsWithOverride builds a RouteDeps whose settings.Store
// carries signupEnabledOverride, sharing deps' handle so the same tables an
// ordinary newTestRouteDeps route sees are visible here too. It exists
// because RouteDeps carries no settings.Store field of its own: the settings
// handlers reach it through Service, so testing the locked path means
// building a whole second Service around the same database.
func settingsRouteDepsWithOverride(t *testing.T, deps testDeps, override bool) (*Service, RouteDeps) {
	t.Helper()

	lockedPolicy := settings.NewStore(deps.handle, settings.Options{SignupEnabledOverride: &override}, zap.NewNop(), deps.clock.Now)
	checker := authz.NewChecker(deps.roles)

	svc := NewService(deps.handle, deps.users, deps.sessions, deps.roles, checker, deps.recorder, deps.invites, lockedPolicy, nil, zap.NewNop(), deps.clock.Now, AccountDeps{})

	routeDeps := newTestRouteDeps(t, deps, false)

	return svc, routeDeps
}

// inviteRouteDepsWithMaxTTL builds a second Service, sharing deps' handle so
// the same tables an ordinary newTestRouteDeps route sees are visible here
// too, whose invite.Service and settings.Store carry a configured invite max
// TTL. It exists because testDeps' shared invite.Service and settings.Store
// are both built with a fixed empty settings.Options, and AC-008.80's
// ceiling can only be observed by a policy that carries one.
func inviteRouteDepsWithMaxTTL(t *testing.T, deps testDeps, maxTTL time.Duration) (*Service, RouteDeps) {
	t.Helper()

	policy := settings.NewStore(deps.handle, settings.Options{InviteMaxTTL: maxTTL}, zap.NewNop(), deps.clock.Now)

	invites, err := invite.NewService(deps.handle, policy, testTokenBytes, zap.NewNop(), deps.clock.Now)
	if err != nil {
		t.Fatalf("invite.NewService() error = %v", err)
	}

	checker := authz.NewChecker(deps.roles)

	svc := NewService(deps.handle, deps.users, deps.sessions, deps.roles, checker, deps.recorder, invites, policy, nil, zap.NewNop(), deps.clock.Now, AccountDeps{})

	routeDeps := newTestRouteDeps(t, deps, false)

	return svc, routeDeps
}

// TestHandleInvitesCreate_TTLAboveMaxIs400 covers AC-008.80: a request whose
// ttl_secs exceeds the configured maximum invite lifetime is refused as
// invalid rather than accepted or silently capped.
func TestHandleInvitesCreate_TTLAboveMaxIs400(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	svc, routeDeps := inviteRouteDepsWithMaxTTL(t, deps, time.Hour)

	mux := http.NewServeMux()
	svc.Routes(mux, routeDeps)
	handler := svc.Authenticate(deps.sessions, mux)

	setSignupPolicy(t, deps.policy, settings.Update{InviteDefaultQuota: new(5)})

	_, token := newInviteMember(t, deps, "sub-invite-ttl-too-long")

	req := acctReqBody(t, http.MethodPost, "/api/v1/invites", token, `{"ttl_secs":7200}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}

	want := `{"errors":[{"status":"400","code":"invalid_request","title":"Invalid request"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

// TestHandleInviteLanding_InfrastructureErrorIsNotJSON covers AC-008.57: a
// Lookup failure that is not invite.ErrInvalid (a database outage, here)
// must never answer with a JSON body. GET /i/{file} is reached from a
// browser navigation rather than an API client, so an application/json
// error document here would be shown to a person instead of parsed by code.
func TestHandleInviteLanding_InfrastructureErrorIsNotJSON(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	deps.handle.Close()

	req := httptest.NewRequest(http.MethodGet, "https://service.example/i/does-not-matter", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body = %s", rec.Code, rec.Body.String())
	}

	if ct := rec.Header().Get("Content-Type"); strings.Contains(ct, "json") {
		t.Fatalf("Content-Type = %q, want a non-JSON content type", ct)
	}
}

// TestHandleInvitesGet_ShapeMatchesCreateWithoutSecrets covers AC-008.63:
// GET /api/v1/invites/{id}'s response carries exactly the create response's
// keys, minus token, url, and qr_url.
func TestHandleInvitesGet_ShapeMatchesCreateWithoutSecrets(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{InviteDefaultQuota: new(5)})

	_, token := newInviteMember(t, deps, "sub-invite-shape")

	createRec := httptest.NewRecorder()
	handler.ServeHTTP(createRec, acctReqBody(t, http.MethodPost, "/api/v1/invites", token, `{}`))

	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201, body = %s", createRec.Code, createRec.Body.String())
	}

	var created map[string]any
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decoding create response: %v", err)
	}

	id, ok := created["id"].(string)
	if !ok {
		t.Fatalf("create response id = %v, want a string", created["id"])
	}

	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, acctReq(t, http.MethodGet, "/api/v1/invites/"+id, token))

	if getRec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200, body = %s", getRec.Code, getRec.Body.String())
	}

	var got map[string]any
	if err := json.Unmarshal(getRec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding get response: %v", err)
	}

	wantKeys := make(map[string]bool)

	for key := range created {
		if key == "token" || key == "url" || key == "qr_url" {
			continue
		}

		wantKeys[key] = true
	}

	gotKeys := make(map[string]bool)
	for key := range got {
		gotKeys[key] = true
	}

	if len(gotKeys) != len(wantKeys) {
		t.Fatalf("get response keys = %v, want %v", gotKeys, wantKeys)
	}

	for key := range wantKeys {
		if !gotKeys[key] {
			t.Errorf("get response missing key %q", key)
		}
	}
}

// TestHandleAdminSettingsPatch_Forbidden_ForMember covers AC-008.74: a
// caller without settings.manage cannot patch settings.
func TestHandleAdminSettingsPatch_Forbidden_ForMember(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	_, token := newInviteMember(t, deps, "sub-settings-forbidden")

	req := acctReqBody(t, http.MethodPatch, "/api/v1/admin/settings", token, `{"signup_enabled":false}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

// TestHandleAdminSettingsPatch_Success_ChangesOneKeyLeavesRest covers
// AC-008.74: an admin's PATCH changes exactly the named key.
func TestHandleAdminSettingsPatch_Success_ChangesOneKeyLeavesRest(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin-settings@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	adminIn := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-settings-admin",
		Email:         "admin-settings@example.com",
		EmailVerified: true,
		DisplayName:   "Admin",
		Methods:       []string{session.MethodOIDC},
	}
	_, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-settings-admin", "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	req := acctReqBody(t, http.MethodPatch, "/api/v1/admin/settings", adminToken, `{"invite_default_quota":7}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var body settingsResponse
	if unmarshalErr := json.Unmarshal(rec.Body.Bytes(), &body); unmarshalErr != nil {
		t.Fatalf("decoding response: %v", unmarshalErr)
	}

	if body.InviteDefaultQuota != 7 {
		t.Fatalf("body.InviteDefaultQuota = %d, want 7", body.InviteDefaultQuota)
	}

	if !body.SignupEnabled {
		t.Fatal("body.SignupEnabled = false, want unchanged true")
	}

	if body.Locked == nil {
		t.Fatal("body.Locked = nil, want a non-nil (possibly empty) slice")
	}
}

// TestHandleAdminSettingsPatch_Locked_ReturnsConflictSettingLocked covers
// AC-008.75: a PATCH naming a setting the environment overrides answers 409
// setting_locked and changes nothing.
func TestHandleAdminSettingsPatch_Locked_ReturnsConflictSettingLocked(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin-locked@example.com"})
	svc, routeDeps := settingsRouteDepsWithOverride(t, deps, true)

	mux := http.NewServeMux()
	svc.Routes(mux, routeDeps)
	handler := svc.Authenticate(deps.sessions, mux)

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	adminIn := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-settings-locked-admin",
		Email:         "admin-locked@example.com",
		EmailVerified: true,
		DisplayName:   "Admin",
		Methods:       []string{session.MethodOIDC},
	}
	// Logged in through deps.service, not svc: svc was built with no
	// bootstrap admin list (settingsRouteDepsWithOverride passes nil), so
	// only deps.service would grant the admin role on this address. Sessions
	// and roles are both read from the same deps.handle regardless of which
	// Service issued the token, so the token still authenticates against
	// svc's own mux.
	_, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-settings-locked", "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	req := acctReqBody(t, http.MethodPatch, "/api/v1/admin/settings", adminToken, `{"signup_enabled":false}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}

	wantBody := `{"errors":[{"status":"409","code":"setting_locked","title":"Setting locked by the environment"}]}`
	if got := exactErrorBody(rec); got != wantBody {
		t.Fatalf("body = %s, want %s", got, wantBody)
	}
}

// TestHandleAdminSettingsPatch_EmptyBody_Returns400InvalidRequest covers
// AC-008.74: a body naming no key this type recognises is refused rather
// than silently accepted as a no-op.
func TestHandleAdminSettingsPatch_EmptyBody_Returns400InvalidRequest(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin-empty-body@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	adminIn := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-settings-empty-body",
		Email:         "admin-empty-body@example.com",
		EmailVerified: true,
		DisplayName:   "Admin",
		Methods:       []string{session.MethodOIDC},
	}
	_, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-settings-empty-body", "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	req := acctReqBody(t, http.MethodPatch, "/api/v1/admin/settings", adminToken, `{"nonsense_key":true}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

// TestHandleAdminSettingsGet_ReportsLockedList covers AC-008.75: locked is
// [] with no override and ["signup_enabled"] with one.
func TestHandleAdminSettingsGet_ReportsLockedList(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin-locked-list@example.com"})

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	adminIn := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-settings-locked-list",
		Email:         "admin-locked-list@example.com",
		EmailVerified: true,
		DisplayName:   "Admin",
		Methods:       []string{session.MethodOIDC},
	}
	_, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-settings-locked-list", "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	unlockedHandler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))
	unlockedRec := httptest.NewRecorder()
	unlockedHandler.ServeHTTP(unlockedRec, acctReq(t, http.MethodGet, "/api/v1/admin/settings", adminToken))

	var unlockedBody settingsResponse
	if unmarshalErr := json.Unmarshal(unlockedRec.Body.Bytes(), &unlockedBody); unmarshalErr != nil {
		t.Fatalf("decoding unlocked response: %v", unmarshalErr)
	}

	if len(unlockedBody.Locked) != 0 {
		t.Fatalf("unlocked body.Locked = %v, want empty", unlockedBody.Locked)
	}

	lockedSvc, lockedRouteDeps := settingsRouteDepsWithOverride(t, deps, true)
	lockedMux := http.NewServeMux()
	lockedSvc.Routes(lockedMux, lockedRouteDeps)
	lockedHandler := lockedSvc.Authenticate(deps.sessions, lockedMux)

	lockedRec := httptest.NewRecorder()
	lockedHandler.ServeHTTP(lockedRec, acctReq(t, http.MethodGet, "/api/v1/admin/settings", adminToken))

	var lockedBody settingsResponse
	if unmarshalErr := json.Unmarshal(lockedRec.Body.Bytes(), &lockedBody); unmarshalErr != nil {
		t.Fatalf("decoding locked response: %v", unmarshalErr)
	}

	if len(lockedBody.Locked) != 1 || lockedBody.Locked[0] != "signup_enabled" {
		t.Fatalf("locked body.Locked = %v, want [signup_enabled]", lockedBody.Locked)
	}
}

// TestHandleAdminUsers_StatusPendingFilter_ListsOnlyPending covers
// AC-008.72: the approval queue is GET /api/v1/admin/users?status=pending,
// an existing route this unit adds no new registration for.
func TestHandleAdminUsers_StatusPendingFilter_ListsOnlyPending(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin-pending-list@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	pendingID := newPendingAccount(t, deps, "sub-pending-list")

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false), SignupRequireApproval: new(false)})
	newInviteMember(t, deps, "sub-pending-list-active")

	adminIn := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-pending-list-admin",
		Email:         "admin-pending-list@example.com",
		EmailVerified: true,
		DisplayName:   "Admin",
		Methods:       []string{session.MethodOIDC},
	}
	_, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-pending-list-admin", "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, acctReq(t, http.MethodGet, "/api/v1/admin/users?status=pending", adminToken))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var body adminUsersResponse
	if unmarshalErr := json.Unmarshal(rec.Body.Bytes(), &body); unmarshalErr != nil {
		t.Fatalf("decoding response: %v", unmarshalErr)
	}

	if len(body.Users) != 1 || body.Users[0].ID.String() != pendingID {
		t.Fatalf("body.Users = %+v, want exactly [%s]", body.Users, pendingID)
	}
}

// newPendingAccount creates an account through the real signup path while
// signup_require_approval is on, returning its id. LogIn itself returns
// ErrApprovalPending, which this helper treats as the expected outcome
// rather than a failure.
func newPendingAccount(t *testing.T, deps testDeps, subject string) string {
	t.Helper()

	setSignupPolicy(t, deps.policy, settings.Update{
		SignupEnabled:         new(true),
		SignupRequireInvite:   new(false),
		SignupRequireApproval: new(true),
	})

	in := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       subject,
		Email:         subject + "@example.com",
		EmailVerified: true,
		DisplayName:   "Pending User",
		Methods:       []string{session.MethodOIDC},
	}

	_, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-"+subject, "")
	if !errors.Is(err, ErrApprovalPending) {
		t.Fatalf("LogIn() error = %v, want ErrApprovalPending", err)
	}

	account, _, err := deps.users.ByIdentity(t.Context(), in.Provider, in.Subject)
	if err != nil {
		t.Fatalf("ByIdentity() error = %v", err)
	}

	return account.ID.String()
}

// TestHandleAdminUsersApprove_PendingAccount_Returns200AndAllowsLogin covers
// AC-008.72 and AC-008.73: approving a pending account answers 200, and the
// same identity can then complete a login that previously returned
// ErrApprovalPending.
func TestHandleAdminUsersApprove_PendingAccount_Returns200AndAllowsLogin(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin-approve@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	pendingID := newPendingAccount(t, deps, "sub-approve-pending")

	setSignupPolicy(t, deps.policy, settings.Update{SignupRequireApproval: new(false)})

	adminIn := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-approve-admin",
		Email:         "admin-approve@example.com",
		EmailVerified: true,
		DisplayName:   "Admin",
		Methods:       []string{session.MethodOIDC},
	}
	_, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-approve-admin", "")
	if err != nil {
		t.Fatalf("LogIn() admin error = %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, acctReq(t, http.MethodPost, "/api/v1/admin/users/"+pendingID+"/approve", adminToken))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var body accountResponse
	if unmarshalErr := json.Unmarshal(rec.Body.Bytes(), &body); unmarshalErr != nil {
		t.Fatalf("decoding response: %v", unmarshalErr)
	}

	if body.Status != "active" {
		t.Fatalf("body.Status = %q, want %q", body.Status, "active")
	}

	loginIn := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-approve-pending",
		Email:         "sub-approve-pending@example.com",
		EmailVerified: true,
		DisplayName:   "Pending User",
		Methods:       []string{session.MethodOIDC},
	}

	if _, _, _, logInErr := deps.service.LogIn(t.Context(), loginIn, "203.0.113.6", "test-agent", "req-approve-followup", ""); logInErr != nil {
		t.Fatalf("LogIn() after approval error = %v, want nil", logInErr)
	}
}

// TestHandleAdminUsersApprove_ActiveAccount_ReturnsConflictNotPending
// covers AC-008.72: approving an account that is not pending answers 409
// not_pending.
func TestHandleAdminUsersApprove_ActiveAccount_ReturnsConflictNotPending(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin-approve-active@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})
	activeID, _ := newInviteMember(t, deps, "sub-approve-already-active")

	adminIn := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-approve-active-admin",
		Email:         "admin-approve-active@example.com",
		EmailVerified: true,
		DisplayName:   "Admin",
		Methods:       []string{session.MethodOIDC},
	}
	_, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-approve-active-admin", "")
	if err != nil {
		t.Fatalf("LogIn() admin error = %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, acctReq(t, http.MethodPost, "/api/v1/admin/users/"+activeID+"/approve", adminToken))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}

	wantBody := `{"errors":[{"status":"409","code":"not_pending","title":"Account is not awaiting approval"}]}`
	if got := exactErrorBody(rec); got != wantBody {
		t.Fatalf("body = %s, want %s", got, wantBody)
	}
}

// TestHandleAdminUsersReject_PendingAccount_Returns200AndUnauthenticatable
// covers AC-008.72: rejecting a pending account answers 200, and the
// rejected account can no longer complete a login.
func TestHandleAdminUsersReject_PendingAccount_Returns200AndUnauthenticatable(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin-reject@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	pendingID := newPendingAccount(t, deps, "sub-reject-pending")

	adminIn := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-reject-admin",
		Email:         "admin-reject@example.com",
		EmailVerified: true,
		DisplayName:   "Admin",
		Methods:       []string{session.MethodOIDC},
	}
	_, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-reject-admin", "")
	if err != nil {
		t.Fatalf("LogIn() admin error = %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, acctReq(t, http.MethodPost, "/api/v1/admin/users/"+pendingID+"/reject", adminToken))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	setSignupPolicy(t, deps.policy, settings.Update{SignupRequireApproval: new(false)})

	loginIn := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-reject-pending",
		Email:         "sub-reject-pending@example.com",
		EmailVerified: true,
		DisplayName:   "Pending User",
		Methods:       []string{session.MethodOIDC},
	}

	if _, _, _, loginErr := deps.service.LogIn(t.Context(), loginIn, "203.0.113.6", "test-agent", "req-reject-followup", ""); !errors.Is(loginErr, ErrSuspended) {
		t.Fatalf("LogIn() after rejection error = %v, want ErrSuspended (deleted account)", loginErr)
	}

	events, err := deps.recorder.List(t.Context(), 50, audit.Cursor{})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	found := false

	for _, e := range events {
		if e.Action == "user.rejected" {
			found = true
		}
	}

	if !found {
		t.Fatal("no user.rejected audit row was recorded")
	}
}

// TestHandleAdminUsersReject_ActiveAccount_ReturnsConflictNotPendingAndLeavesActive
// covers AC-008.72:
// rejecting an already-active account must answer 409 not_pending and leave
// it active and able to authenticate, never soft-deleting it.
func TestHandleAdminUsersReject_ActiveAccount_ReturnsConflictNotPendingAndLeavesActive(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin-reject-active@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})
	_, targetToken := newInviteMember(t, deps, "sub-reject-already-active")

	targetSubject, ok := subjectFromToken(t, deps, targetToken)
	if !ok {
		t.Fatal("could not resolve target subject")
	}

	adminIn := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-reject-active-admin",
		Email:         "admin-reject-active@example.com",
		EmailVerified: true,
		DisplayName:   "Admin",
		Methods:       []string{session.MethodOIDC},
	}
	_, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-reject-active-admin", "")
	if err != nil {
		t.Fatalf("LogIn() admin error = %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, acctReq(t, http.MethodPost, "/api/v1/admin/users/"+targetSubject+"/reject", adminToken))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}

	wantBody := `{"errors":[{"status":"409","code":"not_pending","title":"Account is not awaiting approval"}]}`
	if got := exactErrorBody(rec); got != wantBody {
		t.Fatalf("body = %s, want %s", got, wantBody)
	}

	meRec := httptest.NewRecorder()
	handler.ServeHTTP(meRec, acctReq(t, http.MethodGet, "/api/v1/me", targetToken))

	if meRec.Code != http.StatusOK {
		t.Fatalf("target GET /api/v1/me status = %d, want 200 (must still be able to authenticate), body = %s", meRec.Code, meRec.Body.String())
	}
}

// TestHandleAdminUsersApproveReject_Forbidden_ForMember covers AC-008.72: a
// member holding no user.approve permission cannot approve or reject.
func TestHandleAdminUsersApproveReject_Forbidden_ForMember(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	pendingID := newPendingAccount(t, deps, "sub-approve-reject-forbidden-target")

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false), SignupRequireApproval: new(false)})
	_, memberToken := newInviteMember(t, deps, "sub-approve-reject-forbidden-member")

	approveRec := httptest.NewRecorder()
	handler.ServeHTTP(approveRec, acctReq(t, http.MethodPost, "/api/v1/admin/users/"+pendingID+"/approve", memberToken))

	if approveRec.Code != http.StatusForbidden {
		t.Fatalf("approve status = %d, want 403, body = %s", approveRec.Code, approveRec.Body.String())
	}

	rejectRec := httptest.NewRecorder()
	handler.ServeHTTP(rejectRec, acctReq(t, http.MethodPost, "/api/v1/admin/users/"+pendingID+"/reject", memberToken))

	if rejectRec.Code != http.StatusForbidden {
		t.Fatalf("reject status = %d, want 403, body = %s", rejectRec.Code, rejectRec.Body.String())
	}
}

// subjectFromToken resolves the user id a session token belongs to, using
// GET /api/v1/me through handler, so this test file does not need its own
// direct session lookup helper.
func subjectFromToken(t *testing.T, deps testDeps, token string) (string, bool) {
	t.Helper()

	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	req := acctReq(t, http.MethodGet, "/api/v1/me", token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		return "", false
	}

	var body meResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		return "", false
	}

	return body.ID.String(), true
}
