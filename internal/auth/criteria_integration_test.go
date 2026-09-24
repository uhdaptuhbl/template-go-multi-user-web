//go:build integration

package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	goidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/audit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/invite"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/settings"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/user"
)

// This file closes verification-status gaps left open in
// specs/008-users-and-auth/requirements.md: each test below observes exactly
// one of the criteria that record named as not yet fully observed, reusing
// this package's own existing fixtures rather than adding new ones.

// TestHandleAdminSettingsPatch_RecordsExactlyOneAuditRowNamingActorAndChange
// covers AC-008.76: a signup-policy change made through
// PATCH /api/v1/admin/settings leaves exactly one settings.updated audit row,
// naming the admin who made it as actor, "settings:global" as subject, and a
// detail that names only the key the request changed and its new value.
func TestHandleAdminSettingsPatch_RecordsExactlyOneAuditRowNamingActorAndChange(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin-audit-settings@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	adminIn := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-settings-audit-admin",
		Email:         "admin-audit-settings@example.com",
		EmailVerified: true,
		DisplayName:   "Admin",
		Methods:       []string{session.MethodOIDC},
	}

	adminUser, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-settings-audit", "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	req := acctReqBody(t, http.MethodPatch, "/api/v1/admin/settings", adminToken, `{"invite_default_quota":9}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	rows, err := deps.handle.Pool().Query(t.Context(),
		`SELECT actor_id, subject, outcome, detail::text FROM audit_events WHERE action = $1`,
		audit.ActionSettingsUpdated)
	if err != nil {
		t.Fatalf("querying audit_events: %v", err)
	}
	defer rows.Close()

	var count int

	var actorID uuid.UUID

	var subject string

	var outcome string

	var detail string

	for rows.Next() {
		if scanErr := rows.Scan(&actorID, &subject, &outcome, &detail); scanErr != nil {
			t.Fatalf("scanning audit_events row: %v", scanErr)
		}

		count++
	}

	if rowsErr := rows.Err(); rowsErr != nil {
		t.Fatalf("iterating audit_events rows: %v", rowsErr)
	}

	if count != 1 {
		t.Fatalf("settings.updated rows = %d, want exactly 1", count)
	}

	if actorID != adminUser.ID {
		t.Errorf("actor_id = %s, want %s", actorID, adminUser.ID)
	}

	if subject != "settings:global" {
		t.Errorf("subject = %q, want %q", subject, "settings:global")
	}

	if outcome != string(audit.OutcomeSuccess) {
		t.Errorf("outcome = %q, want %q", outcome, audit.OutcomeSuccess)
	}

	var parsed map[string]any
	if unmarshalErr := json.Unmarshal([]byte(detail), &parsed); unmarshalErr != nil {
		t.Fatalf("decoding detail: %v", unmarshalErr)
	}

	if got, ok := parsed["invite_default_quota"]; !ok || got != float64(9) {
		t.Errorf("detail[invite_default_quota] = %v (present=%v), want 9", got, ok)
	}

	if len(parsed) != 1 {
		t.Errorf("detail = %v, want exactly one key (invite_default_quota)", parsed)
	}
}

// TestIntegration_StateChangingRequestAuditRowCarriesAllFiveContractHFields
// covers AC-008.39: a state-changing request driven through the real
// request-id middleware (server.NewMux) from a known client address leaves
// an audit row carrying the request identifier, the client address, the
// acting account, the action, and the outcome.
func TestIntegration_StateChangingRequestAuditRowCarriesAllFiveContractHFields(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	token := issueAccountSession(t, deps, userID)

	routeDeps := newAccountRouteDeps(t, deps)
	apiMux := http.NewServeMux()
	deps.service.Routes(apiMux, routeDeps)
	authedAPI := deps.service.Authenticate(deps.sessions, apiMux)

	handler := server.NewMux(server.DefaultConfig(), routeDeps.Proxies, server.NewReadiness(), zap.NewNop(), server.Telemetry{},
		http.NotFoundHandler(), func(mux *http.ServeMux) {
			mux.Handle("/api/v1/", authedAPI)
		})

	const knownClientAddr = "203.0.113.77"

	req := acctReq(t, http.MethodDelete, "/api/v1/me/sessions", token)
	req.RemoteAddr = knownClientAddr + ":54321"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}

	var actorID uuid.UUID

	var subject string

	var outcome string

	var requestID string

	var clientIP string

	err := deps.handle.Pool().QueryRow(t.Context(),
		`SELECT actor_id, subject, outcome, request_id, host(client_ip) FROM audit_events WHERE action = $1`,
		audit.ActionSessionRevoked).Scan(&actorID, &subject, &outcome, &requestID, &clientIP)
	if err != nil {
		t.Fatalf("querying audit_events: %v", err)
	}

	if actorID != userID {
		t.Errorf("actor_id = %s, want %s", actorID, userID)
	}

	if subject != "user:"+userID.String() {
		t.Errorf("subject = %q, want %q", subject, "user:"+userID.String())
	}

	if outcome != string(audit.OutcomeSuccess) {
		t.Errorf("outcome = %q, want %q", outcome, audit.OutcomeSuccess)
	}

	if requestID == "" {
		t.Error("request_id is empty, want a value assigned by the request-id middleware")
	}

	if clientIP != knownClientAddr {
		t.Errorf("client_ip = %q, want %q", clientIP, knownClientAddr)
	}
}

// TestHandleOTPVerify_SuspendedAccountAnswersIdenticallyToWrongCode covers
// AC-008.42 at the HTTP boundary: verifying a correct code for a suspended
// account and verifying a wrong code for an unrelated address answer the
// exact same status and body, so a caller cannot distinguish "the account
// exists but is suspended" from "the credential was wrong".
func TestHandleOTPVerify_SuspendedAccountAnswersIdenticallyToWrongCode(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	sender := &recordingOTPSender{}
	routeDeps := newTestRouteDepsWithOTPSender(t, deps, sender)
	handler := newAuthedMux(deps, routeDeps)

	// Create the account this test will suspend, through the real OTP
	// signup ceremony, so it exists exactly the way a suspended production
	// account would.
	const suspendedEmail = "suspend-me@example.com"

	startSuspended := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/start", strings.NewReader(`{"email":"`+suspendedEmail+`"}`))
	startSuspended.Header.Set("Content-Type", "application/json")
	startSuspendedRec := httptest.NewRecorder()
	handler.ServeHTTP(startSuspendedRec, startSuspended)

	if startSuspendedRec.Code != http.StatusAccepted {
		t.Fatalf("first start status = %d, want 202, body = %s", startSuspendedRec.Code, startSuspendedRec.Body.String())
	}

	firstCode := codeFromMessage(t, sender.last(t))
	firstBindingCookie := integrationFindCookie(startSuspendedRec, otpBindingCookieNamePlain)

	if firstBindingCookie == nil {
		t.Fatal("no otp binding cookie set on first start")
	}

	verifySuspended := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/verify",
		strings.NewReader(`{"email":"`+suspendedEmail+`","code":"`+firstCode+`"}`))
	verifySuspended.Header.Set("Content-Type", "application/json")
	verifySuspended.Header.Set("Sec-Fetch-Site", "same-origin")
	verifySuspended.AddCookie(firstBindingCookie)
	verifySuspendedRec := httptest.NewRecorder()
	handler.ServeHTTP(verifySuspendedRec, verifySuspended)

	if verifySuspendedRec.Code != http.StatusNoContent {
		t.Fatalf("account creation verify status = %d, want 204, body = %s", verifySuspendedRec.Code, verifySuspendedRec.Body.String())
	}

	suspendedUser, err := deps.users.ByEmail(t.Context(), suspendedEmail)
	if err != nil {
		t.Fatalf("ByEmail() error = %v", err)
	}

	if _, setStatusErr := deps.users.SetStatus(t.Context(), suspendedUser.ID, user.StatusSuspended); setStatusErr != nil {
		t.Fatalf("SetStatus() error = %v", setStatusErr)
	}

	startAgain := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/start", strings.NewReader(`{"email":"`+suspendedEmail+`"}`))
	startAgain.Header.Set("Content-Type", "application/json")
	startAgainRec := httptest.NewRecorder()
	handler.ServeHTTP(startAgainRec, startAgain)

	if startAgainRec.Code != http.StatusAccepted {
		t.Fatalf("second start status = %d, want 202, body = %s", startAgainRec.Code, startAgainRec.Body.String())
	}

	secondCode := codeFromMessage(t, sender.last(t))
	secondBindingCookie := integrationFindCookie(startAgainRec, otpBindingCookieNamePlain)

	if secondBindingCookie == nil {
		t.Fatal("no otp binding cookie set on second start")
	}

	// The correct code for the now-suspended account: LogIn resolves the
	// existing identity and returns ErrSuspended.
	suspendedReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/verify",
		strings.NewReader(`{"email":"`+suspendedEmail+`","code":"`+secondCode+`"}`))
	suspendedReq.Header.Set("Content-Type", "application/json")
	suspendedReq.Header.Set("Sec-Fetch-Site", "same-origin")
	suspendedReq.AddCookie(secondBindingCookie)
	suspendedRec := httptest.NewRecorder()
	handler.ServeHTTP(suspendedRec, suspendedReq)

	// A wrong code for an address that has never signed up: otp.ErrVerification.
	const wrongCodeEmail = "never-signed-up@example.com"

	startWrong := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/start", strings.NewReader(`{"email":"`+wrongCodeEmail+`"}`))
	startWrong.Header.Set("Content-Type", "application/json")
	startWrongRec := httptest.NewRecorder()
	handler.ServeHTTP(startWrongRec, startWrong)

	if startWrongRec.Code != http.StatusAccepted {
		t.Fatalf("wrong-code start status = %d, want 202, body = %s", startWrongRec.Code, startWrongRec.Body.String())
	}

	wrongBindingCookie := integrationFindCookie(startWrongRec, otpBindingCookieNamePlain)

	if wrongBindingCookie == nil {
		t.Fatal("no otp binding cookie set on wrong-code start")
	}

	wrongReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/verify",
		strings.NewReader(`{"email":"`+wrongCodeEmail+`","code":"000000"}`))
	wrongReq.Header.Set("Content-Type", "application/json")
	wrongReq.Header.Set("Sec-Fetch-Site", "same-origin")
	wrongReq.AddCookie(wrongBindingCookie)
	wrongRec := httptest.NewRecorder()
	handler.ServeHTTP(wrongRec, wrongReq)

	if suspendedRec.Code != wrongRec.Code {
		t.Fatalf("status: suspended = %d, wrong code = %d, want identical", suspendedRec.Code, wrongRec.Code)
	}

	if got, want := suspendedRec.Body.String(), wrongRec.Body.String(); got != want {
		t.Fatalf("body: suspended = %s, wrong code = %s, want identical", got, want)
	}

	if suspendedRec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", suspendedRec.Code)
	}
}

// TestPurgeExpired_InviteAttributionSurvivesIssuerPurge covers AC-008.69: an
// account admitted through an invite still names the invite that admitted
// it, and the invite still names its issuer by created_by_ref, after that
// issuing account has been permanently removed.
func TestPurgeExpired_InviteAttributionSurvivesIssuerPurge(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(true)})

	issuer := createTestAdmin(t, deps)
	issuerRef := "user:" + issuer.String()

	issued, err := deps.invites.Create(t.Context(), issuer, issuerRef, true, invite.Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	in := newAuthenticated(t)
	in.InviteID = uuid.NullUUID{UUID: issued.Invite.ID, Valid: true}

	admitted, _, _, err := deps.service.LogIn(t.Context(), in, "203.0.113.9", "test-agent", "req-invite-attribution", "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	// The issuer is deleted and purges immediately: newTestService wires no
	// DeletedGracePeriod, so a zero grace period makes it eligible as soon as
	// any time has passed since deletion, per PurgeExpired's own boundary
	// test in account_test.go.
	if err = deps.users.SoftDelete(t.Context(), issuer); err != nil {
		t.Fatalf("SoftDelete(issuer) error = %v", err)
	}

	deps.clock.Advance(time.Second)

	purged, err := deps.service.PurgeExpired(t.Context())
	if err != nil {
		t.Fatalf("PurgeExpired() error = %v", err)
	}

	if purged != 1 {
		t.Fatalf("PurgeExpired() = %d, want 1", purged)
	}

	if got := countRows(t, deps.handle, `SELECT count(*) FROM users WHERE id = $1`, issuer); got != 0 {
		t.Fatalf("issuer rows = %d, want 0", got)
	}

	var createdByNull bool

	var createdByRef string

	err = deps.handle.Pool().QueryRow(t.Context(),
		`SELECT created_by IS NULL, created_by_ref FROM invites WHERE id = $1`, issued.Invite.ID,
	).Scan(&createdByNull, &createdByRef)
	if err != nil {
		t.Fatalf("querying invite: %v", err)
	}

	if !createdByNull {
		t.Error("invites.created_by is not NULL after the issuer was purged")
	}

	if createdByRef != issuerRef {
		t.Errorf("invites.created_by_ref = %q, want %q (must survive the issuer's removal)", createdByRef, issuerRef)
	}

	var redeemedInviteID uuid.UUID

	err = deps.handle.Pool().QueryRow(t.Context(),
		`SELECT invite_id FROM invite_redemptions WHERE user_id = $1`, admitted.ID,
	).Scan(&redeemedInviteID)
	if err != nil {
		t.Fatalf("querying invite_redemptions for the admitted account: %v", err)
	}

	if redeemedInviteID != issued.Invite.ID {
		t.Errorf("invite_redemptions.invite_id = %s, want %s (the invite that admitted this account)", redeemedInviteID, issued.Invite.ID)
	}
}

// TestFinishRejectsIdentityTokenFromTheWrongIssuer covers AC-008.22 by
// driving a full OIDC login ceremony through the real production handler
// chain (mirroring integration_test.go's integrationLoginViaOIDC, but with
// its own issuer builder rather than that helper's fixed
// provider.server.URL) and presenting an identity token whose "iss" claim
// names a different issuer than the one the registered provider was
// configured with, verified with the correct key and key ID either way.
// go-oidc's verifier rejects it before this service's own code ever sees a
// claims payload to act on.
func TestFinishRejectsIdentityTokenFromTheWrongIssuer(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	provider := newIntegrationOIDCProvider(t)
	routeDeps := newTestRouteDepsWithOIDC(t, deps, provider.server.URL)
	handler := newIntegrationHandler(deps, routeDeps)

	startReq := integrationRequest(t, http.MethodGet, "/api/v1/auth/oidc/test/start", nil)
	startRec := httptest.NewRecorder()
	handler.ServeHTTP(startRec, startReq)

	if startRec.Code != http.StatusSeeOther {
		t.Fatalf("oidc start status = %d, want 303 (body %s)", startRec.Code, startRec.Body.String())
	}

	authURL := startRec.Header().Get("Location")

	binding := integrationFindCookie(startRec, oidcBindingCookieNamePlain)
	if binding == nil {
		t.Fatalf("oidc start response carries no binding cookie (location %q)", authURL)
	}

	nonce, state, challenge := integrationParseAuthURL(t, authURL)

	provider.tokenEP.setChallenge(challenge)

	// The claim that matters: "iss" names a different issuer than
	// provider.server.URL, which is what newTestRouteDepsWithOIDC configured
	// the "test" provider's discovery document to report.
	const wrongIssuer = "https://wrong-issuer.invalid"

	claims := integrationBuildClaims(wrongIssuer, integrationOIDCClientID, "sub-wrong-issuer", nonce, "wrong-issuer@example.com", true, time.Now().Add(time.Hour))
	idToken := oidctest.SignIDToken(provider.key, integrationOIDCKeyID, goidc.RS256, claims)

	provider.tokenEP.setIDToken(idToken)

	callbackReq := integrationRequest(t, http.MethodGet,
		"/api/v1/auth/oidc/test/callback?state="+url.QueryEscape(state)+"&code=integration-test-code", nil)
	callbackReq.AddCookie(binding)

	callbackRec := httptest.NewRecorder()
	handler.ServeHTTP(callbackRec, callbackReq)

	if callbackRec.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d, want 303 (body %s)", callbackRec.Code, callbackRec.Body.String())
	}

	location := callbackRec.Header().Get("Location")
	if !strings.Contains(location, "error="+server.ErrorCodeUnauthenticated) {
		t.Fatalf("callback redirect Location = %q, want it to carry error=%s", location, server.ErrorCodeUnauthenticated)
	}

	if cookie := integrationFindCookie(callbackRec, session.DefaultCookieName); cookie != nil {
		t.Fatalf("a session cookie was set for a token from the wrong issuer: %+v", cookie)
	}

	var outcome string

	err := deps.handle.Pool().QueryRow(t.Context(),
		`SELECT outcome FROM audit_events WHERE action = $1 ORDER BY occurred_at DESC LIMIT 1`,
		audit.ActionOIDCCompleted,
	).Scan(&outcome)
	if err != nil {
		t.Fatalf("querying audit_events: %v", err)
	}

	if outcome != string(audit.OutcomeFailure) {
		t.Errorf("auth.oidc.completed outcome = %q, want %q", outcome, audit.OutcomeFailure)
	}
}
