//go:build integration

package auth

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/ratelimit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/user"
)

// acctRouteTestOrigin is the origin newAccountRouteDeps' RouteDeps reports
// as PublicOrigin, matching the constant handlers_test.go's own route
// fixture family uses.
const acctRouteTestOrigin = "https://service.example"

// newAccountRouteDeps builds a RouteDeps from deps' own collaborators. It is
// a separate fixture family from newTestRouteDeps in handlers_test.go
// because that one takes the package's other testDeps type, which carries no
// AccountDeps-wired Service; this file's tests need Service.RemoveCredential,
// RemoveIdentity, DeleteAccount, SetStatus, RestoreAccount, and
// StartIdentityLink/FinishIdentityLink to actually work, so they always run
// against an accountTestDeps built by newAccountTestDeps or
// newLinkedAccountDeps. Providers is threaded through from
// deps.service's own AccountDeps.Providers, so a link ceremony started
// through this RouteDeps and one finished through the Service share the same
// registry.
func newAccountRouteDeps(t *testing.T, deps accountTestDeps) RouteDeps {
	t.Helper()

	limiter := ratelimit.New(1000, 1000, deps.clock.Now)

	proxies, err := server.NewTrustedProxies(server.DefaultProxyConfig())
	if err != nil {
		t.Fatalf("NewTrustedProxies() error = %v", err)
	}

	return RouteDeps{
		Sessions:     deps.sessions,
		Users:        deps.users,
		Roles:        deps.roles,
		Credentials:  deps.credentials,
		Providers:    deps.service.accounts.Providers,
		Limiter:      limiter,
		Proxies:      proxies,
		Logger:       zap.NewNop(),
		PublicOrigin: acctRouteTestOrigin,
		CookieSecure: false,
		FlowTTL:      time.Minute,
	}
}

// newAccountAuthedMux wraps a fresh mux carrying deps.service's Routes with
// deps.service.Authenticate, mirroring newAuthedMux in handlers_test.go for
// this file's own accountTestDeps fixture family.
func newAccountAuthedMux(deps accountTestDeps, routeDeps RouteDeps) http.Handler {
	mux := http.NewServeMux()
	deps.service.Routes(mux, routeDeps)

	return deps.service.Authenticate(deps.sessions, mux)
}

// issueAccountSession mints a session token for userID directly through
// deps.sessions.Issue, bypassing the signup/login ceremony entirely: this
// file's account fixtures (newAccountUser) create rows directly rather than
// through LogIn, so there is no identity to log in with.
func issueAccountSession(t *testing.T, deps accountTestDeps, userID uuid.UUID) string {
	t.Helper()

	_, token, err := deps.sessions.Issue(t.Context(), userID, "203.0.113.9", "test-agent", []string{session.MethodOIDC})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	return token
}

// acctReq builds a request carrying token as the session cookie, for method
// and pathAndQuery, which may carry its own "?query" component: it is split
// out and assigned to RawQuery separately, since ServeMux and this file's own
// query-parameter tests both need it there rather than left inside Path,
// where net/http's router would never match it.
func acctReq(t *testing.T, method, pathAndQuery, token string) *http.Request {
	t.Helper()

	req := requestWithSessionCookie(t, token)
	req.Method = method

	path, query, _ := strings.Cut(pathAndQuery, "?")
	req.URL.Path = path
	req.URL.RawQuery = query

	return req
}

// acctReqBody is acctReq with a JSON request body.
func acctReqBody(t *testing.T, method, path, token, body string) *http.Request {
	t.Helper()

	req := acctReq(t, method, path, token)
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(strings.NewReader(body))

	return req
}

// ===== Group A: PATCH /api/v1/me =====

// TestHandleMePatch_Success_UpdatesDisplayNameAndPersists covers AC-008.45:
// a successful PATCH /api/v1/me changes the display name and the response
// carries the GET /api/v1/me shape; a following GET shows it too.
func TestHandleMePatch_Success_UpdatesDisplayNameAndPersists(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	token := issueAccountSession(t, deps, userID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := acctReqBody(t, http.MethodPatch, "/api/v1/me", token, `{"display_name":"Ada L"}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var body meResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	if body.DisplayName != "Ada L" {
		t.Fatalf("body.DisplayName = %q, want %q", body.DisplayName, "Ada L")
	}

	getReq := acctReq(t, http.MethodGet, "/api/v1/me", token)
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, getReq)

	var getBody meResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &getBody); err != nil {
		t.Fatalf("decoding GET response: %v", err)
	}

	if getBody.DisplayName != "Ada L" {
		t.Fatalf("GET /api/v1/me DisplayName = %q, want %q", getBody.DisplayName, "Ada L")
	}
}

// TestHandleMePatch_EmptyName_ReturnsExact400Body covers the empty-name
// refusal: PATCH /api/v1/me with an empty display name is 400
// invalid_request.
// Covers AC-008.45.
func TestHandleMePatch_EmptyName_ReturnsExact400Body(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	token := issueAccountSession(t, deps, userID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := acctReqBody(t, http.MethodPatch, "/api/v1/me", token, `{"display_name":""}`)
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

// TestHandleMePatch_Unauthenticated_Returns401 covers AC-008.34 for this
// route: no session cookie is refused with the exact 401 body.
func TestHandleMePatch_Unauthenticated_Returns401(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/me", strings.NewReader(`{"display_name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// ===== Group B: DELETE /api/v1/me =====

// TestHandleMeDelete_Success_ClearsCookieAndSessionIsGone covers AC-008.46:
// a successful DELETE /api/v1/me answers 204, clears the session cookie, and
// the same cookie then answers 401.
func TestHandleMeDelete_Success_ClearsCookieAndSessionIsGone(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	token := issueAccountSession(t, deps, userID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := acctReq(t, http.MethodDelete, "/api/v1/me", token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}

	assertCookieCleared(t, rec)

	meReq := acctReq(t, http.MethodGet, "/api/v1/me", token)
	meRec := httptest.NewRecorder()
	handler.ServeHTTP(meRec, meReq)

	if meRec.Code != http.StatusUnauthorized {
		t.Fatalf("post-delete /api/v1/me status = %d, want 401", meRec.Code)
	}
}

// TestHandleMeDelete_LastAdmin_ReturnsExact409AndAccountStillResolves covers
// AC-008.50's last-admin refusal: deleting the sole active admin's own
// account is 409 conflict, and the account still resolves afterward.
func TestHandleMeDelete_LastAdmin_ReturnsExact409AndAccountStillResolves(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, userID)
	token := issueAccountSession(t, deps, userID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := acctReq(t, http.MethodDelete, "/api/v1/me", token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}

	want := `{"errors":[{"status":"409","code":"conflict","title":"Request conflicts with current state"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}

	meReq := acctReq(t, http.MethodGet, "/api/v1/me", token)
	meRec := httptest.NewRecorder()
	handler.ServeHTTP(meRec, meReq)

	if meRec.Code != http.StatusOK {
		t.Fatalf("account no longer resolves after a refused delete: status = %d, body = %s", meRec.Code, meRec.Body.String())
	}
}

// TestHandleMeDelete_Unauthenticated_Returns401 covers AC-008.34 for this
// route.
func TestHandleMeDelete_Unauthenticated_Returns401(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// ===== Group C: DELETE /api/v1/me/sessions =====

// TestHandleMeSessionsDeleteAll_RevokesEverySessionAndClearsCookie covers
// AC-008.48: revoking all of the caller's own sessions invalidates a second
// session belonging to the same account and clears the cookie.
func TestHandleMeSessionsDeleteAll_RevokesEverySessionAndClearsCookie(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	firstToken := issueAccountSession(t, deps, userID)
	secondToken := issueAccountSession(t, deps, userID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := acctReq(t, http.MethodDelete, "/api/v1/me/sessions", firstToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}

	assertCookieCleared(t, rec)

	if _, err := deps.sessions.Lookup(t.Context(), firstToken); err == nil {
		t.Fatal("first (calling) session still resolves after DELETE /api/v1/me/sessions")
	}

	if _, err := deps.sessions.Lookup(t.Context(), secondToken); err == nil {
		t.Fatal("second session still resolves after DELETE /api/v1/me/sessions")
	}
}

// TestHandleMeSessionsDeleteAll_RecordsSessionRevokedAudit covers AC-008.38:
// DELETE /api/v1/me/sessions must record an audit event for the session
// revocation it performs, matching handleAdminUsersSessions' own behavior
// when revoked > 0. The request travels through the full middleware stack
// (server.NewMux plus Service.Authenticate) rather than the bare
// newAccountAuthedMux fixture, because RequestIDFromContext only resolves to
// a real value once withRequestID has run, and the audit row's request_id
// column must be non-empty.
func TestHandleMeSessionsDeleteAll_RecordsSessionRevokedAudit(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	firstToken := issueAccountSession(t, deps, userID)
	issueAccountSession(t, deps, userID)

	routeDeps := newAccountRouteDeps(t, deps)
	apiMux := http.NewServeMux()
	deps.service.Routes(apiMux, routeDeps)
	authedAPI := deps.service.Authenticate(deps.sessions, apiMux)

	handler := server.NewMux(server.DefaultConfig(), routeDeps.Proxies, server.NewReadiness(), zap.NewNop(), server.Telemetry{},
		http.NotFoundHandler(), func(mux *http.ServeMux) {
			mux.Handle("/api/v1/", authedAPI)
		})

	req := acctReq(t, http.MethodDelete, "/api/v1/me/sessions", firstToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}

	rows, err := deps.handle.Pool().Query(t.Context(),
		`SELECT actor_id, subject, outcome, request_id FROM audit_events WHERE action = $1`,
		audit.ActionSessionRevoked)
	if err != nil {
		t.Fatalf("querying audit_events: %v", err)
	}
	defer rows.Close()

	var count int

	for rows.Next() {
		var actorID uuid.UUID
		var subject string
		var outcome string
		var requestID string

		if scanErr := rows.Scan(&actorID, &subject, &outcome, &requestID); scanErr != nil {
			t.Fatalf("scanning audit_events row: %v", scanErr)
		}

		count++

		if actorID != userID {
			t.Errorf("actor_id = %s, want %s", actorID, userID)
		}

		wantSubject := "user:" + userID.String()
		if subject != wantSubject {
			t.Errorf("subject = %s, want %s", subject, wantSubject)
		}

		if outcome != string(audit.OutcomeSuccess) {
			t.Errorf("outcome = %s, want %s", outcome, audit.OutcomeSuccess)
		}

		if requestID == "" {
			t.Error("request_id is empty, want non-empty")
		}
	}

	if rowsErr := rows.Err(); rowsErr != nil {
		t.Fatalf("iterating audit_events rows: %v", rowsErr)
	}

	if count != 1 {
		t.Fatalf("session.revoked audit rows = %d, want exactly 1", count)
	}
}

// TestHandleMeSessionsDeleteAll_Unauthenticated_Returns401 covers AC-008.34
// for this route.
func TestHandleMeSessionsDeleteAll_Unauthenticated_Returns401(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/sessions", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// ===== Group D: GET /api/v1/me/identities =====

// TestHandleMeIdentities_ListsOwnOnly covers the ownership predicate
// (design.md's "Authorization path"): an account's identity listing carries
// its own identity and never another account's.
// Covers AC-008.35.
func TestHandleMeIdentities_ListsOwnOnly(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	userA := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	userB := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	idA := newAccountIdentity(t, deps.users, userA, "test-provider", "sub-identities-a")
	newAccountIdentity(t, deps.users, userB, "test-provider", "sub-identities-b")
	tokenA := issueAccountSession(t, deps, userA)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := acctReq(t, http.MethodGet, "/api/v1/me/identities", tokenA)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var body identitiesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	if len(body.Identities) != 1 || body.Identities[0].ID != idA {
		t.Fatalf("Identities = %+v, want exactly [%v]", body.Identities, idA)
	}
}

// TestHandleMeIdentities_Unauthenticated_Returns401 covers AC-008.34 for
// this route.
func TestHandleMeIdentities_Unauthenticated_Returns401(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/identities", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// ===== Group E: GET /api/v1/me/identities/{provider}/link/start =====

// TestHandleMeIdentitiesLinkStart_SetsBindingCookieAndRedirects covers
// AC-008.43 and amendment B: a successful start sets the OIDC binding
// cookie, exactly as the login start route does, and answers 303 to the
// provider.
func TestHandleMeIdentitiesLinkStart_SetsBindingCookieAndRedirects(t *testing.T) {
	t.Parallel()

	deps := newLinkedAccountDeps(t)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	token := issueAccountSession(t, deps.accountTestDeps, userID)
	handler := newAccountAuthedMux(deps.accountTestDeps, newAccountRouteDeps(t, deps.accountTestDeps))

	req := acctReq(t, http.MethodGet, "/api/v1/me/identities/"+accountLinkProviderKey+"/link/start", token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303, body = %s", rec.Code, rec.Body.String())
	}

	var binding *http.Cookie

	for _, c := range rec.Result().Cookies() {
		if c.Name == oidcBindingCookieNamePlain {
			binding = c
		}
	}

	if binding == nil {
		t.Fatal("no oidc binding cookie set")
	}

	if binding.Value == "" {
		t.Fatal("binding cookie value is empty")
	}

	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, deps.srv.URL) {
		t.Fatalf("Location = %q, want a redirect to the configured provider %q", loc, deps.srv.URL)
	}
}

// TestHandleMeIdentitiesLinkStart_UnknownProvider_ReturnsExact404Body covers
// the unconfigured-provider case: a provider key the registry does not
// carry answers 404, exactly as the login start route does, and sets no
// binding cookie.
// Covers AC-008.43.
func TestHandleMeIdentitiesLinkStart_UnknownProvider_ReturnsExact404Body(t *testing.T) {
	t.Parallel()

	deps := newLinkedAccountDeps(t)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	token := issueAccountSession(t, deps.accountTestDeps, userID)
	handler := newAccountAuthedMux(deps.accountTestDeps, newAccountRouteDeps(t, deps.accountTestDeps))

	req := acctReq(t, http.MethodGet, "/api/v1/me/identities/does-not-exist/link/start", token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}

	want := `{"errors":[{"status":"404","code":"not_found","title":"Not found"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}

	for _, c := range rec.Result().Cookies() {
		if c.Name == oidcBindingCookieNamePlain {
			t.Fatalf("binding cookie set despite an unknown provider: %+v", c)
		}
	}
}

// TestHandleMeIdentitiesLinkStart_Unauthenticated_Returns401 covers
// AC-008.34 for this route.
func TestHandleMeIdentitiesLinkStart_Unauthenticated_Returns401(t *testing.T) {
	t.Parallel()

	deps := newLinkedAccountDeps(t)
	handler := newAccountAuthedMux(deps.accountTestDeps, newAccountRouteDeps(t, deps.accountTestDeps))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/identities/"+accountLinkProviderKey+"/link/start", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestHandleMeIdentitiesLinkStart_CrossSiteNavigation_Returns403 covers
// AC-008.18: a top-level navigation to the link-start route whose
// Sec-Fetch-Site header signals cross-site is rejected before a link flow
// starts, so a signed-in victim navigated here by an attacker page cannot
// have another identity silently attached to their account. It answers 403
// cross_site, sets no binding cookie, and starts no link flow, observed the
// same way TestHandleMeIdentitiesLinkStart_UnknownProvider_ReturnsExact404Body
// observes the absence of a link flow: no binding cookie and, since the
// registered provider would otherwise redirect, no redirect Location either.
func TestHandleMeIdentitiesLinkStart_CrossSiteNavigation_Returns403(t *testing.T) {
	t.Parallel()

	deps := newLinkedAccountDeps(t)
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	token := issueAccountSession(t, deps.accountTestDeps, userID)
	handler := newAccountAuthedMux(deps.accountTestDeps, newAccountRouteDeps(t, deps.accountTestDeps))

	req := acctReq(t, http.MethodGet, "/api/v1/me/identities/"+accountLinkProviderKey+"/link/start", token)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}

	want := `{"errors":[{"status":"403","code":"cross_site","title":"Cross-site request rejected"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}

	for _, c := range rec.Result().Cookies() {
		if c.Name == oidcBindingCookieNamePlain {
			t.Fatalf("binding cookie set despite a cross-site navigation: %+v", c)
		}
	}

	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("Location = %q, want no redirect for a rejected cross-site navigation", loc)
	}
}

// ===== Group F: DELETE /api/v1/me/identities/{id} =====

// TestHandleMeIdentitiesDelete_OwnershipIsolation covers the ownership
// predicate (design.md's "Authorization path"): a non-owner's delete
// leaves the victim's identity intact and answers 204
// anyway (so the response cannot be used to probe ownership), while the
// owner's own delete actually removes it.
// Covers AC-008.35.
func TestHandleMeIdentitiesDelete_OwnershipIsolation(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, newConfiguredProviderRegistry(t, "test-provider"))
	userA := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	userB := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	newAccountIdentity(t, deps.users, userA, "test-provider", "sub-iso-a")
	// A also gets a credential: RemoveIdentity's last-factor check counts
	// the calling subject's own factors, not the named identity's owner's,
	// so a same-provider attacker with only the one identity it is
	// attacking with would trip ErrLastFactor before ownership is ever
	// consulted, which would test the wrong refusal.
	newAccountCredential(t, deps.credentials, userA)
	idB := newAccountIdentity(t, deps.users, userB, "test-provider", "sub-iso-b")
	newAccountCredential(t, deps.credentials, userB) // gives B a second factor, so B's own delete below can succeed

	tokenA := issueAccountSession(t, deps, userA)
	tokenB := issueAccountSession(t, deps, userB)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	crossReq := acctReq(t, http.MethodDelete, "/api/v1/me/identities/"+idB.String(), tokenA)
	crossRec := httptest.NewRecorder()
	handler.ServeHTTP(crossRec, crossReq)

	if crossRec.Code != http.StatusNoContent {
		t.Fatalf("cross-account delete status = %d, want 204, body = %s", crossRec.Code, crossRec.Body.String())
	}

	identitiesB, err := deps.users.IdentitiesFor(t.Context(), userB)
	if err != nil {
		t.Fatalf("IdentitiesFor(B) error = %v", err)
	}

	if len(identitiesB) != 1 || identitiesB[0].ID != idB {
		t.Fatalf("B's identities after a cross-account delete = %+v, want [%v] untouched", identitiesB, idB)
	}

	ownReq := acctReq(t, http.MethodDelete, "/api/v1/me/identities/"+idB.String(), tokenB)
	ownRec := httptest.NewRecorder()
	handler.ServeHTTP(ownRec, ownReq)

	if ownRec.Code != http.StatusNoContent {
		t.Fatalf("own delete status = %d, want 204, body = %s", ownRec.Code, ownRec.Body.String())
	}

	identitiesBAfter, err := deps.users.IdentitiesFor(t.Context(), userB)
	if err != nil {
		t.Fatalf("IdentitiesFor(B) after own delete error = %v", err)
	}

	if len(identitiesBAfter) != 0 {
		t.Fatalf("B's identities after its own delete = %+v, want empty", identitiesBAfter)
	}
}

// TestHandleMeIdentitiesDelete_LastFactor_ReturnsExact409AndIdentitySurvives
// covers the last-factor refusal: removing an account's sole authentication
// factor is 409 conflict and the identity remains attached.
// Covers AC-008.44.
func TestHandleMeIdentitiesDelete_LastFactor_ReturnsExact409AndIdentitySurvives(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, newConfiguredProviderRegistry(t, "test-provider"))
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	idOnly := newAccountIdentity(t, deps.users, userID, "test-provider", "sub-last-factor")
	token := issueAccountSession(t, deps, userID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := acctReq(t, http.MethodDelete, "/api/v1/me/identities/"+idOnly.String(), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}

	want := `{"errors":[{"status":"409","code":"conflict","title":"Request conflicts with current state"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}

	identities, err := deps.users.IdentitiesFor(t.Context(), userID)
	if err != nil {
		t.Fatalf("IdentitiesFor() error = %v", err)
	}

	if len(identities) != 1 {
		t.Fatalf("identities after a refused last-factor delete = %+v, want the one identity still present", identities)
	}
}

// TestHandleMeIdentitiesDelete_UnparseableID_MatchesForeignIDResponse
// ensures an unparseable identity id answers with the same status and body
// as a well-formed but foreign id.
// Covers AC-008.35.
func TestHandleMeIdentitiesDelete_UnparseableID_MatchesForeignIDResponse(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, newConfiguredProviderRegistry(t, "test-provider"))
	userID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	newAccountIdentity(t, deps.users, userID, "test-provider", "sub-unparseable")
	newAccountCredential(t, deps.credentials, userID)
	token := issueAccountSession(t, deps, userID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	badReq := acctReq(t, http.MethodDelete, "/api/v1/me/identities/not-a-uuid", token)
	badRec := httptest.NewRecorder()
	handler.ServeHTTP(badRec, badReq)

	foreignReq := acctReq(t, http.MethodDelete, "/api/v1/me/identities/"+uuid.New().String(), token)
	foreignRec := httptest.NewRecorder()
	handler.ServeHTTP(foreignRec, foreignReq)

	if badRec.Code != foreignRec.Code || badRec.Code != http.StatusNoContent {
		t.Fatalf("unparseable id status = %d, foreign id status = %d, want both 204", badRec.Code, foreignRec.Code)
	}

	if badRec.Body.String() != foreignRec.Body.String() {
		t.Fatalf("unparseable id body = %q, foreign id body = %q, want equal", badRec.Body.String(), foreignRec.Body.String())
	}
}

// TestHandleMeIdentitiesDelete_Unauthenticated_Returns401 covers AC-008.34
// for this route.
func TestHandleMeIdentitiesDelete_Unauthenticated_Returns401(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/identities/"+uuid.New().String(), http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// ===== Group G: PATCH /api/v1/admin/users/{id}/status =====

// TestHandleAdminUsersStatus_PermissionMatrix covers the permission gate: a
// member lacking user.write is refused with the exact 403 body, and an
// admin's request against another account succeeds.
// Covers AC-008.33 and AC-008.47.
func TestHandleAdminUsersStatus_PermissionMatrix(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	memberID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	targetID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	adminToken := issueAccountSession(t, deps, adminID)
	memberToken := issueAccountSession(t, deps, memberID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	memberReq := acctReqBody(t, http.MethodPatch, "/api/v1/admin/users/"+targetID.String()+"/status", memberToken, `{"status":"suspended"}`)
	memberRec := httptest.NewRecorder()
	handler.ServeHTTP(memberRec, memberReq)

	if memberRec.Code != http.StatusForbidden {
		t.Fatalf("member status = %d, want 403, body = %s", memberRec.Code, memberRec.Body.String())
	}

	wantForbidden := `{"errors":[{"status":"403","code":"forbidden","title":"Permission denied"}]}`
	if got := exactErrorBody(memberRec); got != wantForbidden {
		t.Fatalf("member body = %s, want %s", got, wantForbidden)
	}

	adminReq := acctReqBody(t, http.MethodPatch, "/api/v1/admin/users/"+targetID.String()+"/status", adminToken, `{"status":"suspended"}`)
	adminRec := httptest.NewRecorder()
	handler.ServeHTTP(adminRec, adminReq)

	if adminRec.Code != http.StatusOK {
		t.Fatalf("admin status = %d, want 200, body = %s", adminRec.Code, adminRec.Body.String())
	}

	var body accountResponse
	if err := json.Unmarshal(adminRec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding admin response: %v", err)
	}

	if body.Status != string(user.StatusSuspended) {
		t.Fatalf("body.Status = %q, want %q", body.Status, user.StatusSuspended)
	}
}

// TestHandleAdminUsersStatus_Suspend_TargetCookieBecomesUnauthenticated
// covers AC-008.47: suspending an account makes that account's existing
// cookie answer 401 on the next request.
func TestHandleAdminUsersStatus_Suspend_TargetCookieBecomesUnauthenticated(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	targetID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	adminToken := issueAccountSession(t, deps, adminID)
	targetToken := issueAccountSession(t, deps, targetID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := acctReqBody(t, http.MethodPatch, "/api/v1/admin/users/"+targetID.String()+"/status", adminToken, `{"status":"suspended"}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	targetReq := acctReq(t, http.MethodGet, "/api/v1/me", targetToken)
	targetRec := httptest.NewRecorder()
	handler.ServeHTTP(targetRec, targetReq)

	if targetRec.Code != http.StatusUnauthorized {
		t.Fatalf("suspended target status = %d, want 401", targetRec.Code)
	}
}

// TestHandleAdminUsersStatus_SuspendSelf_ReturnsExact409Body covers
// ErrSelfAction: an administrator may not suspend their own account.
// Covers AC-008.47.
func TestHandleAdminUsersStatus_SuspendSelf_ReturnsExact409Body(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	adminToken := issueAccountSession(t, deps, adminID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := acctReqBody(t, http.MethodPatch, "/api/v1/admin/users/"+adminID.String()+"/status", adminToken, `{"status":"suspended"}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}

	want := `{"errors":[{"status":"409","code":"conflict","title":"Request conflicts with current state"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

// TestHandleAdminUsersStatus_PendingTarget_ReturnsExact409IsPendingForEveryStatus
// covers AC-008.72's is_pending refusal: whatever status is requested
// against a pending account, the response is 409 is_pending and the account
// is still pending afterward, which is the mechanical proof that user.write
// does not grant approval.
func TestHandleAdminUsersStatus_PendingTarget_ReturnsExact409IsPendingForEveryStatus(t *testing.T) {
	t.Parallel()

	for _, requested := range []string{"active", "suspended"} {
		t.Run(requested, func(t *testing.T) {
			t.Parallel()

			deps := newAccountTestDeps(t, false, time.Hour, nil)
			adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
			grantAccountAdmin(t, deps.roles, adminID)
			adminToken := issueAccountSession(t, deps, adminID)
			handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

			targetID := uuid.New()
			const insertPending = `
INSERT INTO users (id, display_name, email, email_verified_at, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, 'pending', $5, $5)
`
			now := deps.clock.Now()
			if _, err := deps.handle.Pool().Exec(t.Context(), insertPending, targetID, "pending user", targetID.String()+"@example.com", now, now); err != nil {
				t.Fatalf("inserting pending user: %v", err)
			}

			req := acctReqBody(t, http.MethodPatch, "/api/v1/admin/users/"+targetID.String()+"/status", adminToken, fmt.Sprintf(`{"status":%q}`, requested))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
			}

			want := `{"errors":[{"status":"409","code":"is_pending","title":"Account is awaiting approval"}]}`
			if got := exactErrorBody(rec); got != want {
				t.Fatalf("body = %s, want %s", got, want)
			}

			after, err := deps.users.ByIDAnyStatus(t.Context(), targetID)
			if err != nil {
				t.Fatalf("ByIDAnyStatus() error = %v", err)
			}

			if after.Status != user.StatusPending {
				t.Fatalf("target status after refusal = %q, want %q", after.Status, user.StatusPending)
			}
		})
	}
}

// TestHandleAdminUsersStatus_ActiveOnDeletedWithinGrace_Restores covers
// AC-008.52: {"status":"active"} on an account deleted inside its grace
// period restores it.
func TestHandleAdminUsersStatus_ActiveOnDeletedWithinGrace_Restores(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	targetID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	adminToken := issueAccountSession(t, deps, adminID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	if err := deps.service.DeleteAccount(t.Context(), targetID, "203.0.113.5", "req-delete"); err != nil {
		t.Fatalf("DeleteAccount() error = %v", err)
	}

	req := acctReqBody(t, http.MethodPatch, "/api/v1/admin/users/"+targetID.String()+"/status", adminToken, `{"status":"active"}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var body accountResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	if body.Status != string(user.StatusActive) {
		t.Fatalf("body.Status = %q, want %q", body.Status, user.StatusActive)
	}

	restored, err := deps.users.ByID(t.Context(), targetID)
	if err != nil {
		t.Fatalf("ByID() error = %v, want the account to resolve as active again", err)
	}

	if restored.Status != user.StatusActive {
		t.Fatalf("restored.Status = %q, want %q", restored.Status, user.StatusActive)
	}
}

// TestHandleAdminUsersStatus_ActiveOnDeletedPastGrace_ReturnsExact404Body
// covers AC-008.52: the same restore call past the grace period is 404, the
// exact body an unknown identifier answers with.
func TestHandleAdminUsersStatus_ActiveOnDeletedPastGrace_ReturnsExact404Body(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, 0, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	targetID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	adminToken := issueAccountSession(t, deps, adminID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	if err := deps.service.DeleteAccount(t.Context(), targetID, "203.0.113.5", "req-delete"); err != nil {
		t.Fatalf("DeleteAccount() error = %v", err)
	}

	// A zero grace period still leaves the exact instant of deletion
	// eligible (RestoreAccount's own boundary test advances the clock for
	// the same reason): the clock must move past that instant before a
	// restore is actually outside the window.
	deps.clock.Advance(time.Minute)

	req := acctReqBody(t, http.MethodPatch, "/api/v1/admin/users/"+targetID.String()+"/status", adminToken, `{"status":"active"}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}

	want := `{"errors":[{"status":"404","code":"not_found","title":"Not found"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

// TestHandleAdminUsersStatus_SuspendDeletedAccount_ReturnsExact409BodyAndLeavesDeleted
// covers AC-008.52: a status write against a self-deleted account must not
// revive it outside the restore path, so {"status":"suspended"} against a
// deleted target answers the same 409 conflict body ErrSelfAction and
// ErrLastAdmin answer, and leaves the account deleted with deleted_at
// unchanged, so PurgeExpired still removes it once its grace period elapses.
func TestHandleAdminUsersStatus_SuspendDeletedAccount_ReturnsExact409BodyAndLeavesDeleted(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, 0, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	targetID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	adminToken := issueAccountSession(t, deps, adminID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	if err := deps.service.DeleteAccount(t.Context(), targetID, "203.0.113.5", "req-delete"); err != nil {
		t.Fatalf("DeleteAccount() error = %v", err)
	}

	before, err := deps.users.ByIDAnyStatus(t.Context(), targetID)
	if err != nil {
		t.Fatalf("ByIDAnyStatus() error = %v, want nil", err)
	}

	req := acctReqBody(t, http.MethodPatch, "/api/v1/admin/users/"+targetID.String()+"/status", adminToken, `{"status":"suspended"}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}

	want := `{"errors":[{"status":"409","code":"conflict","title":"Request conflicts with current state"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}

	after, err := deps.users.ByIDAnyStatus(t.Context(), targetID)
	if err != nil {
		t.Fatalf("ByIDAnyStatus() error = %v, want nil", err)
	}

	if after.Status != user.StatusDeleted {
		t.Fatalf("after.Status = %q, want %q (unchanged)", after.Status, user.StatusDeleted)
	}

	if after.DeletedAt == nil || before.DeletedAt == nil || !after.DeletedAt.Equal(*before.DeletedAt) {
		t.Fatalf("after.DeletedAt = %v, want %v (unchanged)", after.DeletedAt, before.DeletedAt)
	}

	// A zero grace period still leaves the exact instant of deletion
	// eligible (RestoreAccount's own boundary test advances the clock for
	// the same reason), so the clock must move past that instant before
	// the sweeper's purge is guaranteed to reach it.
	deps.clock.Advance(time.Minute)

	purged, err := deps.service.PurgeExpired(t.Context())
	if err != nil {
		t.Fatalf("PurgeExpired() error = %v, want nil", err)
	}

	if purged != 1 {
		t.Fatalf("PurgeExpired() = %d, want 1 (the conflict refusal must not have defeated the purge)", purged)
	}
}

// newRejectedPendingAccount inserts a pending account row directly, links an
// identity to it, and rejects it through user.Repository.Reject, leaving a
// terminal rejected-and-deleted row plus the identity a follow-up LogIn
// attempt needs to prove the account cannot sign in.
func newRejectedPendingAccount(t *testing.T, deps accountTestDeps, subject string) uuid.UUID {
	t.Helper()

	targetID := uuid.New()

	const insertPending = `
INSERT INTO users (id, display_name, email, email_verified_at, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, 'pending', $5, $5)
`
	now := deps.clock.Now()

	if _, err := deps.handle.Pool().Exec(t.Context(), insertPending, targetID, "rejected pending user", targetID.String()+"@example.com", now, now); err != nil {
		t.Fatalf("inserting pending user: %v", err)
	}

	newAccountIdentity(t, deps.users, targetID, "https://issuer.example", subject)

	changed, err := deps.users.Reject(t.Context(), targetID)
	if err != nil {
		t.Fatalf("Reject() error = %v, want nil", err)
	}

	if !changed {
		t.Fatalf("Reject() changed = false, want true")
	}

	return targetID
}

// TestPatchStatusActiveOnRejectedAccountIs409 covers AC-008.78: a rejected
// account can never be restored, so {"status":"active"} against one answers
// the same 409 conflict body a last-admin or self-action refusal answers,
// leaves the row deleted, and the identity still cannot complete a login
// afterward.
func TestPatchStatusActiveOnRejectedAccountIs409(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	adminToken := issueAccountSession(t, deps, adminID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	const subject = "subject-status-active-rejected"

	targetID := newRejectedPendingAccount(t, deps, subject)

	req := acctReqBody(t, http.MethodPatch, "/api/v1/admin/users/"+targetID.String()+"/status", adminToken, `{"status":"active"}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}

	want := `{"errors":[{"status":"409","code":"conflict","title":"Request conflicts with current state"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}

	after, err := deps.users.ByIDAnyStatus(t.Context(), targetID)
	if err != nil {
		t.Fatalf("ByIDAnyStatus() error = %v, want nil", err)
	}

	if after.Status != user.StatusDeleted {
		t.Fatalf("after.Status = %q, want %q (unchanged)", after.Status, user.StatusDeleted)
	}

	_, _, _, loginErr := deps.service.LogIn(t.Context(), Authenticated{
		Provider:      "https://issuer.example",
		Subject:       subject,
		Email:         subject + "@example.com",
		EmailVerified: true,
		DisplayName:   "Rejected User",
		Methods:       []string{session.MethodOIDC},
	}, "203.0.113.5", "test-agent", "req-login-after-reject-active", "")
	if !errors.Is(loginErr, ErrSuspended) {
		t.Fatalf("LogIn() after refused restore error = %v, want ErrSuspended", loginErr)
	}
}

// TestPatchStatusSuspendedOnRejectedAccountIs409 covers AC-008.78:
// {"status":"suspended"} against a rejected account answers the same 409
// conflict body a self-deleted account already answers through
// user.ErrIsDeleted, and leaves the row deleted.
func TestPatchStatusSuspendedOnRejectedAccountIs409(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	adminToken := issueAccountSession(t, deps, adminID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	targetID := newRejectedPendingAccount(t, deps, "subject-status-suspend-rejected")

	req := acctReqBody(t, http.MethodPatch, "/api/v1/admin/users/"+targetID.String()+"/status", adminToken, `{"status":"suspended"}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}

	want := `{"errors":[{"status":"409","code":"conflict","title":"Request conflicts with current state"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}

	after, err := deps.users.ByIDAnyStatus(t.Context(), targetID)
	if err != nil {
		t.Fatalf("ByIDAnyStatus() error = %v, want nil", err)
	}

	if after.Status != user.StatusDeleted {
		t.Fatalf("after.Status = %q, want %q (unchanged)", after.Status, user.StatusDeleted)
	}
}

// TestHandleAdminUsersStatus_UnknownID_ReturnsExact404Body covers
// AC-008.90 and the indistinguishability rule from the other side: a
// well-formed id naming no account at all answers the identical 404 body.
func TestHandleAdminUsersStatus_UnknownID_ReturnsExact404Body(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	adminToken := issueAccountSession(t, deps, adminID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := acctReqBody(t, http.MethodPatch, "/api/v1/admin/users/"+uuid.New().String()+"/status", adminToken, `{"status":"active"}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}

	want := `{"errors":[{"status":"404","code":"not_found","title":"Not found"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

// TestHandleAdminUsersStatus_DeletedRequested_ReturnsExact400Body covers the
// refusal of {"status":"deleted"}: deletion is the account holder's own
// action through DELETE /api/v1/me, not something an administrator writes.
// Covers AC-008.46 and AC-008.47.
func TestHandleAdminUsersStatus_DeletedRequested_ReturnsExact400Body(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	targetID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	adminToken := issueAccountSession(t, deps, adminID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := acctReqBody(t, http.MethodPatch, "/api/v1/admin/users/"+targetID.String()+"/status", adminToken, `{"status":"deleted"}`)
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

// TestHandleAdminUsersStatus_UnparseableID_ReturnsExact400Body covers a
// path id that does not parse as a UUID.
// Covers AC-008.47.
func TestHandleAdminUsersStatus_UnparseableID_ReturnsExact400Body(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	adminToken := issueAccountSession(t, deps, adminID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := acctReqBody(t, http.MethodPatch, "/api/v1/admin/users/not-a-uuid/status", adminToken, `{"status":"active"}`)
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

// TestHandleAdminUsersStatus_Unauthenticated_Returns401 covers AC-008.34
// for this route.
func TestHandleAdminUsersStatus_Unauthenticated_Returns401(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/users/"+uuid.New().String()+"/status", strings.NewReader(`{"status":"active"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// ===== Group H: DELETE /api/v1/admin/users/{id}/sessions =====

// TestHandleAdminUsersSessions_PermissionMatrix covers the permission gate:
// a member lacking session.revoke.any is refused with the exact 403 body,
// and an admin's request succeeds with 204.
// Covers AC-008.33 and AC-008.48.
func TestHandleAdminUsersSessions_PermissionMatrix(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	memberID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	targetID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	adminToken := issueAccountSession(t, deps, adminID)
	memberToken := issueAccountSession(t, deps, memberID)
	issueAccountSession(t, deps, targetID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	memberReq := acctReq(t, http.MethodDelete, "/api/v1/admin/users/"+targetID.String()+"/sessions", memberToken)
	memberRec := httptest.NewRecorder()
	handler.ServeHTTP(memberRec, memberReq)

	if memberRec.Code != http.StatusForbidden {
		t.Fatalf("member status = %d, want 403, body = %s", memberRec.Code, memberRec.Body.String())
	}

	wantForbidden := `{"errors":[{"status":"403","code":"forbidden","title":"Permission denied"}]}`
	if got := exactErrorBody(memberRec); got != wantForbidden {
		t.Fatalf("member body = %s, want %s", got, wantForbidden)
	}

	adminReq := acctReq(t, http.MethodDelete, "/api/v1/admin/users/"+targetID.String()+"/sessions", adminToken)
	adminRec := httptest.NewRecorder()
	handler.ServeHTTP(adminRec, adminReq)

	if adminRec.Code != http.StatusNoContent {
		t.Fatalf("admin status = %d, want 204, body = %s", adminRec.Code, adminRec.Body.String())
	}
}

// TestHandleAdminUsersSessions_InvalidatesTargetLeavesActorWorking covers
// AC-008.48: revoking a target account's sessions invalidates its cookie
// and leaves the acting administrator's own session working.
func TestHandleAdminUsersSessions_InvalidatesTargetLeavesActorWorking(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	targetID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	adminToken := issueAccountSession(t, deps, adminID)
	targetToken := issueAccountSession(t, deps, targetID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := acctReq(t, http.MethodDelete, "/api/v1/admin/users/"+targetID.String()+"/sessions", adminToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}

	if _, err := deps.sessions.Lookup(t.Context(), targetToken); err == nil {
		t.Fatal("target session still resolves after DELETE /api/v1/admin/users/{id}/sessions")
	}

	adminMeReq := acctReq(t, http.MethodGet, "/api/v1/me", adminToken)
	adminMeRec := httptest.NewRecorder()
	handler.ServeHTTP(adminMeRec, adminMeReq)

	if adminMeRec.Code != http.StatusOK {
		t.Fatalf("admin's own session status = %d, want 200 (still working), body = %s", adminMeRec.Code, adminMeRec.Body.String())
	}
}

// TestHandleAdminUsersSessions_UnknownID_ReturnsExact404Body covers
// AC-008.90: revoking the sessions of an account that does not exist answers
// 404, so a mistyped id is not reported as a successful revocation.
func TestHandleAdminUsersSessions_UnknownID_ReturnsExact404Body(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	adminToken := issueAccountSession(t, deps, adminID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := acctReq(t, http.MethodDelete, "/api/v1/admin/users/"+uuid.New().String()+"/sessions", adminToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}

	want := `{"errors":[{"status":"404","code":"not_found","title":"Not found"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

// TestHandleAdminUsersSessions_UnparseableID_ReturnsExact400Body covers a
// path id that does not parse as a UUID.
// Covers AC-008.48.
func TestHandleAdminUsersSessions_UnparseableID_ReturnsExact400Body(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	adminToken := issueAccountSession(t, deps, adminID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := acctReq(t, http.MethodDelete, "/api/v1/admin/users/not-a-uuid/sessions", adminToken)
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

// TestHandleAdminUsersSessions_Unauthenticated_Returns401 covers AC-008.34
// for this route.
func TestHandleAdminUsersSessions_Unauthenticated_Returns401(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/"+uuid.New().String()+"/sessions", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// ===== Group I: GET /api/v1/admin/audit =====

// TestHandleAdminAudit_PermissionMatrix covers the permission gate: a
// member lacking audit.read is refused with the exact 403 body, and an
// admin's request succeeds with 200.
// Covers AC-008.33 and AC-008.49.
func TestHandleAdminAudit_PermissionMatrix(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	memberID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	adminToken := issueAccountSession(t, deps, adminID)
	memberToken := issueAccountSession(t, deps, memberID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	memberReq := acctReq(t, http.MethodGet, "/api/v1/admin/audit", memberToken)
	memberRec := httptest.NewRecorder()
	handler.ServeHTTP(memberRec, memberReq)

	if memberRec.Code != http.StatusForbidden {
		t.Fatalf("member status = %d, want 403, body = %s", memberRec.Code, memberRec.Body.String())
	}

	wantForbidden := `{"errors":[{"status":"403","code":"forbidden","title":"Permission denied"}]}`
	if got := exactErrorBody(memberRec); got != wantForbidden {
		t.Fatalf("member body = %s, want %s", got, wantForbidden)
	}

	adminReq := acctReq(t, http.MethodGet, "/api/v1/admin/audit", adminToken)
	adminRec := httptest.NewRecorder()
	handler.ServeHTTP(adminRec, adminReq)

	if adminRec.Code != http.StatusOK {
		t.Fatalf("admin status = %d, want 200, body = %s", adminRec.Code, adminRec.Body.String())
	}
}

// TestHandleAdminAudit_NewestFirstLimitAndCursor covers AC-008.49: events
// return newest first, honour limit, and page with next_cursor.
func TestHandleAdminAudit_NewestFirstLimitAndCursor(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	adminToken := issueAccountSession(t, deps, adminID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	// grantAccountAdmin above and the three sessions issued so far already
	// wrote audit rows; three more, spaced out on the clock, give this test
	// its own unambiguous ordering to assert against.
	for i := range 3 {
		deps.clock.Advance(time.Minute)
		s := fmt.Sprintf("cursor-test-%d", i)
		if err := deps.recorder.Record(t.Context(), audit.Event{
			Subject: "user:" + adminID.String(),
			Action:  "test.marker." + s,
			Outcome: audit.OutcomeSuccess,
		}); err != nil {
			t.Fatalf("Record() error = %v", err)
		}
	}

	page1 := fetchAuditPage(t, handler, adminToken, "limit=2")

	if len(page1.Events) != 2 {
		t.Fatalf("len(page1.Events) = %d, want 2", len(page1.Events))
	}

	if page1.Events[0].Action != "test.marker.cursor-test-2" {
		t.Fatalf("page1.Events[0].Action = %q, want the most recent marker", page1.Events[0].Action)
	}

	if page1.Events[1].Action != "test.marker.cursor-test-1" {
		t.Fatalf("page1.Events[1].Action = %q, want the second most recent marker", page1.Events[1].Action)
	}

	if page1.NextCursor == nil {
		t.Fatal("page1.NextCursor is nil, want the second event's occurred_at")
	}

	page2 := fetchAuditPage(t, handler, adminToken, "limit=10&before="+*page1.NextCursor)

	if auditEventsContainAction(page2, "test.marker.cursor-test-1") || auditEventsContainAction(page2, "test.marker.cursor-test-2") {
		t.Fatalf("page 2 = %+v, want it to omit every event already returned on page 1", page2.Events)
	}

	if !auditEventsContainAction(page2, "test.marker.cursor-test-0") {
		t.Fatalf("page 2 = %+v, want it to contain the oldest marker event", page2.Events)
	}
}

// fetchAuditPage issues GET /api/v1/admin/audit through handler with token
// and rawQuery, failing t unless the response is 200, and decodes its body.
func fetchAuditPage(t *testing.T, handler http.Handler, token, rawQuery string) auditEventsResponse {
	t.Helper()

	req := acctReq(t, http.MethodGet, "/api/v1/admin/audit", token)
	req.URL.RawQuery = rawQuery
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var page auditEventsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	return page
}

// auditEventsContainAction reports whether page carries an event whose
// Action equals action.
func auditEventsContainAction(page auditEventsResponse, action string) bool {
	for _, e := range page.Events {
		if e.Action == action {
			return true
		}
	}

	return false
}

// TestHandleAdminAudit_InvalidBefore_ReturnsExact400Body covers the before
// parameter's validation: a value that does not parse as RFC 3339 is 400
// invalid_request.
// Covers AC-008.49.
func TestHandleAdminAudit_InvalidBefore_ReturnsExact400Body(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	adminToken := issueAccountSession(t, deps, adminID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := acctReq(t, http.MethodGet, "/api/v1/admin/audit", adminToken)
	req.URL.RawQuery = "before=not-a-timestamp"
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

// TestHandleAdminAudit_OutOfRangeLimit_IsClampedNotRejected covers the limit
// boundary from design.md's "Interfaces" section: a limit below
// auditListMinLimit is adjusted up rather than answering an empty page or an
// error, and the route still answers 200.
// Covers AC-008.49.
func TestHandleAdminAudit_OutOfRangeLimit_IsClampedNotRejected(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	adminToken := issueAccountSession(t, deps, adminID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	// grantAccountAdmin above already wrote one audit row; a second, later
	// one gives this test two rows to distinguish a clamped limit of one
	// from an unclamped, rejected, or zero-length one.
	deps.clock.Advance(time.Minute)

	if err := deps.recorder.Record(t.Context(), audit.Event{
		Subject: "user:" + adminID.String(),
		Action:  "test.marker.clamp",
		Outcome: audit.OutcomeSuccess,
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	page := fetchAuditPage(t, handler, adminToken, "limit=0")

	if len(page.Events) != auditListMinLimit {
		t.Fatalf("len(page.Events) = %d, want %d (limit=0 clamped to auditListMinLimit)", len(page.Events), auditListMinLimit)
	}

	if page.Events[0].Action != "test.marker.clamp" {
		t.Fatalf("page.Events[0].Action = %q, want the most recent row", page.Events[0].Action)
	}
}

// TestHandleAdminAudit_BodyNeverCarriesSessionTokenOrDigest covers AC-008.40:
// the audit listing's body contains no raw session token and no rendering of
// a live session's digest, mirroring
// TestHandleMeSessions_BodyNeverCarriesLiveDigest's guarantee for the
// caller's own session listing.
func TestHandleAdminAudit_BodyNeverCarriesSessionTokenOrDigest(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	adminToken := issueAccountSession(t, deps, adminID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := acctReq(t, http.MethodGet, "/api/v1/admin/audit", adminToken)
	req.URL.RawQuery = "limit=200"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	digest := session.Digest(adminToken)
	forbidden := []string{adminToken, hex.EncodeToString(digest)}

	body := rec.Body.String()
	for _, needle := range forbidden {
		if strings.Contains(body, needle) {
			t.Fatalf("response body contains forbidden substring %q", needle)
		}
	}
}

// TestHandleAdminAudit_ExactlyFullLastPage_NextCursorIsNull covers
// AC-008.49: when the number of available rows exactly equals limit, the
// page is the last one and next_cursor is JSON null rather than a cursor
// that would page into an empty result.
func TestHandleAdminAudit_ExactlyFullLastPage_NextCursorIsNull(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	adminToken := issueAccountSession(t, deps, adminID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	// Write a few more marker rows so the table is guaranteed to hold more
	// than zero events: a boundary test at zero rows would pass trivially
	// under buggy logic too (an empty page never sets a cursor either way).
	for i := range 3 {
		deps.clock.Advance(time.Minute)

		if err := deps.recorder.Record(t.Context(), audit.Event{
			Subject: "user:" + adminID.String(),
			Action:  fmt.Sprintf("test.marker.exact-page-%d", i),
			Outcome: audit.OutcomeSuccess,
		}); err != nil {
			t.Fatalf("Record() error = %v", err)
		}
	}

	// Discover exactly how many rows now exist, then request that exact
	// count as the limit: the page returned is then the whole table, with
	// nothing left for a next page.
	all := fetchAuditPage(t, handler, adminToken, "limit=1000")
	total := len(all.Events)

	if total == 0 {
		t.Fatal("total = 0, want at least the 3 marker events just recorded")
	}

	page := fetchAuditPage(t, handler, adminToken, fmt.Sprintf("limit=%d", total))

	if len(page.Events) != total {
		t.Fatalf("len(page.Events) = %d, want %d", len(page.Events), total)
	}

	if page.NextCursor != nil {
		t.Fatalf("page.NextCursor = %q, want nil on an exactly-full last page", *page.NextCursor)
	}
}

// TestHandleAdminAudit_MalformedCursorBefore_ReturnsExact400Body covers
// AC-008.49: a before value that is not a String-encoded audit.Cursor -
// timestamp-shaped but paired with a garbage id - is rejected as 400
// invalid_request rather than silently truncated or ignored.
func TestHandleAdminAudit_MalformedCursorBefore_ReturnsExact400Body(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	adminToken := issueAccountSession(t, deps, adminID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := acctReq(t, http.MethodGet, "/api/v1/admin/audit", adminToken)
	req.URL.RawQuery = "before=" + url.QueryEscape("2026-01-01T00:00:00Z_not-a-uuid")
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

// TestHandleAdminAudit_NullClientIP_RendersAsJSONNull covers AC-008.49: an
// event recorded with no ClientIP renders its client_ip field as JSON null,
// not the empty string.
func TestHandleAdminAudit_NullClientIP_RendersAsJSONNull(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	adminID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	grantAccountAdmin(t, deps.roles, adminID)
	adminToken := issueAccountSession(t, deps, adminID)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	deps.clock.Advance(time.Minute)

	if err := deps.recorder.Record(t.Context(), audit.Event{
		Subject: "user:" + adminID.String(),
		Action:  "test.marker.no-client-ip",
		Outcome: audit.OutcomeSuccess,
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	req := acctReq(t, http.MethodGet, "/api/v1/admin/audit", adminToken)
	req.URL.RawQuery = "limit=1"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var decoded map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	events, ok := decoded["events"].([]any)
	if !ok || len(events) != 1 {
		t.Fatalf("decoded events = %v, want exactly one entry", decoded["events"])
	}

	entry, ok := events[0].(map[string]any)
	if !ok {
		t.Fatalf("decoded events[0] = %v, want an object", events[0])
	}

	clientIP, present := entry["client_ip"]
	if !present {
		t.Fatal("decoded events[0] has no client_ip key")
	}

	if clientIP != nil {
		t.Errorf("events[0].client_ip = %v, want JSON null", clientIP)
	}
}

// TestHandleAdminAudit_Unauthenticated_Returns401 covers AC-008.34 for this
// route.
func TestHandleAdminAudit_Unauthenticated_Returns401(t *testing.T) {
	t.Parallel()

	deps := newAccountTestDeps(t, false, time.Hour, nil)
	handler := newAccountAuthedMux(deps, newAccountRouteDeps(t, deps))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// ===== Amendment A1: the shared OIDC callback route =====

// TestHandleOIDCCallback_LoginKindFlow_StillLogsIn_WithLinkProvidersConfigured
// covers amendment A1's core premise end to end through the real routes: an
// ordinary login ceremony still completes when the Service's own
// AccountDeps.Providers is configured (so FinishIdentityLink is genuinely
// tried and refused with oidc.ErrInvalidState) rather than nil, proving the
// callback's link-first attempt falls through to login without disturbing
// it.
// Covers AC-008.43.
func TestHandleOIDCCallback_LoginKindFlow_StillLogsIn_WithLinkProvidersConfigured(t *testing.T) {
	t.Parallel()

	deps := newLinkedAccountDeps(t)
	routeDeps := newAccountRouteDeps(t, deps.accountTestDeps)
	handler := newAccountAuthedMux(deps.accountTestDeps, routeDeps)

	// The identity is pre-linked so LogIn takes its "already known" branch
	// (users.ByIdentity finds it) rather than admitAccount's signup-policy
	// path: this test exists to prove the ordinary login route still works
	// once Service.accounts.Providers is configured for linking, not to
	// re-exercise the signup admission rules, which the rest of this
	// package's suite already covers in full.
	loginUserID := newAccountUser(t, deps.handle, deps.clock.Now(), true)
	newAccountIdentity(t, deps.users, loginUserID, accountLinkProviderKey, "sub-login-still-works")

	startReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/"+accountLinkProviderKey+"/start", http.NoBody)
	startRec := httptest.NewRecorder()
	handler.ServeHTTP(startRec, startReq)

	if startRec.Code != http.StatusSeeOther {
		t.Fatalf("start status = %d, want 303, body = %s", startRec.Code, startRec.Body.String())
	}

	var binding *http.Cookie

	for _, c := range startRec.Result().Cookies() {
		if c.Name == oidcBindingCookieNamePlain {
			binding = c
		}
	}

	if binding == nil {
		t.Fatal("no oidc binding cookie set by start")
	}

	loc := startRec.Header().Get("Location")
	nonce, state := parseAccountLinkAuthURL(t, loc)

	claims := buildAccountLinkClaims(deps.srv.URL, "sub-login-still-works", nonce, time.Now().Add(time.Hour))
	deps.tokenEP.setIDToken(oidctest.SignIDToken(deps.priv, accountLinkKeyID, goidc.RS256, claims))

	callbackReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/auth/oidc/"+accountLinkProviderKey+"/callback?state="+state+"&code=test-code", http.NoBody)
	callbackReq.AddCookie(binding)
	callbackRec := httptest.NewRecorder()
	handler.ServeHTTP(callbackRec, callbackReq)

	if callbackRec.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d, want 303, body = %s", callbackRec.Code, callbackRec.Body.String())
	}

	if got := callbackRec.Header().Get("Location"); got != "/" {
		t.Fatalf("Location = %q, want /", got)
	}

	var sessionCookie *http.Cookie

	for _, c := range callbackRec.Result().Cookies() {
		if c.Name == session.DefaultCookieName {
			sessionCookie = c
		}
	}

	if sessionCookie == nil {
		t.Fatal("no session cookie set on a successful login callback")
	}

	resolved, err := deps.sessions.Lookup(t.Context(), sessionCookie.Value)
	if err != nil {
		t.Fatalf("Lookup() new session error = %v", err)
	}

	if resolved.UserID != loginUserID {
		t.Fatalf("Lookup() UserID = %v, want %v (the pre-linked account, not a newly admitted one)", resolved.UserID, loginUserID)
	}
}

// TestHandleOIDCCallback_LinkUnderDifferentSession_RefusesNothingLinked
// covers amendment C: a link ceremony completing under a different session
// than the one that started it is refused, and no identity is attached to
// either account.
// Covers AC-008.43.
func TestHandleOIDCCallback_LinkUnderDifferentSession_RefusesNothingLinked(t *testing.T) {
	t.Parallel()

	deps := newLinkedAccountDeps(t)
	routeDeps := newAccountRouteDeps(t, deps.accountTestDeps)
	handler := newAccountAuthedMux(deps.accountTestDeps, routeDeps)

	starter := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	other := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	starterToken := issueAccountSession(t, deps.accountTestDeps, starter)
	otherToken := issueAccountSession(t, deps.accountTestDeps, other)

	startReq := acctReq(t, http.MethodGet, "/api/v1/me/identities/"+accountLinkProviderKey+"/link/start", starterToken)
	startRec := httptest.NewRecorder()
	handler.ServeHTTP(startRec, startReq)

	if startRec.Code != http.StatusSeeOther {
		t.Fatalf("start status = %d, want 303, body = %s", startRec.Code, startRec.Body.String())
	}

	var binding *http.Cookie

	for _, c := range startRec.Result().Cookies() {
		if c.Name == oidcBindingCookieNamePlain {
			binding = c
		}
	}

	if binding == nil {
		t.Fatal("no oidc binding cookie set by start")
	}

	nonce, state := parseAccountLinkAuthURL(t, startRec.Header().Get("Location"))

	claims := buildAccountLinkClaims(deps.srv.URL, "sub-cross-session", nonce, time.Now().Add(time.Hour))
	deps.tokenEP.setIDToken(oidctest.SignIDToken(deps.priv, accountLinkKeyID, goidc.RS256, claims))

	callbackReq := acctReq(t, http.MethodGet,
		"/api/v1/auth/oidc/"+accountLinkProviderKey+"/callback?state="+state+"&code=test-code", otherToken)
	callbackReq.AddCookie(binding)
	callbackRec := httptest.NewRecorder()
	handler.ServeHTTP(callbackRec, callbackReq)

	if callbackRec.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d, want 303, body = %s", callbackRec.Code, callbackRec.Body.String())
	}

	loc := callbackRec.Header().Get("Location")
	if loc == "/" || !strings.Contains(loc, "error=") {
		t.Fatalf("Location = %q, want a redirect carrying an error, not a successful link", loc)
	}

	for _, c := range callbackRec.Result().Cookies() {
		if c.Name == session.DefaultCookieName {
			t.Fatalf("a refused link ceremony set a session cookie: %+v", c)
		}
	}

	if got := countRows(t, deps.handle,
		`SELECT count(*) FROM identities WHERE provider = $1 AND subject = $2`,
		accountLinkProviderKey, "sub-cross-session"); got != 0 {
		t.Fatalf("identity rows = %d, want 0 (a session mismatch must link nothing)", got)
	}

	starterIdentities, err := deps.users.IdentitiesFor(t.Context(), starter)
	if err != nil {
		t.Fatalf("IdentitiesFor(starter) error = %v", err)
	}

	if len(starterIdentities) != 0 {
		t.Fatalf("starter's identities = %+v, want empty", starterIdentities)
	}

	otherIdentities, err := deps.users.IdentitiesFor(t.Context(), other)
	if err != nil {
		t.Fatalf("IdentitiesFor(other) error = %v", err)
	}

	if len(otherIdentities) != 0 {
		t.Fatalf("other's identities = %+v, want empty", otherIdentities)
	}
}

// TestHandleOIDCCallback_LinkSameSession_AttachesIdentityWithoutSessionCookie
// covers AC-008.43 through the full HTTP route rather than through the
// Service method directly: a link ceremony completed under the same session
// that started it attaches the identity to that session's own account, per
// the sessionUserID the callback reads from the request's authenticated
// subject, and never sets a session cookie, since linking is not a login.
func TestHandleOIDCCallback_LinkSameSession_AttachesIdentityWithoutSessionCookie(t *testing.T) {
	t.Parallel()

	deps := newLinkedAccountDeps(t)
	routeDeps := newAccountRouteDeps(t, deps.accountTestDeps)
	handler := newAccountAuthedMux(deps.accountTestDeps, routeDeps)

	starter := newAccountUser(t, deps.handle, deps.clock.Now(), false)
	starterToken := issueAccountSession(t, deps.accountTestDeps, starter)

	startReq := acctReq(t, http.MethodGet, "/api/v1/me/identities/"+accountLinkProviderKey+"/link/start", starterToken)
	startRec := httptest.NewRecorder()
	handler.ServeHTTP(startRec, startReq)

	if startRec.Code != http.StatusSeeOther {
		t.Fatalf("start status = %d, want 303, body = %s", startRec.Code, startRec.Body.String())
	}

	var binding *http.Cookie

	for _, c := range startRec.Result().Cookies() {
		if c.Name == oidcBindingCookieNamePlain {
			binding = c
		}
	}

	if binding == nil {
		t.Fatal("no oidc binding cookie set by start")
	}

	nonce, state := parseAccountLinkAuthURL(t, startRec.Header().Get("Location"))

	claims := buildAccountLinkClaims(deps.srv.URL, "sub-same-session", nonce, time.Now().Add(time.Hour))
	deps.tokenEP.setIDToken(oidctest.SignIDToken(deps.priv, accountLinkKeyID, goidc.RS256, claims))

	callbackReq := acctReq(t, http.MethodGet,
		"/api/v1/auth/oidc/"+accountLinkProviderKey+"/callback?state="+state+"&code=test-code", starterToken)
	callbackReq.AddCookie(binding)
	callbackRec := httptest.NewRecorder()
	handler.ServeHTTP(callbackRec, callbackReq)

	if callbackRec.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d, want 303, body = %s", callbackRec.Code, callbackRec.Body.String())
	}

	if got := callbackRec.Header().Get("Location"); got != "/" {
		t.Fatalf("Location = %q, want / (a successful link)", got)
	}

	for _, c := range callbackRec.Result().Cookies() {
		if c.Name == session.DefaultCookieName {
			t.Fatalf("a successful link ceremony set a session cookie: %+v", c)
		}
	}

	linkedUser, _, err := deps.users.ByIdentity(t.Context(), accountLinkProviderKey, "sub-same-session")
	if err != nil {
		t.Fatalf("ByIdentity() error = %v, want the identity attached to the starter's account", err)
	}

	if linkedUser.ID != starter {
		t.Fatalf("ByIdentity() user.ID = %v, want %v (the session that started and finished the ceremony)", linkedUser.ID, starter)
	}
}
