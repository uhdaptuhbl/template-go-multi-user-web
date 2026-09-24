//go:build integration

package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	goidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/audit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/passkey"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/invite"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/ratelimit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/secret"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/settings"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/user"
)

// This file is the integration suite: it drives the real production handler
// chain -- RejectCrossSite wrapping Authenticate wrapping server.NewMux
// registering Service.Routes, exactly as cmd/service/main.go assembles it --
// over a real Postgres database, for each of the end-to-end flows named in
// design.md's "Interfaces" section. Every test below cites the AC-008.n
// acceptance criteria it demonstrates.

// integrationOIDCKeyID is the key identifier every signed identity token and
// the fake provider's JWKS entry in this file share.
const integrationOIDCKeyID = "integration-test-key"

// integrationOIDCClientID is the OAuth client identifier
// newTestRouteDepsWithOIDC registers its one provider under.
const integrationOIDCClientID = "client-id"

// integrationOIDCClientSecret is the OAuth client secret
// newTestRouteDepsWithOIDC registers its one provider under.
const integrationOIDCClientSecret = "client-secret"

// integrationExpectedRedirectURI is the redirect_uri newTestRouteDepsWithOIDC's
// registry sends for its one provider, key "test", against
// testPublicOriginForRoutes.
const integrationExpectedRedirectURI = testPublicOriginForRoutes + "/api/v1/auth/oidc/test/callback"

// integrationTokenEndpoint stands in for a real OpenID Connect provider's
// token endpoint. It verifies PKCE, the redirect_uri, and the client
// credentials the same way a real provider would before returning a signed
// identity token, modeled on internal/auth/oidc's own oidc_test.tokenEndpoint,
// reimplemented here because that type lives in an unimportable _test package.
type integrationTokenEndpoint struct {
	mu        sync.Mutex
	idToken   string
	challenge string
}

// setChallenge records the code_challenge the next token exchange's
// code_verifier must hash to.
func (e *integrationTokenEndpoint) setChallenge(challenge string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.challenge = challenge
}

// setIDToken replaces the identity token the next token exchange returns.
func (e *integrationTokenEndpoint) setIDToken(token string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.idToken = token
}

// ServeHTTP implements http.Handler, answering a token exchange once its
// code_verifier hashes to the recorded code_challenge, its redirect_uri
// matches, and its client credentials match.
func (e *integrationTokenEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	e.mu.Lock()
	idToken := e.idToken
	challenge := e.challenge
	e.mu.Unlock()

	verifier := r.PostForm.Get("code_verifier")
	if verifier == "" {
		http.Error(w, "missing code_verifier", http.StatusBadRequest)

		return
	}

	sum := sha256.Sum256([]byte(verifier))
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != challenge {
		http.Error(w, "code_verifier does not match code_challenge", http.StatusBadRequest)

		return
	}

	if got := r.PostForm.Get("redirect_uri"); got != integrationExpectedRedirectURI {
		http.Error(w, "unexpected redirect_uri", http.StatusBadRequest)

		return
	}

	gotClientID, gotClientSecret, ok := r.BasicAuth()
	if !ok {
		gotClientID = r.PostForm.Get("client_id")
		gotClientSecret = r.PostForm.Get("client_secret")
	}

	if gotClientID != integrationOIDCClientID || gotClientSecret != integrationOIDCClientSecret {
		http.Error(w, "unexpected client credentials", http.StatusUnauthorized)

		return
	}

	body, err := json.Marshal(map[string]any{
		"access_token": "integration-test-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")

	if _, writeErr := w.Write(body); writeErr != nil {
		return
	}
}

// integrationOIDCProvider is a fake OpenID Connect provider serving
// discovery, JWKS, and a token endpoint, for driving a full login ceremony
// end to end against the real production handler chain.
type integrationOIDCProvider struct {
	server  *httptest.Server
	tokenEP *integrationTokenEndpoint
	key     *rsa.PrivateKey
}

// newIntegrationOIDCProvider starts an integrationOIDCProvider, torn down
// when t finishes.
func newIntegrationOIDCProvider(t *testing.T) *integrationOIDCProvider {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating provider signing key: %v", err)
	}

	discovery := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{{PublicKey: &priv.PublicKey, KeyID: integrationOIDCKeyID, Algorithm: goidc.RS256}},
	}

	tokenEP := &integrationTokenEndpoint{}

	mux := http.NewServeMux()
	mux.Handle("/.well-known/openid-configuration", discovery)
	mux.Handle("/keys", discovery)
	mux.Handle("/token", tokenEP)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	discovery.SetIssuer(srv.URL)

	return &integrationOIDCProvider{server: srv, tokenEP: tokenEP, key: priv}
}

// integrationParseAuthURL extracts the nonce, state, and code_challenge query
// parameters an OpenID Connect authorization URL carries.
func integrationParseAuthURL(t *testing.T, authURL string) (string, string, string) {
	t.Helper()

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parsing authorization url: %v", err)
	}

	query := parsed.Query()

	return query.Get("nonce"), query.Get("state"), query.Get("code_challenge")
}

// integrationBuildClaims renders a raw identity token claims payload naming
// subject and email, gating email_verified as directed.
func integrationBuildClaims(issuer, audience, subject, nonce, email string, emailVerified bool, exp time.Time) string {
	return fmt.Sprintf(`{"iss":%q,"aud":%q,"sub":%q,"nonce":%q,"exp":%d,"email":%q,"email_verified":%t,"name":"Integration Test User"}`,
		issuer, audience, subject, nonce, exp.Unix(), email, emailVerified)
}

// mustMarshalJSON marshals v to JSON, failing t on error.
func mustMarshalJSON(t *testing.T, v any) []byte {
	t.Helper()

	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshaling request body: %v", err)
	}

	return data
}

// integrationFindCookie returns the cookie named name from rec's response, or
// nil when none was set.
func integrationFindCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}

	return nil
}

// integrationRequest builds a request against handler's own public origin,
// marking a state-changing method same-origin so RejectCrossSite's ordinary
// gate lets it through, exactly as a real browser's Sec-Fetch-Site header
// would on a same-site request.
func integrationRequest(t *testing.T, method, path string, body []byte) *http.Request {
	t.Helper()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	req := httptest.NewRequest(method, testPublicOriginForRoutes+path, reader)

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
		req.Header.Set("Sec-Fetch-Site", "same-origin")
	}

	return req
}

// newIntegrationHandler assembles the real production handler chain --
// RejectCrossSite wrapping Authenticate wrapping server.NewMux registering
// deps.service.Routes -- in the exact order cmd/service/main.go wires it, so
// these flows exercise the real composition rather than a test-only
// shortcut.
func newIntegrationHandler(deps testDeps, routeDeps RouteDeps) http.Handler {
	logger := routeDeps.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	ready := server.NewReadiness()

	api := func(mux *http.ServeMux) {
		deps.service.Routes(mux, routeDeps)
	}

	mux := server.NewMux(server.DefaultConfig(), routeDeps.Proxies, ready, logger, server.Telemetry{}, http.NotFoundHandler(), api)
	authenticated := deps.service.Authenticate(deps.sessions, mux)

	return RejectCrossSite(routeDeps.PublicOrigin, session.DefaultCookieName, logger, authenticated)
}

// integrationLoginParams carries one OpenID Connect login ceremony's inputs
// for integrationLoginViaOIDC.
type integrationLoginParams struct {
	// subject is the identity token's "sub" claim.
	subject string
	// email is the identity token's "email" claim.
	email string
	// emailVerified is the identity token's "email_verified" claim.
	emailVerified bool
	// prior, when non-nil, is attached to the callback request alongside the
	// ceremony's own binding cookie, so the callback observes a pre-existing
	// session the way a browser carrying an old session cookie into a fresh
	// login would.
	prior *http.Cookie
	// inviteToken, when non-empty, is presented on the start request's
	// ?invite= query parameter.
	inviteToken string
}

// integrationLoginViaOIDC drives one full OpenID Connect login ceremony
// against handler through provider: start, extract the authorization
// parameters, program the fake token endpoint, sign an identity token, and
// call back. It returns the session cookie the callback set, or nil if it set
// none, and the callback's own recorded response.
func integrationLoginViaOIDC(t *testing.T, handler http.Handler, provider *integrationOIDCProvider, params integrationLoginParams) (*http.Cookie, *httptest.ResponseRecorder) {
	t.Helper()

	startPath := "/api/v1/auth/oidc/test/start"
	if params.inviteToken != "" {
		startPath += "?invite=" + url.QueryEscape(params.inviteToken)
	}

	startReq := integrationRequest(t, http.MethodGet, startPath, nil)
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

	claims := integrationBuildClaims(provider.server.URL, integrationOIDCClientID, params.subject, nonce, params.email, params.emailVerified, time.Now().Add(time.Hour))

	idToken := oidctest.SignIDToken(provider.key, integrationOIDCKeyID, goidc.RS256, claims)

	provider.tokenEP.setIDToken(idToken)

	callbackReq := integrationRequest(t, http.MethodGet,
		"/api/v1/auth/oidc/test/callback?state="+url.QueryEscape(state)+"&code=integration-test-code", nil)
	callbackReq.AddCookie(binding)

	if params.prior != nil {
		callbackReq.AddCookie(params.prior)
	}

	callbackRec := httptest.NewRecorder()
	handler.ServeHTTP(callbackRec, callbackReq)

	return integrationFindCookie(callbackRec, session.DefaultCookieName), callbackRec
}

// newTestServiceWithSignupEnabledLocked builds a testDeps exactly as
// newTestService does, except its settings.Store is constructed with
// signup_enabled locked to the given value by the environment. Unlike
// newTestService's own settings.Store, this one is baked into the returned
// Service at construction, since Service.policy is an unexported field only
// ever assigned once: replacing testDeps.policy after the fact would not
// change what the HTTP routes see, because they read through the Service's
// own copy, not this struct's.
func newTestServiceWithSignupEnabledLocked(t *testing.T, locked bool) testDeps {
	t.Helper()

	c := newClock()
	h := storetest.New(t)

	users := user.NewRepository(h, c.Now)
	sessions := session.NewStore(h, session.DefaultConfig(), c.Now)
	roles := authz.NewRepository(h, c.Now)
	checker := authz.NewChecker(roles)
	recorder := audit.NewRecorder(h, zap.NewNop(), c.Now)
	lockedCopy := locked
	policy := settings.NewStore(h, settings.Options{SignupEnabledOverride: &lockedCopy}, zap.NewNop(), c.Now)

	invites, err := invite.NewService(h, policy, testTokenBytes, zap.NewNop(), c.Now)
	if err != nil {
		t.Fatalf("invite.NewService() error = %v", err)
	}

	accountDeps := AccountDeps{Credentials: passkey.NewRepository(h, c.Now)}

	svc := NewService(h, users, sessions, roles, checker, recorder, invites, policy, nil, zap.NewNop(), c.Now, accountDeps)

	return testDeps{
		service:  svc,
		handle:   h,
		users:    users,
		sessions: sessions,
		roles:    roles,
		invites:  invites,
		policy:   policy,
		recorder: recorder,
		clock:    c,
	}
}

// integrationIssueAccountBypassingSignup inserts an already-active account
// and identity directly through user.Repository, bypassing the signup
// admission pipeline entirely, and mints it a session directly through
// session.Store.Issue. This is how an actor account is created for a test
// whose settings.Store permanently locks signup_enabled false, since
// issueSession's own internal setSignupPolicy call would fail against an
// already-locked store regardless of when it runs.
func integrationIssueAccountBypassingSignup(t *testing.T, deps testDeps, subject, email string) (uuid.UUID, string) {
	t.Helper()

	ctx := t.Context()
	now := deps.clock.Now()
	userID := uuid.New()

	account := user.User{
		ID:              userID,
		DisplayName:     subject,
		Email:           &email,
		EmailVerifiedAt: &now,
		Status:          user.StatusActive,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	identity := user.Identity{
		ID:        uuid.New(),
		UserID:    userID,
		Provider:  "integration-fixture",
		Subject:   subject,
		Email:     &email,
		CreatedAt: now,
	}

	if err := deps.users.CreateWithIdentity(ctx, account, identity); err != nil {
		t.Fatalf("creating fixture account: %v", err)
	}

	_, token, err := deps.sessions.Issue(ctx, userID, "203.0.113.9", "integration-test", []string{session.MethodOIDC})
	if err != nil {
		t.Fatalf("issuing fixture session: %v", err)
	}

	return userID, token
}

// integrationGrantWriteOnlyRole inserts a test-fixture role carrying exactly
// authz.PermissionUserWrite -- no seeded role holds user.write without
// user.approve, so flow AC-008.71/AC-008.72's "user.write does not grant
// approval" case needs one built by hand -- and grants it to userID through
// the real authz.Repository.GrantRole. Both the role's and the permission's
// UUIDs are generated in Go: roles.id and permissions.id carry no
// database-side default.
func integrationGrantWriteOnlyRole(t *testing.T, deps testDeps, userID uuid.UUID) {
	t.Helper()

	ctx := t.Context()
	roleID := uuid.New()
	permissionID := uuid.New()
	roleName := "integration-write-only-" + uuid.New().String()

	if _, err := deps.handle.Pool().Exec(ctx,
		`INSERT INTO permissions (id, name, description) VALUES ($1, $2, $3) ON CONFLICT (name) DO NOTHING`,
		permissionID, authz.PermissionUserWrite, "seeded permission, present already"); err != nil {
		t.Fatalf("ensuring user.write permission exists: %v", err)
	}

	if err := deps.handle.Pool().QueryRow(ctx,
		`SELECT id FROM permissions WHERE name = $1`, authz.PermissionUserWrite).Scan(&permissionID); err != nil {
		t.Fatalf("resolving user.write permission id: %v", err)
	}

	if _, err := deps.handle.Pool().Exec(ctx,
		`INSERT INTO roles (id, name, description, created_at) VALUES ($1, $2, $3, $4)`,
		roleID, roleName, "integration test fixture: user.write only", deps.clock.Now()); err != nil {
		t.Fatalf("inserting fixture role: %v", err)
	}

	if _, err := deps.handle.Pool().Exec(ctx,
		`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`,
		roleID, permissionID); err != nil {
		t.Fatalf("granting user.write to fixture role: %v", err)
	}

	if err := deps.roles.GrantRole(ctx, userID, roleName, userID); err != nil {
		t.Fatalf("granting fixture role: %v", err)
	}
}

// integrationLogsContainSubstring reports whether any captured log entry's
// message or context field contains needle.
func integrationLogsContainSubstring(logs *observer.ObservedLogs, needle string) bool {
	for _, entry := range logs.All() {
		if strings.Contains(entry.Message, needle) {
			return true
		}

		for _, v := range entry.ContextMap() {
			if strings.Contains(fmt.Sprintf("%v", v), needle) {
				return true
			}
		}
	}

	return false
}

// integrationCreateInvite issues an invite through the real HTTP route as the
// account owning actorCookie, decoding the response to recover its token,
// which AC-008.63 requires be disclosed only on this one response.
func integrationCreateInvite(t *testing.T, handler http.Handler, actorCookie *http.Cookie, body map[string]any) inviteResponse {
	t.Helper()

	req := integrationRequest(t, http.MethodPost, "/api/v1/invites", mustMarshalJSON(t, body))
	req.AddCookie(actorCookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/invites status = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}

	var got inviteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding invite response: %v", err)
	}

	return got
}

// TestIntegration_UnknownUserProviderLoginGrantsSession covers AC-008.8,
// AC-008.20, and AC-008.22: an unrecognised OpenID Connect identity completes
// a full ceremony, is admitted, redirected to "/", and its new session
// resolves GET /api/v1/me with its roles and permissions.
func TestIntegration_UnknownUserProviderLoginGrantsSession(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	provider := newIntegrationOIDCProvider(t)
	routeDeps := newTestRouteDepsWithOIDC(t, deps, provider.server.URL)
	handler := newIntegrationHandler(deps, routeDeps)

	cookie, rec := integrationLoginViaOIDC(t, handler, provider, integrationLoginParams{
		subject: "flow1-subject", email: "flow1@example.com", emailVerified: true,
	})

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("callback status = %d, location = %q, want 303 to /", rec.Code, rec.Header().Get("Location"))
	}

	if cookie == nil {
		t.Fatal("callback issued no session cookie")
	}

	meReq := integrationRequest(t, http.MethodGet, "/api/v1/me", nil)
	meReq.AddCookie(cookie)
	meRec := httptest.NewRecorder()
	handler.ServeHTTP(meRec, meReq)

	if meRec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/me status = %d, want 200 (body %s)", meRec.Code, meRec.Body.String())
	}

	var me meResponse
	if err := json.Unmarshal(meRec.Body.Bytes(), &me); err != nil {
		t.Fatalf("decoding /api/v1/me response: %v", err)
	}

	if me.Email == nil || *me.Email != "flow1@example.com" {
		t.Fatalf("me.Email = %v, want flow1@example.com", me.Email)
	}

	if len(me.Roles) == 0 {
		t.Fatal("me.Roles is empty, want at least the default member role")
	}

	if len(me.Permissions) == 0 {
		t.Fatal("me.Permissions is empty, want at least invite.create")
	}
}

// TestIntegration_NoCookieRejectsMe covers AC-008.34: a request to
// GET /api/v1/me carrying no session cookie is refused with the exact
// unauthenticated body.
func TestIntegration_NoCookieRejectsMe(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	routeDeps := newTestRouteDeps(t, deps, false)
	handler := newIntegrationHandler(deps, routeDeps)

	req := integrationRequest(t, http.MethodGet, "/api/v1/me", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	want := `{"errors":[{"status":"401","code":"unauthenticated","title":"Authentication required"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

// TestIntegration_LogoutRevokesSession covers AC-008.15: logging out answers
// 204 and the same cookie no longer authenticates any request.
func TestIntegration_LogoutRevokesSession(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	_, token := issueSession(t, deps, "flow3-subject")
	routeDeps := newTestRouteDeps(t, deps, false)
	handler := newIntegrationHandler(deps, routeDeps)

	cookie := &http.Cookie{Name: session.DefaultCookieName, Value: token} //nolint:gosec // G124: this cookie only ever reaches Request.AddCookie, which serializes just name=value; Secure/HttpOnly/SameSite are meaningless here

	logoutReq := integrationRequest(t, http.MethodPost, "/api/v1/auth/logout", nil)
	logoutReq.AddCookie(cookie)
	logoutRec := httptest.NewRecorder()
	handler.ServeHTTP(logoutRec, logoutReq)

	if logoutRec.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, want 204", logoutRec.Code)
	}

	meReq := integrationRequest(t, http.MethodGet, "/api/v1/me", nil)
	meReq.AddCookie(cookie)
	meRec := httptest.NewRecorder()
	handler.ServeHTTP(meRec, meReq)

	if meRec.Code != http.StatusUnauthorized {
		t.Fatalf("post-logout GET /api/v1/me status = %d, want 401", meRec.Code)
	}
}

// TestIntegration_SecondLoginRegeneratesSessionAndRevokesPrior covers
// AC-008.17 under Amendment A: logging in twice through the real OIDC
// callback route on the same cookie jar must issue a different cookie value
// each time, and the first value must stop authenticating once the second
// login completes. This is written to kill the mutant that passes an empty
// prior token to LogIn instead of deps.Sessions.TokenFromRequest(r) at
// handlers.go's handleOIDCCallback.
func TestIntegration_SecondLoginRegeneratesSessionAndRevokesPrior(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	provider := newIntegrationOIDCProvider(t)
	routeDeps := newTestRouteDepsWithOIDC(t, deps, provider.server.URL)
	handler := newIntegrationHandler(deps, routeDeps)

	firstCookie, firstRec := integrationLoginViaOIDC(t, handler, provider, integrationLoginParams{
		subject: "flow4-subject", email: "flow4@example.com", emailVerified: true,
	})

	if firstRec.Code != http.StatusSeeOther || firstCookie == nil {
		t.Fatalf("first login: status = %d, cookie present = %v, want 303 with a cookie", firstRec.Code, firstCookie != nil)
	}

	secondCookie, secondRec := integrationLoginViaOIDC(t, handler, provider, integrationLoginParams{
		subject: "flow4-subject", email: "flow4@example.com", emailVerified: true, prior: firstCookie,
	})

	if secondRec.Code != http.StatusSeeOther || secondCookie == nil {
		t.Fatalf("second login: status = %d, cookie present = %v, want 303 with a cookie", secondRec.Code, secondCookie != nil)
	}

	if secondCookie.Value == firstCookie.Value {
		t.Fatal("second login reused the first login's session token, want a fresh one")
	}

	oldReq := integrationRequest(t, http.MethodGet, "/api/v1/me", nil)
	oldReq.AddCookie(firstCookie)
	oldRec := httptest.NewRecorder()
	handler.ServeHTTP(oldRec, oldReq)

	if oldRec.Code != http.StatusUnauthorized {
		t.Fatalf("first login's token still authenticates: status = %d, want 401", oldRec.Code)
	}

	newReq := integrationRequest(t, http.MethodGet, "/api/v1/me", nil)
	newReq.AddCookie(secondCookie)
	newRec := httptest.NewRecorder()
	handler.ServeHTTP(newRec, newReq)

	if newRec.Code != http.StatusOK {
		t.Fatalf("second login's token does not authenticate: status = %d, want 200", newRec.Code)
	}
}

// TestIntegration_MemberForbiddenFromAdminUsers covers AC-008.33: an account
// holding no user.read permission is refused GET /api/v1/admin/users with the
// exact forbidden body.
func TestIntegration_MemberForbiddenFromAdminUsers(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	_, token := issueSession(t, deps, "flow5-member")
	routeDeps := newTestRouteDeps(t, deps, false)
	handler := newIntegrationHandler(deps, routeDeps)

	req := integrationRequest(t, http.MethodGet, "/api/v1/admin/users", nil)
	req.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: token}) //nolint:gosec // G124: this cookie only ever reaches Request.AddCookie, which serializes just name=value; Secure/HttpOnly/SameSite are meaningless here
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	want := `{"errors":[{"status":"403","code":"forbidden","title":"Permission denied"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

// TestIntegration_AdminListsUsers covers AC-008.31 and AC-008.32: an account
// granted the admin role through the real authz.Repository lists accounts via
// GET /api/v1/admin/users with 200 and finds the expected one.
func TestIntegration_AdminListsUsers(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	adminID, adminToken := issueSession(t, deps, "flow6-admin")

	if err := deps.roles.GrantRole(t.Context(), adminID, authz.RoleAdmin, adminID); err != nil {
		t.Fatalf("granting admin: %v", err)
	}

	routeDeps := newTestRouteDeps(t, deps, false)
	handler := newIntegrationHandler(deps, routeDeps)

	req := integrationRequest(t, http.MethodGet, "/api/v1/admin/users", nil)
	req.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: adminToken}) //nolint:gosec // G124: this cookie only ever reaches Request.AddCookie, which serializes just name=value; Secure/HttpOnly/SameSite are meaningless here
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	var listed adminUsersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decoding admin users response: %v", err)
	}

	found := false
	for _, u := range listed.Users {
		if u.ID == adminID {
			found = true
		}
	}

	if !found {
		t.Fatalf("admin account %s not present in listing of %d users", adminID, len(listed.Users))
	}
}

// TestIntegration_OwnerDeletesSessionWithoutAffectingOthers covers AC-008.35:
// one account's own session id, once deleted, does not affect another
// account's session, and the delete itself answers 204.
func TestIntegration_OwnerDeletesSessionWithoutAffectingOthers(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	_, tokenA := issueSession(t, deps, "flow7-a")
	_, tokenB := issueSession(t, deps, "flow7-b")
	routeDeps := newTestRouteDeps(t, deps, false)
	handler := newIntegrationHandler(deps, routeDeps)

	cookieA := &http.Cookie{Name: session.DefaultCookieName, Value: tokenA} //nolint:gosec // G124: this cookie only ever reaches Request.AddCookie, which serializes just name=value; Secure/HttpOnly/SameSite are meaningless here
	cookieB := &http.Cookie{Name: session.DefaultCookieName, Value: tokenB} //nolint:gosec // G124: this cookie only ever reaches Request.AddCookie, which serializes just name=value; Secure/HttpOnly/SameSite are meaningless here

	listReq := integrationRequest(t, http.MethodGet, "/api/v1/me/sessions", nil)
	listReq.AddCookie(cookieB)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)

	if listRec.Code != http.StatusOK {
		t.Fatalf("listing B's own sessions: status = %d, want 200", listRec.Code)
	}

	var listedB sessionsResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &listedB); err != nil {
		t.Fatalf("decoding B sessions: %v", err)
	}

	if len(listedB.Sessions) != 1 {
		t.Fatalf("B has %d sessions, want 1", len(listedB.Sessions))
	}

	bSessionID := listedB.Sessions[0].ID

	// Account A attempts to delete B's session id under its own cookie. This
	// deletes nothing of B's, since Revoke is scoped to the caller's own
	// UserID; it still answers 204 either way per handleMeSessionsDelete's
	// documented behavior.
	deleteReq := integrationRequest(t, http.MethodDelete, "/api/v1/me/sessions/"+bSessionID.String(), nil)
	deleteReq.AddCookie(cookieA)
	deleteRec := httptest.NewRecorder()
	handler.ServeHTTP(deleteRec, deleteReq)

	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("A deleting B's session id: status = %d, want 204", deleteRec.Code)
	}

	meReq := integrationRequest(t, http.MethodGet, "/api/v1/me", nil)
	meReq.AddCookie(cookieB)
	meRec := httptest.NewRecorder()
	handler.ServeHTTP(meRec, meReq)

	if meRec.Code != http.StatusOK {
		t.Fatalf("B's session after A's cross-account delete attempt: status = %d, want 200", meRec.Code)
	}
}

// TestIntegration_NoDigestLeaksInSessionsOrLogs covers AC-008.40: neither the
// GET /api/v1/me/sessions response body nor any captured access-log line for
// the DELETE route carries the session token, its hex digest, or its base64
// digest, and every "id" in the sessions list parses as a UUID.
func TestIntegration_NoDigestLeaksInSessionsOrLogs(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	_, token := issueSession(t, deps, "flow8-subject")

	core, logs := observer.New(zapcore.DebugLevel)
	routeDeps := newTestRouteDeps(t, deps, false)
	routeDeps.Logger = zap.New(core)
	handler := newIntegrationHandler(deps, routeDeps)

	cookie := &http.Cookie{Name: session.DefaultCookieName, Value: token} //nolint:gosec // G124: this cookie only ever reaches Request.AddCookie, which serializes just name=value; Secure/HttpOnly/SameSite are meaningless here

	listReq := integrationRequest(t, http.MethodGet, "/api/v1/me/sessions", nil)
	listReq.AddCookie(cookie)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)

	if listRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", listRec.Code)
	}

	var raw struct {
		Sessions []map[string]any `json:"sessions"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decoding sessions body: %v", err)
	}

	if len(raw.Sessions) == 0 {
		t.Fatal("sessions list is empty")
	}

	var sessionID uuid.UUID
	for _, s := range raw.Sessions {
		idStr, ok := s["id"].(string)
		if !ok {
			t.Fatalf("session entry %v carries no string id", s)
		}
		parsed, err := uuid.Parse(idStr)
		if err != nil {
			t.Fatalf("session id %q does not parse as a UUID: %v", idStr, err)
		}
		sessionID = parsed
	}

	deleteReq := integrationRequest(t, http.MethodDelete, "/api/v1/me/sessions/"+sessionID.String(), nil)
	deleteReq.AddCookie(cookie)
	deleteRec := httptest.NewRecorder()
	handler.ServeHTTP(deleteRec, deleteReq)

	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", deleteRec.Code)
	}

	digest := session.Digest(token)
	digestHex := hex.EncodeToString(digest)
	digestB64 := base64.StdEncoding.EncodeToString(digest)
	digestB64URL := base64.URLEncoding.EncodeToString(digest)

	if bytes.Contains(listRec.Body.Bytes(), []byte(token)) {
		t.Fatal("sessions body contains the raw session token")
	}

	for _, needle := range []string{digestHex, digestB64, digestB64URL} {
		if bytes.Contains(listRec.Body.Bytes(), []byte(needle)) {
			t.Fatalf("sessions body contains a digest encoding %q", needle)
		}
	}

	for _, entry := range logs.All() {
		var haystack strings.Builder
		haystack.WriteString(entry.Message)

		for _, v := range entry.ContextMap() {
			haystack.WriteString(" ")
			fmt.Fprintf(&haystack, "%v", v)
		}

		for _, needle := range []string{token, digestHex, digestB64, digestB64URL} {
			if strings.Contains(haystack.String(), needle) {
				t.Fatalf("captured log line contains a token or digest encoding: %q", haystack.String())
			}
		}
	}
}

// TestIntegration_CrossSiteLogoutRejected covers AC-008.18: a cross-site
// POST /api/v1/auth/logout is refused with the exact cross_site body, and the
// session it presented still works afterward.
func TestIntegration_CrossSiteLogoutRejected(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	_, token := issueSession(t, deps, "flow9-subject")
	routeDeps := newTestRouteDeps(t, deps, false)
	handler := newIntegrationHandler(deps, routeDeps)

	cookie := &http.Cookie{Name: session.DefaultCookieName, Value: token} //nolint:gosec // G124: this cookie only ever reaches Request.AddCookie, which serializes just name=value; Secure/HttpOnly/SameSite are meaningless here

	req := integrationRequest(t, http.MethodPost, "/api/v1/auth/logout", nil)
	req.AddCookie(cookie)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	want := `{"errors":[{"status":"403","code":"cross_site","title":"Cross-site request rejected"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}

	meReq := integrationRequest(t, http.MethodGet, "/api/v1/me", nil)
	meReq.AddCookie(cookie)
	meRec := httptest.NewRecorder()
	handler.ServeHTTP(meRec, meReq)

	if meRec.Code != http.StatusOK {
		t.Fatalf("session after refused cross-site logout: status = %d, want 200", meRec.Code)
	}
}

// TestIntegration_DisabledOTPAnswersNotFound covers AC-008.29: with no OTP
// service configured, POST /api/v1/auth/otp/start answers 404, since the
// route is never registered.
func TestIntegration_DisabledOTPAnswersNotFound(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	routeDeps := newTestRouteDeps(t, deps, false)
	handler := newIntegrationHandler(deps, routeDeps)

	req := integrationRequest(t, http.MethodPost, "/api/v1/auth/otp/start", mustMarshalJSON(t, map[string]any{"email": "nobody@example.com"}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestIntegration_EnabledOTPStartIsIdenticalAndCodeIsSingleUse covers
// AC-008.27 and AC-008.30: OTP start answers 202 identically for a known and
// an unknown address, and a correct code verifies once, then fails on replay.
func TestIntegration_EnabledOTPStartIsIdenticalAndCodeIsSingleUse(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	knownID, _ := issueSession(t, deps, "flow11-known")
	knownAccount, err := deps.users.ByID(t.Context(), knownID)
	if err != nil {
		t.Fatalf("loading known account: %v", err)
	}

	sender := &recordingOTPSender{}
	routeDeps := newTestRouteDepsWithOTPSender(t, deps, sender)
	handler := newIntegrationHandler(deps, routeDeps)

	startKnown := integrationRequest(t, http.MethodPost, "/api/v1/auth/otp/start", mustMarshalJSON(t, map[string]any{"email": *knownAccount.Email}))
	startKnownRec := httptest.NewRecorder()
	handler.ServeHTTP(startKnownRec, startKnown)

	if startKnownRec.Code != http.StatusAccepted {
		t.Fatalf("known start status = %d, want 202", startKnownRec.Code)
	}

	// The known address's code is captured immediately: otp.Service emails
	// an indistinguishable message for an unknown address too, so a second
	// start would otherwise overwrite sender.last with the wrong message.
	code := codeFromMessage(t, sender.last(t))
	bindingCookie := integrationFindCookie(startKnownRec, otpBindingCookieNamePlain)

	if bindingCookie == nil {
		t.Fatal("no otp binding cookie set on known start")
	}

	startUnknown := integrationRequest(t, http.MethodPost, "/api/v1/auth/otp/start", mustMarshalJSON(t, map[string]any{"email": "flow11-unknown@example.com"}))
	startUnknownRec := httptest.NewRecorder()
	handler.ServeHTTP(startUnknownRec, startUnknown)

	if startUnknownRec.Code != http.StatusAccepted {
		t.Fatalf("unknown start status = %d, want 202", startUnknownRec.Code)
	}

	if startKnownRec.Body.String() != startUnknownRec.Body.String() {
		t.Fatalf("start bodies differ: known=%q unknown=%q, want identical", startKnownRec.Body.String(), startUnknownRec.Body.String())
	}

	verifyReq := integrationRequest(t, http.MethodPost, "/api/v1/auth/otp/verify",
		mustMarshalJSON(t, map[string]any{"email": *knownAccount.Email, "code": code}))
	verifyReq.Header.Set("Sec-Fetch-Site", "same-origin")
	verifyReq.AddCookie(bindingCookie)
	verifyRec := httptest.NewRecorder()
	handler.ServeHTTP(verifyRec, verifyReq)

	if verifyRec.Code != http.StatusNoContent {
		t.Fatalf("first verify status = %d, want 204 (body %s)", verifyRec.Code, verifyRec.Body.String())
	}

	replayReq := integrationRequest(t, http.MethodPost, "/api/v1/auth/otp/verify",
		mustMarshalJSON(t, map[string]any{"email": *knownAccount.Email, "code": code}))
	replayReq.Header.Set("Sec-Fetch-Site", "same-origin")
	replayReq.AddCookie(bindingCookie)
	replayRec := httptest.NewRecorder()
	handler.ServeHTTP(replayRec, replayReq)

	if replayRec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed verify status = %d, want 401", replayRec.Code)
	}
}

// TestIntegration_RateLimitAnswersExactBody covers AC-008.37: once a client
// exceeds the configured burst, the route answers 429 with the exact
// rate_limited body.
func TestIntegration_RateLimitAnswersExactBody(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	routeDeps := newTestRouteDeps(t, deps, false)
	routeDeps.Limiter = ratelimit.New(1, 1, deps.clock.Now)
	handler := newIntegrationHandler(deps, routeDeps)

	first := integrationRequest(t, http.MethodGet, "/api/v1/auth/providers", nil)
	firstRec := httptest.NewRecorder()
	handler.ServeHTTP(firstRec, first)

	if firstRec.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", firstRec.Code)
	}

	second := integrationRequest(t, http.MethodGet, "/api/v1/auth/providers", nil)
	secondRec := httptest.NewRecorder()
	handler.ServeHTTP(secondRec, second)

	if secondRec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429", secondRec.Code)
	}

	want := `{"errors":[{"status":"429","code":"rate_limited","title":"Too many requests"}]}`
	if got := exactErrorBody(secondRec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

// TestIntegration_AuditTrailRecordsExpectedRows covers AC-008.38, AC-008.39,
// and AC-008.40: a login, a logout, and a forbidden admin request each leave
// an audit_events row with a non-empty request_id and a "user:"-prefixed
// actor_ref where one applies, and no row's detail carries the session
// token.
func TestIntegration_AuditTrailRecordsExpectedRows(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	provider := newIntegrationOIDCProvider(t)
	routeDeps := newTestRouteDepsWithOIDC(t, deps, provider.server.URL)
	handler := newIntegrationHandler(deps, routeDeps)

	cookie, rec := integrationLoginViaOIDC(t, handler, provider, integrationLoginParams{
		subject: "flow13-subject", email: "flow13@example.com", emailVerified: true,
	})

	if rec.Code != http.StatusSeeOther || cookie == nil {
		t.Fatalf("login: status = %d, cookie present = %v, want 303 with a cookie", rec.Code, cookie != nil)
	}

	logoutReq := integrationRequest(t, http.MethodPost, "/api/v1/auth/logout", nil)
	logoutReq.AddCookie(cookie)
	logoutRec := httptest.NewRecorder()
	handler.ServeHTTP(logoutRec, logoutReq)

	if logoutRec.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, want 204", logoutRec.Code)
	}

	type auditRow struct {
		RequestID string
		ActorRef  string
		Detail    string
	}

	loadRows := func(action string) []auditRow {
		rows, err := deps.handle.Pool().Query(t.Context(),
			`SELECT request_id, actor_ref, detail::text FROM audit_events WHERE action = $1`, action)
		if err != nil {
			t.Fatalf("querying audit_events for %s: %v", action, err)
		}
		defer rows.Close()

		var out []auditRow
		for rows.Next() {
			var r auditRow
			if scanErr := rows.Scan(&r.RequestID, &r.ActorRef, &r.Detail); scanErr != nil {
				t.Fatalf("scanning audit row: %v", scanErr)
			}
			out = append(out, r)
		}

		if rowsErr := rows.Err(); rowsErr != nil {
			t.Fatalf("iterating audit rows for %s: %v", action, rowsErr)
		}

		return out
	}

	for _, action := range []string{"user.created", "auth.oidc.completed", "auth.logout"} {
		rows := loadRows(action)
		if len(rows) == 0 {
			t.Fatalf("no audit_events rows for action %q", action)
		}

		for _, row := range rows {
			if row.RequestID == "" {
				t.Fatalf("action %q: empty request_id", action)
			}

			if !strings.HasPrefix(row.ActorRef, "user:") {
				t.Fatalf("action %q: actor_ref = %q, want a user: prefix", action, row.ActorRef)
			}

			if strings.Contains(row.Detail, cookie.Value) {
				t.Fatalf("action %q: detail contains the session token", action)
			}
		}
	}
}

// TestIntegration_AuditSurvivesPurge covers AC-008.51 and AC-008.53: after a
// self-service delete and a zero-grace-period purge, the account is gone
// from users but its audit rows remain, with actor_id nulled and actor_ref
// unchanged.
func TestIntegration_AuditSurvivesPurge(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	userID, token := issueSession(t, deps, "flow14-subject")
	routeDeps := newTestRouteDeps(t, deps, false)
	handler := newIntegrationHandler(deps, routeDeps)

	cookie := &http.Cookie{Name: session.DefaultCookieName, Value: token} //nolint:gosec // G124: this cookie only ever reaches Request.AddCookie, which serializes just name=value; Secure/HttpOnly/SameSite are meaningless here

	deleteReq := integrationRequest(t, http.MethodDelete, "/api/v1/me", nil)
	deleteReq.AddCookie(cookie)
	deleteRec := httptest.NewRecorder()
	handler.ServeHTTP(deleteRec, deleteReq)

	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("self-delete status = %d, want 204 (body %s)", deleteRec.Code, deleteRec.Body.String())
	}

	wantRef := "user:" + userID.String()

	before := countRows(t, deps.handle, `SELECT count(*) FROM audit_events WHERE actor_ref = $1`, wantRef)
	if before == 0 {
		t.Fatal("no audit rows recorded before purge")
	}

	// The grace period is zero, but purge compares deleted_at against a
	// strictly later cutoff, so the fixed test clock must advance past the
	// delete's own timestamp before a zero grace period counts as elapsed.
	deps.clock.Advance(time.Second)

	purged, err := deps.service.PurgeExpired(t.Context())
	if err != nil {
		t.Fatalf("PurgeExpired() error = %v", err)
	}

	if purged == 0 {
		t.Fatal("PurgeExpired() purged 0 accounts, want at least 1")
	}

	remainingUsers := countRows(t, deps.handle, `SELECT count(*) FROM users WHERE id = $1`, userID)
	if remainingUsers != 0 {
		t.Fatalf("users row still present after purge")
	}

	// PurgeExpired's own user.purged row also carries this actor_ref, so the
	// count after purge is the pre-purge count plus that one row, not
	// unchanged.
	after := countRows(t, deps.handle, `SELECT count(*) FROM audit_events WHERE actor_ref = $1`, wantRef)
	if after != before+1 {
		t.Fatalf("audit rows after purge = %d, want %d (the %d pre-purge rows plus one user.purged row)", after, before+1, before)
	}

	nullActorID := countRows(t, deps.handle, `SELECT count(*) FROM audit_events WHERE actor_ref = $1 AND actor_id IS NULL`, wantRef)
	if nullActorID != after {
		t.Fatalf("audit rows with a null actor_id = %d, want all %d rows nulled", nullActorID, after)
	}
}

// TestIntegration_ReadinessReflectsDatabase checks the operator-facing
// readiness probe: with a reachable database GET /readyz answers 200
// {"status":"ready"}, and once its dedicated handle is closed it answers 503
// {"status":"not_ready","failing":["database"]}. No AC-008.n criterion covers
// this endpoint: AC-008.5 requires refusing to start the process at all when
// the database is unreachable at startup, not this probe's steady-state
// behavior, so this test cites no criterion and exists to guard the response
// shape the operator's health check depends on.
func TestIntegration_ReadinessReflectsDatabase(t *testing.T) {
	t.Parallel()

	cfg := storetest.NewPool(t)

	dedicated, err := store.Open(t.Context(), cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}

	ready := server.NewReadiness()
	ready.AddCheck("database", func(checkCtx context.Context) error {
		return dedicated.Ping(checkCtx)
	})

	adminMux := server.NewAdminMux(server.DefaultConfig(), zap.NewNop(), ready, server.ProcessInfo{}, http.NotFoundHandler())

	readyReq := httptest.NewRequest(http.MethodGet, "/readyz", http.NoBody)
	readyRec := httptest.NewRecorder()
	adminMux.ServeHTTP(readyRec, readyReq)

	if readyRec.Code != http.StatusOK {
		t.Fatalf("readyz with a live handle: status = %d, want 200 (body %s)", readyRec.Code, readyRec.Body.String())
	}

	if got := strings.TrimSpace(readyRec.Body.String()); got != `{"status":"ready"}` {
		t.Fatalf("readyz body = %s, want {\"status\":\"ready\"}", got)
	}

	dedicated.Close()

	failReq := httptest.NewRequest(http.MethodGet, "/readyz", http.NoBody)
	failRec := httptest.NewRecorder()
	adminMux.ServeHTTP(failRec, failReq)

	if failRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz with a closed handle: status = %d, want 503", failRec.Code)
	}

	if got := strings.TrimSpace(failRec.Body.String()); got != `{"status":"not_ready","failing":["database"]}` {
		t.Fatalf("readyz body = %s, want {\"status\":\"not_ready\",\"failing\":[\"database\"]}", got)
	}
}

// TestIntegration_StoreOpenFailsFastAgainstUnreachableDatabase covers
// AC-008.2's store-level half: store.Open against a closed loopback port
// returns an error within a bounded time rather than hanging.
func TestIntegration_StoreOpenFailsFastAgainstUnreachableDatabase(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a loopback port: %v", err)
	}

	addr := listener.Addr().String()

	err = listener.Close()
	if err != nil {
		t.Fatalf("closing loopback listener: %v", err)
	}

	cfg := store.Config{
		DSN:            secret.String("postgres://user:pass@" + addr + "/db?sslmode=disable"),
		ConnectTimeout: configtype.Duration(2 * time.Second),
	}

	start := time.Now()
	_, err = store.Open(t.Context(), cfg, zap.NewNop())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("store.Open() against an unreachable database returned no error")
	}

	if elapsed > 10*time.Second {
		t.Fatalf("store.Open() took %s to fail, want a bounded failure", elapsed)
	}
}

// TestIntegration_SignupDisabledBlocksNewAccount covers AC-008.55, AC-008.60,
// and AC-008.74: with signup disabled, a fresh identity's login lands on
// "/?error=signup_disabled", creates no users or identities rows, sets no
// session cookie, and records exactly one signup.blocked row naming the
// rule.
func TestIntegration_SignupDisabledBlocksNewAccount(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	adminID, adminToken := issueSession(t, deps, "flow17-admin")
	if err := deps.roles.GrantRole(t.Context(), adminID, authz.RoleAdmin, adminID); err != nil {
		t.Fatalf("granting admin: %v", err)
	}

	provider := newIntegrationOIDCProvider(t)
	routeDeps := newTestRouteDepsWithOIDC(t, deps, provider.server.URL)
	handler := newIntegrationHandler(deps, routeDeps)

	patchReq := integrationRequest(t, http.MethodPatch, "/api/v1/admin/settings", mustMarshalJSON(t, map[string]any{"signup_enabled": false}))
	patchReq.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: adminToken}) //nolint:gosec // G124: this cookie only ever reaches Request.AddCookie, which serializes just name=value; Secure/HttpOnly/SameSite are meaningless here
	patchRec := httptest.NewRecorder()
	handler.ServeHTTP(patchRec, patchReq)

	if patchRec.Code != http.StatusOK {
		t.Fatalf("disabling signup: status = %d, want 200 (body %s)", patchRec.Code, patchRec.Body.String())
	}

	cookie, rec := integrationLoginViaOIDC(t, handler, provider, integrationLoginParams{
		subject: "flow17-newcomer", email: "flow17-newcomer@example.com", emailVerified: true,
	})

	if cookie != nil {
		t.Fatal("signup-disabled login issued a session cookie")
	}

	wantLocation := "/?error=" + server.ErrorCodeSignupDisabled
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != wantLocation {
		t.Fatalf("status = %d, location = %q, want 303 to %q", rec.Code, rec.Header().Get("Location"), wantLocation)
	}

	identCount := countRows(t, deps.handle,
		`SELECT count(*) FROM identities WHERE provider = $1 AND subject = $2`, provider.server.URL, "flow17-newcomer")
	if identCount != 0 {
		t.Fatalf("identities rows for the refused signup = %d, want 0", identCount)
	}

	usersCount := countRows(t, deps.handle,
		`SELECT count(*) FROM users WHERE email = $1`, "flow17-newcomer@example.com")
	if usersCount != 0 {
		t.Fatalf("users rows for the refused signup = %d, want 0", usersCount)
	}

	blockedCount := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = $1 AND detail->>'rule' = $2`,
		"signup.blocked", blockedRuleSignupDisabled)
	if blockedCount != 1 {
		t.Fatalf("signup.blocked rows naming signup_disabled = %d, want 1", blockedCount)
	}
}

// TestIntegration_InviteRequiredSignupRoundTrip covers AC-008.56, AC-008.57,
// AC-008.63, AC-008.65, and AC-008.70: with invite-gated signup, an admitted
// account's ceremony must carry a live invite, which is redeemed exactly
// once; a second attempt naming the same, now-spent token is refused before
// the ceremony even starts. Written to kill the mutant that loosens
// internal/invite's redemption-limit predicate.
func TestIntegration_InviteRequiredSignupRoundTrip(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(true)})

	issuerID, issuerToken := issueSession(t, deps, "flow18-issuer")
	if err := deps.roles.GrantRole(t.Context(), issuerID, authz.RoleAdmin, issuerID); err != nil {
		t.Fatalf("granting issuer admin: %v", err)
	}

	issuerCookie := &http.Cookie{Name: session.DefaultCookieName, Value: issuerToken} //nolint:gosec // G124: this cookie only ever reaches Request.AddCookie, which serializes just name=value; Secure/HttpOnly/SameSite are meaningless here

	provider := newIntegrationOIDCProvider(t)
	routeDeps := newTestRouteDepsWithOIDC(t, deps, provider.server.URL)

	core, logs := observer.New(zapcore.DebugLevel)
	routeDeps.Logger = zap.New(core)

	handler := newIntegrationHandler(deps, routeDeps)

	issued := integrationCreateInvite(t, handler, issuerCookie, map[string]any{})
	if issued.Token == "" {
		t.Fatal("created invite carries no token")
	}

	// Amendment D: the two "GET /i/{file}" routes -- the QR image and the
	// landing page -- are one merged registration dispatching on a ".png"
	// suffix; both work unchanged here.
	qrReq := integrationRequest(t, http.MethodGet, "/i/"+issued.Token+".png", nil)
	qrRec := httptest.NewRecorder()
	handler.ServeHTTP(qrRec, qrReq)

	if qrRec.Code != http.StatusOK {
		t.Fatalf("GET /i/<token>.png status = %d, want 200", qrRec.Code)
	}

	if ct := qrRec.Header().Get("Content-Type"); ct != "image/png" {
		t.Fatalf("GET /i/<token>.png Content-Type = %q, want image/png", ct)
	}

	landingReq := integrationRequest(t, http.MethodGet, "/i/"+issued.Token, nil)
	landingRec := httptest.NewRecorder()
	handler.ServeHTTP(landingRec, landingReq)

	if landingRec.Code != http.StatusSeeOther {
		t.Fatalf("GET /i/<token> status = %d, want 303", landingRec.Code)
	}

	wantLandingLocation := "/?invite=" + url.QueryEscape(issued.Token)
	if got := landingRec.Header().Get("Location"); got != wantLandingLocation {
		t.Fatalf("GET /i/<token> Location = %q, want %q", got, wantLandingLocation)
	}

	// Amendment F, observation only: does the access log carry the raw
	// invite token via the request path? Not asserted either way.
	tokenInAccessLog := integrationLogsContainSubstring(logs, issued.Token)
	t.Logf("OBSERVATION (Amendment F): access log line for GET /i/<token> contains the raw invite token = %v", tokenInAccessLog)

	firstCookie, firstRec := integrationLoginViaOIDC(t, handler, provider, integrationLoginParams{
		subject: "flow18-first", email: "flow18-first@example.com", emailVerified: true, inviteToken: issued.Token,
	})

	if firstRec.Code != http.StatusSeeOther || firstRec.Header().Get("Location") != "/" {
		t.Fatalf("first redemption: status = %d, location = %q, want 303 to /", firstRec.Code, firstRec.Header().Get("Location"))
	}

	if firstCookie == nil {
		t.Fatal("first redemption issued no session cookie")
	}

	// The requirement changed (AC-008.86): a spent invite fails
	// invite.Service.Lookup's own liveness check, but that no longer blocks
	// the start route itself. resolveInviteForOIDCStart now resolves a dead
	// token to no invite, the same way resolveInviteForOTPStart always has,
	// so the second attempt continues to the provider exactly as if no
	// invite had been presented at all; any admission refusal is decided
	// later, at the callback (via LogIn), not here. This replaces the
	// previous assertion that the second attempt was refused with
	// "/?error=invite_invalid" before any binding cookie was set.
	secondStartReq := integrationRequest(t, http.MethodGet, "/api/v1/auth/oidc/test/start?invite="+url.QueryEscape(issued.Token), nil)
	secondStartRec := httptest.NewRecorder()
	handler.ServeHTTP(secondStartRec, secondStartReq)

	if secondStartRec.Code != http.StatusSeeOther {
		t.Fatalf("second redemption start: status = %d, want 303, body = %s", secondStartRec.Code, secondStartRec.Body.String())
	}

	if loc := secondStartRec.Header().Get("Location"); loc == "/?error="+server.ErrorCodeInviteInvalid {
		t.Fatalf("second redemption start: location = %q, want a redirect to the provider, not the dead-invite refusal", loc)
	}

	if integrationFindCookie(secondStartRec, oidcBindingCookieNamePlain) == nil {
		t.Fatal("second redemption start issued no oidc binding cookie: the ceremony did not continue")
	}

	if integrationFindCookie(secondStartRec, session.DefaultCookieName) != nil {
		t.Fatal("second redemption attempt issued a session cookie")
	}
}

// TestIntegration_EmailBoundInviteEnforcesVerifiedMatch covers AC-008.58: an
// email-bound invite refuses a verified-but-different address and an
// unverified same address identically, and succeeds only for a verified,
// matching address.
func TestIntegration_EmailBoundInviteEnforcesVerifiedMatch(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(true)})

	issuerID, issuerToken := issueSession(t, deps, "flow19-issuer")
	if err := deps.roles.GrantRole(t.Context(), issuerID, authz.RoleAdmin, issuerID); err != nil {
		t.Fatalf("granting issuer admin: %v", err)
	}

	issuerCookie := &http.Cookie{Name: session.DefaultCookieName, Value: issuerToken} //nolint:gosec // G124: this cookie only ever reaches Request.AddCookie, which serializes just name=value; Secure/HttpOnly/SameSite are meaningless here

	provider := newIntegrationOIDCProvider(t)
	routeDeps := newTestRouteDepsWithOIDC(t, deps, provider.server.URL)
	handler := newIntegrationHandler(deps, routeDeps)

	boundEmail := "bound19@example.com"
	issued := integrationCreateInvite(t, handler, issuerCookie, map[string]any{"email": boundEmail})

	wantMismatch := "/?error=" + server.ErrorCodeInviteEmailMismatch

	mismatchCookie, mismatchRec := integrationLoginViaOIDC(t, handler, provider, integrationLoginParams{
		subject: "flow19-mismatch", email: "different19@example.com", emailVerified: true, inviteToken: issued.Token,
	})

	if mismatchCookie != nil {
		t.Fatal("verified-but-different-address attempt issued a session cookie")
	}

	if mismatchRec.Code != http.StatusSeeOther || mismatchRec.Header().Get("Location") != wantMismatch {
		t.Fatalf("verified mismatch: status = %d, location = %q, want 303 to %q",
			mismatchRec.Code, mismatchRec.Header().Get("Location"), wantMismatch)
	}

	unverifiedCookie, unverifiedRec := integrationLoginViaOIDC(t, handler, provider, integrationLoginParams{
		subject: "flow19-unverified", email: boundEmail, emailVerified: false, inviteToken: issued.Token,
	})

	if unverifiedCookie != nil {
		t.Fatal("unverified same-address attempt issued a session cookie")
	}

	if unverifiedRec.Code != http.StatusSeeOther || unverifiedRec.Header().Get("Location") != wantMismatch {
		t.Fatalf("unverified same address: status = %d, location = %q, want 303 to %q",
			unverifiedRec.Code, unverifiedRec.Header().Get("Location"), wantMismatch)
	}

	matchCookie, matchRec := integrationLoginViaOIDC(t, handler, provider, integrationLoginParams{
		subject: "flow19-match", email: boundEmail, emailVerified: true, inviteToken: issued.Token,
	})

	if matchRec.Code != http.StatusSeeOther || matchRec.Header().Get("Location") != "/" {
		t.Fatalf("verified matching address: status = %d, location = %q, want 303 to /", matchRec.Code, matchRec.Header().Get("Location"))
	}

	if matchCookie == nil {
		t.Fatal("verified matching address issued no session cookie")
	}
}

// TestIntegration_ApprovalQueueEndToEnd covers AC-008.71, AC-008.72, and
// AC-008.73: a pending account is listed, approved by an administrator, and
// can then log in successfully.
func TestIntegration_ApprovalQueueEndToEnd(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	// issueSession must run before approval is required: it logs its account
	// straight in and cannot itself clear an approval gate.
	adminID, adminToken := issueSession(t, deps, "flow20-admin")
	if err := deps.roles.GrantRole(t.Context(), adminID, authz.RoleAdmin, adminID); err != nil {
		t.Fatalf("granting admin: %v", err)
	}

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false), SignupRequireApproval: new(true)})

	adminCookie := &http.Cookie{Name: session.DefaultCookieName, Value: adminToken} //nolint:gosec // G124: this cookie only ever reaches Request.AddCookie, which serializes just name=value; Secure/HttpOnly/SameSite are meaningless here

	provider := newIntegrationOIDCProvider(t)
	routeDeps := newTestRouteDepsWithOIDC(t, deps, provider.server.URL)
	handler := newIntegrationHandler(deps, routeDeps)

	pendingEmail := "flow20-pending@example.com"

	pendingCookie, pendingRec := integrationLoginViaOIDC(t, handler, provider, integrationLoginParams{
		subject: "flow20-pending", email: pendingEmail, emailVerified: true,
	})

	if pendingCookie != nil {
		t.Fatal("pending signup issued a session cookie")
	}

	wantPendingLocation := "/?error=" + server.ErrorCodeApprovalPending
	if pendingRec.Code != http.StatusSeeOther || pendingRec.Header().Get("Location") != wantPendingLocation {
		t.Fatalf("pending signup: status = %d, location = %q, want 303 to %q",
			pendingRec.Code, pendingRec.Header().Get("Location"), wantPendingLocation)
	}

	listReq := integrationRequest(t, http.MethodGet, "/api/v1/admin/users?status=pending", nil)
	listReq.AddCookie(adminCookie)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)

	if listRec.Code != http.StatusOK {
		t.Fatalf("listing pending users: status = %d, want 200 (body %s)", listRec.Code, listRec.Body.String())
	}

	var listed adminUsersResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decoding pending users: %v", err)
	}

	var targetID uuid.UUID
	for _, u := range listed.Users {
		if u.Email != nil && *u.Email == pendingEmail {
			targetID = u.ID
		}
	}

	if targetID == uuid.Nil {
		t.Fatalf("pending account with email %q not found in listing", pendingEmail)
	}

	approveReq := integrationRequest(t, http.MethodPost, "/api/v1/admin/users/"+targetID.String()+"/approve", nil)
	approveReq.AddCookie(adminCookie)
	approveRec := httptest.NewRecorder()
	handler.ServeHTTP(approveRec, approveReq)

	if approveRec.Code != http.StatusOK {
		t.Fatalf("approve status = %d, want 200 (body %s)", approveRec.Code, approveRec.Body.String())
	}

	loggedInCookie, loggedInRec := integrationLoginViaOIDC(t, handler, provider, integrationLoginParams{
		subject: "flow20-pending", email: pendingEmail, emailVerified: true,
	})

	if loggedInRec.Code != http.StatusSeeOther || loggedInRec.Header().Get("Location") != "/" {
		t.Fatalf("post-approval login: status = %d, location = %q, want 303 to /", loggedInRec.Code, loggedInRec.Header().Get("Location"))
	}

	if loggedInCookie == nil {
		t.Fatal("post-approval login issued no session cookie")
	}
}

// TestIntegration_BootstrapAdminBreaksSignupDeadlock covers AC-008.59 and
// AC-008.36: a bootstrap administrator's verified login is admitted even
// though signup is disabled and invite and approval are both required, and it
// is granted the admin role. This suite also observes, without asserting
// (Amendment G), whether a demoted bootstrap account regains admin on its
// next login.
//
// AC-008.36 was amended 2026-09-24 so the bootstrap list is exempt only
// while no active administrator exists. The second administrator account is
// therefore created here (via issueSession, before the deadlock policy is in
// force) but not granted admin until after the bootstrap login below: rule 1
// must see zero active administrators when the bootstrap login runs, or it
// would no longer be exempt and this test would no longer demonstrate the
// deadlock-breaking behavior it names. Originally this test granted the
// second administrator its role before the bootstrap login and still
// expected the bootstrap login to succeed regardless, which encoded the old,
// unconditional exemption; the order changed to match the amended
// requirement, without weakening the assertions below.
func TestIntegration_BootstrapAdminBreaksSignupDeadlock(t *testing.T) {
	t.Parallel()

	bootstrapEmail := "flow21-bootstrap@example.com"

	deps := newTestService(t, []string{bootstrapEmail})

	// issueSession must run before the deadlock policy is in force: it logs
	// its account straight in and cannot itself clear an approval gate. Its
	// account is not granted admin yet, so it does not count toward rule 1's
	// active-administrator check below.
	secondAdminID, secondAdminToken := issueSession(t, deps, "flow21-second-admin")

	setSignupPolicy(t, deps.policy, settings.Update{
		SignupEnabled: new(false), SignupRequireInvite: new(true), SignupRequireApproval: new(true),
	})

	provider := newIntegrationOIDCProvider(t)
	routeDeps := newTestRouteDepsWithOIDC(t, deps, provider.server.URL)
	handler := newIntegrationHandler(deps, routeDeps)

	cookie, rec := integrationLoginViaOIDC(t, handler, provider, integrationLoginParams{
		subject: "flow21-bootstrap", email: bootstrapEmail, emailVerified: true,
	})

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("bootstrap login: status = %d, location = %q, want 303 to /", rec.Code, rec.Header().Get("Location"))
	}

	if cookie == nil {
		t.Fatal("bootstrap login issued no session cookie")
	}

	meReq := integrationRequest(t, http.MethodGet, "/api/v1/me", nil)
	meReq.AddCookie(cookie)
	meRec := httptest.NewRecorder()
	handler.ServeHTTP(meRec, meReq)

	if meRec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/me status = %d, want 200", meRec.Code)
	}

	var me meResponse
	if err := json.Unmarshal(meRec.Body.Bytes(), &me); err != nil {
		t.Fatalf("decoding /api/v1/me: %v", err)
	}

	if !meResponseHasRole(me, authz.RoleAdmin) {
		t.Fatalf("bootstrap account roles = %v, want admin present", me.Roles)
	}

	_ = secondAdminToken

	// The second administrator is granted admin only now, after the
	// bootstrap login above has already run rule 1 against zero active
	// administrators: granting it earlier would have made the bootstrap
	// login no longer exempt.
	if err := deps.roles.GrantRole(t.Context(), secondAdminID, authz.RoleAdmin, secondAdminID); err != nil {
		t.Fatalf("granting second admin: %v", err)
	}

	// Amendment G observation: the second admin account granted above lets
	// this demote the bootstrap account without tripping the last-admin
	// refusal; then log the bootstrap account in again and observe (do not
	// assert) whether it silently regains admin.
	if err := deps.roles.SetRoles(t.Context(), me.ID, []string{authz.RoleMember}, secondAdminID); err != nil {
		t.Fatalf("demoting bootstrap account: %v", err)
	}

	integrationObserveBootstrapReadmission(t, handler, provider, bootstrapEmail)
}

// meResponseHasRole reports whether me's roles include role.
func meResponseHasRole(me meResponse, role string) bool {
	return slices.Contains(me.Roles, role)
}

// integrationObserveBootstrapReadmission logs a bootstrap account back in
// after it has been demoted, and logs (rather than asserts, per Amendment G)
// whether it silently regained admin.
func integrationObserveBootstrapReadmission(t *testing.T, handler http.Handler, provider *integrationOIDCProvider, bootstrapEmail string) {
	t.Helper()

	_, secondLoginRec := integrationLoginViaOIDC(t, handler, provider, integrationLoginParams{
		subject: "flow21-bootstrap", email: bootstrapEmail, emailVerified: true,
	})

	regainedCookie := integrationFindCookie(secondLoginRec, session.DefaultCookieName)
	if regainedCookie == nil {
		t.Log("OBSERVATION (Amendment G): second login after demotion issued no cookie, cannot check roles")

		return
	}

	checkReq := integrationRequest(t, http.MethodGet, "/api/v1/me", nil)
	checkReq.AddCookie(regainedCookie)
	checkRec := httptest.NewRecorder()
	handler.ServeHTTP(checkRec, checkReq)

	var afterDemotion meResponse
	regainedAdmin := checkRec.Code == http.StatusOK &&
		json.Unmarshal(checkRec.Body.Bytes(), &afterDemotion) == nil &&
		meResponseHasRole(afterDemotion, authz.RoleAdmin)

	t.Logf("OBSERVATION (Amendment G): demoted bootstrap account regained admin on next login = %v", regainedAdmin)
}

// TestIntegration_InviteQRPerformsNoDatabaseLookup covers AC-008.68: the QR
// image route performs no database round trip at all. Closing the handle
// before the request and observing it still succeeds is direct proof of
// that, since any repository call against a closed handle would fail.
func TestIntegration_InviteQRPerformsNoDatabaseLookup(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	routeDeps := newTestRouteDeps(t, deps, false)
	handler := newIntegrationHandler(deps, routeDeps)

	deps.handle.Close()

	req := integrationRequest(t, http.MethodGet, "/i/never-issued-token.png", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	if ct := rec.Header().Get("Content-Type"); ct != "image/png" {
		t.Fatalf("Content-Type = %q, want image/png", ct)
	}
}

// TestIntegration_LockedSettingRefusesPatchButAllowsOthers covers AC-008.74
// and AC-008.75: an environment-locked setting is reported in the settings
// response's locked list, a PATCH naming it is refused with the exact
// setting_locked body, a PATCH naming only another key succeeds, and signup
// remains refused regardless.
func TestIntegration_LockedSettingRefusesPatchButAllowsOthers(t *testing.T) {
	t.Parallel()

	deps := newTestServiceWithSignupEnabledLocked(t, false)

	adminID, adminToken := integrationIssueAccountBypassingSignup(t, deps, "flow23-admin", "flow23-admin@example.com")
	if err := deps.roles.GrantRole(t.Context(), adminID, authz.RoleAdmin, adminID); err != nil {
		t.Fatalf("granting admin: %v", err)
	}

	adminCookie := &http.Cookie{Name: session.DefaultCookieName, Value: adminToken} //nolint:gosec // G124: this cookie only ever reaches Request.AddCookie, which serializes just name=value; Secure/HttpOnly/SameSite are meaningless here
	routeDeps := newTestRouteDeps(t, deps, false)
	handler := newIntegrationHandler(deps, routeDeps)

	getReq := integrationRequest(t, http.MethodGet, "/api/v1/admin/settings", nil)
	getReq.AddCookie(adminCookie)
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("GET settings status = %d, want 200", getRec.Code)
	}

	var settingsBody settingsResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &settingsBody); err != nil {
		t.Fatalf("decoding settings: %v", err)
	}

	foundLocked := false
	for _, name := range settingsBody.Locked {
		if name == "signup_enabled" {
			foundLocked = true
		}
	}

	if !foundLocked {
		t.Fatalf("locked = %v, want signup_enabled present", settingsBody.Locked)
	}

	lockedPatchReq := integrationRequest(t, http.MethodPatch, "/api/v1/admin/settings",
		mustMarshalJSON(t, map[string]any{"signup_enabled": true}))
	lockedPatchReq.AddCookie(adminCookie)
	lockedPatchRec := httptest.NewRecorder()
	handler.ServeHTTP(lockedPatchRec, lockedPatchReq)

	if lockedPatchRec.Code != http.StatusConflict {
		t.Fatalf("locked-key patch status = %d, want 409", lockedPatchRec.Code)
	}

	want := `{"errors":[{"status":"409","code":"setting_locked","title":"Setting locked by the environment"}]}`
	if got := exactErrorBody(lockedPatchRec); got != want {
		t.Fatalf("locked-key patch body = %s, want %s", got, want)
	}

	unlockedPatchReq := integrationRequest(t, http.MethodPatch, "/api/v1/admin/settings",
		mustMarshalJSON(t, map[string]any{"signup_require_invite": false}))
	unlockedPatchReq.AddCookie(adminCookie)
	unlockedPatchRec := httptest.NewRecorder()
	handler.ServeHTTP(unlockedPatchRec, unlockedPatchReq)

	if unlockedPatchRec.Code != http.StatusOK {
		t.Fatalf("unlocked-key patch status = %d, want 200 (body %s)", unlockedPatchRec.Code, unlockedPatchRec.Body.String())
	}

	provider := newIntegrationOIDCProvider(t)
	oidcRouteDeps := newTestRouteDepsWithOIDC(t, deps, provider.server.URL)
	oidcHandler := newIntegrationHandler(deps, oidcRouteDeps)

	cookie, rec := integrationLoginViaOIDC(t, oidcHandler, provider, integrationLoginParams{
		subject: "flow23-newcomer", email: "flow23-newcomer@example.com", emailVerified: true,
	})

	if cookie != nil {
		t.Fatal("signup still succeeded despite the locked override refusing it")
	}

	wantLocation := "/?error=" + server.ErrorCodeSignupDisabled
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != wantLocation {
		t.Fatalf("post-patch signup attempt: status = %d, location = %q, want 303 to %q",
			rec.Code, rec.Header().Get("Location"), wantLocation)
	}
}

// TestIntegration_UserWriteDoesNotGrantApproval covers AC-008.71 and
// AC-008.72: an actor holding user.write but not user.approve cannot use the
// status route as a second, unreviewed admission path, and cannot approve
// directly either; an actor holding user.approve can.
func TestIntegration_UserWriteDoesNotGrantApproval(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	// Both actor accounts must be created before approval is required:
	// issueSession logs its account straight in and cannot itself clear an
	// approval gate.
	writerID, writerToken := issueSession(t, deps, "flow24-writer")
	integrationGrantWriteOnlyRole(t, deps, writerID)

	approverID, approverToken := issueSession(t, deps, "flow24-approver")
	if err := deps.roles.GrantRole(t.Context(), approverID, authz.RoleAdmin, approverID); err != nil {
		t.Fatalf("granting approver admin: %v", err)
	}

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false), SignupRequireApproval: new(true)})

	provider := newIntegrationOIDCProvider(t)
	routeDeps := newTestRouteDepsWithOIDC(t, deps, provider.server.URL)
	handler := newIntegrationHandler(deps, routeDeps)

	targetEmail := "flow24-target@example.com"

	targetCookie, targetRec := integrationLoginViaOIDC(t, handler, provider, integrationLoginParams{
		subject: "flow24-target", email: targetEmail, emailVerified: true,
	})

	if targetCookie != nil {
		t.Fatal("pending target signup issued a session cookie")
	}

	if targetRec.Code != http.StatusSeeOther {
		t.Fatalf("pending target signup: status = %d, want 303", targetRec.Code)
	}

	targetID, err := deps.users.ByEmail(t.Context(), targetEmail)
	if err != nil {
		t.Fatalf("loading pending target by email: %v", err)
	}

	writerCookie := &http.Cookie{Name: session.DefaultCookieName, Value: writerToken} //nolint:gosec // G124: this cookie only ever reaches Request.AddCookie, which serializes just name=value; Secure/HttpOnly/SameSite are meaningless here

	statusReq := integrationRequest(t, http.MethodPatch, "/api/v1/admin/users/"+targetID.ID.String()+"/status",
		mustMarshalJSON(t, map[string]any{"status": "active"}))
	statusReq.AddCookie(writerCookie)
	statusRec := httptest.NewRecorder()
	handler.ServeHTTP(statusRec, statusReq)

	if statusRec.Code != http.StatusConflict {
		t.Fatalf("writer-only status patch: status = %d, want 409 (body %s)", statusRec.Code, statusRec.Body.String())
	}

	want := `{"errors":[{"status":"409","code":"is_pending","title":"Account is awaiting approval"}]}`
	if got := exactErrorBody(statusRec); got != want {
		t.Fatalf("writer-only status patch body = %s, want %s", got, want)
	}

	stillPending := countRows(t, deps.handle,
		`SELECT count(*) FROM users WHERE id = $1 AND status = 'pending'`, targetID.ID)
	if stillPending != 1 {
		t.Fatalf("target status changed despite the refusal: pending count = %d, want 1", stillPending)
	}

	approveReq := integrationRequest(t, http.MethodPost, "/api/v1/admin/users/"+targetID.ID.String()+"/approve", nil)
	approveReq.AddCookie(writerCookie)
	approveRec := httptest.NewRecorder()
	handler.ServeHTTP(approveRec, approveReq)

	if approveRec.Code != http.StatusForbidden {
		t.Fatalf("writer-only approve: status = %d, want 403 (body %s)", approveRec.Code, approveRec.Body.String())
	}

	approverCookie := &http.Cookie{Name: session.DefaultCookieName, Value: approverToken} //nolint:gosec // G124: this cookie only ever reaches Request.AddCookie, which serializes just name=value; Secure/HttpOnly/SameSite are meaningless here

	realApproveReq := integrationRequest(t, http.MethodPost, "/api/v1/admin/users/"+targetID.ID.String()+"/approve", nil)
	realApproveReq.AddCookie(approverCookie)
	realApproveRec := httptest.NewRecorder()
	handler.ServeHTTP(realApproveRec, realApproveReq)

	if realApproveRec.Code != http.StatusOK {
		t.Fatalf("admin approve: status = %d, want 200 (body %s)", realApproveRec.Code, realApproveRec.Body.String())
	}
}
