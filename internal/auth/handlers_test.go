//go:build integration

package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
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
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/oidc"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/otp"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/passkey"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authflow"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/invite"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/mail"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/ratelimit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/secret"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/settings"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/user"
)

// testPublicOriginForRoutes is the origin the RejectCrossSiteAlways-wrapped
// routes in this file compare a request's Origin header against.
const testPublicOriginForRoutes = "https://service.example"

// newTestRouteDeps builds a RouteDeps from deps' already-migrated
// collaborators. When full is true, Providers, Passkeys, and Codes are all
// non-nil, using syntactically valid but never-dialed configuration (a
// provider issuer that resolves to nothing and an authenticator RP that
// exists only in test data), so the route-registration matrix can be
// observed through mux.Handler without ever reaching a live external
// service. When full is false, all three are nil, leaving only the
// always-on routes registered.
func newTestRouteDeps(t *testing.T, deps testDeps, full bool) RouteDeps {
	t.Helper()

	limiter := ratelimit.New(1000, 1000, deps.clock.Now)

	proxies, err := server.NewTrustedProxies(server.DefaultProxyConfig())
	if err != nil {
		t.Fatalf("NewTrustedProxies() error = %v", err)
	}

	routeDeps := RouteDeps{
		Sessions:     deps.sessions,
		Users:        deps.users,
		Roles:        deps.roles,
		Limiter:      limiter,
		Proxies:      proxies,
		Logger:       zap.NewNop(),
		PublicOrigin: testPublicOriginForRoutes,
		CookieSecure: false,
		// Credentials backs the two credential self-service routes, which
		// are registered whether or not Passkeys is, matching production's
		// RouteDeps.Credentials being wired up regardless of WebAuthn.
		Credentials: passkey.NewRepository(deps.handle, deps.clock.Now),
		FlowTTL:     time.Minute,
	}

	if !full {
		return routeDeps
	}

	flows := authflow.NewStore(deps.handle, time.Minute, deps.clock.Now)

	oidcCfg := oidc.Config{
		PublicOrigin: testPublicOriginForRoutes,
		Providers: []oidc.ProviderConfig{
			{
				Key:          "test",
				Issuer:       "https://issuer.invalid",
				ClientID:     "client-id",
				ClientSecret: secret.String("client-secret"),
				Scopes:       []string{"profile"},
				DisplayName:  "Test Provider",
			},
		},
		ClockSkew: configtype.Duration(30 * time.Second),
	}

	registry, err := oidc.NewRegistry(oidcCfg, flows, http.DefaultClient, zap.NewNop())
	if err != nil {
		t.Fatalf("oidc.NewRegistry() error = %v", err)
	}

	credentials := passkey.NewRepository(deps.handle, deps.clock.Now)

	passkeys, err := passkey.NewService(passkey.Config{
		Enabled:       true,
		RPID:          "service.example",
		RPDisplayName: "service",
		RPOrigins:     []string{testPublicOriginForRoutes},
	}, credentials, flows, zap.NewNop())
	if err != nil {
		t.Fatalf("passkey.NewService() error = %v", err)
	}

	codes := otp.NewService(otp.Config{
		Enabled:     true,
		CodeTTL:     configtype.Duration(10 * time.Minute),
		MaxAttempts: 5,
	}, deps.handle, mail.NewDisabledSender(), zap.NewNop(), deps.clock.Now)

	routeDeps.Providers = registry
	routeDeps.Passkeys = passkeys
	routeDeps.Credentials = credentials
	routeDeps.Codes = codes

	return routeDeps
}

// newAuthedMux wraps a fresh mux carrying deps.svc's Routes with
// deps.service.Authenticate, so a request presenting a session cookie
// resolves to an authenticated subject the way the real application does.
func newAuthedMux(deps testDeps, routeDeps RouteDeps) http.Handler {
	mux := http.NewServeMux()
	deps.service.Routes(mux, routeDeps)

	return deps.service.Authenticate(deps.sessions, mux)
}

// exactErrorBody reads rec's body, trims the trailing newline WriteJSON's
// encoder adds, and returns it for a byte-for-byte comparison against the
// error shape design.md's "Interfaces" section fixes.
func exactErrorBody(rec *httptest.ResponseRecorder) string {
	return strings.TrimSuffix(rec.Body.String(), "\n")
}

// recordingOTPSender is a mail.Sender that records every message handed to
// it, so a test can recover the code emailed to an address without the otp
// package ever exposing it directly.
type recordingOTPSender struct {
	mu       sync.Mutex
	messages []mail.Message
}

// Send implements mail.Sender by recording msg and never failing.
func (s *recordingOTPSender) Send(_ context.Context, msg mail.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.messages = append(s.messages, msg)

	return nil
}

// last returns the most recently recorded message, failing t when none has
// been recorded.
func (s *recordingOTPSender) last(t *testing.T) mail.Message {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.messages) == 0 {
		t.Fatal("recordingOTPSender: no messages recorded")
	}

	return s.messages[len(s.messages)-1]
}

// otpCodePattern matches the 8-digit code otp.Service emails.
var otpCodePattern = regexp.MustCompile(`\b\d{8}\b`)

// codeFromMessage extracts the emailed code from msg's body, failing t when
// none is found.
func codeFromMessage(t *testing.T, msg mail.Message) string {
	t.Helper()

	code := otpCodePattern.FindString(msg.Body)
	if code == "" {
		t.Fatalf("no code found in message body %q", msg.Body)
	}

	return code
}

// newTestRouteDepsWithOTPSender returns a RouteDeps with only Codes wired,
// backed by sender, so a test can recover the code a route mails without
// standing up the full route matrix newTestRouteDeps(deps, true) builds.
func newTestRouteDepsWithOTPSender(t *testing.T, deps testDeps, sender mail.Sender) RouteDeps {
	t.Helper()

	routeDeps := newTestRouteDeps(t, deps, false)
	routeDeps.Codes = otp.NewService(otp.Config{
		Enabled:     true,
		CodeTTL:     configtype.Duration(10 * time.Minute),
		MaxAttempts: 5,
	}, deps.handle, sender, zap.NewNop(), deps.clock.Now)

	return routeDeps
}

// newOIDCDiscoveryServer starts a minimal OpenID Connect discovery server
// (discovery document plus JWKS, no token endpoint) so a test can drive
// Registry.Start through a real discovery round trip without needing a full
// login ceremony to complete.
func newOIDCDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	discovery := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{{PublicKey: &priv.PublicKey, KeyID: "test-key", Algorithm: goidc.RS256}},
	}

	mux := http.NewServeMux()
	mux.Handle("/.well-known/openid-configuration", discovery)
	mux.Handle("/keys", discovery)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	discovery.SetIssuer(srv.URL)

	return srv
}

// newTestRouteDepsWithOIDC returns a RouteDeps whose Providers is a live
// Registry with one provider, "test", discoverable against issuerURL.
func newTestRouteDepsWithOIDC(t *testing.T, deps testDeps, issuerURL string) RouteDeps {
	t.Helper()

	routeDeps := newTestRouteDeps(t, deps, false)

	flows := authflow.NewStore(deps.handle, time.Minute, deps.clock.Now)

	oidcCfg := oidc.Config{
		PublicOrigin: testPublicOriginForRoutes,
		Providers: []oidc.ProviderConfig{
			{
				Key:          "test",
				Issuer:       issuerURL,
				ClientID:     "client-id",
				ClientSecret: secret.String("client-secret"),
				Scopes:       []string{"profile"},
				DisplayName:  "Test Provider",
			},
		},
		ClockSkew: configtype.Duration(30 * time.Second),
	}

	registry, err := oidc.NewRegistry(oidcCfg, flows, http.DefaultClient, zap.NewNop())
	if err != nil {
		t.Fatalf("oidc.NewRegistry() error = %v", err)
	}

	routeDeps.Providers = registry

	return routeDeps
}

// TestRoutes_FullyEnabled_RegistersAllSeventeen covers the route-enablement
// matrix half of design.md's "Interfaces" section where every optional
// method is configured: all 17 routes this package owns must be registered.
// Covers AC-008.29.
func TestRoutes_FullyEnabled_RegistersAllSeventeen(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	routeDeps := newTestRouteDeps(t, deps, true)

	mux := http.NewServeMux()
	deps.service.Routes(mux, routeDeps)

	registered := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/auth/providers"},
		{http.MethodGet, "/api/v1/auth/oidc/test/start"},
		{http.MethodGet, "/api/v1/auth/oidc/test/callback"},
		{http.MethodPost, "/api/v1/auth/webauthn/register/start"},
		{http.MethodPost, "/api/v1/auth/webauthn/register/finish"},
		{http.MethodPost, "/api/v1/auth/webauthn/login/start"},
		{http.MethodPost, "/api/v1/auth/webauthn/login/finish"},
		{http.MethodGet, "/api/v1/me/credentials"},
		{http.MethodDelete, "/api/v1/me/credentials/" + uuid.New().String()},
		{http.MethodPost, "/api/v1/auth/otp/start"},
		{http.MethodPost, "/api/v1/auth/otp/verify"},
		{http.MethodPost, "/api/v1/auth/logout"},
		{http.MethodGet, "/api/v1/me"},
		{http.MethodGet, "/api/v1/me/sessions"},
		{http.MethodDelete, "/api/v1/me/sessions/" + uuid.New().String()},
		{http.MethodGet, "/api/v1/admin/users"},
		{http.MethodPatch, "/api/v1/admin/users/" + uuid.New().String() + "/roles"},
	}

	if len(registered) != 17 {
		t.Fatalf("test table lists %d routes, want 17", len(registered))
	}

	for _, route := range registered {
		req := httptest.NewRequest(route.method, route.path, http.NoBody)

		_, pattern := mux.Handler(req)
		if pattern == "" {
			t.Errorf("%s %s: not registered", route.method, route.path)
		}
	}
}

// TestRoutes_MinimalConfig_RegistersOnlyAlwaysOn covers the other half of the
// route-enablement matrix: with Providers, Passkeys, and Codes all nil, only
// the routes that do not depend on an optional method are registered, and
// every route gated by one of them answers as unregistered (mux.Handler
// returns an empty pattern, which is what makes ServeMux answer 404).
// Covers AC-008.29.
func TestRoutes_MinimalConfig_RegistersOnlyAlwaysOn(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	routeDeps := newTestRouteDeps(t, deps, false)

	mux := http.NewServeMux()
	deps.service.Routes(mux, routeDeps)

	alwaysOn := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/auth/providers"},
		{http.MethodPost, "/api/v1/auth/logout"},
		{http.MethodGet, "/api/v1/me"},
		{http.MethodGet, "/api/v1/me/sessions"},
		{http.MethodDelete, "/api/v1/me/sessions/" + uuid.New().String()},
		{http.MethodGet, "/api/v1/me/credentials"},
		{http.MethodDelete, "/api/v1/me/credentials/" + uuid.New().String()},
		{http.MethodGet, "/api/v1/admin/users"},
		{http.MethodPatch, "/api/v1/admin/users/" + uuid.New().String() + "/roles"},
	}

	for _, route := range alwaysOn {
		req := httptest.NewRequest(route.method, route.path, http.NoBody)

		_, pattern := mux.Handler(req)
		if pattern == "" {
			t.Errorf("%s %s: expected always-on route to be registered", route.method, route.path)
		}
	}

	gated := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/auth/oidc/test/start"},
		{http.MethodGet, "/api/v1/auth/oidc/test/callback"},
		{http.MethodPost, "/api/v1/auth/webauthn/register/start"},
		{http.MethodPost, "/api/v1/auth/webauthn/register/finish"},
		{http.MethodPost, "/api/v1/auth/webauthn/login/start"},
		{http.MethodPost, "/api/v1/auth/webauthn/login/finish"},
		{http.MethodPost, "/api/v1/auth/otp/start"},
		{http.MethodPost, "/api/v1/auth/otp/verify"},
	}

	for _, route := range gated {
		req := httptest.NewRequest(route.method, route.path, http.NoBody)

		_, pattern := mux.Handler(req)
		if pattern != "" {
			t.Errorf("%s %s: expected gated route to be unregistered when its method is disabled, got pattern %q", route.method, route.path, pattern)
		}
	}
}

// TestHandleMe_Unauthenticated_ReturnsExact401Body covers AC-008.34: an
// unauthenticated request to GET /api/v1/me is rejected with the exact 401
// body every unauthenticated request answers with.
func TestHandleMe_Unauthenticated_ReturnsExact401Body(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", http.NoBody)
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

// TestHandleMe_Authenticated_ReturnsOwnAccount covers GET /api/v1/me's
// success path: every field of an authenticated caller's own account, roles,
// and permissions comes back as issueSession and LogIn established it.
// Covers AC-008.31 and AC-008.35.
func TestHandleMe_Authenticated_ReturnsOwnAccount(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	userID, token := issueSession(t, deps, "sub-me")
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	req := requestWithSessionCookie(t, token)
	req.Method = http.MethodGet
	req.URL.Path = "/api/v1/me"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var body meResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	if body.ID != userID {
		t.Fatalf("body.ID = %v, want %v", body.ID, userID)
	}

	if body.DisplayName != "Test User" {
		t.Fatalf("body.DisplayName = %q, want %q", body.DisplayName, "Test User")
	}

	if body.Email == nil || *body.Email != "sub-me@example.com" {
		t.Fatalf("body.Email = %v, want %q", body.Email, "sub-me@example.com")
	}

	if !body.EmailVerified {
		t.Fatal("body.EmailVerified = false, want true")
	}

	if body.Status != string(user.StatusActive) {
		t.Fatalf("body.Status = %q, want %q", body.Status, user.StatusActive)
	}

	if !slices.Equal(body.Roles, []string{authz.RoleMember}) {
		t.Fatalf("body.Roles = %v, want [%s]", body.Roles, authz.RoleMember)
	}

	if len(body.Permissions) == 0 {
		t.Fatal("body.Permissions is empty, want the member role's permissions")
	}

	if body.CreatedAt.IsZero() {
		t.Fatal("body.CreatedAt is zero")
	}
}

// TestHandleAdminUsers_PermissionMatrix covers AC-008.33/AC-008.35: a member
// lacking user.read is refused with the exact 403 body, and an admin's 200
// lists that member with its roles, and an account holding none with an
// empty list rather than null.
func TestHandleAdminUsers_PermissionMatrix(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	memberID, memberToken := issueSession(t, deps, "sub-admin-member")
	rolelessID, _ := issueSession(t, deps, "sub-admin-roleless")
	stripRoles(t, deps, rolelessID.String())

	adminIn := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-admin-caller",
		Email:         "admin@example.com",
		EmailVerified: true,
		DisplayName:   "Admin Caller",
		Methods:       []string{session.MethodOIDC},
	}
	_, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-admin", "")
	if err != nil {
		t.Fatalf("LogIn() admin error = %v", err)
	}

	memberReq := requestWithSessionCookie(t, memberToken)
	memberReq.Method = http.MethodGet
	memberReq.URL.Path = "/api/v1/admin/users"
	memberRec := httptest.NewRecorder()
	handler.ServeHTTP(memberRec, memberReq)

	if memberRec.Code != http.StatusForbidden {
		t.Fatalf("member status = %d, want 403, body = %s", memberRec.Code, memberRec.Body.String())
	}

	wantForbidden := `{"errors":[{"status":"403","code":"forbidden","title":"Permission denied"}]}`
	if got := exactErrorBody(memberRec); got != wantForbidden {
		t.Fatalf("member body = %s, want %s", got, wantForbidden)
	}

	adminReq := requestWithSessionCookie(t, adminToken)
	adminReq.Method = http.MethodGet
	adminReq.URL.Path = "/api/v1/admin/users"
	adminRec := httptest.NewRecorder()
	handler.ServeHTTP(adminRec, adminReq)

	if adminRec.Code != http.StatusOK {
		t.Fatalf("admin status = %d, want 200, body = %s", adminRec.Code, adminRec.Body.String())
	}

	var body adminUsersResponse
	if unmarshalErr := json.Unmarshal(adminRec.Body.Bytes(), &body); unmarshalErr != nil {
		t.Fatalf("decoding admin response: %v", unmarshalErr)
	}

	var listedMember *adminUserResponse

	for i := range body.Users {
		if body.Users[i].ID == memberID {
			listedMember = &body.Users[i]
		}
	}

	if listedMember == nil {
		t.Fatalf("member %v not present in admin listing: %+v", memberID, body.Users)
	}

	if !slices.Equal(listedMember.Roles, []string{authz.RoleMember}) {
		t.Fatalf("listed member Roles = %v, want [%s]", listedMember.Roles, authz.RoleMember)
	}

	var rawBody struct {
		Users []struct {
			ID    uuid.UUID       `json:"id"`
			Roles json.RawMessage `json:"roles"`
		} `json:"users"`
	}
	if unmarshalErr := json.Unmarshal(adminRec.Body.Bytes(), &rawBody); unmarshalErr != nil {
		t.Fatalf("decoding admin response: %v", unmarshalErr)
	}

	rolelessListed := false

	for _, listed := range rawBody.Users {
		if listed.ID != rolelessID {
			continue
		}

		rolelessListed = true

		if string(listed.Roles) != "[]" {
			t.Errorf("roleless account roles = %s, want []", listed.Roles)
		}
	}

	if !rolelessListed {
		t.Fatalf("roleless account %v not present in admin listing", rolelessID)
	}
}

// TestHandleAdminUsers_UnknownStatus_ReturnsExact400Body covers a status
// query value outside {pending,active,suspended,deleted}: the repository is
// never reached, and the response is the fixed 400 invalid_request body.
// Covers AC-008.72.
func TestHandleAdminUsers_UnknownStatus_ReturnsExact400Body(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin2@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	adminIn := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-bogus-status",
		Email:         "admin2@example.com",
		EmailVerified: true,
		DisplayName:   "Admin Caller",
		Methods:       []string{session.MethodOIDC},
	}
	_, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-admin2", "")
	if err != nil {
		t.Fatalf("LogIn() admin error = %v", err)
	}

	req := requestWithSessionCookie(t, adminToken)
	req.Method = http.MethodGet
	req.URL.Path = "/api/v1/admin/users"
	req.URL.RawQuery = "status=bogus"
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

// TestHandleMeSessionsDelete_OwnershipIsolation covers the ownership
// predicate's isolation for sessions (design.md's "Authorization path"): a
// non-owner's delete leaves the victim's session
// intact and still resolvable, while the owner's own delete actually
// revokes it. Both answer 204.
// Covers AC-008.16 and AC-008.35.
func TestHandleMeSessionsDelete_OwnershipIsolation(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	_, victimToken := issueSession(t, deps, "sub-session-victim")
	_, attackerToken := issueSession(t, deps, "sub-session-attacker")

	victimSession, err := deps.sessions.Lookup(t.Context(), victimToken)
	if err != nil {
		t.Fatalf("Lookup() victim error = %v", err)
	}

	attackerReq := requestWithSessionCookie(t, attackerToken)
	attackerReq.Method = http.MethodDelete
	attackerReq.URL.Path = "/api/v1/me/sessions/" + victimSession.PublicID.String()
	attackerRec := httptest.NewRecorder()
	handler.ServeHTTP(attackerRec, attackerReq)

	if attackerRec.Code != http.StatusNoContent {
		t.Fatalf("attacker delete status = %d, want 204", attackerRec.Code)
	}

	if _, lookupErr := deps.sessions.Lookup(t.Context(), victimToken); lookupErr != nil {
		t.Fatalf("victim session no longer resolves after a non-owner delete: %v", lookupErr)
	}

	victimReq := requestWithSessionCookie(t, victimToken)
	victimReq.Method = http.MethodDelete
	victimReq.URL.Path = "/api/v1/me/sessions/" + victimSession.PublicID.String()
	victimRec := httptest.NewRecorder()
	handler.ServeHTTP(victimRec, victimReq)

	if victimRec.Code != http.StatusNoContent {
		t.Fatalf("owner delete status = %d, want 204", victimRec.Code)
	}

	if _, lookupErr := deps.sessions.Lookup(t.Context(), victimToken); lookupErr == nil {
		t.Fatal("victim session still resolves after the owner's own delete")
	}
}

// TestHandleMeSessionsDelete_UnparseableID_MatchesForeignIDResponse ensures an
// unparseable session id answers with the same status and body as a
// well-formed but foreign id, so neither response lets a caller distinguish
// "not a UUID" from "not yours".
// Covers AC-008.35.
func TestHandleMeSessionsDelete_UnparseableID_MatchesForeignIDResponse(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	_, token := issueSession(t, deps, "sub-session-self")

	badReq := requestWithSessionCookie(t, token)
	badReq.Method = http.MethodDelete
	badReq.URL.Path = "/api/v1/me/sessions/not-a-uuid"
	badRec := httptest.NewRecorder()
	handler.ServeHTTP(badRec, badReq)

	foreignReq := requestWithSessionCookie(t, token)
	foreignReq.Method = http.MethodDelete
	foreignReq.URL.Path = "/api/v1/me/sessions/" + uuid.New().String()
	foreignRec := httptest.NewRecorder()
	handler.ServeHTTP(foreignRec, foreignReq)

	if badRec.Code != foreignRec.Code {
		t.Fatalf("unparseable id status = %d, foreign id status = %d, want equal", badRec.Code, foreignRec.Code)
	}

	if badRec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", badRec.Code)
	}

	if badRec.Body.String() != foreignRec.Body.String() {
		t.Fatalf("unparseable id body = %q, foreign id body = %q, want equal", badRec.Body.String(), foreignRec.Body.String())
	}
}

// TestHandleMeSessions_BodyNeverCarriesLiveDigest asserts that GET
// /api/v1/me/sessions' response contains no raw session token and no
// rendering (hex, base64 standard, base64 raw-URL) of a live session's
// digest, since the response is meant to identify a session by its public id
// only.
// Covers AC-008.12 and AC-008.16.
func TestHandleMeSessions_BodyNeverCarriesLiveDigest(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	_, token := issueSession(t, deps, "sub-sessions-list")

	req := requestWithSessionCookie(t, token)
	req.Method = http.MethodGet
	req.URL.Path = "/api/v1/me/sessions"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	digest := session.Digest(token)
	forbidden := []string{
		token,
		hex.EncodeToString(digest),
		base64.StdEncoding.EncodeToString(digest),
		base64.RawURLEncoding.EncodeToString(digest),
	}

	body := rec.Body.String()

	for _, needle := range forbidden {
		if strings.Contains(body, needle) {
			t.Fatalf("response body contains forbidden substring %q", needle)
		}
	}
}

// TestHandleLogout_ClearsCookieAndAudits covers logout: the session cookie
// is cleared, the same cookie is unauthenticated afterward, and a logout
// audit row is written naming the actor.
// Covers AC-008.15 and AC-008.38.
func TestHandleLogout_ClearsCookieAndAudits(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	userID, token := issueSession(t, deps, "sub-logout")

	req := requestWithSessionCookie(t, token)
	req.Method = http.MethodPost
	req.URL.Path = "/api/v1/auth/logout"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}

	assertCookieCleared(t, rec)

	if _, lookupErr := deps.sessions.Lookup(t.Context(), token); lookupErr == nil {
		t.Fatal("session still resolves after logout")
	}

	meReq := requestWithSessionCookie(t, token)
	meReq.Method = http.MethodGet
	meReq.URL.Path = "/api/v1/me"
	meRec := httptest.NewRecorder()
	handler.ServeHTTP(meRec, meReq)

	if meRec.Code != http.StatusUnauthorized {
		t.Fatalf("post-logout /api/v1/me status = %d, want 401", meRec.Code)
	}

	count := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = $1 AND actor_id = $2`,
		audit.ActionLogout, userID)
	if count != 1 {
		t.Fatalf("logout audit row count = %d, want 1", count)
	}
}

// TestHandleOTPStart_IdenticalForKnownAndUnknown covers AC-008.30, the
// indistinguishability requirement on POST /api/v1/auth/otp/start: a known
// and an unknown address
// answer with the same status and body.
func TestHandleOTPStart_IdenticalForKnownAndUnknown(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	sender := &recordingOTPSender{}
	handler := newAuthedMux(deps, newTestRouteDepsWithOTPSender(t, deps, sender))

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	_, _ = issueSession(t, deps, "sub-otp-known")

	knownReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/start", bytes.NewBufferString(`{"email":"sub-otp-known@example.com"}`))
	knownReq.Header.Set("Content-Type", "application/json")
	knownRec := httptest.NewRecorder()
	handler.ServeHTTP(knownRec, knownReq)

	knownMessage := sender.last(t)

	unknownReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/start", bytes.NewBufferString(`{"email":"never-seen@example.com"}`))
	unknownReq.Header.Set("Content-Type", "application/json")
	unknownRec := httptest.NewRecorder()
	handler.ServeHTTP(unknownRec, unknownReq)

	if knownRec.Code != http.StatusAccepted || unknownRec.Code != http.StatusAccepted {
		t.Fatalf("known status = %d, unknown status = %d, want both 202", knownRec.Code, unknownRec.Code)
	}

	if knownRec.Body.String() != unknownRec.Body.String() {
		t.Fatalf("known body = %q, unknown body = %q, want equal", knownRec.Body.String(), unknownRec.Body.String())
	}

	if knownMessage.To != "sub-otp-known@example.com" {
		t.Fatalf("known request's message.To = %q, want %q", knownMessage.To, "sub-otp-known@example.com")
	}

	if codeFromMessage(t, knownMessage) == "" {
		t.Fatal("known request's message carries no code")
	}

	unknownMessage := sender.last(t)
	if unknownMessage.To != "never-seen@example.com" {
		t.Fatalf("unknown request's message.To = %q, want %q", unknownMessage.To, "never-seen@example.com")
	}

	if codeFromMessage(t, unknownMessage) == "" {
		t.Fatal("unknown request's message carries no code")
	}
}

// TestHandleOTPStart_SetsBindingCookie covers AC-008.82: a start response
// sets the email-code binding cookie (HttpOnly, SameSite=Lax, Path=/,
// positive MaxAge, the plain cookie name since CookieSecure is false).
func TestHandleOTPStart_SetsBindingCookie(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	sender := &recordingOTPSender{}
	handler := newAuthedMux(deps, newTestRouteDepsWithOTPSender(t, deps, sender))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/start", bytes.NewBufferString(`{"email":"binding-cookie@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body = %s", rec.Code, rec.Body.String())
	}

	binding := integrationFindCookie(rec, otpBindingCookieNamePlain)
	if binding == nil {
		t.Fatal("no otp binding cookie set")
	}

	if binding.Value == "" {
		t.Fatal("binding cookie value is empty")
	}

	if !binding.HttpOnly {
		t.Fatal("binding cookie is not HttpOnly")
	}

	if binding.SameSite != http.SameSiteLaxMode {
		t.Fatalf("binding cookie SameSite = %v, want Lax", binding.SameSite)
	}

	if binding.Path != "/" {
		t.Fatalf("binding cookie Path = %q, want /", binding.Path)
	}

	if binding.MaxAge <= 0 {
		t.Fatalf("binding cookie MaxAge = %d, want positive", binding.MaxAge)
	}
}

// TestHandleOTPVerify_WithoutBindingCookieIs401 covers AC-008.83: a verify
// carrying a correct code but no binding cookie answers the same 401 a wrong
// code would, since Verify never finds a code requested under no binding.
func TestHandleOTPVerify_WithoutBindingCookieIs401(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	sender := &recordingOTPSender{}
	handler := newAuthedMux(deps, newTestRouteDepsWithOTPSender(t, deps, sender))

	const address = "no-binding-cookie@example.com"

	startReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/start", strings.NewReader(`{"email":"`+address+`"}`))
	startReq.Header.Set("Content-Type", "application/json")
	startRec := httptest.NewRecorder()
	handler.ServeHTTP(startRec, startReq)

	if startRec.Code != http.StatusAccepted {
		t.Fatalf("start status = %d, want 202, body = %s", startRec.Code, startRec.Body.String())
	}

	code := codeFromMessage(t, sender.last(t))

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/verify",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"code":%q}`, address, code)))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.Header.Set("Sec-Fetch-Site", "same-origin")
	verifyRec := httptest.NewRecorder()
	handler.ServeHTTP(verifyRec, verifyReq)

	if verifyRec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body = %s", verifyRec.Code, verifyRec.Body.String())
	}

	want := `{"errors":[{"status":"401","code":"unauthenticated","title":"Authentication required"}]}`
	if got := exactErrorBody(verifyRec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

// TestHandleOTP_AttackerCannotStripVictimsInvite covers AC-008.82: an
// attacker who knows a victim's email address and starts an OTP request for
// it from a different browser must not be able to strip the invite the
// victim's own outstanding code carries. The victim starts with an invite on
// cookie jar V; the attacker then starts for the same address with no
// binding cookie of its own, getting a fresh binding on jar A and never
// verifying. The victim's later verify, on jar V, must still be admitted
// under require-invite policy, proving the attacker's bindingless request
// never touched the victim's row.
func TestHandleOTP_AttackerCannotStripVictimsInvite(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(true)})

	sender := &recordingOTPSender{}
	handler := newAuthedMux(deps, newTestRouteDepsWithOTPSender(t, deps, sender))

	issuer := createTestAdmin(t, deps)

	issued, err := deps.invites.Create(t.Context(), issuer, "user:"+issuer.String(), true, invite.Params{MaxUses: 1})
	if err != nil {
		t.Fatalf("invites.Create() error = %v", err)
	}

	const address = "victim-invite-strip@example.com"

	victimStartReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/start",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"invite":%q}`, address, issued.Token)))
	victimStartReq.Header.Set("Content-Type", "application/json")
	victimStartRec := httptest.NewRecorder()
	handler.ServeHTTP(victimStartRec, victimStartReq)

	if victimStartRec.Code != http.StatusAccepted {
		t.Fatalf("victim start status = %d, want 202, body = %s", victimStartRec.Code, victimStartRec.Body.String())
	}

	victimBinding := integrationFindCookie(victimStartRec, otpBindingCookieNamePlain)
	if victimBinding == nil {
		t.Fatal("no otp binding cookie set on victim start")
	}

	victimCode := codeFromMessage(t, sender.last(t))

	// The attacker starts for the same address from a different browser: no
	// cookie is attached, so the handler mints its own fresh binding on jar
	// A. The attacker never verifies; this request's only purpose is to try
	// to knock the victim's outstanding code off its invite.
	attackerStartReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/start",
		strings.NewReader(fmt.Sprintf(`{"email":%q}`, address)))
	attackerStartReq.Header.Set("Content-Type", "application/json")
	attackerStartRec := httptest.NewRecorder()
	handler.ServeHTTP(attackerStartRec, attackerStartReq)

	if attackerStartRec.Code != http.StatusAccepted {
		t.Fatalf("attacker start status = %d, want 202, body = %s", attackerStartRec.Code, attackerStartRec.Body.String())
	}

	attackerBinding := integrationFindCookie(attackerStartRec, otpBindingCookieNamePlain)
	if attackerBinding == nil {
		t.Fatal("no otp binding cookie set on attacker start")
	}

	if attackerBinding.Value == victimBinding.Value {
		t.Fatal("attacker binding equals victim binding, want distinct per-browser values")
	}

	victimVerifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/verify",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"code":%q}`, address, victimCode)))
	victimVerifyReq.Header.Set("Content-Type", "application/json")
	victimVerifyReq.Header.Set("Sec-Fetch-Site", "same-origin")
	victimVerifyReq.AddCookie(victimBinding)
	victimVerifyRec := httptest.NewRecorder()
	handler.ServeHTTP(victimVerifyRec, victimVerifyReq)

	if victimVerifyRec.Code != http.StatusNoContent {
		t.Fatalf("victim verify status = %d, want 204, body = %s", victimVerifyRec.Code, victimVerifyRec.Body.String())
	}

	account, err := deps.users.ByEmail(t.Context(), address)
	if err != nil {
		t.Fatalf("ByEmail() error = %v (account should have been admitted through the victim's invite)", err)
	}

	var redeemedInviteID uuid.UUID

	err = deps.handle.Pool().QueryRow(t.Context(),
		`SELECT invite_id FROM invite_redemptions WHERE user_id = $1`, account.ID,
	).Scan(&redeemedInviteID)
	if err != nil {
		t.Fatalf("querying invite_redemptions for the admitted account: %v", err)
	}

	if redeemedInviteID != issued.Invite.ID {
		t.Errorf("invite_redemptions.invite_id = %s, want %s (the victim's own invite)", redeemedInviteID, issued.Invite.ID)
	}
}

// TestHandleOTPVerify_CrossSite_ReturnsExact403Body covers the CSRF defense
// on the login-completing OTP verify route: a cross-site POST is rejected
// before ever reaching otp.Service.Verify.
// Covers AC-008.18.
func TestHandleOTPVerify_CrossSite_ReturnsExact403Body(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, true))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/verify", bytes.NewBufferString(`{"email":"x@example.com","code":"000000"}`))
	req.Header.Set("Content-Type", "application/json")
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
}

// TestDecodeBody_MalformedJSON_ReturnsExact400Body covers the fixed
// invalid_request body every JSON-decoding route answers a malformed body
// with, exercised through POST /api/v1/auth/otp/start.
// Covers AC-005.4.
func TestDecodeBody_MalformedJSON_ReturnsExact400Body(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, true))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/start", bytes.NewBufferString(`{not json`))
	req.Header.Set("Content-Type", "application/json")
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

// TestHandleAdminUsersRoles_LastAdmin_ReturnsExact409AndLeavesRoleUnchanged
// covers the last-admin rule: removing admin from the sole active admin is
// refused with 409, and the role assignment is left untouched.
// Covers AC-008.50.
func TestHandleAdminUsersRoles_LastAdmin_ReturnsExact409AndLeavesRoleUnchanged(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"solo-admin@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	adminIn := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-solo-admin",
		Email:         "solo-admin@example.com",
		EmailVerified: true,
		DisplayName:   "Solo Admin",
		Methods:       []string{session.MethodOIDC},
	}
	adminAccount, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-solo-admin", "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	req := requestWithSessionCookie(t, adminToken)
	req.Method = http.MethodPatch
	req.URL.Path = "/api/v1/admin/users/" + adminAccount.ID.String() + "/roles"
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(strings.NewReader(`{"roles":["member"]}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}

	want := `{"errors":[{"status":"409","code":"conflict","title":"Request conflicts with current state"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}

	roles, err := deps.roles.RolesFor(t.Context(), adminAccount.ID)
	if err != nil {
		t.Fatalf("RolesFor() error = %v", err)
	}

	found := false

	for _, role := range roles {
		if role == authz.RoleAdmin {
			found = true
		}
	}

	if !found {
		t.Fatalf("roles = %v, want to still contain admin after a refused removal", roles)
	}
}

// TestHandleMeCredentialsDelete_UnauthenticatedRoute_Returns401 covers
// AC-008.34: the credential deletion route's authentication gate. Ownership
// isolation for the credential itself is covered separately by
// TestHandleMeCredentials_OwnershipIsolationAndListingScope, which inserts
// credentials directly rather than running a WebAuthn ceremony.
func TestHandleMeCredentialsDelete_UnauthenticatedRoute_Returns401(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, true))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/credentials/"+uuid.New().String(), http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestHandleMeCredentials_OwnershipIsolationAndListingScope covers the
// ownership predicate (design.md's "Authorization path"), AC-008.26, and
// AC-008.35: credentials are inserted directly for two
// accounts (no WebAuthn ceremony needed), account A's delete of B's
// credential answers 204 and leaves it listed for B, A's delete of its own
// answers 204 and removes it from A's own listing, and each account's GET
// /api/v1/me/credentials lists only its own. A cross-account delete records
// no audit row; the real delete records exactly one.
func TestHandleMeCredentials_OwnershipIsolationAndListingScope(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	routeDeps := newTestRouteDeps(t, deps, true)
	handler := newAuthedMux(deps, routeDeps)

	userA, tokenA := issueSession(t, deps, "sub-cred-a")
	userB, tokenB := issueSession(t, deps, "sub-cred-b")

	credA := passkey.Credential{
		ID: uuid.New(), UserID: userA, CredentialID: []byte("cred-a-identifier"), PublicKey: []byte("pub-a"),
		AttestationType: "none", Transports: []string{"internal"}, AAGUID: []byte{}, Name: "A's key", CreatedAt: deps.clock.Now(),
	}
	credB := passkey.Credential{
		ID: uuid.New(), UserID: userB, CredentialID: []byte("cred-b-identifier"), PublicKey: []byte("pub-b"),
		AttestationType: "none", Transports: []string{"internal"}, AAGUID: []byte{}, Name: "B's key", CreatedAt: deps.clock.Now(),
	}

	if err := routeDeps.Credentials.Create(t.Context(), credA); err != nil {
		t.Fatalf("Create() credA error = %v", err)
	}

	if err := routeDeps.Credentials.Create(t.Context(), credB); err != nil {
		t.Fatalf("Create() credB error = %v", err)
	}

	listB := func() string {
		req := requestWithSessionCookie(t, tokenB)
		req.Method = http.MethodGet
		req.URL.Path = "/api/v1/me/credentials"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("GET credentials (B) status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}

		return rec.Body.String()
	}

	beforeB := listB()
	if !strings.Contains(beforeB, credB.ID.String()) {
		t.Fatalf("B's own listing missing B's credential: %s", beforeB)
	}

	if strings.Contains(beforeB, credA.ID.String()) {
		t.Fatalf("B's listing leaks A's credential: %s", beforeB)
	}

	crossReq := requestWithSessionCookie(t, tokenA)
	crossReq.Method = http.MethodDelete
	crossReq.URL.Path = "/api/v1/me/credentials/" + credB.ID.String()
	crossRec := httptest.NewRecorder()
	handler.ServeHTTP(crossRec, crossReq)

	if crossRec.Code != http.StatusNoContent {
		t.Fatalf("cross-account delete status = %d, want 204", crossRec.Code)
	}

	afterCross := listB()
	if !strings.Contains(afterCross, credB.ID.String()) {
		t.Fatalf("B's credential vanished after A's cross-account delete: %s", afterCross)
	}

	crossAuditCount := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = $1 AND subject = $2`,
		audit.ActionPasskeyRemoved, "credential:"+credB.ID.String())
	if crossAuditCount != 0 {
		t.Fatalf("cross-account delete recorded %d audit rows, want 0", crossAuditCount)
	}

	ownReq := requestWithSessionCookie(t, tokenA)
	ownReq.Method = http.MethodDelete
	ownReq.URL.Path = "/api/v1/me/credentials/" + credA.ID.String()
	ownRec := httptest.NewRecorder()
	handler.ServeHTTP(ownRec, ownReq)

	if ownRec.Code != http.StatusNoContent {
		t.Fatalf("own delete status = %d, want 204", ownRec.Code)
	}

	listAReq := requestWithSessionCookie(t, tokenA)
	listAReq.Method = http.MethodGet
	listAReq.URL.Path = "/api/v1/me/credentials"
	listARec := httptest.NewRecorder()
	handler.ServeHTTP(listARec, listAReq)

	if strings.Contains(listARec.Body.String(), credA.ID.String()) {
		t.Fatalf("A's own credential still listed after a real delete: %s", listARec.Body.String())
	}

	ownAuditCount := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = $1 AND subject = $2`,
		audit.ActionPasskeyRemoved, "credential:"+credA.ID.String())
	if ownAuditCount != 1 {
		t.Fatalf("own delete recorded %d audit rows, want 1", ownAuditCount)
	}
}

// TestHandleOIDCStart_SetsBindingCookieAndRedirects covers AC-008.20: a
// successful start sets the OIDC binding cookie (HttpOnly, SameSite=Lax,
// Path=/, positive Max-Age, the plain cookie name since CookieSecure is
// false) and answers 303 to the provider.
func TestHandleOIDCStart_SetsBindingCookieAndRedirects(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	srv := newOIDCDiscoveryServer(t)
	handler := newAuthedMux(deps, newTestRouteDepsWithOIDC(t, deps, srv.URL))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/test/start", http.NoBody)
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

	if !binding.HttpOnly {
		t.Fatal("binding cookie is not HttpOnly")
	}

	if binding.SameSite != http.SameSiteLaxMode {
		t.Fatalf("binding cookie SameSite = %v, want Lax", binding.SameSite)
	}

	if binding.Path != "/" {
		t.Fatalf("binding cookie Path = %q, want /", binding.Path)
	}

	if binding.MaxAge <= 0 {
		t.Fatalf("binding cookie MaxAge = %d, want positive", binding.MaxAge)
	}
}

// TestHandleOIDCCallback_BogusState_ClearsBindingCookieAndAuditsFailure
// covers AC-008.21 and AC-008.38: a callback presenting an unknown state
// clears the binding cookie (Max-Age <= 0, same name and Path) and redirects
// to "/?error=unauthenticated", and records auth.oidc.completed with outcome
// failure, actor nil, and subject "provider:<key>".
func TestHandleOIDCCallback_BogusState_ClearsBindingCookieAndAuditsFailure(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	srv := newOIDCDiscoveryServer(t)
	handler := newAuthedMux(deps, newTestRouteDepsWithOIDC(t, deps, srv.URL))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/test/callback?state=bogus-state&code=irrelevant", http.NoBody)
	req.AddCookie(&http.Cookie{Name: oidcBindingCookieNamePlain, Value: "some-binding-secret"}) //nolint:gosec // a request cookie, not a response one

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303, body = %s", rec.Code, rec.Body.String())
	}

	if loc := rec.Header().Get("Location"); loc != "/?error=unauthenticated" {
		t.Fatalf("Location = %q, want /?error=unauthenticated", loc)
	}

	var cleared *http.Cookie

	for _, c := range rec.Result().Cookies() {
		if c.Name == oidcBindingCookieNamePlain {
			cleared = c
		}
	}

	if cleared == nil {
		t.Fatal("no Set-Cookie clearing the oidc binding cookie")
	}

	if cleared.MaxAge > 0 {
		t.Fatalf("cleared cookie MaxAge = %d, want <= 0", cleared.MaxAge)
	}

	if cleared.Path != "/" {
		t.Fatalf("cleared cookie Path = %q, want /", cleared.Path)
	}

	var actorIsNull bool

	if err := deps.handle.Pool().QueryRow(t.Context(),
		`SELECT actor_id IS NULL FROM audit_events WHERE action = $1 AND subject = $2 AND outcome = 'failure'`,
		audit.ActionOIDCCompleted, "provider:test",
	).Scan(&actorIsNull); err != nil {
		t.Fatalf("querying audit row: %v", err)
	}

	if !actorIsNull {
		t.Fatal("actor_id is not NULL, want NULL")
	}
}

// TestHandleOIDCStart_DeadInviteContinuesWithoutInvite covers AC-008.86: a
// dead invite token no longer blocks the ceremony. The requirement changed:
// the route used to redirect to "/?error=invite_invalid" without ever
// calling Registry.Start,
// which is what
// TestHandleOIDCStart_DeadInviteToken_RedirectsWithoutBindingCookie asserted;
// this route has not yet revealed anything about an address, so a dead
// invite is no longer a reason to stop the caller from reaching the
// provider, the same way a dead invite never stops handleOTPStart.
func TestHandleOIDCStart_DeadInviteContinuesWithoutInvite(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	srv := newOIDCDiscoveryServer(t)
	handler := newAuthedMux(deps, newTestRouteDepsWithOIDC(t, deps, srv.URL))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/test/start?invite=not-a-real-invite-token", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303, body = %s", rec.Code, rec.Body.String())
	}

	if loc := rec.Header().Get("Location"); loc == "/?error=invite_invalid" {
		t.Fatalf("Location = %q, want a redirect to the provider, not the dead-invite refusal", loc)
	}

	var binding *http.Cookie

	for _, c := range rec.Result().Cookies() {
		if c.Name == oidcBindingCookieNamePlain {
			binding = c
		}
	}

	if binding == nil {
		t.Fatal("no oidc binding cookie set: the ceremony did not continue")
	}
}

// TestHandleOTPVerify_SessionRotationAndReplay covers AC-008.17 and
// AC-008.42: a verify carrying an existing session cookie ends with a new
// cookie, the old token then answers 401 on GET /api/v1/me, and verifying the
// same code a second time answers the exact 401 body.
func TestHandleOTPVerify_SessionRotationAndReplay(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	sender := &recordingOTPSender{}
	routeDeps := newTestRouteDepsWithOTPSender(t, deps, sender)
	handler := newAuthedMux(deps, routeDeps)

	_, oldToken := issueSession(t, deps, "sub-otp-rotate")

	startReq := requestWithSessionCookie(t, oldToken)
	startReq.Method = http.MethodPost
	startReq.URL.Path = "/api/v1/auth/otp/start"
	startReq.Header.Set("Content-Type", "application/json")
	startReq.Body = io.NopCloser(strings.NewReader(`{"email":"sub-otp-rotate@example.com"}`))
	startRec := httptest.NewRecorder()
	handler.ServeHTTP(startRec, startReq)

	if startRec.Code != http.StatusAccepted {
		t.Fatalf("start status = %d, want 202, body = %s", startRec.Code, startRec.Body.String())
	}

	code := codeFromMessage(t, sender.last(t))
	verifyBody := fmt.Sprintf(`{"email":"sub-otp-rotate@example.com","code":%q}`, code)
	bindingCookie := integrationFindCookie(startRec, otpBindingCookieNamePlain)

	if bindingCookie == nil {
		t.Fatal("no otp binding cookie set on start")
	}

	verifyReq := requestWithSessionCookie(t, oldToken)
	verifyReq.Method = http.MethodPost
	verifyReq.URL.Path = "/api/v1/auth/otp/verify"
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.Header.Set("Sec-Fetch-Site", "same-origin")
	verifyReq.Body = io.NopCloser(strings.NewReader(verifyBody))
	verifyReq.AddCookie(bindingCookie)
	verifyRec := httptest.NewRecorder()
	handler.ServeHTTP(verifyRec, verifyReq)

	if verifyRec.Code != http.StatusNoContent {
		t.Fatalf("verify status = %d, want 204, body = %s", verifyRec.Code, verifyRec.Body.String())
	}

	var newToken string

	for _, c := range verifyRec.Result().Cookies() {
		if c.Name == session.DefaultCookieName {
			newToken = c.Value
		}
	}

	if newToken == "" {
		t.Fatal("no new session cookie set on verify")
	}

	if newToken == oldToken {
		t.Fatal("verify did not rotate the session token")
	}

	oldMeReq := requestWithSessionCookie(t, oldToken)
	oldMeReq.Method = http.MethodGet
	oldMeReq.URL.Path = "/api/v1/me"
	oldMeRec := httptest.NewRecorder()
	handler.ServeHTTP(oldMeRec, oldMeReq)

	if oldMeRec.Code != http.StatusUnauthorized {
		t.Fatalf("old token /api/v1/me status = %d, want 401", oldMeRec.Code)
	}

	replayReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/verify", strings.NewReader(verifyBody))
	replayReq.Header.Set("Content-Type", "application/json")
	replayReq.Header.Set("Sec-Fetch-Site", "same-origin")
	replayReq.AddCookie(bindingCookie)
	replayRec := httptest.NewRecorder()
	handler.ServeHTTP(replayRec, replayReq)

	if replayRec.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401, body = %s", replayRec.Code, replayRec.Body.String())
	}

	want := `{"errors":[{"status":"401","code":"unauthenticated","title":"Authentication required"}]}`
	if got := exactErrorBody(replayRec); got != want {
		t.Fatalf("replay body = %s, want %s", got, want)
	}
}

// TestHandleMeSessions_CurrentFlagsExactlyCallersSession covers AC-008.16: of
// two live sessions belonging to the same account, GET /api/v1/me/sessions
// reports current true for exactly the caller's own session and false for
// the other.
func TestHandleMeSessions_CurrentFlagsExactlyCallersSession(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	_, tokenA := issueSession(t, deps, "sub-two-sessions")

	in := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-two-sessions",
		Email:         "sub-two-sessions@example.com",
		EmailVerified: true,
		DisplayName:   "Test User",
		Methods:       []string{session.MethodOIDC},
	}

	_, _, tokenB, err := deps.service.LogIn(t.Context(), in, "203.0.113.9", "second-agent", "req-second-session", "")
	if err != nil {
		t.Fatalf("LogIn() second session error = %v", err)
	}

	sessA, err := deps.sessions.Lookup(t.Context(), tokenA)
	if err != nil {
		t.Fatalf("Lookup() sessA error = %v", err)
	}

	req := requestWithSessionCookie(t, tokenB)
	req.Method = http.MethodGet
	req.URL.Path = "/api/v1/me/sessions"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var body sessionsResponse
	if unmarshalErr := json.Unmarshal(rec.Body.Bytes(), &body); unmarshalErr != nil {
		t.Fatalf("decoding response: %v", unmarshalErr)
	}

	if len(body.Sessions) != 2 {
		t.Fatalf("got %d sessions, want 2", len(body.Sessions))
	}

	for _, s := range body.Sessions {
		wantCurrent := s.ID != sessA.PublicID
		if s.Current != wantCurrent {
			t.Fatalf("session %v Current = %v, want %v", s.ID, s.Current, wantCurrent)
		}
	}
}

// TestRateLimit_AuthRouteOverBurst_ReturnsExact429Body covers AC-008.37: an
// /api/v1/auth/ route over the configured per-IP burst answers the exact 429
// body.
func TestRateLimit_AuthRouteOverBurst_ReturnsExact429Body(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	routeDeps := newTestRouteDeps(t, deps, false)
	routeDeps.Limiter = ratelimit.New(1000, 1, deps.clock.Now)
	handler := newAuthedMux(deps, routeDeps)

	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/providers", http.NoBody)
		req.RemoteAddr = "203.0.113.60:1111"

		return req
	}

	firstRec := httptest.NewRecorder()
	handler.ServeHTTP(firstRec, newReq())

	if firstRec.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", firstRec.Code)
	}

	secondRec := httptest.NewRecorder()
	handler.ServeHTTP(secondRec, newReq())

	if secondRec.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want 429, body = %s", secondRec.Code, secondRec.Body.String())
	}

	want := `{"errors":[{"status":"429","code":"rate_limited","title":"Too many requests"}]}`
	if got := exactErrorBody(secondRec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

// TestRateLimit_LogoutRouteNotRateLimited covers AC-008.37's carve-out:
// POST /api/v1/auth/logout is the one /api/v1/auth/ route not wrapped in
// the rate limiter, so it keeps answering 204 past the burst that would
// trip every other auth route.
func TestRateLimit_LogoutRouteNotRateLimited(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	routeDeps := newTestRouteDeps(t, deps, false)
	routeDeps.Limiter = ratelimit.New(1000, 1, deps.clock.Now)
	handler := newAuthedMux(deps, routeDeps)

	for i := range 3 {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", http.NoBody)
		req.RemoteAddr = "203.0.113.61:2222"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("iteration %d status = %d, want 204, body = %s", i, rec.Code, rec.Body.String())
		}
	}
}

// TestRateLimitedRecordsOneAuditEventPerRefusalRun covers AC-008.88: three
// requests over a burst of one from the same client answer 200, 429, 429, and
// exactly one auth.rate_limited row is recorded, carrying subject
// "anonymous:ip".
func TestRateLimitedRecordsOneAuditEventPerRefusalRun(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	routeDeps := newTestRouteDeps(t, deps, false)
	routeDeps.Limiter = ratelimit.New(1000, 1, deps.clock.Now)
	handler := newAuthedMux(deps, routeDeps)

	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/providers", http.NoBody)
		req.RemoteAddr = "203.0.113.70:3333"

		return req
	}

	wantCodes := []int{http.StatusOK, http.StatusTooManyRequests, http.StatusTooManyRequests}

	for i, want := range wantCodes {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, newReq())

		if rec.Code != want {
			t.Fatalf("request %d status = %d, want %d, body = %s", i, rec.Code, want, rec.Body.String())
		}
	}

	var count int

	if err := deps.handle.Pool().QueryRow(t.Context(),
		`SELECT count(*) FROM audit_events WHERE action = $1 AND subject = $2`,
		audit.ActionRateLimited, "anonymous:ip",
	).Scan(&count); err != nil {
		t.Fatalf("querying audit row count: %v", err)
	}

	if count != 1 {
		t.Fatalf("auth.rate_limited row count = %d, want 1", count)
	}
}

// TestRateLimitedKeysIPv6ByPrefix covers AC-008.37: two IPv6 addresses inside
// the same /64 share a rate-limit bucket, but an address in a different /64
// gets its own.
func TestRateLimitedKeysIPv6ByPrefix(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	routeDeps := newTestRouteDeps(t, deps, false)
	routeDeps.Limiter = ratelimit.New(1000, 1, deps.clock.Now)
	handler := newAuthedMux(deps, routeDeps)

	newReq := func(addr string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/providers", http.NoBody)
		req.RemoteAddr = "[" + addr + "]:1111"

		return req
	}

	firstRec := httptest.NewRecorder()
	handler.ServeHTTP(firstRec, newReq("2001:db8:1:2::1"))

	if firstRec.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200, body = %s", firstRec.Code, firstRec.Body.String())
	}

	secondRec := httptest.NewRecorder()
	handler.ServeHTTP(secondRec, newReq("2001:db8:1:2::2"))

	if secondRec.Code != http.StatusTooManyRequests {
		t.Fatalf("second status (same /64 as first) = %d, want 429, body = %s", secondRec.Code, secondRec.Body.String())
	}

	thirdRec := httptest.NewRecorder()
	handler.ServeHTTP(thirdRec, newReq("2001:db8:9:9::1"))

	if thirdRec.Code != http.StatusOK {
		t.Fatalf("third status (different /64) = %d, want 200, body = %s", thirdRec.Code, thirdRec.Body.String())
	}
}

// TestOIDCBindingCookieMaxAgeFollowsFlowTTL covers AC-008.21: the OIDC
// binding cookie's MaxAge is deps.FlowTTL's whole seconds, not a fixed
// constant.
func TestOIDCBindingCookieMaxAgeFollowsFlowTTL(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	srv := newOIDCDiscoveryServer(t)
	routeDeps := newTestRouteDepsWithOIDC(t, deps, srv.URL)
	routeDeps.FlowTTL = 5 * time.Minute
	handler := newAuthedMux(deps, routeDeps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/test/start", http.NoBody)
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

	want := int((5 * time.Minute).Seconds())
	if binding.MaxAge != want {
		t.Fatalf("binding cookie MaxAge = %d, want %d", binding.MaxAge, want)
	}
}

// TestSessionsListRendersNullClientIPAsNull covers AC-008.16: a session with
// no recorded client IP renders GET /api/v1/me/sessions' client_ip field as
// JSON null, not the empty string.
func TestSessionsListRendersNullClientIPAsNull(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	in := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       "sub-null-client-ip",
		Email:         "sub-null-client-ip@example.com",
		EmailVerified: true,
		DisplayName:   "Test User",
		Methods:       []string{session.MethodOIDC},
	}

	_, _, token, err := deps.service.LogIn(t.Context(), in, "", "test-agent", "req-null-client-ip", "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	req := requestWithSessionCookie(t, token)
	req.Method = http.MethodGet
	req.URL.Path = "/api/v1/me/sessions"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var decoded map[string]any
	if unmarshalErr := json.Unmarshal(rec.Body.Bytes(), &decoded); unmarshalErr != nil {
		t.Fatalf("decoding response: %v", unmarshalErr)
	}

	sessions, ok := decoded["sessions"].([]any)
	if !ok || len(sessions) != 1 {
		t.Fatalf("decoded sessions = %v, want exactly one entry", decoded["sessions"])
	}

	entry, ok := sessions[0].(map[string]any)
	if !ok {
		t.Fatalf("decoded sessions[0] = %v, want an object", sessions[0])
	}

	clientIP, present := entry["client_ip"]
	if !present {
		t.Fatal("decoded sessions[0] has no client_ip key")
	}

	if clientIP != nil {
		t.Errorf("sessions[0].client_ip = %v, want JSON null", clientIP)
	}
}

// TestMeCredentialsRoutesExistWithPasskeysDisabled covers AC-008.26: the two
// credential self-service routes answer, rather than 404, even when
// deps.Passkeys is nil (WebAuthn disabled), because they are gated on
// deps.Credentials being wired up, not on Passkeys.
func TestMeCredentialsRoutesExistWithPasskeysDisabled(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	routeDeps := newTestRouteDeps(t, deps, false)
	handler := newAuthedMux(deps, routeDeps)

	_, token := issueSession(t, deps, "sub-credentials-no-passkeys")

	listReq := requestWithSessionCookie(t, token)
	listReq.Method = http.MethodGet
	listReq.URL.Path = "/api/v1/me/credentials"
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)

	if listRec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/me/credentials status = %d, want 200, body = %s", listRec.Code, listRec.Body.String())
	}

	// The route's existence is what this test covers, not
	// Service.RemoveCredential's last-factor rule: this account has only its
	// one OIDC identity as a sign-in factor, so removing anything (even a
	// nonexistent credential ID) is correctly refused with 409 before
	// existence is even checked. A 404 here would mean the route itself is
	// unregistered, which is the one outcome this test must rule out.
	deleteReq := requestWithSessionCookie(t, token)
	deleteReq.Method = http.MethodDelete
	deleteReq.URL.Path = "/api/v1/me/credentials/" + uuid.New().String()
	deleteRec := httptest.NewRecorder()
	handler.ServeHTTP(deleteRec, deleteReq)

	if deleteRec.Code == http.StatusNotFound {
		t.Fatalf("DELETE /api/v1/me/credentials/{id} status = %d, want anything but 404 (route unregistered), body = %s",
			deleteRec.Code, deleteRec.Body.String())
	}
}

// TestHandleWebAuthnLoginFinish_CrossSite_ReturnsExact403Body covers
// AC-008.18: webauthn/login/finish with no session cookie and a cross-site
// Sec-Fetch-Site is rejected by RejectCrossSiteAlways before ever reaching
// passkey.Service.FinishLogin.
func TestHandleWebAuthnLoginFinish_CrossSite_ReturnsExact403Body(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, true))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/login/finish", bytes.NewBufferString(`{"flow_id":"x","credential":{}}`))
	req.Header.Set("Content-Type", "application/json")
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
}

// TestHandleWebAuthnRegisterStart_Unauthenticated_ReturnsExact401Body covers
// AC-008.34: registering a passkey requires an authenticated caller.
func TestHandleWebAuthnRegisterStart_Unauthenticated_ReturnsExact401Body(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, true))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/register/start", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}

	want := `{"errors":[{"status":"401","code":"unauthenticated","title":"Authentication required"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

// TestHandleOTPStart_RecordsRequestedAuditRow covers AC-008.38: a code
// request writes auth.otp.requested with subject "email:<address>".
func TestHandleOTPStart_RecordsRequestedAuditRow(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, true))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/start", bytes.NewBufferString(`{"email":"audit-otp-start@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body = %s", rec.Code, rec.Body.String())
	}

	count := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = $1 AND subject = $2`,
		audit.ActionOTPRequested, "email:audit-otp-start@example.com")
	if count != 1 {
		t.Fatalf("auth.otp.requested row count = %d, want 1", count)
	}
}

// TestHandleAdminUsersRoles_NotLastAdmin_Succeeds200AndUpdatesRoles covers
// the positive side of AC-008.50's last-admin guard: with two active admins,
// demoting one to member succeeds with 200 and the target's roles reflect
// the change, since removing it does not leave the deployment with zero
// admins.
func TestHandleAdminUsersRoles_NotLastAdmin_Succeeds200AndUpdatesRoles(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin-one@example.com", "admin-two@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	callerIn := Authenticated{
		Provider: "https://issuer.example", Subject: "sub-admin-one", Email: "admin-one@example.com",
		EmailVerified: true, DisplayName: "Admin One", Methods: []string{session.MethodOIDC},
	}

	_, _, callerToken, err := deps.service.LogIn(t.Context(), callerIn, "203.0.113.5", "test-agent", "req-admin-one", "")
	if err != nil {
		t.Fatalf("LogIn() admin one error = %v", err)
	}

	targetIn := Authenticated{
		Provider: "https://issuer.example", Subject: "sub-admin-two", Email: "admin-two@example.com",
		EmailVerified: true, DisplayName: "Admin Two", Methods: []string{session.MethodOIDC},
	}

	targetAccount, _, _, err := deps.service.LogIn(t.Context(), targetIn, "203.0.113.6", "test-agent", "req-admin-two", "")
	if err != nil {
		t.Fatalf("LogIn() admin two error = %v", err)
	}

	req := requestWithSessionCookie(t, callerToken)
	req.Method = http.MethodPatch
	req.URL.Path = "/api/v1/admin/users/" + targetAccount.ID.String() + "/roles"
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(strings.NewReader(`{"roles":["member"]}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	roles, err := deps.roles.RolesFor(t.Context(), targetAccount.ID)
	if err != nil {
		t.Fatalf("RolesFor() error = %v", err)
	}

	if !slices.Equal(roles, []string{authz.RoleMember}) {
		t.Fatalf("roles = %v, want exactly [%s]", roles, authz.RoleMember)
	}
}

// TestHandleAdminUsersRoles_RecordsGrantedAndRevokedAuditRows covers
// AC-008.38: replacing a target's roles writes user.role.granted for each
// added role and user.role.revoked for each removed one, each carrying actor
// "user:<admin id>" and subject "user:<target id>".
func TestHandleAdminUsersRoles_RecordsGrantedAndRevokedAuditRows(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin-audit-roles@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	adminIn := Authenticated{
		Provider: "https://issuer.example", Subject: "sub-audit-roles-admin", Email: "admin-audit-roles@example.com",
		EmailVerified: true, DisplayName: "Admin", Methods: []string{session.MethodOIDC},
	}

	adminAccount, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-audit-roles-admin", "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	targetID, _ := issueSession(t, deps, "sub-audit-roles-target")

	req := requestWithSessionCookie(t, adminToken)
	req.Method = http.MethodPatch
	req.URL.Path = "/api/v1/admin/users/" + targetID.String() + "/roles"
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(strings.NewReader(`{"roles":["admin"]}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	grantedCount := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = $1 AND actor_ref = $2 AND subject = $3`,
		audit.ActionRoleGranted, "user:"+adminAccount.ID.String(), "user:"+targetID.String())
	if grantedCount != 1 {
		t.Fatalf("user.role.granted row count = %d, want 1", grantedCount)
	}

	revokedCount := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = $1 AND actor_ref = $2 AND subject = $3`,
		audit.ActionRoleRevoked, "user:"+adminAccount.ID.String(), "user:"+targetID.String())
	if revokedCount != 1 {
		t.Fatalf("user.role.revoked row count = %d, want 1", revokedCount)
	}
}

// TestHandleProviders_ExactBodyForConfiguration covers AC-008.29: the exact
// providers body for a deployment with one OIDC provider, WebAuthn, and OTP
// all enabled.
func TestHandleProviders_ExactBodyForConfiguration(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, true))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/providers", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	want := `{"providers":[{"kind":"oidc","key":"test","display_name":"Test Provider"},{"kind":"webauthn"},{"kind":"otp"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

// TestHandleProviders_OTPDisabled_OmitsEntryAndOTPRoutesAnswer404 covers
// AC-008.29: with Codes nil, the providers list carries no {"kind":"otp"}
// entry and the otp routes are unregistered, so they answer 404.
func TestHandleProviders_OTPDisabled_OmitsEntryAndOTPRoutesAnswer404(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/providers", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	if strings.Contains(rec.Body.String(), `"kind":"otp"`) {
		t.Fatalf("providers body lists otp while disabled: %s", rec.Body.String())
	}

	startReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/start", http.NoBody)
	startRec := httptest.NewRecorder()
	handler.ServeHTTP(startRec, startReq)

	if startRec.Code != http.StatusNotFound {
		t.Fatalf("otp/start status = %d, want 404", startRec.Code)
	}
}

// TestHandleLogout_RevokeTokenFails_ClearsCookieAndReturns5xx covers the
// logout failure path (AC-008.15): a RevokeToken failure still clears the
// cookie, so a browser does not keep presenting a token the server could not
// confirm revoking, but the response is the 5xx it is rather than the
// ordinary 204, so a caller can tell the two apart. The route is exercised
// directly through Routes rather than through Authenticate, since a request
// carrying the about-to-be-dropped sessions table's token would otherwise be
// rejected by Authenticate's own dependency-failure path first.
func TestHandleLogout_RevokeTokenFails_ClearsCookieAndReturns5xx(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	mux := http.NewServeMux()
	deps.service.Routes(mux, newTestRouteDeps(t, deps, false))

	_, token := issueSession(t, deps, "sub-logout-fails")

	if _, err := deps.handle.Pool().Exec(t.Context(), `DROP TABLE sessions CASCADE`); err != nil {
		t.Fatalf("dropping sessions table: %v", err)
	}

	req := requestWithSessionCookie(t, token)
	req.Method = http.MethodPost
	req.URL.Path = "/api/v1/auth/logout"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code < 500 {
		t.Fatalf("status = %d, want 5xx, body = %s", rec.Code, rec.Body.String())
	}

	assertCookieCleared(t, rec)
}

// TestHandleOTPStart_InviteLookupInfraFailure_LogsErrorButStillReturns202
// covers the OTP start invite resolution: a Lookup failure that is not
// invite.ErrInvalid (forced here by dropping the invites table) is logged at
// Error, but the route still answers 202 identically, per AC-008.30.
func TestHandleOTPStart_InviteLookupInfraFailure_LogsErrorButStillReturns202(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	core, logs := observer.New(zapcore.DebugLevel)
	obsLogger := zap.New(core)
	svc := newTestServiceWithLogger(deps, obsLogger)

	if _, err := deps.handle.Pool().Exec(t.Context(), `DROP TABLE invites CASCADE`); err != nil {
		t.Fatalf("dropping invites table: %v", err)
	}

	routeDeps := newTestRouteDeps(t, deps, true)
	routeDeps.Logger = obsLogger

	mux := http.NewServeMux()
	svc.Routes(mux, routeDeps)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/start",
		strings.NewReader(`{"email":"invite-broken@example.com","invite":"some-token"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body = %s", rec.Code, rec.Body.String())
	}

	entries := logs.FilterMessage("auth: looking up invite for otp start").All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}

	if entries[0].Level != zapcore.ErrorLevel {
		t.Fatalf("level = %v, want Error", entries[0].Level)
	}
}

// TestHandleWebAuthnLoginFinish_VerificationFailure_RecordsFailureAudit
// covers AC-008.38: a passkey login finish failure for an unknown flow --
// which resolves no credential at all -- records auth.passkey.completed
// with outcome failure, actor nil, and subject "anonymous:webauthn". Before
// this fix the subject named a "provider" kind pointing at the literal
// method name: "webauthn" is a method, not a provider, and the audit
// subject grammar's "anonymous" kind exists precisely for a failure that
// never resolved to an account. This expectation changed with the
// requirement, per this project's rule that a test is edited only when the
// requirement itself changed.
func TestHandleWebAuthnLoginFinish_VerificationFailure_RecordsFailureAudit(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, true))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/login/finish",
		strings.NewReader(`{"flow_id":"does-not-exist","credential":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}

	var actorIsNull bool

	if err := deps.handle.Pool().QueryRow(t.Context(),
		`SELECT actor_id IS NULL FROM audit_events WHERE action = $1 AND subject = $2 AND outcome = 'failure'`,
		audit.ActionPasskeyCompleted, "anonymous:webauthn",
	).Scan(&actorIsNull); err != nil {
		t.Fatalf("querying audit row: %v", err)
	}

	if !actorIsNull {
		t.Fatal("actor_id is not NULL, want NULL")
	}
}

// fakeUnknownWebAuthnCredential returns a syntactically valid WebAuthn
// assertion credential, as the JSON shape webauthnLoginFinishRequest.Credential
// carries, naming a credential ID no repository has ever stored and a
// non-empty user handle so the server treats it as a discoverable-login
// attempt. See passkey package's fakeUnknownAssertionBody for why this needs
// no genuine signature: the credential lookup fails, and FinishLogin returns
// ErrVerification, before any cryptographic check runs.
func fakeUnknownWebAuthnCredential(t *testing.T) json.RawMessage {
	t.Helper()

	rawID := []byte("unknown-credential-id-000")
	userHandle := []byte("unknown-user-handle-00000")
	clientData := []byte(`{"type":"webauthn.get","challenge":"x","origin":"https://example.com"}`)
	authData := make([]byte, 37)

	credential := map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(rawID),
		"rawId": base64.RawURLEncoding.EncodeToString(rawID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
			"signature":         base64.RawURLEncoding.EncodeToString([]byte{0x01}),
			"userHandle":        base64.RawURLEncoding.EncodeToString(userHandle),
		},
	}

	encoded, err := json.Marshal(credential)
	if err != nil {
		t.Fatalf("marshaling fake credential: %v", err)
	}

	return json.RawMessage(encoded)
}

// TestHandleWebAuthnLoginFinish_UnknownCredentialAuditsAnonymousWebauthn
// covers AC-008.38: a login finish naming a real, unexpired flow but an
// unknown credential ID -- so the credential handler runs and still resolves
// nothing -- also records auth.passkey.completed with subject
// "anonymous:webauthn", the same as the unknown-flow case above but reaching
// ErrVerification by a different path through passkey.Service.FinishLogin.
func TestHandleWebAuthnLoginFinish_UnknownCredentialAuditsAnonymousWebauthn(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	routeDeps := newTestRouteDeps(t, deps, true)
	handler := newAuthedMux(deps, routeDeps)

	_, flowID, err := routeDeps.Passkeys.BeginLogin(t.Context())
	if err != nil {
		t.Fatalf("BeginLogin() error = %v", err)
	}

	reqBody, err := json.Marshal(webauthnLoginFinishRequest{
		FlowID:     flowID,
		Credential: fakeUnknownWebAuthnCredential(t),
	})
	if err != nil {
		t.Fatalf("marshaling request body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/login/finish", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}

	count := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = $1 AND subject = $2 AND outcome = 'failure'`,
		audit.ActionPasskeyCompleted, "anonymous:webauthn")
	if count != 1 {
		t.Fatalf("auth.passkey.completed anonymous:webauthn row count = %d, want 1", count)
	}
}

// TestHandleOTPVerify_WrongCode_RecordsFailureAuditWithoutCode covers
// AC-008.38 and AC-008.40: an OTP verify failure records auth.otp.completed
// with outcome failure, actor nil, and subject "email:<address>", and the
// detail never contains the submitted code.
func TestHandleOTPVerify_WrongCode_RecordsFailureAuditWithoutCode(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, true))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/verify",
		strings.NewReader(`{"email":"otp-wrong-code@example.com","code":"99999999"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}

	var actorIsNull bool

	var detail []byte

	if err := deps.handle.Pool().QueryRow(t.Context(),
		`SELECT actor_id IS NULL, detail FROM audit_events WHERE action = $1 AND subject = $2 AND outcome = 'failure'`,
		audit.ActionOTPCompleted, "email:otp-wrong-code@example.com",
	).Scan(&actorIsNull, &detail); err != nil {
		t.Fatalf("querying audit row: %v", err)
	}

	if !actorIsNull {
		t.Fatal("actor_id is not NULL, want NULL")
	}

	if strings.Contains(string(detail), "99999999") {
		t.Fatalf("detail contains the submitted code: %s", detail)
	}
}

// TestHandleOTPVerify_NonVerificationError_Returns5xxAndLogs covers: an error
// from otp.Service.Verify that is not otp.ErrVerification (forced here by
// dropping the otp_codes table) is logged at Error and rendered as a 5xx via
// server.WriteError, never folded into the ordinary 401.
// Covers AC-005.6.
func TestHandleOTPVerify_NonVerificationError_Returns5xxAndLogs(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	core, logs := observer.New(zapcore.DebugLevel)
	obsLogger := zap.New(core)
	svc := newTestServiceWithLogger(deps, obsLogger)

	routeDeps := newTestRouteDeps(t, deps, true)
	routeDeps.Logger = obsLogger

	mux := http.NewServeMux()
	svc.Routes(mux, routeDeps)

	if _, err := deps.handle.Pool().Exec(t.Context(), `DROP TABLE otp_codes CASCADE`); err != nil {
		t.Fatalf("dropping otp_codes table: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/verify",
		strings.NewReader(`{"email":"otp-infra-fail@example.com","code":"00000000"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	// A binding cookie is required here so Verify reaches its currentCode
	// query (and hits the dropped table) rather than short-circuiting on an
	// empty binding, which would otherwise mask the infrastructure failure
	// this test exists to exercise behind an ordinary 401.
	req.AddCookie(&http.Cookie{Name: otpBindingCookieNamePlain, Value: strings.Repeat("a", otpBindingLength)}) //nolint:gosec // a request cookie, not a response one
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code < 500 {
		t.Fatalf("status = %d, want 5xx, body = %s", rec.Code, rec.Body.String())
	}

	entries := logs.FilterMessage("auth: verifying otp code").All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}

	if entries[0].Level != zapcore.ErrorLevel {
		t.Fatalf("level = %v, want Error", entries[0].Level)
	}
}

// TestHandleOTPStart_PerAddressRateLimit_TripsAcrossDifferentIPs covers
// AC-008.37: handleOTPStart also limits by the normalized address, so
// requests for the same address from different client IPs still trip the
// per-address bucket even though no single IP's own bucket is exhausted.
func TestHandleOTPStart_PerAddressRateLimit_TripsAcrossDifferentIPs(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	routeDeps := newTestRouteDeps(t, deps, true)
	routeDeps.Limiter = ratelimit.New(1000, 1, deps.clock.Now)
	handler := newAuthedMux(deps, routeDeps)

	body := `{"email":"rate-limited-start@example.com"}`

	first := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/start", strings.NewReader(body))
	first.Header.Set("Content-Type", "application/json")
	first.RemoteAddr = "203.0.113.10:1111"
	firstRec := httptest.NewRecorder()
	handler.ServeHTTP(firstRec, first)

	if firstRec.Code != http.StatusAccepted {
		t.Fatalf("first status = %d, want 202, body = %s", firstRec.Code, firstRec.Body.String())
	}

	second := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/start", strings.NewReader(body))
	second.Header.Set("Content-Type", "application/json")
	second.RemoteAddr = "203.0.113.20:2222"
	secondRec := httptest.NewRecorder()
	handler.ServeHTTP(secondRec, second)

	if secondRec.Code != http.StatusTooManyRequests {
		t.Fatalf("second status (different IP, same address) = %d, want 429, body = %s", secondRec.Code, secondRec.Body.String())
	}

	want := `{"errors":[{"status":"429","code":"rate_limited","title":"Too many requests"}]}`
	if got := exactErrorBody(secondRec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

// TestHandleOTPVerify_PerAddressRateLimit_TripsAcrossDifferentIPs covers
// AC-008.37: handleOTPVerify also limits by the normalized address, isolated
// from the per-IP limiter the same way handleOTPStart's is.
func TestHandleOTPVerify_PerAddressRateLimit_TripsAcrossDifferentIPs(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	routeDeps := newTestRouteDeps(t, deps, true)
	routeDeps.Limiter = ratelimit.New(1000, 1, deps.clock.Now)
	handler := newAuthedMux(deps, routeDeps)

	body := `{"email":"rate-limited-verify@example.com","code":"00000000"}`

	first := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/verify", strings.NewReader(body))
	first.Header.Set("Content-Type", "application/json")
	first.Header.Set("Sec-Fetch-Site", "same-origin")
	first.RemoteAddr = "203.0.113.30:1111"
	firstRec := httptest.NewRecorder()
	handler.ServeHTTP(firstRec, first)

	if firstRec.Code != http.StatusUnauthorized {
		t.Fatalf("first status = %d, want 401 (wrong code, but past the limiter), body = %s", firstRec.Code, firstRec.Body.String())
	}

	second := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/verify", strings.NewReader(body))
	second.Header.Set("Content-Type", "application/json")
	second.Header.Set("Sec-Fetch-Site", "same-origin")
	second.RemoteAddr = "203.0.113.40:2222"
	secondRec := httptest.NewRecorder()
	handler.ServeHTTP(secondRec, second)

	if secondRec.Code != http.StatusTooManyRequests {
		t.Fatalf("second status (different IP, same address) = %d, want 429, body = %s", secondRec.Code, secondRec.Body.String())
	}

	want := `{"errors":[{"status":"429","code":"rate_limited","title":"Too many requests"}]}`
	if got := exactErrorBody(secondRec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

// TestHandleOTPVerify_FirstRefusalAuditsEmailSubject covers AC-008.88:
// handleOTPVerify's per-address rate limit records exactly one
// auth.rate_limited event, carrying subject "email:<address>", across a run
// of refusals for the same address.
func TestHandleOTPVerify_FirstRefusalAuditsEmailSubject(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	routeDeps := newTestRouteDeps(t, deps, true)
	routeDeps.Limiter = ratelimit.New(1000, 1, deps.clock.Now)
	handler := newAuthedMux(deps, routeDeps)

	body := `{"email":"otp-verify-audit@example.com","code":"00000000"}`

	newReq := func(remoteAddr string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/verify", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.RemoteAddr = remoteAddr

		return req
	}

	firstRec := httptest.NewRecorder()
	handler.ServeHTTP(firstRec, newReq("203.0.113.50:1111"))

	if firstRec.Code != http.StatusUnauthorized {
		t.Fatalf("first status = %d, want 401 (wrong code, but past the limiter), body = %s", firstRec.Code, firstRec.Body.String())
	}

	secondRec := httptest.NewRecorder()
	handler.ServeHTTP(secondRec, newReq("203.0.113.51:2222"))

	if secondRec.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want 429, body = %s", secondRec.Code, secondRec.Body.String())
	}

	thirdRec := httptest.NewRecorder()
	handler.ServeHTTP(thirdRec, newReq("203.0.113.52:3333"))

	if thirdRec.Code != http.StatusTooManyRequests {
		t.Fatalf("third status = %d, want 429, body = %s", thirdRec.Code, thirdRec.Body.String())
	}

	var count int

	if err := deps.handle.Pool().QueryRow(t.Context(),
		`SELECT count(*) FROM audit_events WHERE action = $1 AND subject = $2`,
		audit.ActionRateLimited, "email:otp-verify-audit@example.com",
	).Scan(&count); err != nil {
		t.Fatalf("querying audit row count: %v", err)
	}

	if count != 1 {
		t.Fatalf("auth.rate_limited row count = %d, want 1", count)
	}
}

// TestHandleAdminUsersRoles_UnknownTarget_ReturnsExact404Body covers
// AC-008.90 for a role change aimed at an id naming no account: the target
// is loaded first, so the response is 404 before any role write is attempted.
func TestHandleAdminUsersRoles_UnknownTarget_ReturnsExact404Body(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin-404@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	adminIn := Authenticated{
		Provider: "https://issuer.example", Subject: "sub-admin-404", Email: "admin-404@example.com",
		EmailVerified: true, DisplayName: "Admin", Methods: []string{session.MethodOIDC},
	}

	_, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-admin-404", "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	req := requestWithSessionCookie(t, adminToken)
	req.Method = http.MethodPatch
	req.URL.Path = "/api/v1/admin/users/" + uuid.New().String() + "/roles"
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(strings.NewReader(`{"roles":["member"]}`))
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

// TestHandleAdminUsersRoles_SoftDeletedTarget_Returns404AndLeavesRolesUnchanged
// covers: user.Repository.ByID excludes a soft-deleted account, so a role
// change aimed at one also answers 404, before any role write, leaving its
// roles unchanged.
// Covers AC-008.90.
func TestHandleAdminUsersRoles_SoftDeletedTarget_Returns404AndLeavesRolesUnchanged(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin-deleted-target@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	adminIn := Authenticated{
		Provider: "https://issuer.example", Subject: "sub-admin-deleted-target", Email: "admin-deleted-target@example.com",
		EmailVerified: true, DisplayName: "Admin", Methods: []string{session.MethodOIDC},
	}

	_, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-admin-deleted-target", "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	targetID, _ := issueSession(t, deps, "sub-role-deleted-target")

	if err = deps.users.SoftDelete(t.Context(), targetID); err != nil {
		t.Fatalf("SoftDelete() error = %v", err)
	}

	before, err := deps.roles.RolesFor(t.Context(), targetID)
	if err != nil {
		t.Fatalf("RolesFor() before error = %v", err)
	}

	req := requestWithSessionCookie(t, adminToken)
	req.Method = http.MethodPatch
	req.URL.Path = "/api/v1/admin/users/" + targetID.String() + "/roles"
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(strings.NewReader(`{"roles":["admin"]}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}

	after, err := deps.roles.RolesFor(t.Context(), targetID)
	if err != nil {
		t.Fatalf("RolesFor() after error = %v", err)
	}

	if !slices.Equal(before, after) {
		t.Fatalf("roles changed from %v to %v against a soft-deleted target", before, after)
	}
}

// TestHandleAdminUsersRoles_NilRolesField_ReturnsExact400BodyAndWritesNothing
// covers a request body whose roles key is absent or null: it decodes to a
// nil slice, which is refused with 400 before any write, leaving the
// target's roles unchanged. An explicit empty array remains a legal request
// (covered by TestHandleAdminUsersRoles_DuplicateRoleNames_DedupedAndSucceeds
// using the same handler path for a non-empty body).
// Covers AC-008.31.
func TestHandleAdminUsersRoles_NilRolesField_ReturnsExact400BodyAndWritesNothing(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin-nil-roles@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	adminIn := Authenticated{
		Provider: "https://issuer.example", Subject: "sub-admin-nil-roles", Email: "admin-nil-roles@example.com",
		EmailVerified: true, DisplayName: "Admin", Methods: []string{session.MethodOIDC},
	}

	_, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-admin-nil-roles", "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	targetID, _ := issueSession(t, deps, "sub-role-nil-target")

	before, err := deps.roles.RolesFor(t.Context(), targetID)
	if err != nil {
		t.Fatalf("RolesFor() before error = %v", err)
	}

	req := requestWithSessionCookie(t, adminToken)
	req.Method = http.MethodPatch
	req.URL.Path = "/api/v1/admin/users/" + targetID.String() + "/roles"
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}

	want := `{"errors":[{"status":"400","code":"invalid_request","title":"Invalid request"}]}`
	if got := exactErrorBody(rec); got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}

	after, err := deps.roles.RolesFor(t.Context(), targetID)
	if err != nil {
		t.Fatalf("RolesFor() after error = %v", err)
	}

	if !slices.Equal(before, after) {
		t.Fatalf("roles changed from %v to %v on a refused nil-roles request", before, after)
	}
}

// TestHandleAdminUsersRoles_DuplicateRoleNames_DedupedAndSucceeds covers
// deduping a request naming the same role twice: SetRoles issues one INSERT
// per name with no ON CONFLICT clause, so an undeduplicated ["member",
// "member"] would fail as a 500 instead of succeeding.
// Covers AC-008.31.
func TestHandleAdminUsersRoles_DuplicateRoleNames_DedupedAndSucceeds(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin-dupe-roles@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	adminIn := Authenticated{
		Provider: "https://issuer.example", Subject: "sub-admin-dupe-roles", Email: "admin-dupe-roles@example.com",
		EmailVerified: true, DisplayName: "Admin", Methods: []string{session.MethodOIDC},
	}

	_, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-admin-dupe-roles", "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	targetID, _ := issueSession(t, deps, "sub-role-dupe-target")

	req := requestWithSessionCookie(t, adminToken)
	req.Method = http.MethodPatch
	req.URL.Path = "/api/v1/admin/users/" + targetID.String() + "/roles"
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(strings.NewReader(`{"roles":["member","member"]}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	roles, err := deps.roles.RolesFor(t.Context(), targetID)
	if err != nil {
		t.Fatalf("RolesFor() error = %v", err)
	}

	if !slices.Equal(roles, []string{authz.RoleMember}) {
		t.Fatalf("roles = %v, want exactly [%s]", roles, authz.RoleMember)
	}
}

// TestHandleAdminUsers_UnparseableCursor_ReturnsExact400BodyBeforeRepository
// covers a non-empty cursor query parameter that does not uuid.Parse: it
// answers 400 invalid_request before user.Repository.List is ever reached.
// Covers AC-008.72.
func TestHandleAdminUsers_UnparseableCursor_ReturnsExact400BodyBeforeRepository(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, []string{"admin-cursor@example.com"})
	handler := newAuthedMux(deps, newTestRouteDeps(t, deps, false))

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	adminIn := Authenticated{
		Provider: "https://issuer.example", Subject: "sub-admin-cursor", Email: "admin-cursor@example.com",
		EmailVerified: true, DisplayName: "Admin", Methods: []string{session.MethodOIDC},
	}

	_, _, adminToken, err := deps.service.LogIn(t.Context(), adminIn, "203.0.113.5", "test-agent", "req-admin-cursor", "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	req := requestWithSessionCookie(t, adminToken)
	req.Method = http.MethodGet
	req.URL.Path = "/api/v1/admin/users"
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

// TestHandleOTPVerify_NewAccount_DisplayNameIsFixedNotAddress covers the
// fixed display name every OTP-created account receives: the submitted
// address must never become the account's display name.
// Covers AC-008.8.
func TestHandleOTPVerify_NewAccount_DisplayNameIsFixedNotAddress(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	sender := &recordingOTPSender{}
	handler := newAuthedMux(deps, newTestRouteDepsWithOTPSender(t, deps, sender))

	const address = "new-otp-user@example.com"

	startReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/start", strings.NewReader(`{"email":"`+address+`"}`))
	startReq.Header.Set("Content-Type", "application/json")
	startRec := httptest.NewRecorder()
	handler.ServeHTTP(startRec, startReq)

	if startRec.Code != http.StatusAccepted {
		t.Fatalf("start status = %d, want 202, body = %s", startRec.Code, startRec.Body.String())
	}

	code := codeFromMessage(t, sender.last(t))
	bindingCookie := integrationFindCookie(startRec, otpBindingCookieNamePlain)

	if bindingCookie == nil {
		t.Fatal("no otp binding cookie set on start")
	}

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/verify",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"code":%q}`, address, code)))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.Header.Set("Sec-Fetch-Site", "same-origin")
	verifyReq.AddCookie(bindingCookie)
	verifyRec := httptest.NewRecorder()
	handler.ServeHTTP(verifyRec, verifyReq)

	if verifyRec.Code != http.StatusNoContent {
		t.Fatalf("verify status = %d, want 204, body = %s", verifyRec.Code, verifyRec.Body.String())
	}

	account, err := deps.users.ByEmail(t.Context(), address)
	if err != nil {
		t.Fatalf("ByEmail() error = %v", err)
	}

	if account.DisplayName != otpDisplayName {
		t.Fatalf("DisplayName = %q, want %q", account.DisplayName, otpDisplayName)
	}

	if account.DisplayName == address {
		t.Fatal("DisplayName is the submitted address")
	}
}
