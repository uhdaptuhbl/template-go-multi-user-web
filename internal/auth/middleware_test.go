//go:build integration

package auth

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authz"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/settings"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/user"
)

// testCookieName is used in place of session.DefaultCookieName by the
// RejectCrossSite and RejectCrossSiteAlways tables in this file, so nothing
// there can pass because the code happens to match the compiled-in default.
// The Authenticate tests use the store's configured default instead, since
// they exercise the cookie session.Store itself sets and clears.
const testCookieName = "service_session"

// testPublicOrigin is the configured origin RejectCrossSite compares Origin
// headers against in every test in this file.
const testPublicOrigin = "https://service.example"

// nextRecorder is a next handler that records whether it ran and captures the
// request it saw, so a test can inspect the context Authenticate attached.
type nextRecorder struct {
	called bool
	req    *http.Request
}

func (n *nextRecorder) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.called = true
		n.req = r
		w.WriteHeader(http.StatusOK)
	})
}

// newTestServiceWithLogger builds a Service from deps' already-migrated
// collaborators but with logger substituted for the nop one newTestService
// wires by default, so a test can observe what Authenticate logs. It stands
// up no new database state; every collaborator it passes is the one
// newTestService already built.
func newTestServiceWithLogger(deps testDeps, logger *zap.Logger) *Service {
	checker := authz.NewChecker(deps.roles)

	return NewService(deps.handle, deps.users, deps.sessions, deps.roles, checker, deps.recorder, deps.invites, deps.policy, nil, logger, deps.clock.Now, AccountDeps{})
}

// issueSession logs a fresh account in through the real signup path and
// returns the account id and raw session token, enabling signup first so the
// login succeeds.
func issueSession(t *testing.T, deps testDeps, subject string) (uuid.UUID, string) {
	t.Helper()

	setSignupPolicy(t, deps.policy, settings.Update{SignupEnabled: new(true), SignupRequireInvite: new(false)})

	in := Authenticated{
		Provider:      "https://issuer.example",
		Subject:       subject,
		Email:         subject + "@example.com",
		EmailVerified: true,
		DisplayName:   "Test User",
		Methods:       []string{session.MethodOIDC},
	}

	account, _, token, err := deps.service.LogIn(t.Context(), in, "203.0.113.5", "test-agent", "req-"+subject, "")
	if err != nil {
		t.Fatalf("LogIn() error = %v", err)
	}

	return account.ID, token
}

// requestWithSessionCookie returns a GET request carrying the session cookie
// under session.DefaultCookieName with value token.
func requestWithSessionCookie(t *testing.T, token string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "https://service.example/", http.NoBody)
	req.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: token}) //nolint:gosec // a request cookie, not a response one; Secure/HttpOnly/SameSite do not apply

	return req
}

// TestAuthenticate_NoCookie_RunsNextUnauthenticated covers AC-008.14: a
// request with no session cookie reaches next unchanged, with no subject
// attached to its context.
func TestAuthenticate_NoCookie_RunsNextUnauthenticated(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	next := &nextRecorder{}
	handler := deps.service.Authenticate(deps.sessions, next.handler())

	req := httptest.NewRequest(http.MethodGet, "https://service.example/", http.NoBody)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !next.called {
		t.Fatal("Authenticate() did not call next for a request with no cookie")
	}

	if _, ok := authz.SubjectFromContext(next.req.Context()); ok {
		t.Fatal("Authenticate() attached a subject for a request with no cookie")
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// TestAuthenticate_ValidCookie_AttachesSubject covers AC-008.14: a valid
// session cookie attaches a Subject whose UserID, SessionPublicID, and
// Permissions match the account and session that were resolved.
func TestAuthenticate_ValidCookie_AttachesSubject(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	userID, token := issueSession(t, deps, "sub-valid-cookie")

	sess, err := deps.sessions.Lookup(t.Context(), token)
	if err != nil {
		t.Fatalf("session.Lookup() error = %v", err)
	}

	// Lookup above already advanced last_seen_at/idle_expires_at; that is
	// harmless here since Authenticate below performs its own Lookup and
	// only PublicID and UserID, which do not change, are asserted against.
	next := &nextRecorder{}
	handler := deps.service.Authenticate(deps.sessions, next.handler())

	req := requestWithSessionCookie(t, token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !next.called {
		t.Fatal("Authenticate() did not call next for a valid cookie")
	}

	subject, ok := authz.SubjectFromContext(next.req.Context())
	if !ok {
		t.Fatal("Authenticate() did not attach a subject for a valid cookie")
	}

	if subject.UserID != userID {
		t.Fatalf("subject.UserID = %v, want %v", subject.UserID, userID)
	}

	if subject.SessionPublicID != sess.PublicID {
		t.Fatalf("subject.SessionPublicID = %v, want %v", subject.SessionPublicID, sess.PublicID)
	}

	wantPermissions := []string{authz.PermissionInviteCreate}
	if len(subject.Permissions) != len(wantPermissions) || subject.Permissions[0] != wantPermissions[0] {
		t.Fatalf("subject.Permissions = %v, want %v", subject.Permissions, wantPermissions)
	}
}

// TestAuthenticate_ExpiredSession_RunsNextAndClearsCookie covers AC-008.14:
// a session past its idle expiry resolves through session.ErrNotFound, which
// Authenticate treats as "no session" rather than an error: next runs with
// no subject attached, and the response clears the cookie.
func TestAuthenticate_ExpiredSession_RunsNextAndClearsCookie(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	_, token := issueSession(t, deps, "sub-expired")

	deps.clock.Advance(session.DefaultIdleTimeout.Duration() + time.Hour)

	next := &nextRecorder{}
	handler := deps.service.Authenticate(deps.sessions, next.handler())

	req := requestWithSessionCookie(t, token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !next.called {
		t.Fatal("Authenticate() did not call next for an expired session")
	}

	if _, ok := authz.SubjectFromContext(next.req.Context()); ok {
		t.Fatal("Authenticate() attached a subject for an expired session")
	}

	assertCookieCleared(t, rec)
}

// TestAuthenticate_SuspendedAccount_RunsNextAndClearsCookie covers
// AC-008.47: a session belonging to a suspended account resolves through
// session.ErrNotFound exactly as an expired session does, so it is treated
// as signed-out rather than as an error.
func TestAuthenticate_SuspendedAccount_RunsNextAndClearsCookie(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	userID, token := issueSession(t, deps, "sub-suspended-mw")

	if _, err := deps.users.SetStatus(t.Context(), userID, user.StatusSuspended); err != nil {
		t.Fatalf("SetStatus() error = %v", err)
	}

	next := &nextRecorder{}
	handler := deps.service.Authenticate(deps.sessions, next.handler())

	req := requestWithSessionCookie(t, token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !next.called {
		t.Fatal("Authenticate() did not call next for a suspended account's session")
	}

	if _, ok := authz.SubjectFromContext(next.req.Context()); ok {
		t.Fatal("Authenticate() attached a subject for a suspended account's session")
	}

	assertCookieCleared(t, rec)
}

// TestAuthenticate_DatabaseUnavailable_Returns503 covers AC-008.14: a
// database failure during session resolution must not be indistinguishable
// from a signed-out user, so it answers 503 with the exact body and does not
// call next.
func TestAuthenticate_DatabaseUnavailable_Returns503(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	_, token := issueSession(t, deps, "sub-db-down")

	deps.handle.Close()

	next := &nextRecorder{}
	handler := deps.service.Authenticate(deps.sessions, next.handler())

	req := requestWithSessionCookie(t, token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if next.called {
		t.Fatal("Authenticate() called next despite a database failure")
	}

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}

	wantBody := `{"errors":[{"status":"503","code":"unavailable","title":"Service unavailable"}]}`
	gotBody := strings.TrimSuffix(rec.Body.String(), "\n")

	if gotBody != wantBody {
		t.Fatalf("body = %s, want %s", gotBody, wantBody)
	}
}

// TestAuthenticateReissuesCookieOnStaleSession covers AC-008.77: once a
// session's cookie was last issued more than an hour ago, Authenticate
// resends it in the same request that resolves the session, so an active
// browser's cookie tracks the server-side session instead of expiring out
// from under continuous use.
func TestAuthenticateReissuesCookieOnStaleSession(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	_, token := issueSession(t, deps, "sub-stale-cookie")

	before, err := deps.sessions.Lookup(t.Context(), token)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}

	deps.clock.Advance(time.Hour + time.Minute)

	next := &nextRecorder{}
	handler := deps.service.Authenticate(deps.sessions, next.handler())

	req := requestWithSessionCookie(t, token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !next.called {
		t.Fatal("Authenticate() did not call next for a stale-cookie session")
	}

	var reissued *http.Cookie

	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == session.DefaultCookieName {
			reissued = cookie

			break
		}
	}

	if reissued == nil {
		t.Fatal("Authenticate() did not reissue the session cookie for a stale session")
	}

	if reissued.Value != token {
		t.Errorf("reissued cookie value = %q, want %q", reissued.Value, token)
	}

	if reissued.MaxAge <= 0 {
		t.Errorf("reissued cookie MaxAge = %d, want positive", reissued.MaxAge)
	}

	after, err := deps.sessions.Lookup(t.Context(), token)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}

	if !after.CookieIssuedAt.After(before.CookieIssuedAt) {
		t.Errorf("CookieIssuedAt = %v, want later than %v", after.CookieIssuedAt, before.CookieIssuedAt)
	}
}

// TestAuthenticateSkipsSessionLookupForHealthProbes covers AC-008.84: a
// liveness or readiness probe answers without touching the session table, so
// a database outage does not turn a passing probe into a false negative. The
// pool is closed before the request runs, so Authenticate would fail if it
// attempted any session lookup at all.
func TestAuthenticateSkipsSessionLookupForHealthProbes(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	_, token := issueSession(t, deps, "sub-health-probe")

	deps.handle.Close()

	for _, path := range []string{"/healthz", "/readyz"} {
		t.Run(path, func(t *testing.T) {
			next := &nextRecorder{}
			handler := deps.service.Authenticate(deps.sessions, next.handler())

			req := httptest.NewRequest(http.MethodGet, "https://service.example"+path, http.NoBody)
			req.AddCookie(&http.Cookie{Name: session.DefaultCookieName, Value: token}) //nolint:gosec // a request cookie, not a response one
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if !next.called {
				t.Fatalf("Authenticate() did not call next for %s despite a closed pool", path)
			}

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
		})
	}
}

// TestAuthenticate_SubjectFailure_Returns503 covers AC-008.14: a session that
// resolves fine but whose permission resolution then fails must not be
// treated as "no session" and must not fall through to next; it answers 503
// with the exact body Authenticate always uses for a dependency failure, and
// logs the Error line change 2 added naming the failed step. Permission
// resolution is broken deterministically by dropping role_permissions, the
// table authz.Repository.PermissionsFor joins through, while leaving
// sessions and users intact so Lookup still succeeds.
func TestAuthenticate_SubjectFailure_Returns503(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	core, logs := observer.New(zapcore.DebugLevel)
	obsLogger := zap.New(core)

	svc := newTestServiceWithLogger(deps, obsLogger)

	_, token := issueSession(t, deps, "sub-subject-down")

	if _, err := deps.handle.Pool().Exec(t.Context(), `DROP TABLE role_permissions CASCADE`); err != nil {
		t.Fatalf("dropping role_permissions: %v", err)
	}

	next := &nextRecorder{}
	handler := svc.Authenticate(deps.sessions, next.handler())

	req := requestWithSessionCookie(t, token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if next.called {
		t.Fatal("Authenticate() called next despite a subject resolution failure")
	}

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}

	wantBody := `{"errors":[{"status":"503","code":"unavailable","title":"Service unavailable"}]}`
	gotBody := strings.TrimSuffix(rec.Body.String(), "\n")

	if gotBody != wantBody {
		t.Fatalf("body = %s, want %s", gotBody, wantBody)
	}

	errorEntries := logs.FilterMessage("auth: resolving subject").All()
	if len(errorEntries) != 1 {
		t.Fatalf("got %d %q log entries, want 1", len(errorEntries), "auth: resolving subject")
	}

	if errorEntries[0].Level != zapcore.ErrorLevel {
		t.Fatalf("%q level = %v, want Error", "auth: resolving subject", errorEntries[0].Level)
	}
}

// TestRequireAuthentication_NoSubject_Returns401 covers AC-008.34: a request
// with no authenticated subject in its context is rejected with the exact
// 401 body, and next does not run.
func TestRequireAuthentication_NoSubject_Returns401(t *testing.T) {
	t.Parallel()

	next := &nextRecorder{}
	handler := RequireAuthentication(zap.NewNop(), next.handler())

	req := httptest.NewRequest(http.MethodGet, "https://service.example/", http.NoBody)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if next.called {
		t.Fatal("RequireAuthentication() called next with no subject present")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	wantBody := `{"errors":[{"status":"401","code":"unauthenticated","title":"Authentication required"}]}`
	gotBody := strings.TrimSuffix(rec.Body.String(), "\n")

	if gotBody != wantBody {
		t.Fatalf("body = %s, want %s", gotBody, wantBody)
	}
}

// TestRequireAuthentication_WithSubject_RunsNext covers AC-008.34: a request
// whose context already carries a subject passes through to next.
func TestRequireAuthentication_WithSubject_RunsNext(t *testing.T) {
	t.Parallel()

	next := &nextRecorder{}
	handler := RequireAuthentication(zap.NewNop(), next.handler())

	req := httptest.NewRequest(http.MethodGet, "https://service.example/", http.NoBody)
	req = req.WithContext(authz.WithSubject(req.Context(), authz.Subject{}))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !next.called {
		t.Fatal("RequireAuthentication() did not call next with a subject present")
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// crossSiteCase is one row of the RejectCrossSite table.
type crossSiteCase struct {
	name string
	// method is the request method. Defaults to POST when empty.
	method string
	// noCookie, when true, means the request carries no cookie at all.
	noCookie bool
	// cookieName overrides testCookieName for the cookie the request
	// carries; empty means testCookieName.
	cookieName string
	// emptyCookieValue, when true, sends the session cookie with an empty
	// value instead of "token".
	emptyCookieValue bool
	secFetchSite     string
	origin           string
	wantBlocked      bool
}

// TestRejectCrossSite covers AC-008.18 across method, cookie presence, and
// Sec-Fetch-Site/Origin combinations. Its "neither header" row covers
// AC-008.19 instead: the absence of both headers on a cookie-bearing request,
// rather than either header naming another site.
func TestRejectCrossSite(t *testing.T) {
	t.Parallel()

	cases := []crossSiteCase{
		{
			name:         "GET cross-site Sec-Fetch-Site allowed, not state-changing",
			method:       http.MethodGet,
			secFetchSite: "cross-site",
			wantBlocked:  false,
		},
		{
			name:         "POST without session cookie allowed",
			method:       http.MethodPost,
			noCookie:     true,
			secFetchSite: "cross-site",
			wantBlocked:  false,
		},
		{
			name:         "POST cookie Sec-Fetch-Site same-origin allowed",
			method:       http.MethodPost,
			secFetchSite: "same-origin",
			wantBlocked:  false,
		},
		{
			name:         "POST cookie Sec-Fetch-Site none allowed",
			method:       http.MethodPost,
			secFetchSite: "none",
			wantBlocked:  false,
		},
		{
			name:         "POST cookie Sec-Fetch-Site cross-site rejected",
			method:       http.MethodPost,
			secFetchSite: "cross-site",
			wantBlocked:  true,
		},
		{
			name:        "POST cookie no Sec-Fetch-Site matching Origin allowed",
			method:      http.MethodPost,
			origin:      testPublicOrigin,
			wantBlocked: false,
		},
		{
			name:        "POST cookie no Sec-Fetch-Site different Origin rejected",
			method:      http.MethodPost,
			origin:      "https://attacker.example",
			wantBlocked: true,
		},
		{
			// AC-008.19: neither header present is itself the signature of
			// a forged request, not merely a case of AC-008.18.
			name:        "POST cookie neither header rejected",
			method:      http.MethodPost,
			wantBlocked: true,
		},
		{
			name:         "POST cookie Sec-Fetch-Site cross-site with matching Origin still rejected",
			method:       http.MethodPost,
			secFetchSite: "cross-site",
			origin:       testPublicOrigin,
			wantBlocked:  true,
		},
		{
			name:         "POST cookie Sec-Fetch-Site same-site rejected",
			method:       http.MethodPost,
			secFetchSite: "same-site",
			wantBlocked:  true,
		},
		{
			name:        "POST cookie Origin with publicOrigin as mere prefix rejected",
			method:      http.MethodPost,
			origin:      testPublicOrigin + ".evil.example",
			wantBlocked: true,
		},
		{
			name:         "HEAD cross-site allowed",
			method:       http.MethodHead,
			secFetchSite: "cross-site",
			wantBlocked:  false,
		},
		{
			name:         "OPTIONS cross-site allowed",
			method:       http.MethodOptions,
			secFetchSite: "cross-site",
			wantBlocked:  false,
		},
		{
			name:         "PUT cross-site rejected",
			method:       http.MethodPut,
			secFetchSite: "cross-site",
			wantBlocked:  true,
		},
		{
			name:         "DELETE cross-site rejected",
			method:       http.MethodDelete,
			secFetchSite: "cross-site",
			wantBlocked:  true,
		},
		{
			name:         "PATCH cross-site rejected",
			method:       http.MethodPatch,
			secFetchSite: "cross-site",
			wantBlocked:  true,
		},
		{
			name:             "POST cookie present with empty value still counts as carried, rejected",
			method:           http.MethodPost,
			emptyCookieValue: true,
			secFetchSite:     "cross-site",
			wantBlocked:      true,
		},
		{
			name:         "POST different cookie name only, cross-site headers, allowed",
			method:       http.MethodPost,
			cookieName:   "some_other_cookie",
			secFetchSite: "cross-site",
			wantBlocked:  false,
		},
		{
			// AC-008.18: Origin "null" is a real browser value (sent from a
			// sandboxed or file:// context) and never equals publicOrigin.
			name:        "POST cookie Origin null no Sec-Fetch-Site rejected",
			method:      http.MethodPost,
			origin:      "null",
			wantBlocked: true,
		},
		{
			// AC-008.18: Sec-Fetch-Site's grammar is lowercase tokens; a
			// capitalized value must not be mistaken for "same-origin".
			name:         "POST cookie Sec-Fetch-Site capitalized Same-Origin rejected",
			method:       http.MethodPost,
			secFetchSite: "Same-Origin",
			wantBlocked:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			next := &nextRecorder{}
			handler := RejectCrossSite(testPublicOrigin, testCookieName, zap.NewNop(), next.handler())

			method := tc.method
			if method == "" {
				method = http.MethodPost
			}

			req := httptest.NewRequest(method, "https://service.example/action", http.NoBody)

			if !tc.noCookie {
				name := tc.cookieName
				if name == "" {
					name = testCookieName
				}

				value := "token"
				if tc.emptyCookieValue {
					value = ""
				}

				req.AddCookie(&http.Cookie{Name: name, Value: value}) //nolint:gosec // a request cookie, not a response one; Secure/HttpOnly/SameSite do not apply
			}

			if tc.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetchSite)
			}

			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}

			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if tc.wantBlocked {
				if next.called {
					t.Fatal("RejectCrossSite() called next for a request that should have been blocked")
				}

				if rec.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want 403", rec.Code)
				}

				wantBody := `{"errors":[{"status":"403","code":"cross_site","title":"Cross-site request rejected"}]}`
				gotBody := strings.TrimSuffix(rec.Body.String(), "\n")

				if gotBody != wantBody {
					t.Fatalf("body = %s, want %s", gotBody, wantBody)
				}

				return
			}

			if !next.called {
				t.Fatal("RejectCrossSite() blocked a request that should have been allowed")
			}
		})
	}
}

// TestRejectCrossSite_EmptyValueCookieCounted covers AC-008.18 directly: an
// attacker-controlled cookie with an empty value must still count as
// "carries the session cookie", since r.Cookie succeeds on it. This is
// written as its own request (rather than through the header trick used in
// the table above) so the assertion is unambiguous.
func TestRejectCrossSite_EmptyValueCookieCounted(t *testing.T) {
	t.Parallel()

	next := &nextRecorder{}
	handler := RejectCrossSite(testPublicOrigin, testCookieName, zap.NewNop(), next.handler())

	req := httptest.NewRequest(http.MethodPost, "https://service.example/action", http.NoBody)
	req.Header.Set("Cookie", testCookieName+"=")
	req.Header.Set("Sec-Fetch-Site", "cross-site")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if next.called {
		t.Fatal("RejectCrossSite() allowed a cross-site request carrying an empty-valued session cookie")
	}

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// TestRejectCrossSite_LogsExactlyOneWarnWithRequestFields covers AC-008.18: a
// blocked request produces exactly one Warn entry, carrying the request's own
// method, path, sec_fetch_site, and origin values.
func TestRejectCrossSite_LogsExactlyOneWarnWithRequestFields(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	next := &nextRecorder{}
	handler := RejectCrossSite(testPublicOrigin, testCookieName, logger, next.handler())

	req := httptest.NewRequest(http.MethodPost, "https://service.example/action", http.NoBody)
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: "token"}) //nolint:gosec // a request cookie, not a response one
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Origin", "https://attacker.example")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	warnEntries := logs.FilterLevelExact(zapcore.WarnLevel).All()
	if len(warnEntries) != 1 {
		t.Fatalf("got %d Warn entries, want 1", len(warnEntries))
	}

	fields := warnEntries[0].ContextMap()

	if got, ok := fields["method"].(string); !ok || got != http.MethodPost {
		t.Errorf("method field = %v, want %q", fields["method"], http.MethodPost)
	}

	if got, ok := fields["path"].(string); !ok || got != "/action" {
		t.Errorf("path field = %v, want %q", fields["path"], "/action")
	}

	if got, ok := fields["sec_fetch_site"].(string); !ok || got != "cross-site" {
		t.Errorf("sec_fetch_site field = %v, want %q", fields["sec_fetch_site"], "cross-site")
	}

	if got, ok := fields["origin"].(string); !ok || got != "https://attacker.example" {
		t.Errorf("origin field = %v, want %q", fields["origin"], "https://attacker.example")
	}
}

// crossSiteAlwaysCase is one row of the RejectCrossSiteAlways table.
type crossSiteAlwaysCase struct {
	name         string
	method       string
	noCookie     bool
	secFetchSite string
	origin       string
	wantBlocked  bool
}

// TestRejectCrossSiteAlways covers AC-008.18 and, for the neither-header row,
// AC-008.19: RejectCrossSiteAlways applies the same cross-site decision as
// RejectCrossSite, but never exempts a request for lacking the session
// cookie, since the login and signup-completion routes it protects run
// before any session exists.
func TestRejectCrossSiteAlways(t *testing.T) {
	t.Parallel()

	cases := []crossSiteAlwaysCase{
		{
			name:         "POST no cookie cross-site Sec-Fetch-Site rejected",
			method:       http.MethodPost,
			noCookie:     true,
			secFetchSite: "cross-site",
			wantBlocked:  true,
		},
		{
			name:         "POST no cookie Sec-Fetch-Site same-origin allowed",
			method:       http.MethodPost,
			noCookie:     true,
			secFetchSite: "same-origin",
			wantBlocked:  false,
		},
		{
			name:        "POST no cookie no Sec-Fetch-Site matching Origin allowed",
			method:      http.MethodPost,
			noCookie:    true,
			origin:      testPublicOrigin,
			wantBlocked: false,
		},
		{
			// AC-008.19: neither header present is rejected even with no
			// cookie in play at all.
			name:        "POST no cookie neither header rejected",
			method:      http.MethodPost,
			noCookie:    true,
			wantBlocked: true,
		},
		{
			name:         "GET no cookie cross-site allowed, not state-changing",
			method:       http.MethodGet,
			noCookie:     true,
			secFetchSite: "cross-site",
			wantBlocked:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			next := &nextRecorder{}
			handler := RejectCrossSiteAlways(testPublicOrigin, zap.NewNop(), next.handler())

			req := httptest.NewRequest(tc.method, "https://service.example/login/complete", http.NoBody)

			if !tc.noCookie {
				req.AddCookie(&http.Cookie{Name: testCookieName, Value: "token"}) //nolint:gosec // a request cookie, not a response one
			}

			if tc.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetchSite)
			}

			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if tc.wantBlocked {
				if next.called {
					t.Fatal("RejectCrossSiteAlways() called next for a request that should have been blocked")
				}

				if rec.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want 403", rec.Code)
				}

				wantBody := `{"errors":[{"status":"403","code":"cross_site","title":"Cross-site request rejected"}]}`
				gotBody := strings.TrimSuffix(rec.Body.String(), "\n")

				if gotBody != wantBody {
					t.Fatalf("body = %s, want %s", gotBody, wantBody)
				}

				return
			}

			if !next.called {
				t.Fatal("RejectCrossSiteAlways() blocked a request that should have been allowed")
			}
		})
	}
}

// crossSiteNavigationCase is one row of the RejectCrossSiteNavigation table.
type crossSiteNavigationCase struct {
	name         string
	method       string
	secFetchSite string
	origin       string
	wantBlocked  bool
}

// TestRejectCrossSiteNavigation covers AC-008.18 for a state-changing route
// that must remain a GET, such as the identity-link start route that
// redirects the browser to an identity provider: unlike RejectCrossSite and
// RejectCrossSiteAlways, it applies to every method rather than exempting
// GET, HEAD, and OPTIONS. Each signal scenario runs under both GET and POST
// to show the decision does not depend on method.
func TestRejectCrossSiteNavigation(t *testing.T) {
	t.Parallel()

	cases := []crossSiteNavigationCase{
		{name: "GET Sec-Fetch-Site same-origin allowed", method: http.MethodGet, secFetchSite: "same-origin", wantBlocked: false},
		{name: "POST Sec-Fetch-Site same-origin allowed", method: http.MethodPost, secFetchSite: "same-origin", wantBlocked: false},
		{name: "GET Sec-Fetch-Site none allowed", method: http.MethodGet, secFetchSite: "none", wantBlocked: false},
		{name: "POST Sec-Fetch-Site none allowed", method: http.MethodPost, secFetchSite: "none", wantBlocked: false},
		{name: "GET Sec-Fetch-Site same-site rejected", method: http.MethodGet, secFetchSite: "same-site", wantBlocked: true},
		{name: "POST Sec-Fetch-Site same-site rejected", method: http.MethodPost, secFetchSite: "same-site", wantBlocked: true},
		{name: "GET Sec-Fetch-Site cross-site rejected", method: http.MethodGet, secFetchSite: "cross-site", wantBlocked: true},
		{name: "POST Sec-Fetch-Site cross-site rejected", method: http.MethodPost, secFetchSite: "cross-site", wantBlocked: true},
		{name: "GET no Sec-Fetch-Site matching Origin allowed", method: http.MethodGet, origin: testPublicOrigin, wantBlocked: false},
		{name: "POST no Sec-Fetch-Site matching Origin allowed", method: http.MethodPost, origin: testPublicOrigin, wantBlocked: false},
		{name: "GET no Sec-Fetch-Site foreign Origin rejected", method: http.MethodGet, origin: "https://attacker.example", wantBlocked: true},
		{name: "POST no Sec-Fetch-Site foreign Origin rejected", method: http.MethodPost, origin: "https://attacker.example", wantBlocked: true},
		{
			// Deliberately lenient, unlike crossSiteAllowed: a top-level GET
			// from a browser sending neither header carries no evidence
			// either way, and every current browser sends Sec-Fetch-Site.
			name:        "GET neither header allowed",
			method:      http.MethodGet,
			wantBlocked: false,
		},
		{
			name:        "POST neither header allowed",
			method:      http.MethodPost,
			wantBlocked: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			next := &nextRecorder{}
			handler := RejectCrossSiteNavigation(testPublicOrigin, zap.NewNop(), next.handler())

			req := httptest.NewRequest(tc.method, "https://service.example/api/v1/me/identities/google/link/start", http.NoBody)

			if tc.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetchSite)
			}

			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if tc.wantBlocked {
				if next.called {
					t.Fatal("RejectCrossSiteNavigation() called next for a request that should have been blocked")
				}

				if rec.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want 403", rec.Code)
				}

				wantBody := `{"errors":[{"status":"403","code":"cross_site","title":"Cross-site request rejected"}]}`
				gotBody := strings.TrimSuffix(rec.Body.String(), "\n")

				if gotBody != wantBody {
					t.Fatalf("body = %s, want %s", gotBody, wantBody)
				}

				return
			}

			if !next.called {
				t.Fatal("RejectCrossSiteNavigation() blocked a request that should have been allowed")
			}
		})
	}
}

// TestMiddleware_NeverLogsTokenOrCookieHeader covers AC-008.40: across a
// successful Authenticate, a stale-cookie Authenticate, a cross-site
// rejection that sends a real Cookie header, and a Lookup failure caused by
// a closed database pool, no logged message or field contains a raw session
// token, the literal Cookie header value, or any of a token's digest
// encodings (hex, base64 standard, base64 raw-URL) that a careless log line
// might reach for instead of the token itself. It also proves that the 503
// this last case answers with is accompanied by the Error line change 2
// added, so a real outage is never silent.
func TestMiddleware_NeverLogsTokenOrCookieHeader(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)

	core, logs := observer.New(zapcore.DebugLevel)
	obsLogger := zap.New(core)

	svc := newTestServiceWithLogger(deps, obsLogger)

	_, validToken := issueSession(t, deps, "sub-log-valid")

	validReq := requestWithSessionCookie(t, validToken)
	validRec := httptest.NewRecorder()
	svc.Authenticate(deps.sessions, (&nextRecorder{}).handler()).ServeHTTP(validRec, validReq)

	_, staleToken := issueSession(t, deps, "sub-log-stale")
	deps.clock.Advance(session.DefaultIdleTimeout.Duration() + time.Hour)

	staleReq := requestWithSessionCookie(t, staleToken)
	staleRec := httptest.NewRecorder()
	svc.Authenticate(deps.sessions, (&nextRecorder{}).handler()).ServeHTTP(staleRec, staleReq)

	crossSiteReq := httptest.NewRequest(http.MethodPost, "https://service.example/action", http.NoBody)
	crossSiteReq.Header.Set("Cookie", testCookieName+"="+validToken)
	crossSiteReq.Header.Set("Sec-Fetch-Site", "cross-site")
	crossSiteRec := httptest.NewRecorder()
	RejectCrossSite(testPublicOrigin, testCookieName, obsLogger, (&nextRecorder{}).handler()).ServeHTTP(crossSiteRec, crossSiteReq)

	// Issue one more session before breaking the pool, then drive the
	// Lookup-error 503 path. (The Subject-error 503 path is T5's
	// TestAuthenticate_SubjectFailure_Returns503, in a database of its own.)
	_, unavailableToken := issueSession(t, deps, "sub-log-unavailable")
	deps.handle.Close()

	unavailableReq := requestWithSessionCookie(t, unavailableToken)
	unavailableRec := httptest.NewRecorder()
	svc.Authenticate(deps.sessions, (&nextRecorder{}).handler()).ServeHTTP(unavailableRec, unavailableReq)

	if unavailableRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", unavailableRec.Code)
	}

	sessionErrorEntries := logs.FilterMessage("auth: resolving session").All()
	if len(sessionErrorEntries) != 1 {
		t.Fatalf("got %d %q log entries, want 1", len(sessionErrorEntries), "auth: resolving session")
	}

	if sessionErrorEntries[0].Level != zapcore.ErrorLevel {
		t.Fatalf("%q level = %v, want Error", "auth: resolving session", sessionErrorEntries[0].Level)
	}

	tokens := []string{validToken, staleToken, unavailableToken}
	forbiddenSubstrings := make([]string, 1, 1+4*len(tokens))
	forbiddenSubstrings[0] = "Cookie"

	for _, token := range tokens {
		digest := session.Digest(token)
		forbiddenSubstrings = append(forbiddenSubstrings,
			token,
			hex.EncodeToString(digest),
			base64.StdEncoding.EncodeToString(digest),
			base64.RawURLEncoding.EncodeToString(digest),
		)
	}

	for _, entry := range logs.All() {
		for _, needle := range forbiddenSubstrings {
			if strings.Contains(entry.Message, needle) {
				t.Fatalf("log message %q contains forbidden substring %q", entry.Message, needle)
			}
		}

		for key, value := range entry.ContextMap() {
			rendered := fmt.Sprintf("%s=%v", key, value)

			for _, needle := range forbiddenSubstrings {
				if strings.Contains(rendered, needle) {
					t.Fatalf("log field %q contains forbidden substring %q", rendered, needle)
				}
			}
		}
	}
}

// assertCookieCleared fails t unless rec carries a Set-Cookie header that
// clears the session cookie: an empty value and a negative MaxAge.
func assertCookieCleared(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	cookies := rec.Result().Cookies()

	for _, c := range cookies {
		if c.Name != session.DefaultCookieName {
			continue
		}

		if c.Value != "" {
			t.Fatalf("cleared cookie value = %q, want empty", c.Value)
		}

		if c.MaxAge >= 0 {
			t.Fatalf("cleared cookie MaxAge = %d, want negative", c.MaxAge)
		}

		return
	}

	t.Fatal("response carries no Set-Cookie header for the session cookie")
}
