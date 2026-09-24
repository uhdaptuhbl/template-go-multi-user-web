//go:build integration

package oidc_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	goidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/auth/oidc"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authflow"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/secret"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
)

// testKeyID is the key identifier every signed test token and the test
// server's published JWKS entry share.
const testKeyID = "test-key"

// providerKey is the configured Key for the one provider every test
// registers.
const providerKey = "test"

// otherProviderKey is a second configured Key, used by tests proving a
// ceremony is bound to the provider it was started against.
const otherProviderKey = "test-other"

// expectedRedirectURI is the redirect_uri every token exchange in this file
// must send, matching the provider's configured callback.
const expectedRedirectURI = "https://app.example/api/v1/auth/oidc/" + providerKey + "/callback"

// clientID is the OAuth client identifier every test registers the provider
// with, and the expected audience of every valid test token.
const clientID = "test-client-id"

// clientSecret is the OAuth client secret every test registers the provider
// with.
const clientSecret = "test-client-secret"

// tokenEndpoint is an http.Handler standing in for a provider's token
// endpoint. It always returns the identity token most recently set on it, so
// a test can control the token exchange's response without a live
// authorization step. It also proves PKCE is exercised: it rejects any
// exchange whose code_verifier does not hash to the code_challenge the test
// captured from the authorization URL, whose redirect_uri does not match the
// configured callback, or whose client credentials do not match the
// provider's.
type tokenEndpoint struct {
	mu            sync.Mutex
	idToken       string
	challenge     string
	exchangeCount int
}

// setIDToken replaces the identity token the next token exchange returns.
func (e *tokenEndpoint) setIDToken(token string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.idToken = token
}

// setChallenge records the code_challenge a successful exchange's
// code_verifier must hash to.
func (e *tokenEndpoint) setChallenge(challenge string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.challenge = challenge
}

// hits reports how many times the token endpoint has returned a successful
// exchange, so a test can prove a rejected ceremony never reached it.
func (e *tokenEndpoint) hits() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.exchangeCount
}

// ServeHTTP implements http.Handler. It returns HTTP 400 unless the request
// carries a code_verifier hashing to the expected code_challenge and the
// expected redirect_uri, and HTTP 401 unless the client credentials match
// the configured provider; otherwise it returns a token response carrying
// the currently configured identity token.
func (e *tokenEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	if got := r.PostForm.Get("redirect_uri"); got != expectedRedirectURI {
		http.Error(w, "unexpected redirect_uri", http.StatusBadRequest)

		return
	}

	gotClientID, gotClientSecret, ok := r.BasicAuth()
	if !ok {
		gotClientID = r.PostForm.Get("client_id")
		gotClientSecret = r.PostForm.Get("client_secret")
	}

	if gotClientID != clientID || gotClientSecret != clientSecret {
		http.Error(w, "unexpected client credentials", http.StatusUnauthorized)

		return
	}

	e.mu.Lock()
	e.exchangeCount++
	e.mu.Unlock()

	body, err := json.Marshal(map[string]any{
		"access_token": "test-access-token",
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

// newProviderServer starts a test identity provider serving discovery, a
// JWKS advertising pub under keyID, and a token endpoint whose response is
// controlled by the returned tokenEndpoint.
func newProviderServer(t *testing.T, pub any, keyID string) (*httptest.Server, *tokenEndpoint) {
	t.Helper()

	discovery := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{
			{PublicKey: pub, KeyID: keyID, Algorithm: goidc.RS256},
		},
	}

	tokenEP := &tokenEndpoint{}

	mux := http.NewServeMux()
	mux.Handle("/.well-known/openid-configuration", discovery)
	mux.Handle("/keys", discovery)
	mux.Handle("/token", tokenEP)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	discovery.SetIssuer(srv.URL)

	return srv, tokenEP
}

// newFlows returns an authflow.Store backed by a fresh migrated database.
func newFlows(t *testing.T) *authflow.Store {
	t.Helper()

	handle := storetest.New(t)

	return authflow.NewStore(handle, time.Minute, time.Now)
}

// newLinkFlows returns an authflow.Store backed by a fresh migrated
// database, together with the handle, so a link-ceremony test can insert the
// real user row auth_flows.user_id's foreign key requires.
func newLinkFlows(t *testing.T) (*authflow.Store, *store.Handle) {
	t.Helper()

	handle := storetest.New(t)

	return authflow.NewStore(handle, time.Minute, time.Now), handle
}

// insertLinkTestUser inserts a minimal active user row directly, since this
// package does not depend on internal/user, so a link ceremony's userID
// satisfies auth_flows.user_id's foreign key to users(id).
func insertLinkTestUser(t *testing.T, h *store.Handle) uuid.UUID {
	t.Helper()

	id := uuid.New()

	const insertUserQuery = `
INSERT INTO users (id, display_name, status, created_at, updated_at)
VALUES ($1, $2, 'active', now(), now())
`

	if _, err := h.Pool().Exec(t.Context(), insertUserQuery, id, "oidc link test user"); err != nil {
		t.Fatalf("insertLinkTestUser: inserting: %v", err)
	}

	return id
}

// newRegistry returns a Registry with one provider, "test", registered
// against issuer and reached through httpClient.
func newRegistry(t *testing.T, issuer string, httpClient *http.Client, flows *authflow.Store, clockSkew time.Duration) *oidc.Registry {
	t.Helper()

	cfg := oidc.Config{
		PublicOrigin: "https://app.example",
		Providers: []oidc.ProviderConfig{
			{
				Key:          providerKey,
				Issuer:       issuer,
				ClientID:     clientID,
				ClientSecret: secret.String(clientSecret),
				Scopes:       []string{"profile"},
				DisplayName:  "Test Provider",
			},
		},
		ClockSkew: configtype.Duration(clockSkew),
	}

	registry, err := oidc.NewRegistry(cfg, flows, httpClient, zap.NewNop())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	return registry
}

// newTwoProviderRegistry returns a Registry with two providers, "test" and
// "test-other", both discoverable against issuer through httpClient, so a
// ceremony started against one can be presented to Finish against the other.
func newTwoProviderRegistry(t *testing.T, issuer string, httpClient *http.Client, flows *authflow.Store) *oidc.Registry {
	t.Helper()

	cfg := oidc.Config{
		PublicOrigin: "https://app.example",
		Providers: []oidc.ProviderConfig{
			{
				Key:          providerKey,
				Issuer:       issuer,
				ClientID:     clientID,
				ClientSecret: secret.String(clientSecret),
				Scopes:       []string{"profile"},
				DisplayName:  "Test Provider",
			},
			{
				Key:          otherProviderKey,
				Issuer:       issuer,
				ClientID:     clientID,
				ClientSecret: secret.String(clientSecret),
				Scopes:       []string{"profile"},
				DisplayName:  "Other Test Provider",
			},
		},
		ClockSkew: configtype.Duration(30 * time.Second),
	}

	registry, err := oidc.NewRegistry(cfg, flows, httpClient, zap.NewNop())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	return registry
}

// buildClaims renders a raw identity token claims payload.
func buildClaims(t *testing.T, issuer, audience, nonce string, exp time.Time, emailVerified bool) string {
	t.Helper()

	return fmt.Sprintf(`{
		"iss": %q,
		"aud": %q,
		"sub": "user-123",
		"nonce": %q,
		"exp": %d,
		"email": "user@example.com",
		"email_verified": %t,
		"name": "Test User"
	}`, issuer, audience, nonce, exp.Unix(), emailVerified)
}

// parseAuthURL extracts the nonce, state, and code_challenge query
// parameters Start embedded in the authorization URL it returned.
func parseAuthURL(t *testing.T, authURL string) (string, string, string) {
	t.Helper()

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parsing authorization URL: %v", err)
	}

	query := parsed.Query()

	return query.Get("nonce"), query.Get("state"), query.Get("code_challenge")
}

// TestStartUnknownProviderReturnsErrUnknownProvider covers AC-008.20: Start
// for a key with no configuration returns ErrUnknownProvider.
func TestStartUnknownProviderReturnsErrUnknownProvider(t *testing.T) {
	t.Parallel()

	flows := newFlows(t)
	registry := newRegistry(t, "https://issuer.invalid", http.DefaultClient, flows, 30*time.Second)

	_, _, err := registry.Start(t.Context(), "does-not-exist", uuid.NullUUID{})
	if !errors.Is(err, oidc.ErrUnknownProvider) {
		t.Fatalf("Start: got %v, want ErrUnknownProvider", err)
	}
}

// TestStartReturnsAuthorizationURLWithExpectedParameters covers AC-008.20:
// Start returns a URL carrying the PKCE challenge, state, nonce, configured
// scopes, and the expected redirect_uri.
func TestStartReturnsAuthorizationURLWithExpectedParameters(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	srv, _ := newProviderServer(t, priv.Public(), testKeyID)
	flows := newFlows(t)
	registry := newRegistry(t, srv.URL, srv.Client(), flows, 30*time.Second)

	authURL, _, err := registry.Start(t.Context(), providerKey, uuid.NullUUID{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parsing authorization URL: %v", err)
	}

	query := parsed.Query()

	if query.Get("code_challenge") == "" {
		t.Fatalf("Start URL: missing code_challenge")
	}

	if got := query.Get("code_challenge_method"); got != "S256" {
		t.Fatalf("Start URL: code_challenge_method = %q, want S256", got)
	}

	if query.Get("state") == "" {
		t.Fatalf("Start URL: missing state")
	}

	if query.Get("nonce") == "" {
		t.Fatalf("Start URL: missing nonce")
	}

	if scope := query.Get("scope"); !strings.Contains(scope, "openid") || !strings.Contains(scope, "profile") {
		t.Fatalf("Start URL: scope = %q, want it to contain openid and profile", scope)
	}

	wantRedirect := "https://app.example/api/v1/auth/oidc/" + providerKey + "/callback"
	if got := query.Get("redirect_uri"); got != wantRedirect {
		t.Fatalf("Start URL: redirect_uri = %q, want %q", got, wantRedirect)
	}
}

// TestStartFinishRoundTripReturnsClaimsAndInvite covers AC-008.70: a full
// Start then Finish round trip returns the expected claims together with the
// invite the ceremony was bound to.
func TestStartFinishRoundTripReturnsClaimsAndInvite(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	srv, tokenEP := newProviderServer(t, priv.Public(), testKeyID)
	flows := newFlows(t)
	registry := newRegistry(t, srv.URL, srv.Client(), flows, 30*time.Second)

	invite := uuid.NullUUID{UUID: uuid.New(), Valid: true}

	authURL, binding, err := registry.Start(t.Context(), providerKey, invite)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	nonce, state, challenge := parseAuthURL(t, authURL)
	tokenEP.setChallenge(challenge)

	claims := buildClaims(t, srv.URL, clientID, nonce, time.Now().Add(time.Hour), true)
	tokenEP.setIDToken(oidctest.SignIDToken(priv, testKeyID, goidc.RS256, claims))

	gotClaims, gotInvite, err := registry.Finish(t.Context(), providerKey, state, "test-code", binding)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}

	if gotClaims.Subject != "user-123" {
		t.Fatalf("Finish: Subject = %q, want user-123", gotClaims.Subject)
	}

	if gotClaims.Issuer != srv.URL {
		t.Fatalf("Finish: Issuer = %q, want %q", gotClaims.Issuer, srv.URL)
	}

	if gotClaims.Email != "user@example.com" {
		t.Fatalf("Finish: Email = %q, want user@example.com", gotClaims.Email)
	}

	if !gotClaims.EmailVerified {
		t.Fatalf("Finish: EmailVerified = false, want true")
	}

	if !gotInvite.Valid || gotInvite.UUID != invite.UUID {
		t.Fatalf("Finish: invite = %+v, want %+v", gotInvite, invite)
	}
}

// TestFinishAcceptsEmailVerifiedSentAsAString covers AC-008.89: a provider
// that sends email_verified as the JSON string "true" or "false" rather than
// a boolean still completes the login, with the matching verification state.
// Any other string is not a verification claim and fails the token.
func TestFinishAcceptsEmailVerifiedSentAsAString(t *testing.T) {
	t.Parallel()

	priv, keyErr := rsa.GenerateKey(rand.Reader, 2048)
	if keyErr != nil {
		t.Fatalf("generating key: %v", keyErr)
	}

	tests := []struct {
		name    string
		raw     string
		want    bool
		wantErr error
	}{
		{name: "string true", raw: `"true"`, want: true},
		{name: "string false", raw: `"false"`, want: false},
		{name: "string true in capitals", raw: `"TRUE"`, want: true},
		{name: "a string that is not a boolean", raw: `"yes"`, wantErr: oidc.ErrInvalidToken},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			srv, tokenEP := newProviderServer(t, priv.Public(), testKeyID)
			flows := newFlows(t)
			registry := newRegistry(t, srv.URL, srv.Client(), flows, 30*time.Second)

			authURL, binding, err := registry.Start(t.Context(), providerKey, uuid.NullUUID{})
			if err != nil {
				t.Fatalf("Start: %v", err)
			}

			nonce, state, challenge := parseAuthURL(t, authURL)
			tokenEP.setChallenge(challenge)

			claims := strings.Replace(buildClaims(t, srv.URL, clientID, nonce, time.Now().Add(time.Hour), true),
				`"email_verified": true`, `"email_verified": `+test.raw, 1)
			tokenEP.setIDToken(oidctest.SignIDToken(priv, testKeyID, goidc.RS256, claims))

			gotClaims, _, err := registry.Finish(t.Context(), providerKey, state, "test-code", binding)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("Finish error = %v, want %v", err, test.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("Finish: %v", err)
			}

			if gotClaims.EmailVerified != test.want {
				t.Errorf("Finish: EmailVerified = %v, want %v for %s", gotClaims.EmailVerified, test.want, test.raw)
			}
		})
	}
}

// TestFinishUnknownStateReturnsErrInvalidState covers AC-008.21: Finish with
// a state that was never issued returns ErrInvalidState.
func TestFinishUnknownStateReturnsErrInvalidState(t *testing.T) {
	t.Parallel()

	flows := newFlows(t)
	registry := newRegistry(t, "https://issuer.invalid", http.DefaultClient, flows, 30*time.Second)

	_, _, err := registry.Finish(t.Context(), providerKey, "never-issued-state", "code", "binding")
	if !errors.Is(err, oidc.ErrInvalidState) {
		t.Fatalf("Finish: got %v, want ErrInvalidState", err)
	}
}

// TestFinishReplayedStateReturnsErrInvalidState covers AC-008.21: Finish
// replaying a state already consumed returns ErrInvalidState.
func TestFinishReplayedStateReturnsErrInvalidState(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	srv, tokenEP := newProviderServer(t, priv.Public(), testKeyID)
	flows := newFlows(t)
	registry := newRegistry(t, srv.URL, srv.Client(), flows, 30*time.Second)

	authURL, binding, err := registry.Start(t.Context(), providerKey, uuid.NullUUID{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	nonce, state, challenge := parseAuthURL(t, authURL)
	tokenEP.setChallenge(challenge)

	claims := buildClaims(t, srv.URL, clientID, nonce, time.Now().Add(time.Hour), true)
	tokenEP.setIDToken(oidctest.SignIDToken(priv, testKeyID, goidc.RS256, claims))

	if _, _, finishErr := registry.Finish(t.Context(), providerKey, state, "test-code", binding); finishErr != nil {
		t.Fatalf("first Finish: %v", finishErr)
	}

	if _, _, finishErr := registry.Finish(t.Context(), providerKey, state, "test-code", binding); !errors.Is(finishErr, oidc.ErrInvalidState) {
		t.Fatalf("replayed Finish: got %v, want ErrInvalidState", finishErr)
	}
}

// TestFinishRejectsInvalidTokens covers AC-008.22: Finish returns
// ErrInvalidToken for a token whose nonce differs, that is signed by a
// different key, whose audience is another client, or that is expired beyond
// the configured clock skew.
func TestFinishRejectsInvalidTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		buildToken func(t *testing.T, priv *rsa.PrivateKey, issuer, nonce string) string
	}{
		{
			name: "nonce mismatch",
			buildToken: func(t *testing.T, priv *rsa.PrivateKey, issuer, _ string) string {
				t.Helper()

				claims := buildClaims(t, issuer, clientID, "wrong-nonce", time.Now().Add(time.Hour), true)

				return oidctest.SignIDToken(priv, testKeyID, goidc.RS256, claims)
			},
		},
		{
			name: "wrong signing key",
			buildToken: func(t *testing.T, _ *rsa.PrivateKey, issuer, nonce string) string {
				t.Helper()

				other, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("generating key: %v", err)
				}

				claims := buildClaims(t, issuer, clientID, nonce, time.Now().Add(time.Hour), true)

				return oidctest.SignIDToken(other, testKeyID, goidc.RS256, claims)
			},
		},
		{
			name: "wrong audience",
			buildToken: func(t *testing.T, priv *rsa.PrivateKey, issuer, nonce string) string {
				t.Helper()

				claims := buildClaims(t, issuer, "some-other-client", nonce, time.Now().Add(time.Hour), true)

				return oidctest.SignIDToken(priv, testKeyID, goidc.RS256, claims)
			},
		},
		{
			name: "expired beyond skew",
			buildToken: func(t *testing.T, priv *rsa.PrivateKey, issuer, nonce string) string {
				t.Helper()

				claims := buildClaims(t, issuer, clientID, nonce, time.Now().Add(-10*time.Second), true)

				return oidctest.SignIDToken(priv, testKeyID, goidc.RS256, claims)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			priv, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("generating key: %v", err)
			}

			srv, tokenEP := newProviderServer(t, priv.Public(), testKeyID)
			flows := newFlows(t)
			registry := newRegistry(t, srv.URL, srv.Client(), flows, 3*time.Second)

			authURL, binding, err := registry.Start(t.Context(), providerKey, uuid.NullUUID{})
			if err != nil {
				t.Fatalf("Start: %v", err)
			}

			nonce, state, challenge := parseAuthURL(t, authURL)
			tokenEP.setChallenge(challenge)

			tokenEP.setIDToken(tc.buildToken(t, priv, srv.URL, nonce))

			_, _, err = registry.Finish(t.Context(), providerKey, state, "test-code", binding)
			if !errors.Is(err, oidc.ErrInvalidToken) {
				t.Fatalf("Finish: got %v, want ErrInvalidToken", err)
			}
		})
	}
}

// TestFinishExpiredWithinSkewSucceeds covers AC-008.22: a token expired
// within the configured clock skew succeeds.
func TestFinishExpiredWithinSkewSucceeds(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	srv, tokenEP := newProviderServer(t, priv.Public(), testKeyID)
	flows := newFlows(t)
	registry := newRegistry(t, srv.URL, srv.Client(), flows, 3*time.Second)

	authURL, binding, err := registry.Start(t.Context(), providerKey, uuid.NullUUID{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	nonce, state, challenge := parseAuthURL(t, authURL)
	tokenEP.setChallenge(challenge)

	claims := buildClaims(t, srv.URL, clientID, nonce, time.Now().Add(-1*time.Second), true)
	tokenEP.setIDToken(oidctest.SignIDToken(priv, testKeyID, goidc.RS256, claims))

	if _, _, finishErr := registry.Finish(t.Context(), providerKey, state, "test-code", binding); finishErr != nil {
		t.Fatalf("Finish: %v, want success for a token expired within the configured skew", finishErr)
	}
}

// TestFinishPropagatesEmailVerifiedFalse covers AC-008.9: Finish passes
// email_verified: false through unchanged rather than rewriting it.
func TestFinishPropagatesEmailVerifiedFalse(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	srv, tokenEP := newProviderServer(t, priv.Public(), testKeyID)
	flows := newFlows(t)
	registry := newRegistry(t, srv.URL, srv.Client(), flows, 30*time.Second)

	authURL, binding, err := registry.Start(t.Context(), providerKey, uuid.NullUUID{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	nonce, state, challenge := parseAuthURL(t, authURL)
	tokenEP.setChallenge(challenge)

	claims := buildClaims(t, srv.URL, clientID, nonce, time.Now().Add(time.Hour), false)
	tokenEP.setIDToken(oidctest.SignIDToken(priv, testKeyID, goidc.RS256, claims))

	gotClaims, _, err := registry.Finish(t.Context(), providerKey, state, "test-code", binding)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}

	if gotClaims.EmailVerified {
		t.Fatalf("Finish: EmailVerified = true, want false (must not be rewritten)")
	}
}

// TestFinishBindingMismatchReturnsErrInvalidState covers the fix binding a
// ceremony to the browser that started it: Finish with a binding secret that
// does not match the one Start returned is ErrInvalidState, and the
// authorization code is never exchanged.
// Covers AC-008.21.
func TestFinishBindingMismatchReturnsErrInvalidState(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	srv, tokenEP := newProviderServer(t, priv.Public(), testKeyID)
	flows := newFlows(t)
	registry := newRegistry(t, srv.URL, srv.Client(), flows, 30*time.Second)

	authURL, _, err := registry.Start(t.Context(), providerKey, uuid.NullUUID{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	nonce, state, challenge := parseAuthURL(t, authURL)
	tokenEP.setChallenge(challenge)

	claims := buildClaims(t, srv.URL, clientID, nonce, time.Now().Add(time.Hour), true)
	tokenEP.setIDToken(oidctest.SignIDToken(priv, testKeyID, goidc.RS256, claims))

	_, _, err = registry.Finish(t.Context(), providerKey, state, "test-code", "wrong-binding-secret")
	if !errors.Is(err, oidc.ErrInvalidState) {
		t.Fatalf("Finish: got %v, want ErrInvalidState", err)
	}

	if got := tokenEP.hits(); got != 0 {
		t.Fatalf("Finish: token endpoint was hit %d times, want 0 (authorization code must not be exchanged)", got)
	}
}

// TestFinishEmptyBindingReturnsErrInvalidState covers the fix binding a
// ceremony to the browser that started it: Finish with an empty binding
// secret is ErrInvalidState.
// Covers AC-008.21.
func TestFinishEmptyBindingReturnsErrInvalidState(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	srv, _ := newProviderServer(t, priv.Public(), testKeyID)
	flows := newFlows(t)
	registry := newRegistry(t, srv.URL, srv.Client(), flows, 30*time.Second)

	authURL, _, err := registry.Start(t.Context(), providerKey, uuid.NullUUID{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	_, state, _ := parseAuthURL(t, authURL)

	_, _, err = registry.Finish(t.Context(), providerKey, state, "test-code", "")
	if !errors.Is(err, oidc.ErrInvalidState) {
		t.Fatalf("Finish: got %v, want ErrInvalidState", err)
	}
}

// TestFinishProviderMismatchReturnsErrInvalidState covers the fix binding a
// ceremony to the provider it was started against: a state issued by Start
// for one provider, finished against a different provider, returns
// ErrInvalidState.
// Covers AC-008.21.
func TestFinishProviderMismatchReturnsErrInvalidState(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	srv, _ := newProviderServer(t, priv.Public(), testKeyID)
	flows := newFlows(t)
	registry := newTwoProviderRegistry(t, srv.URL, srv.Client(), flows)

	authURL, binding, err := registry.Start(t.Context(), providerKey, uuid.NullUUID{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	_, state, _ := parseAuthURL(t, authURL)

	_, _, err = registry.Finish(t.Context(), otherProviderKey, state, "test-code", binding)
	if !errors.Is(err, oidc.ErrInvalidState) {
		t.Fatalf("Finish: got %v, want ErrInvalidState", err)
	}
}

// TestFinishNonceAbsentReturnsErrInvalidToken covers the fix rejecting an
// empty nonce before the constant-time comparison. crypto/subtle's
// ConstantTimeCompare returns 1 for two zero-length slices, so a ceremony
// stored without a nonce would otherwise turn a token that also carries no
// nonce claim into a valid login. Start always generates a real nonce, so
// the vulnerable state cannot be reached through it; this test seeds the
// ceremony directly through authflow.Store, the way a future code path
// could, to exercise that path.
// Covers AC-008.22.
func TestFinishNonceAbsentReturnsErrInvalidToken(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	srv, tokenEP := newProviderServer(t, priv.Public(), testKeyID)
	flows := newFlows(t)
	registry := newRegistry(t, srv.URL, srv.Client(), flows, 30*time.Second)

	const verifier = "test-pkce-verifier-with-no-stored-nonce"

	const binding = "test-binding-secret-with-no-stored-nonce"

	challengeSum := sha256.Sum256([]byte(verifier))
	tokenEP.setChallenge(base64.RawURLEncoding.EncodeToString(challengeSum[:]))

	bindingSum := sha256.Sum256([]byte(binding))

	payload, err := json.Marshal(map[string]string{
		"verifier":       verifier,
		"nonce":          "",
		"provider":       providerKey,
		"binding_digest": base64.RawURLEncoding.EncodeToString(bindingSum[:]),
	})
	if err != nil {
		t.Fatalf("encoding flow data: %v", err)
	}

	state, err := flows.Begin(t.Context(), authflow.KindOIDC, nil, payload)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	claims := buildClaims(t, srv.URL, clientID, "", time.Now().Add(time.Hour), true)
	tokenEP.setIDToken(oidctest.SignIDToken(priv, testKeyID, goidc.RS256, claims))

	_, _, err = registry.Finish(t.Context(), providerKey, state, "test-code", binding)
	if !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("Finish: got %v, want ErrInvalidToken", err)
	}
}

// TestStartLinkFinishLinkRoundTrip_ReturnsFlowUserID covers AC-008.43:
// StartLink persists the ceremony under KindOIDCLink carrying the account id
// it was started for, and FinishLink returns that id, proving the account
// comes from the flow rather than from any caller-supplied value.
func TestStartLinkFinishLinkRoundTrip_ReturnsFlowUserID(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	srv, tokenEP := newProviderServer(t, priv.Public(), testKeyID)
	flows, handle := newLinkFlows(t)
	registry := newRegistry(t, srv.URL, srv.Client(), flows, 30*time.Second)

	userID := insertLinkTestUser(t, handle)

	authURL, binding, err := registry.StartLink(t.Context(), providerKey, userID)
	if err != nil {
		t.Fatalf("StartLink: %v", err)
	}

	nonce, state, challenge := parseAuthURL(t, authURL)
	tokenEP.setChallenge(challenge)

	claims := buildClaims(t, srv.URL, clientID, nonce, time.Now().Add(time.Hour), true)
	tokenEP.setIDToken(oidctest.SignIDToken(priv, testKeyID, goidc.RS256, claims))

	gotClaims, gotUserID, err := registry.FinishLink(t.Context(), providerKey, state, "test-code", binding)
	if err != nil {
		t.Fatalf("FinishLink: %v", err)
	}

	if gotClaims.Subject != "user-123" {
		t.Fatalf("FinishLink: Subject = %q, want user-123", gotClaims.Subject)
	}

	if gotUserID != userID {
		t.Fatalf("FinishLink: userID = %v, want %v", gotUserID, userID)
	}
}

// TestFinishLink_RejectsLoginKindState covers the rule that a login ceremony
// (KindOIDC) cannot be completed through FinishLink: FinishLink returns
// ErrInvalidState and does not consume the flow, evidenced by an ordinary
// Finish succeeding against the same state afterward.
// Covers AC-008.21 and AC-008.43.
func TestFinishLink_RejectsLoginKindState(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	srv, tokenEP := newProviderServer(t, priv.Public(), testKeyID)
	flows := newFlows(t)
	registry := newRegistry(t, srv.URL, srv.Client(), flows, 30*time.Second)

	authURL, binding, err := registry.Start(t.Context(), providerKey, uuid.NullUUID{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	nonce, state, challenge := parseAuthURL(t, authURL)
	tokenEP.setChallenge(challenge)

	claims := buildClaims(t, srv.URL, clientID, nonce, time.Now().Add(time.Hour), true)
	tokenEP.setIDToken(oidctest.SignIDToken(priv, testKeyID, goidc.RS256, claims))

	if _, _, finishLinkErr := registry.FinishLink(t.Context(), providerKey, state, "test-code", binding); !errors.Is(finishLinkErr, oidc.ErrInvalidState) {
		t.Fatalf("FinishLink on a login-kind state: got %v, want ErrInvalidState", finishLinkErr)
	}

	if got := tokenEP.hits(); got != 0 {
		t.Fatalf("FinishLink on a login-kind state hit the token endpoint %d times, want 0", got)
	}

	// The login flow must still be there: an ordinary Finish gets past the
	// state lookup and completes.
	if _, _, finishErr := registry.Finish(t.Context(), providerKey, state, "test-code", binding); finishErr != nil {
		t.Fatalf("Finish after a rejected FinishLink attempt: %v, want the login flow still consumable", finishErr)
	}
}

// TestFinish_RejectsLinkKindState covers the mirror rule: an identity-link
// ceremony (KindOIDCLink) cannot be completed through the ordinary login
// Finish. Finish returns ErrInvalidState and does not consume the flow,
// evidenced by FinishLink succeeding against the same state afterward.
// Covers AC-008.21.
func TestFinish_RejectsLinkKindState(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	srv, tokenEP := newProviderServer(t, priv.Public(), testKeyID)
	flows, handle := newLinkFlows(t)
	registry := newRegistry(t, srv.URL, srv.Client(), flows, 30*time.Second)

	userID := insertLinkTestUser(t, handle)

	authURL, binding, err := registry.StartLink(t.Context(), providerKey, userID)
	if err != nil {
		t.Fatalf("StartLink: %v", err)
	}

	nonce, state, challenge := parseAuthURL(t, authURL)
	tokenEP.setChallenge(challenge)

	claims := buildClaims(t, srv.URL, clientID, nonce, time.Now().Add(time.Hour), true)
	tokenEP.setIDToken(oidctest.SignIDToken(priv, testKeyID, goidc.RS256, claims))

	if _, _, finishErr := registry.Finish(t.Context(), providerKey, state, "test-code", binding); !errors.Is(finishErr, oidc.ErrInvalidState) {
		t.Fatalf("Finish on a link-kind state: got %v, want ErrInvalidState", finishErr)
	}

	if got := tokenEP.hits(); got != 0 {
		t.Fatalf("Finish on a link-kind state hit the token endpoint %d times, want 0", got)
	}

	// The link flow must still be there: FinishLink gets past the state
	// lookup and completes.
	if _, gotUserID, finishLinkErr := registry.FinishLink(t.Context(), providerKey, state, "test-code", binding); finishLinkErr != nil {
		t.Fatalf("FinishLink after a rejected Finish attempt: %v, want the link flow still consumable", finishLinkErr)
	} else if gotUserID != userID {
		t.Fatalf("FinishLink userID = %v, want %v", gotUserID, userID)
	}
}

// TestFinishLink_BindingMismatchReturnsErrInvalidState covers the same
// browser-binding protection Finish has, applied to FinishLink: a binding
// secret that does not match the one StartLink returned is ErrInvalidState,
// and the authorization code is never exchanged.
// Covers AC-008.21 and AC-008.43.
func TestFinishLink_BindingMismatchReturnsErrInvalidState(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	srv, tokenEP := newProviderServer(t, priv.Public(), testKeyID)
	flows, handle := newLinkFlows(t)
	registry := newRegistry(t, srv.URL, srv.Client(), flows, 30*time.Second)

	authURL, _, err := registry.StartLink(t.Context(), providerKey, insertLinkTestUser(t, handle))
	if err != nil {
		t.Fatalf("StartLink: %v", err)
	}

	nonce, state, challenge := parseAuthURL(t, authURL)
	tokenEP.setChallenge(challenge)

	claims := buildClaims(t, srv.URL, clientID, nonce, time.Now().Add(time.Hour), true)
	tokenEP.setIDToken(oidctest.SignIDToken(priv, testKeyID, goidc.RS256, claims))

	if _, _, finishLinkErr := registry.FinishLink(t.Context(), providerKey, state, "test-code", "wrong-binding-secret"); !errors.Is(finishLinkErr, oidc.ErrInvalidState) {
		t.Fatalf("FinishLink: got %v, want ErrInvalidState", finishLinkErr)
	}

	if got := tokenEP.hits(); got != 0 {
		t.Fatalf("FinishLink: token endpoint was hit %d times, want 0 (authorization code must not be exchanged)", got)
	}
}
