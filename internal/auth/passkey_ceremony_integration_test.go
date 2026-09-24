//go:build integration

package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/google/uuid"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/audit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/session"
)

// This file drives the passkey registration and login ceremonies through the
// real HTTP routes with a scripted, in-process WebAuthn authenticator
// (github.com/descope/virtualwebauthn) rather than a browser, observing
// AC-008.23 through AC-008.25 for the first time. Spec 008 has carried these
// as unverified since no test exercised a full attestation or assertion
// round trip against the real go-webauthn relying party.

// passkeyTestRP is the WebAuthn relying party every scripted ceremony in
// this file runs against, matching the RPID, RPDisplayName, and origin
// newTestRouteDeps(t, deps, true) configures passkey.Service with.
var passkeyTestRP = virtualwebauthn.RelyingParty{
	Name:   "service",
	ID:     "service.example",
	Origin: testPublicOriginForRoutes,
}

// registerScriptedPasskey drives a full registration ceremony for the
// account holding cookie, through handler's real HTTP routes: register/start,
// a scripted attestation from a fresh virtualwebauthn.Authenticator and
// Credential, then register/finish. It fails t unless the ceremony completes
// with 204. The returned authenticator already carries cred, ready for a
// later login ceremony against the same credential.
func registerScriptedPasskey(t *testing.T, handler http.Handler, cookie *http.Cookie) (virtualwebauthn.Authenticator, virtualwebauthn.Credential) {
	t.Helper()

	authenticator := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	startReq := integrationRequest(t, http.MethodPost, "/api/v1/auth/webauthn/register/start", nil)
	startReq.AddCookie(cookie)
	startRec := httptest.NewRecorder()
	handler.ServeHTTP(startRec, startReq)

	if startRec.Code != http.StatusOK {
		t.Fatalf("register/start status = %d, want 200 (body %s)", startRec.Code, startRec.Body.String())
	}

	var startBody webauthnStartResponse
	if err := json.Unmarshal(startRec.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decoding register/start response: %v", err)
	}

	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(startBody.Options))
	if err != nil {
		t.Fatalf("ParseAttestationOptions() error = %v", err)
	}

	attestationResponse := virtualwebauthn.CreateAttestationResponse(passkeyTestRP, authenticator, cred, *attestationOptions)

	finishReq := integrationRequest(t, http.MethodPost, "/api/v1/auth/webauthn/register/finish",
		mustMarshalJSON(t, webauthnRegisterFinishRequest{
			FlowID:     startBody.FlowID,
			Name:       "scripted authenticator",
			Credential: json.RawMessage(attestationResponse),
		}))
	finishReq.AddCookie(cookie)
	finishRec := httptest.NewRecorder()
	handler.ServeHTTP(finishRec, finishReq)

	if finishRec.Code != http.StatusNoContent {
		t.Fatalf("register/finish status = %d, want 204 (body %s)", finishRec.Code, finishRec.Body.String())
	}

	authenticator.AddCredential(cred)

	return authenticator, cred
}

// assertScriptedPasskey drives one login/finish ceremony for cred through
// handler's real HTTP routes: login/start, a scripted assertion, then
// login/finish. userID is cred's owning account; go-webauthn's
// ValidatePasskeyLogin requires the assertion's user handle to equal the
// resolved user's WebAuthnID, which is the owning account's UUID, so it is
// written into the scripted authenticator before the assertion is built.
// It returns the finish call's recorded response, unchecked, so a caller can
// assert either a successful or a refused ceremony.
func assertScriptedPasskey(t *testing.T, handler http.Handler, authenticator *virtualwebauthn.Authenticator, cred virtualwebauthn.Credential, userID uuid.UUID) *httptest.ResponseRecorder {
	t.Helper()

	authenticator.Options.UserHandle = userID[:]

	startReq := integrationRequest(t, http.MethodPost, "/api/v1/auth/webauthn/login/start", nil)
	startRec := httptest.NewRecorder()
	handler.ServeHTTP(startRec, startReq)

	if startRec.Code != http.StatusOK {
		t.Fatalf("login/start status = %d, want 200 (body %s)", startRec.Code, startRec.Body.String())
	}

	var startBody webauthnStartResponse
	if err := json.Unmarshal(startRec.Body.Bytes(), &startBody); err != nil {
		t.Fatalf("decoding login/start response: %v", err)
	}

	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(startBody.Options))
	if err != nil {
		t.Fatalf("ParseAssertionOptions() error = %v", err)
	}

	assertionResponse := virtualwebauthn.CreateAssertionResponse(passkeyTestRP, *authenticator, cred, *assertionOptions)

	finishReq := integrationRequest(t, http.MethodPost, "/api/v1/auth/webauthn/login/finish",
		mustMarshalJSON(t, webauthnLoginFinishRequest{
			FlowID:     startBody.FlowID,
			Credential: json.RawMessage(assertionResponse),
		}))
	finishRec := httptest.NewRecorder()
	handler.ServeHTTP(finishRec, finishReq)

	return finishRec
}

// TestPasskeyRegistrationCompletesWithAScriptedAuthenticator covers
// AC-008.23: a full registration ceremony against the real routes and the
// real go-webauthn relying party, driven by a scripted authenticator,
// completes and leaves exactly one credential listed for the account.
func TestPasskeyRegistrationCompletesWithAScriptedAuthenticator(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	_, token := issueSession(t, deps, "flow25-passkey-register")
	routeDeps := newTestRouteDeps(t, deps, true)
	handler := newIntegrationHandler(deps, routeDeps)

	cookie := &http.Cookie{Name: session.DefaultCookieName, Value: token} //nolint:gosec // G124: this cookie only ever reaches Request.AddCookie, which serializes just name=value; Secure/HttpOnly/SameSite are meaningless here

	registerScriptedPasskey(t, handler, cookie)

	listReq := integrationRequest(t, http.MethodGet, "/api/v1/me/credentials", nil)
	listReq.AddCookie(cookie)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)

	if listRec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/me/credentials status = %d, want 200 (body %s)", listRec.Code, listRec.Body.String())
	}

	var listed credentialsResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decoding credentials response: %v", err)
	}

	if len(listed.Credentials) != 1 {
		t.Fatalf("credentials listed = %d, want 1 (body %s)", len(listed.Credentials), listRec.Body.String())
	}
}

// TestPasskeyLoginAuthenticatesTheCredentialOwner covers AC-008.24: a login
// ceremony against a credential registered moments earlier, driven with no
// session cookie attached (as an unauthenticated browser would present it),
// issues a session for the registering account.
func TestPasskeyLoginAuthenticatesTheCredentialOwner(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	userID, token := issueSession(t, deps, "flow26-passkey-login")
	routeDeps := newTestRouteDeps(t, deps, true)
	handler := newIntegrationHandler(deps, routeDeps)

	cookie := &http.Cookie{Name: session.DefaultCookieName, Value: token} //nolint:gosec // G124: this cookie only ever reaches Request.AddCookie, which serializes just name=value; Secure/HttpOnly/SameSite are meaningless here

	authenticator, cred := registerScriptedPasskey(t, handler, cookie)

	// No cookie is attached to the login ceremony below: this replays the
	// unauthenticated state a fresh browser cookie jar would present.
	finishRec := assertScriptedPasskey(t, handler, &authenticator, cred, userID)

	if finishRec.Code != http.StatusNoContent {
		t.Fatalf("login/finish status = %d, want 204 (body %s)", finishRec.Code, finishRec.Body.String())
	}

	sessionCookie := integrationFindCookie(finishRec, session.DefaultCookieName)
	if sessionCookie == nil {
		t.Fatal("login/finish set no session cookie")
	}

	meReq := integrationRequest(t, http.MethodGet, "/api/v1/me", nil)
	meReq.AddCookie(sessionCookie)
	meRec := httptest.NewRecorder()
	handler.ServeHTTP(meRec, meReq)

	if meRec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/me status = %d, want 200 (body %s)", meRec.Code, meRec.Body.String())
	}

	var me meResponse
	if err := json.Unmarshal(meRec.Body.Bytes(), &me); err != nil {
		t.Fatalf("decoding /api/v1/me: %v", err)
	}

	if me.ID != userID {
		t.Fatalf("me.ID = %v, want %v (the registering account)", me.ID, userID)
	}
}

// TestPasskeyAssertionWithAStaleCounterIsRejectedAndFlagged covers
// AC-008.25 and the known-credential case of AC-008.38: a second assertion
// whose reported counter does not exceed the counter recorded on the
// preceding successful login is refused, the stored credential is flagged
// as a possible clone, and the failure audit row names the credential's
// owner as its subject.
func TestPasskeyAssertionWithAStaleCounterIsRejectedAndFlagged(t *testing.T) {
	t.Parallel()

	deps := newTestService(t, nil)
	userID, token := issueSession(t, deps, "flow27-passkey-clone")
	routeDeps := newTestRouteDeps(t, deps, true)
	handler := newIntegrationHandler(deps, routeDeps)

	cookie := &http.Cookie{Name: session.DefaultCookieName, Value: token} //nolint:gosec // G124: this cookie only ever reaches Request.AddCookie, which serializes just name=value; Secure/HttpOnly/SameSite are meaningless here

	authenticator, cred := registerScriptedPasskey(t, handler, cookie)

	cred.Counter = 5

	firstRec := assertScriptedPasskey(t, handler, &authenticator, cred, userID)
	if firstRec.Code != http.StatusNoContent {
		t.Fatalf("first login/finish status = %d, want 204 (body %s)", firstRec.Code, firstRec.Body.String())
	}

	// A reported counter equal to (or below) the one just recorded is what a
	// cloned authenticator, replaying an earlier state, would present.
	cred.Counter = 3

	secondRec := assertScriptedPasskey(t, handler, &authenticator, cred, userID)

	if secondRec.Code != http.StatusUnauthorized {
		t.Fatalf("stale-counter login/finish status = %d, want 401 (body %s)", secondRec.Code, secondRec.Body.String())
	}

	flaggedCount := countRows(t, deps.handle,
		`SELECT count(*) FROM credentials WHERE user_id = $1 AND clone_warning`, userID)
	if flaggedCount != 1 {
		t.Fatalf("credentials rows flagged clone_warning for user %s = %d, want 1", userID, flaggedCount)
	}

	subject := "user:" + userID.String()
	failureCount := countRows(t, deps.handle,
		`SELECT count(*) FROM audit_events WHERE action = $1 AND subject = $2 AND outcome = 'failure'`,
		audit.ActionPasskeyCompleted, subject)
	if failureCount != 1 {
		t.Fatalf("auth.passkey.completed failure rows for subject %q = %d, want 1", subject, failureCount)
	}
}
