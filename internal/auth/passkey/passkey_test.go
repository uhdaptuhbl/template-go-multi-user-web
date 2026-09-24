//go:build integration

package passkey

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/authflow"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
)

// testConfig returns a Config valid enough to build a Service from.
func testConfig() Config {
	return Config{
		Enabled:       true,
		RPID:          "example.com",
		RPDisplayName: "Test Relying Party",
		RPOrigins:     []string{"https://example.com"},
	}
}

// newTestService returns a Service backed by a fresh migrated database, for
// tests that do not need to inspect the repository or flow store directly.
func newTestService(t *testing.T) *Service {
	t.Helper()

	h := storetest.New(t)
	repo := NewRepository(h, time.Now)
	flows := authflow.NewStore(h, time.Hour, time.Now)

	svc, err := NewService(testConfig(), repo, flows, zap.NewNop())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	return svc
}

// TestNewServiceRejectsEmptyRPID cites no criterion: an empty relying party
// ID is a wiring mistake that process startup already refuses before this
// constructor is reached, the fifth exception in CLAUDE.md's Testing Standards.
func TestNewServiceRejectsEmptyRPID(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := NewRepository(h, time.Now)
	flows := authflow.NewStore(h, time.Hour, time.Now)
	cfg := testConfig()
	cfg.RPID = ""

	_, err := NewService(cfg, repo, flows, zap.NewNop())
	if err == nil {
		t.Fatal("NewService() error = nil, want an error for an empty RPID")
	}
}

// TestBeginRegistrationPersistsFlowAndReturnsChallenge covers AC-008.23.
func TestBeginRegistrationPersistsFlowAndReturnsChallenge(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := NewRepository(h, time.Now)
	flows := authflow.NewStore(h, time.Hour, time.Now)

	svc, err := NewService(testConfig(), repo, flows, zap.NewNop())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	userID := insertUser(t, h)

	options, flowID, err := svc.BeginRegistration(t.Context(), userID, "test user", nil)
	if err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}

	if flowID == "" {
		t.Error("BeginRegistration() flowID = \"\", want a non-empty identifier")
	}

	// The library's wire format is camelCase (it is the client's JSON, not
	// this service's), so options are decoded into generic maps rather than a
	// tagged struct that would have to fight this repo's snake_case json tag
	// convention.
	var decoded map[string]json.RawMessage
	if unmarshalErr := json.Unmarshal(options, &decoded); unmarshalErr != nil {
		t.Fatalf("unmarshaling options: %v", unmarshalErr)
	}

	var publicKey map[string]json.RawMessage
	if unmarshalErr := json.Unmarshal(decoded["publicKey"], &publicKey); unmarshalErr != nil {
		t.Fatalf("unmarshaling options.publicKey: %v", unmarshalErr)
	}

	var challenge string
	if unmarshalErr := json.Unmarshal(publicKey["challenge"], &challenge); unmarshalErr != nil {
		t.Fatalf("unmarshaling options.publicKey.challenge: %v", unmarshalErr)
	}

	if challenge == "" {
		t.Error("options publicKey.challenge = \"\", want a non-empty challenge")
	}

	// Proves the flow was actually persisted under the expected kind, not just
	// that a non-empty identifier was returned.
	if _, consumeErr := flows.Consume(t.Context(), authflow.KindWebAuthnRegister, flowID); consumeErr != nil {
		t.Errorf("Consume() for the flow BeginRegistration reported, error = %v, want success", consumeErr)
	}
}

// TestFinishRegistrationWithUnknownFlowReturnsError covers AC-008.23.
func TestFinishRegistrationWithUnknownFlowReturnsError(t *testing.T) {
	t.Parallel()

	svc := newTestService(t)

	userID, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("generating userID: %v", err)
	}

	_, err = svc.FinishRegistration(t.Context(), userID, "unknown-flow-id", "test credential", []byte("{}"))
	if !errors.Is(err, ErrVerification) {
		t.Errorf("FinishRegistration() error = %v, want ErrVerification", err)
	}
}

// TestFinishRegistrationReplayingConsumedFlowReturnsError covers AC-008.23.
func TestFinishRegistrationReplayingConsumedFlowReturnsError(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := NewRepository(h, time.Now)
	flows := authflow.NewStore(h, time.Hour, time.Now)

	svc, err := NewService(testConfig(), repo, flows, zap.NewNop())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	userID := insertUser(t, h)

	_, flowID, err := svc.BeginRegistration(t.Context(), userID, "test user", nil)
	if err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}

	// Consume the flow out from under the service, simulating a ceremony that
	// already finished, so the identifier is now spent.
	if _, consumeErr := flows.Consume(t.Context(), authflow.KindWebAuthnRegister, flowID); consumeErr != nil {
		t.Fatalf("Consume() error = %v", consumeErr)
	}

	_, err = svc.FinishRegistration(t.Context(), userID, flowID, "test credential", []byte("{}"))
	if !errors.Is(err, ErrVerification) {
		t.Errorf("FinishRegistration() error = %v, want ErrVerification", err)
	}
}

// TestFinishRegistrationForMismatchedUserReturnsErrVerification covers the
// authorised departure from the original FinishRegistration signature: the
// ceremony is bound to the caller's authenticated account, not only to the
// flow's own recorded owner, so a leaked flow identifier alone cannot be
// used to register a credential onto someone else's account.
// Covers AC-008.23.
func TestFinishRegistrationForMismatchedUserReturnsErrVerification(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := NewRepository(h, time.Now)
	flows := authflow.NewStore(h, time.Hour, time.Now)

	svc, err := NewService(testConfig(), repo, flows, zap.NewNop())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	userID := insertUser(t, h)
	otherUserID := insertUser(t, h)

	_, flowID, err := svc.BeginRegistration(t.Context(), userID, "test user", nil)
	if err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}

	_, err = svc.FinishRegistration(t.Context(), otherUserID, flowID, "test credential", []byte("{}"))
	if !errors.Is(err, ErrVerification) {
		t.Errorf("FinishRegistration() error = %v, want ErrVerification", err)
	}
}

// TestFinishRegistrationOwnerCheckRunsBeforeTheSessionIsDecoded covers AC-008.23:
// it proves the owner check itself fires, which the test above cannot.
//
// A black-box test that sends an unparseable body cannot tell the owner check
// from any later check, because every failure in this package collapses to the
// same ErrVerification. This test discriminates by arranging a flow whose stored
// data is not a decodable session: the owner check sits before that decode, so
// with the check present the call fails with ErrVerification, and with the check
// removed it falls through to the decode and fails with a wrapped error that is
// not ErrVerification. Asserting the sentinel therefore fails if the owner check
// is deleted.
func TestFinishRegistrationOwnerCheckRunsBeforeTheSessionIsDecoded(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	repo := NewRepository(h, time.Now)
	flows := authflow.NewStore(h, time.Hour, time.Now)

	svc, err := NewService(testConfig(), repo, flows, zap.NewNop())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	userID := insertUser(t, h)
	otherUserID := insertUser(t, h)

	// Deliberately not a webauthn.SessionData object, so the decode that follows
	// the owner check cannot succeed.
	var flowID string

	flowID, err = flows.Begin(t.Context(), authflow.KindWebAuthnRegister, &userID, json.RawMessage(`[]`))
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}

	_, err = svc.FinishRegistration(t.Context(), otherUserID, flowID, "test credential", []byte("{}"))
	if !errors.Is(err, ErrVerification) {
		t.Errorf("FinishRegistration() error = %v, want ErrVerification from the owner check", err)
	}
}

// TestBeginLoginReturnsNoAllowedCredentials covers AC-008.24.
func TestBeginLoginReturnsNoAllowedCredentials(t *testing.T) {
	t.Parallel()

	svc := newTestService(t)

	options, flowID, err := svc.BeginLogin(t.Context())
	if err != nil {
		t.Fatalf("BeginLogin() error = %v", err)
	}

	if flowID == "" {
		t.Error("BeginLogin() flowID = \"\", want a non-empty identifier")
	}

	// See the comment in TestBeginRegistrationPersistsFlowAndReturnsChallenge
	// for why this decodes into generic maps rather than a tagged struct.
	var decoded map[string]json.RawMessage
	if unmarshalErr := json.Unmarshal(options, &decoded); unmarshalErr != nil {
		t.Fatalf("unmarshaling options: %v", unmarshalErr)
	}

	var publicKey map[string]json.RawMessage
	if unmarshalErr := json.Unmarshal(decoded["publicKey"], &publicKey); unmarshalErr != nil {
		t.Fatalf("unmarshaling options.publicKey: %v", unmarshalErr)
	}

	// allowCredentials is "omitempty" on the wire, so a discoverable-only
	// request omits the key entirely rather than encoding an empty list.
	if _, present := publicKey["allowCredentials"]; present {
		t.Error("options.publicKey carries an allowCredentials key, want it omitted")
	}
}

// TestEvaluateSignCount is table-driven over the sign-count comparison
// FinishLogin uses to detect a possible cloned authenticator, covers
// AC-008.25.
func TestEvaluateSignCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		stored       int64
		reported     int64
		cloneWarning bool
	}{
		{name: "advanced", stored: 5, reported: 6, cloneWarning: false},
		{name: "unchanged-and-nonzero", stored: 5, reported: 5, cloneWarning: true},
		{name: "unchanged-and-zero", stored: 0, reported: 0, cloneWarning: false},
		{name: "regressed", stored: 5, reported: 3, cloneWarning: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := evaluateSignCount(tt.stored, tt.reported)
			if got != tt.cloneWarning {
				t.Errorf("evaluateSignCount(%d, %d) = %v, want %v", tt.stored, tt.reported, got, tt.cloneWarning)
			}
		})
	}
}

// TestFinishLoginWithUnknownFlowReturnsErrVerification guards the flow-not-
// found path FinishLogin shares with FinishRegistration, so ErrVerification
// -- not a bare authflow error -- is what a caller sees.
// Covers AC-008.42.
func TestFinishLoginWithUnknownFlowReturnsErrVerification(t *testing.T) {
	t.Parallel()

	svc := newTestService(t)

	_, err := svc.FinishLogin(t.Context(), "unknown-flow-id", []byte("{}"))
	if !errors.Is(err, ErrVerification) {
		t.Errorf("FinishLogin() error = %v, want ErrVerification", err)
	}
}

// fakeUnknownAssertionBody returns a syntactically valid WebAuthn assertion
// response body naming a credential ID no repository has ever stored, with a
// non-empty user handle so ValidatePasskeyLogin treats it as a discoverable
// login attempt. It carries no genuine signature: ValidatePasskeyLogin calls
// the discoverable-credential handler -- which looks the credential ID up
// and fails -- before any cryptographic check runs, so the fields below only
// need to satisfy protocol.ParseCredentialRequestResponseBytes' structural
// parsing, not signature verification.
func fakeUnknownAssertionBody(t *testing.T) []byte {
	t.Helper()

	rawID := []byte("unknown-credential-id-000")
	userHandle := []byte("unknown-user-handle-00000")
	clientData := []byte(`{"type":"webauthn.get","challenge":"x","origin":"https://example.com"}`)

	// A minimal 37-byte authenticator data value: a 32-byte RP ID hash, one
	// flags byte with no attested-credential or extensions bits set, and a
	// 4-byte signature counter. protocol.AuthenticatorData.Unmarshal accepts
	// exactly this length when neither bit is set.
	authData := make([]byte, 37)

	body := map[string]any{
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

	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshaling fake assertion body: %v", err)
	}

	return encoded
}

// TestFinishLoginUnknownCredentialReturnsNilOwnerWithErrVerification covers
// AC-008.38, for the unknown-credential half of this unit's prescribed test,
// TestFinishLoginReturnsOwnerOnFailedAssertionForKnownCredential. The
// known-credential half -- a stored credential whose assertion fails
// signature verification, proving FinishLogin then returns the resolved
// owner's ID rather than the zero UUID -- needs a scripted authenticator
// that can sign a registration and then a deliberately-failing assertion for
// the same credential; this repository has no such helper yet; see this
// unit's report for the deviation. This test instead covers the other half:
// a credential ID the repository never resolves must still return the zero
// UUID (not a real caller's account) alongside ErrVerification, which is the
// invariant a caller depends on to know an unresolved failure carries no
// attributable audit subject.
func TestFinishLoginUnknownCredentialReturnsNilOwnerWithErrVerification(t *testing.T) {
	t.Parallel()

	svc := newTestService(t)

	_, flowID, err := svc.BeginLogin(t.Context())
	if err != nil {
		t.Fatalf("BeginLogin() error = %v", err)
	}

	userID, err := svc.FinishLogin(t.Context(), flowID, fakeUnknownAssertionBody(t))
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("FinishLogin() error = %v, want ErrVerification", err)
	}

	if userID != uuid.Nil {
		t.Fatalf("FinishLogin() userID = %v, want the zero UUID for an unresolved credential", userID)
	}
}
