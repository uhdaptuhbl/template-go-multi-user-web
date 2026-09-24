//go:build integration

package otp

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/configtype"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/mail"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
)

// codePattern matches the 8-digit code this package emails.
var codePattern = regexp.MustCompile(`\b\d{8}\b`)

// clock is a manually advanced clock for tests that must control the passage
// of time without sleeping.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

// newClock returns a clock starting at the current wall time.
func newClock() *clock {
	return &clock{now: time.Now()}
}

// Now returns the clock's current time.
func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

// Advance moves the clock forward by d.
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

// recordingSender is a mail.Sender that records every message it is handed,
// so a test can recover the code mailed to an address without the package
// under test ever exposing it. It optionally fails every send with a fixed
// error, to exercise Request's handling of a delivery failure.
type recordingSender struct {
	mu       sync.Mutex
	messages []mail.Message
	sendErr  error
}

// Send records msg and returns the sender's configured error, if any.
func (s *recordingSender) Send(_ context.Context, msg mail.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.messages = append(s.messages, msg)

	return s.sendErr
}

// last returns the most recently recorded message.
func (s *recordingSender) last(t *testing.T) mail.Message {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.messages) == 0 {
		t.Fatalf("recordingSender: no messages recorded")
	}

	return s.messages[len(s.messages)-1]
}

// count returns how many messages have been recorded.
func (s *recordingSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.messages)
}

// testConfig returns a Config with a short TTL and a small attempt budget, so
// a test can cross either boundary without a long-running clock advance.
func testConfig() Config {
	cfg := DefaultConfig()
	cfg.CodeTTL = configtype.Duration(10 * time.Minute)
	cfg.MaxAttempts = 3

	return cfg
}

// newTestService returns a Service backed by a fresh migrated database, c's
// clock, and sender.
func newTestService(t *testing.T, c *clock, sender mail.Sender) (*Service, *store.Handle) {
	t.Helper()

	h := storetest.New(t)

	return NewService(testConfig(), h, sender, zap.NewNop(), c.Now), h
}

// extractCode pulls the 8-digit code out of a mailed message's body.
func extractCode(t *testing.T, msg mail.Message) string {
	t.Helper()

	code := codePattern.FindString(msg.Body)
	if code == "" {
		t.Fatalf("extractCode: no 8-digit code found in body %q", msg.Body)
	}

	return code
}

// testBinding is the binding value every test in this file uses unless it is
// specifically exercising binding isolation, standing in for the random
// per-browser value handleOTPStart generates.
const testBinding = "test-binding-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// otherTestBinding is a second, distinct binding value for tests exercising
// isolation between two requesting browsers.
const otherTestBinding = "test-binding-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// TestRequestForUnknownAddressSendsAndReturnsNil covers AC-008.30.
func TestRequestForUnknownAddressSendsAndReturnsNil(t *testing.T) {
	t.Parallel()

	c := newClock()
	sender := &recordingSender{}
	svc, _ := newTestService(t, c, sender)

	if err := svc.Request(t.Context(), "unknown@example.com", testBinding, uuid.NullUUID{}); err != nil {
		t.Fatalf("Request() error = %v, want nil", err)
	}

	if sender.count() != 1 {
		t.Fatalf("sender recorded %d messages, want 1", sender.count())
	}
}

// TestRequestForKnownAndUnknownAddressAreIndistinguishable covers AC-008.30.
func TestRequestForKnownAndUnknownAddressAreIndistinguishable(t *testing.T) {
	t.Parallel()

	c := newClock()
	sender := &recordingSender{}
	svc, h := newTestService(t, c, sender)

	// "Known" here means a row already exists that references the address,
	// which is the only sense of "known" this package can observe: it has no
	// dependency on internal/user.
	insertOTPRow(t, h, "known@example.com", "00000000", c.Now())

	unknownErr := svc.Request(t.Context(), "unknown2@example.com", testBinding, uuid.NullUUID{})
	knownErr := svc.Request(t.Context(), "known@example.com", testBinding, uuid.NullUUID{})

	if unknownErr != nil {
		t.Errorf("Request(unknown) error = %v, want nil", unknownErr)
	}

	if knownErr != nil {
		t.Errorf("Request(known) error = %v, want nil", knownErr)
	}

	if !errors.Is(unknownErr, knownErr) {
		t.Errorf("Request returned distinguishable errors: unknown=%v known=%v", unknownErr, knownErr)
	}
}

// TestRequestMailsAnEightDigitCodeAndStoresOnlyItsHash covers AC-008.27.
func TestRequestMailsAnEightDigitCodeAndStoresOnlyItsHash(t *testing.T) {
	t.Parallel()

	c := newClock()
	sender := &recordingSender{}
	svc, h := newTestService(t, c, sender)

	if err := svc.Request(t.Context(), "code-shape@example.com", testBinding, uuid.NullUUID{}); err != nil {
		t.Fatalf("Request() error = %v, want nil", err)
	}

	msg := sender.last(t)
	code := extractCode(t, msg)

	if len(code) != 8 {
		t.Fatalf("code = %q, want 8 digits", code)
	}

	storedHash := codeHashFor(t, h, "code-shape@example.com")

	if string(storedHash) == code {
		t.Errorf("stored code_hash equals the raw code")
	}

	if len(storedHash) != 32 {
		t.Errorf("stored code_hash is %d bytes, want 32 (a raw sha256 digest)", len(storedHash))
	}
}

// TestVerifyWithTheMailedCodeSucceeds covers AC-008.27.
func TestVerifyWithTheMailedCodeSucceeds(t *testing.T) {
	t.Parallel()

	c := newClock()
	sender := &recordingSender{}
	svc, _ := newTestService(t, c, sender)

	if err := svc.Request(t.Context(), "  Verify@Example.com  ", testBinding, uuid.NullUUID{}); err != nil {
		t.Fatalf("Request() error = %v, want nil", err)
	}

	code := extractCode(t, sender.last(t))

	address, _, err := svc.Verify(t.Context(), "verify@example.com", code, testBinding)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}

	if address != "verify@example.com" {
		t.Errorf("Verify() address = %q, want %q", address, "verify@example.com")
	}
}

// TestVerifyReturnsTheInviteTheCodeWasRequestedWith covers AC-008.70.
func TestVerifyReturnsTheInviteTheCodeWasRequestedWith(t *testing.T) {
	t.Parallel()

	c := newClock()
	sender := &recordingSender{}
	svc, h := newTestService(t, c, sender)

	inviteID := uuid.NullUUID{UUID: insertInvite(t, h), Valid: true}

	if err := svc.Request(t.Context(), "invited@example.com", testBinding, inviteID); err != nil {
		t.Fatalf("Request() error = %v, want nil", err)
	}

	code := extractCode(t, sender.last(t))

	_, gotInvite, err := svc.Verify(t.Context(), "invited@example.com", code, testBinding)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}

	if gotInvite != inviteID {
		t.Errorf("Verify() invite = %+v, want %+v", gotInvite, inviteID)
	}
}

// TestVerifyRejectsTheSameCodeTwice covers AC-008.27.
func TestVerifyRejectsTheSameCodeTwice(t *testing.T) {
	t.Parallel()

	c := newClock()
	sender := &recordingSender{}
	svc, _ := newTestService(t, c, sender)

	if err := svc.Request(t.Context(), "replay@example.com", testBinding, uuid.NullUUID{}); err != nil {
		t.Fatalf("Request() error = %v, want nil", err)
	}

	code := extractCode(t, sender.last(t))

	if _, _, err := svc.Verify(t.Context(), "replay@example.com", code, testBinding); err != nil {
		t.Fatalf("first Verify() error = %v, want nil", err)
	}

	if _, _, err := svc.Verify(t.Context(), "replay@example.com", code, testBinding); !errors.Is(err, ErrVerification) {
		t.Errorf("second Verify() error = %v, want ErrVerification", err)
	}
}

// TestVerifyRejectsAnExpiredCode covers AC-008.27.
func TestVerifyRejectsAnExpiredCode(t *testing.T) {
	t.Parallel()

	c := newClock()
	sender := &recordingSender{}
	svc, _ := newTestService(t, c, sender)

	if err := svc.Request(t.Context(), "expired@example.com", testBinding, uuid.NullUUID{}); err != nil {
		t.Fatalf("Request() error = %v, want nil", err)
	}

	code := extractCode(t, sender.last(t))

	c.Advance(testConfig().CodeTTL.Duration() + time.Minute)

	if _, _, err := svc.Verify(t.Context(), "expired@example.com", code, testBinding); !errors.Is(err, ErrVerification) {
		t.Errorf("Verify() error = %v, want ErrVerification", err)
	}
}

// TestVerifyExhaustsAttemptsThenRejectsTheCorrectCode covers AC-008.28.
func TestVerifyExhaustsAttemptsThenRejectsTheCorrectCode(t *testing.T) {
	t.Parallel()

	c := newClock()
	sender := &recordingSender{}
	svc, _ := newTestService(t, c, sender)

	if err := svc.Request(t.Context(), "exhaust@example.com", testBinding, uuid.NullUUID{}); err != nil {
		t.Fatalf("Request() error = %v, want nil", err)
	}

	code := extractCode(t, sender.last(t))

	cfg := testConfig()

	for range cfg.MaxAttempts {
		if _, _, err := svc.Verify(t.Context(), "exhaust@example.com", "00000000", testBinding); !errors.Is(err, ErrVerification) {
			t.Fatalf("wrong-guess Verify() error = %v, want ErrVerification", err)
		}
	}

	if _, _, err := svc.Verify(t.Context(), "exhaust@example.com", code, testBinding); !errors.Is(err, ErrVerification) {
		t.Errorf("Verify() with correct code after exhausting attempts error = %v, want ErrVerification", err)
	}
}

// TestSecondRequestInvalidatesTheFirstCode covers AC-008.27.
func TestSecondRequestInvalidatesTheFirstCode(t *testing.T) {
	t.Parallel()

	c := newClock()
	sender := &recordingSender{}
	svc, _ := newTestService(t, c, sender)

	if err := svc.Request(t.Context(), "double@example.com", testBinding, uuid.NullUUID{}); err != nil {
		t.Fatalf("first Request() error = %v, want nil", err)
	}

	firstCode := extractCode(t, sender.last(t))

	if err := svc.Request(t.Context(), "double@example.com", testBinding, uuid.NullUUID{}); err != nil {
		t.Fatalf("second Request() error = %v, want nil", err)
	}

	if _, _, err := svc.Verify(t.Context(), "double@example.com", firstCode, testBinding); !errors.Is(err, ErrVerification) {
		t.Errorf("Verify() with the invalidated first code error = %v, want ErrVerification", err)
	}
}

// TestRequestFromAnotherBindingLeavesTheFirstCodeLive covers AC-008.82: a
// second Request for the same address from a different binding does not
// invalidate the first binding's outstanding code, so the first browser's
// code still verifies under its own binding.
func TestRequestFromAnotherBindingLeavesTheFirstCodeLive(t *testing.T) {
	t.Parallel()

	c := newClock()
	sender := &recordingSender{}
	svc, _ := newTestService(t, c, sender)

	if err := svc.Request(t.Context(), "shared@example.com", testBinding, uuid.NullUUID{}); err != nil {
		t.Fatalf("binding A Request() error = %v, want nil", err)
	}

	codeA := extractCode(t, sender.last(t))

	if err := svc.Request(t.Context(), "shared@example.com", otherTestBinding, uuid.NullUUID{}); err != nil {
		t.Fatalf("binding B Request() error = %v, want nil", err)
	}

	if _, _, err := svc.Verify(t.Context(), "shared@example.com", codeA, testBinding); err != nil {
		t.Fatalf("Verify() binding A's code under binding A error = %v, want nil", err)
	}
}

// TestRequestFromSameBindingInvalidatesEarlierCode covers AC-008.82: a second
// Request for the same address from the same binding invalidates that
// binding's own earlier code.
func TestRequestFromSameBindingInvalidatesEarlierCode(t *testing.T) {
	t.Parallel()

	c := newClock()
	sender := &recordingSender{}
	svc, _ := newTestService(t, c, sender)

	if err := svc.Request(t.Context(), "same-binding@example.com", testBinding, uuid.NullUUID{}); err != nil {
		t.Fatalf("first Request() error = %v, want nil", err)
	}

	firstCode := extractCode(t, sender.last(t))

	if err := svc.Request(t.Context(), "same-binding@example.com", testBinding, uuid.NullUUID{}); err != nil {
		t.Fatalf("second Request() error = %v, want nil", err)
	}

	if _, _, err := svc.Verify(t.Context(), "same-binding@example.com", firstCode, testBinding); !errors.Is(err, ErrVerification) {
		t.Errorf("Verify() with the invalidated first code error = %v, want ErrVerification", err)
	}
}

// TestRequestWithoutInviteCarriesForwardTheOutstandingInvite covers
// AC-008.82: binding A requests with an invite, then requests again without
// one; the newest code still returns that invite ID, since the invite from
// the invalidated outstanding code is carried forward onto the replacement.
func TestRequestWithoutInviteCarriesForwardTheOutstandingInvite(t *testing.T) {
	t.Parallel()

	c := newClock()
	sender := &recordingSender{}
	svc, h := newTestService(t, c, sender)

	inviteID := uuid.NullUUID{UUID: insertInvite(t, h), Valid: true}

	if err := svc.Request(t.Context(), "carry-invite@example.com", testBinding, inviteID); err != nil {
		t.Fatalf("first Request() error = %v, want nil", err)
	}

	if err := svc.Request(t.Context(), "carry-invite@example.com", testBinding, uuid.NullUUID{}); err != nil {
		t.Fatalf("second Request() error = %v, want nil", err)
	}

	code := extractCode(t, sender.last(t))

	_, gotInvite, err := svc.Verify(t.Context(), "carry-invite@example.com", code, testBinding)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}

	if gotInvite != inviteID {
		t.Errorf("Verify() invite = %+v, want %+v (carried forward)", gotInvite, inviteID)
	}
}

// TestVerifyFromAnotherBindingFailsWithoutCountingAnAttempt covers AC-008.83:
// MaxAttempts wrong guesses from binding B never find binding A's code, so
// they never count against its attempt budget, and the right code from
// binding A still succeeds afterward.
func TestVerifyFromAnotherBindingFailsWithoutCountingAnAttempt(t *testing.T) {
	t.Parallel()

	c := newClock()
	sender := &recordingSender{}
	svc, _ := newTestService(t, c, sender)

	if err := svc.Request(t.Context(), "attempt-isolation@example.com", testBinding, uuid.NullUUID{}); err != nil {
		t.Fatalf("Request() error = %v, want nil", err)
	}

	code := extractCode(t, sender.last(t))

	cfg := testConfig()

	for range cfg.MaxAttempts {
		if _, _, err := svc.Verify(t.Context(), "attempt-isolation@example.com", code, otherTestBinding); !errors.Is(err, ErrVerification) {
			t.Fatalf("binding B Verify() with the correct code error = %v, want ErrVerification", err)
		}
	}

	if _, _, err := svc.Verify(t.Context(), "attempt-isolation@example.com", code, testBinding); err != nil {
		t.Errorf("binding A Verify() with the correct code after binding B's guesses error = %v, want nil", err)
	}
}

// TestRequestReturnsNilWhenTheSenderFails covers AC-008.30.
func TestRequestReturnsNilWhenTheSenderFails(t *testing.T) {
	t.Parallel()

	c := newClock()
	sender := &recordingSender{sendErr: errors.New("smtp: connection refused")}
	svc, _ := newTestService(t, c, sender)

	if err := svc.Request(t.Context(), "undeliverable@example.com", testBinding, uuid.NullUUID{}); err != nil {
		t.Fatalf("Request() error = %v, want nil", err)
	}

	if sender.count() != 1 {
		t.Fatalf("sender recorded %d messages, want 1", sender.count())
	}
}

// TestRequestDoesNotLogTheAddressWhenTheSenderFails covers AC-008.91: the
// entry recording a failed send carries the cause but not the address.
func TestRequestDoesNotLogTheAddressWhenTheSenderFails(t *testing.T) {
	t.Parallel()

	const address = "undeliverable-private@example.com"

	core, logs := observer.New(zap.DebugLevel)
	sender := &recordingSender{sendErr: errors.New("smtp: connection refused")}
	svc := NewService(testConfig(), storetest.New(t), sender, zap.New(core), newClock().Now)

	if err := svc.Request(t.Context(), address, testBinding, uuid.NullUUID{}); err != nil {
		t.Fatalf("Request() error = %v, want nil", err)
	}

	failures := logs.FilterMessage("otp: sending code failed").All()
	if len(failures) != 1 {
		t.Fatalf("got %d send-failure entries, want 1", len(failures))
	}

	if _, ok := failures[0].ContextMap()["error"]; !ok {
		t.Errorf("failure entry fields = %v, want an error field", failures[0].ContextMap())
	}

	for _, entry := range logs.All() {
		for key, value := range entry.ContextMap() {
			if strings.Contains(fmt.Sprint(value), address) {
				t.Errorf("log entry %q field %q = %v, contains the address", entry.Message, key, value)
			}
		}
	}
}

// TestGeneratedCodesAreUniformlyDistributed covers AC-008.27.
func TestGeneratedCodesAreUniformlyDistributed(t *testing.T) {
	t.Parallel()

	const samples = 200

	c := newClock()
	sender := &recordingSender{}
	svc, _ := newTestService(t, c, sender)

	digitValues := make([]map[byte]struct{}, 8)

	for i := range digitValues {
		digitValues[i] = make(map[byte]struct{})
	}

	for range samples {
		address := uuid.NewString() + "@example.com"

		if err := svc.Request(t.Context(), address, testBinding, uuid.NullUUID{}); err != nil {
			t.Fatalf("Request() error = %v, want nil", err)
		}

		code := extractCode(t, sender.last(t))

		for pos := range digitValues {
			digitValues[pos][code[pos]] = struct{}{}
		}
	}

	// Requiring every one of the 10 digits at every position, rather than
	// requiring only some minimum number of distinct values, is what makes
	// this check assert uniformity rather than mere variation. For a correct
	// generator, the chance that one particular position never sees one
	// particular digit across 200 samples is 0.9^200, and there are 8
	// positions and 10 digits for that to happen to, so by a union bound this
	// check has a false failure rate below 8 * 10 * 0.9^200, well under 1e-7.
	const wantDistinctDigits = 10

	for pos, values := range digitValues {
		if len(values) < wantDistinctDigits {
			t.Errorf("digit position %d took only %d of %d possible distinct value(s) across %d samples", pos, len(values), wantDistinctDigits, samples)
		}
	}
}

// TestDeleteExpiredRemovesOnlyExpiredCodes covers AC-008.27.
func TestDeleteExpiredRemovesOnlyExpiredCodes(t *testing.T) {
	t.Parallel()

	c := newClock()
	sender := &recordingSender{}
	svc, h := newTestService(t, c, sender)

	insertOTPRow(t, h, "live@example.com", "11111111", c.Now().Add(time.Hour))
	insertOTPRow(t, h, "dead@example.com", "22222222", c.Now().Add(-time.Hour))

	removed, err := svc.DeleteExpired(t.Context())
	if err != nil {
		t.Fatalf("DeleteExpired() error = %v, want nil", err)
	}

	if removed != 1 {
		t.Errorf("DeleteExpired() removed %d rows, want 1", removed)
	}
}

// insertOTPRow inserts a minimal otp_codes row directly, bound to
// testBinding, for tests that need a row this package's own Request did not
// create.
func insertOTPRow(t *testing.T, h *store.Handle, email, rawCode string, expiresAt time.Time) {
	t.Helper()

	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("insertOTPRow: generating id: %v", err)
	}

	bindingHash := sha256.Sum256([]byte(testBinding))

	const insertQuery = `
INSERT INTO otp_codes (id, email, code_hash, attempts, invite_id, created_at, expires_at, consumed_at, binding_hash)
VALUES ($1, $2, $3, 0, NULL, $4, $5, NULL, $6)
`

	if _, execErr := h.Pool().Exec(t.Context(), insertQuery, id, email, []byte(rawCode), time.Now(), expiresAt, bindingHash[:]); execErr != nil {
		t.Fatalf("insertOTPRow: inserting row: %v", execErr)
	}
}

// insertInvite inserts a minimal invites row directly, since otp_codes.invite_id
// carries a foreign key to it and this package does not depend on
// internal/invite.
func insertInvite(t *testing.T, h *store.Handle) uuid.UUID {
	t.Helper()

	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("insertInvite: generating id: %v", err)
	}

	const insertQuery = `
INSERT INTO invites (id, token_hash, created_by_ref, note, max_uses, uses, created_at, expires_at)
VALUES ($1, $2, $3, '', 1, 0, $4, $5)
`

	now := time.Now()

	if _, addErr := h.Pool().Exec(t.Context(), insertQuery, id, []byte("token-hash"), "test", now, now.Add(time.Hour)); addErr != nil {
		t.Fatalf("insertInvite: inserting row: %v", addErr)
	}

	return id
}

// codeHashFor returns the code_hash stored for the most recently created
// unconsumed row matching email.
func codeHashFor(t *testing.T, h *store.Handle, email string) []byte {
	t.Helper()

	const selectQuery = `
SELECT code_hash FROM otp_codes
WHERE email = $1
ORDER BY created_at DESC
LIMIT 1
`

	var hash []byte

	if err := h.Pool().QueryRow(t.Context(), selectQuery, email).Scan(&hash); err != nil {
		t.Fatalf("codeHashFor: querying: %v", err)
	}

	return hash
}
