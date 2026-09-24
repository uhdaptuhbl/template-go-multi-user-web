//go:build integration

package audit_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/audit"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store"
	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/store/storetest"
)

// clockFunc returns a now func that advances by one second on every call, so
// events recorded in quick succession still land at distinct, strictly
// increasing timestamps.
func clockFunc(start time.Time) func() time.Time {
	current := start

	return func() time.Time {
		current = current.Add(time.Second)

		return current
	}
}

// insertUser inserts a minimal active user row directly, for tests that need
// a real actor to reference or to delete.
func insertUser(t *testing.T, h *store.Handle) uuid.UUID {
	t.Helper()

	id := uuid.New()
	now := time.Now().UTC()

	_, err := h.Pool().Exec(t.Context(),
		`INSERT INTO users (id, display_name, status, created_at, updated_at) VALUES ($1, $2, 'active', $3, $3)`,
		id, "Test User", now,
	)
	if err != nil {
		t.Fatalf("inserting user: %v", err)
	}

	return id
}

// TestRecordInsertsRowReadableByList covers AC-008.38.
func TestRecordInsertsRowReadableByList(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	recorder := audit.NewRecorder(h, zap.NewNop(), clockFunc(time.Now().UTC()))

	actorID := insertUser(t, h)
	event := audit.Event{
		ActorID:   &actorID,
		Subject:   "user:" + actorID.String(),
		Action:    audit.ActionUserCreated,
		Outcome:   audit.OutcomeSuccess,
		RequestID: "req-1",
		Detail:    json.RawMessage(`{"foo":"bar"}`),
	}

	if err := recorder.Record(t.Context(), event); err != nil {
		t.Fatalf("Record() error = %v, want nil", err)
	}

	events, err := recorder.List(t.Context(), 10, audit.Cursor{})
	if err != nil {
		t.Fatalf("List() error = %v, want nil", err)
	}

	if len(events) != 1 {
		t.Fatalf("List() returned %d events, want 1", len(events))
	}

	if events[0].Action != audit.ActionUserCreated {
		t.Errorf("events[0].Action = %q, want %q", events[0].Action, audit.ActionUserCreated)
	}

	if events[0].Subject != event.Subject {
		t.Errorf("events[0].Subject = %q, want %q", events[0].Subject, event.Subject)
	}

	if events[0].ID.Version() != 7 {
		t.Errorf("events[0].ID.Version() = %d, want 7", events[0].ID.Version())
	}
}

// TestAnonymousActorRoundTrips covers AC-008.39: an event with a NULL
// ActorID round-trips and stores actor_ref as "anonymous".
func TestAnonymousActorRoundTrips(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	recorder := audit.NewRecorder(h, zap.NewNop(), time.Now)

	if err := recorder.Record(t.Context(), audit.Event{
		Subject:   "user:" + uuid.NewString(),
		Action:    audit.ActionOTPRequested,
		Outcome:   audit.OutcomeSuccess,
		RequestID: "req-anon",
	}); err != nil {
		t.Fatalf("Record() error = %v, want nil", err)
	}

	events, err := recorder.List(t.Context(), 10, audit.Cursor{})
	if err != nil {
		t.Fatalf("List() error = %v, want nil", err)
	}

	if len(events) != 1 {
		t.Fatalf("List() returned %d events, want 1", len(events))
	}

	if events[0].ActorID != nil {
		t.Errorf("events[0].ActorID = %v, want nil", events[0].ActorID)
	}

	if events[0].ActorRef != "anonymous" {
		t.Errorf("events[0].ActorRef = %q, want %q", events[0].ActorRef, "anonymous")
	}
}

// TestKnownActorStoresUserRef covers AC-008.39: an event with a set ActorID
// stores actor_ref as "user:<that uuid>".
func TestKnownActorStoresUserRef(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	recorder := audit.NewRecorder(h, zap.NewNop(), time.Now)

	actorID := insertUser(t, h)

	if err := recorder.Record(t.Context(), audit.Event{
		ActorID:   &actorID,
		Subject:   "user:" + actorID.String(),
		Action:    audit.ActionUserUpdated,
		Outcome:   audit.OutcomeSuccess,
		RequestID: "req-known",
	}); err != nil {
		t.Fatalf("Record() error = %v, want nil", err)
	}

	events, err := recorder.List(t.Context(), 10, audit.Cursor{})
	if err != nil {
		t.Fatalf("List() error = %v, want nil", err)
	}

	if len(events) != 1 {
		t.Fatalf("List() returned %d events, want 1", len(events))
	}

	if events[0].ActorID == nil || *events[0].ActorID != actorID {
		t.Errorf("events[0].ActorID = %v, want %v", events[0].ActorID, actorID)
	}

	want := "user:" + actorID.String()
	if events[0].ActorRef != want {
		t.Errorf("events[0].ActorRef = %q, want %q", events[0].ActorRef, want)
	}
}

// TestActorIDNulledOnActorDeletionLeavesActorRefUnchanged covers AC-008.53:
// deleting the actor's row nulls actor_id and leaves actor_ref unchanged,
// read back directly rather than through Recorder, which is the whole point
// of the column.
func TestActorIDNulledOnActorDeletionLeavesActorRefUnchanged(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	recorder := audit.NewRecorder(h, zap.NewNop(), time.Now)

	actorID := insertUser(t, h)
	wantRef := "user:" + actorID.String()

	if err := recorder.Record(t.Context(), audit.Event{
		ActorID:   &actorID,
		Subject:   wantRef,
		Action:    audit.ActionUserSuspended,
		Outcome:   audit.OutcomeSuccess,
		RequestID: "req-delete",
	}); err != nil {
		t.Fatalf("Record() error = %v, want nil", err)
	}

	if _, err := h.Pool().Exec(t.Context(), "DELETE FROM users WHERE id = $1", actorID); err != nil {
		t.Fatalf("deleting actor row: %v", err)
	}

	var gotActorID *uuid.UUID
	var gotActorRef string

	err := h.Pool().QueryRow(t.Context(),
		"SELECT actor_id, actor_ref FROM audit_events WHERE request_id = $1", "req-delete",
	).Scan(&gotActorID, &gotActorRef)
	if err != nil {
		t.Fatalf("reading back audit event: %v", err)
	}

	if gotActorID != nil {
		t.Errorf("actor_id = %v, want nil after actor deletion", gotActorID)
	}

	if gotActorRef != wantRef {
		t.Errorf("actor_ref = %q, want %q (unchanged)", gotActorRef, wantRef)
	}
}

// TestRecordRejectsMalformedSubject covers AC-008.38: an Event whose Subject
// is a bare UUID or a bare email address returns ErrMalformedSubject and
// writes nothing.
func TestRecordRejectsMalformedSubject(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	recorder := audit.NewRecorder(h, zap.NewNop(), time.Now)

	tests := []struct {
		name    string
		subject string
	}{
		{name: "bare UUID", subject: uuid.New().String()},
		{name: "bare email address", subject: "person@example.com"},
	}

	for _, tt := range tests {
		err := recorder.Record(t.Context(), audit.Event{
			Subject:   tt.subject,
			Action:    audit.ActionOIDCStarted,
			Outcome:   audit.OutcomeFailure,
			RequestID: "req-malformed-" + tt.name,
		})
		if !errors.Is(err, audit.ErrMalformedSubject) {
			t.Errorf("%s: Record() error = %v, want ErrMalformedSubject", tt.name, err)
		}
	}

	events, err := recorder.List(t.Context(), 10, audit.Cursor{})
	if err != nil {
		t.Fatalf("List() error = %v, want nil", err)
	}

	if len(events) != 0 {
		t.Fatalf("List() returned %d events, want 0 after rejected records", len(events))
	}
}

// TestListOrdersMostRecentFirstAndPagesByCursor covers AC-008.49: List orders
// most recent first and pages by its before cursor.
func TestListOrdersMostRecentFirstAndPagesByCursor(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	recorder := audit.NewRecorder(h, zap.NewNop(), clockFunc(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)))

	actorID := insertUser(t, h)

	for i := range 3 {
		event := audit.Event{
			ActorID:   &actorID,
			Subject:   "user:" + actorID.String(),
			Action:    audit.ActionLogout,
			Outcome:   audit.OutcomeSuccess,
			RequestID: fmt.Sprintf("req-order-%d", i),
		}
		if err := recorder.Record(t.Context(), event); err != nil {
			t.Fatalf("Record() error = %v, want nil", err)
		}
	}

	all, err := recorder.List(t.Context(), 10, audit.Cursor{})
	if err != nil {
		t.Fatalf("List() error = %v, want nil", err)
	}

	if len(all) != 3 {
		t.Fatalf("List() returned %d events, want 3", len(all))
	}

	if !all[0].OccurredAt.After(all[1].OccurredAt) || !all[1].OccurredAt.After(all[2].OccurredAt) {
		t.Fatalf("List() not ordered most-recent-first: %+v", all)
	}

	paged, err := recorder.List(t.Context(), 10, audit.Cursor{OccurredAt: all[0].OccurredAt, ID: all[0].ID})
	if err != nil {
		t.Fatalf("List() error = %v, want nil", err)
	}

	if len(paged) != 2 {
		t.Fatalf("List() with before cursor returned %d events, want 2", len(paged))
	}

	if paged[0].ID != all[1].ID || paged[1].ID != all[2].ID {
		t.Fatalf("List() with before cursor = %+v, want IDs [%v %v]", paged, all[1].ID, all[2].ID)
	}
}

// TestDetail covers AC-008.40: Detail passes plain fields through unchanged,
// drops any key whose lowercased name indicates a credential, records the
// dropped key names under "dropped", and returns an error rather than a
// placeholder when a field cannot be marshalled.
func TestDetail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       map[string]any
		wantErr     bool
		wantData    map[string]any
		wantDropped []string
	}{
		{
			name:     "plain map passes through unchanged",
			input:    map[string]any{"foo": "bar", "count": float64(3)},
			wantData: map[string]any{"foo": "bar", "count": float64(3)},
		},
		{
			name:        "token key is dropped and named under dropped",
			input:       map[string]any{"foo": "bar", "token": "abc123"},
			wantData:    map[string]any{"foo": "bar"},
			wantDropped: []string{"token"},
		},
		{
			name:        "client_secret, otp_code, and session_token are all dropped",
			input:       map[string]any{"client_secret": "x", "otp_code": "y", "session_token": "z", "keep": "me"},
			wantData:    map[string]any{"keep": "me"},
			wantDropped: []string{"client_secret", "otp_code", "session_token"},
		},
		{
			name:    "an unmarshalable value is an error",
			input:   map[string]any{"bad": make(chan int)},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := audit.Detail(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Detail() = %s, nil; want an error", got)
				}

				return
			}

			if err != nil {
				t.Fatalf("Detail() error = %v, want nil", err)
			}

			var decoded map[string]any
			if unmarshalErr := json.Unmarshal(got, &decoded); unmarshalErr != nil {
				t.Fatalf("json.Unmarshal(Detail() result) error = %v", unmarshalErr)
			}

			gotDroppedRaw, _ := decoded["dropped"].([]any)
			delete(decoded, "dropped")

			if !reflect.DeepEqual(decoded, tt.wantData) {
				t.Errorf("Detail() data = %#v, want %#v", decoded, tt.wantData)
			}

			var gotDropped []string
			for _, v := range gotDroppedRaw {
				s, ok := v.(string)
				if !ok {
					t.Fatalf("Detail() dropped entry = %v, want a string", v)
				}

				gotDropped = append(gotDropped, s)
			}

			sort.Strings(gotDropped)

			wantDropped := append([]string(nil), tt.wantDropped...)
			sort.Strings(wantDropped)

			if !reflect.DeepEqual(gotDropped, wantDropped) {
				t.Errorf("Detail() dropped = %v, want %v", gotDropped, wantDropped)
			}
		})
	}
}

// TestRecordTxRollsBackWithTheTransaction covers AC-008.38: RecordTx appends
// a row inside the caller's transaction, so the row is absent when the
// transaction rolls back and present once it commits.
func TestRecordTxRollsBackWithTheTransaction(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	recorder := audit.NewRecorder(h, zap.NewNop(), time.Now)
	actorID := insertUser(t, h)

	rolledBackTx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}

	if err = recorder.RecordTx(t.Context(), rolledBackTx, audit.Event{
		ActorID:   &actorID,
		Subject:   "user:" + actorID.String(),
		Action:    audit.ActionUserUpdated,
		Outcome:   audit.OutcomeSuccess,
		RequestID: "req-rollback",
	}); err != nil {
		t.Fatalf("RecordTx() error = %v, want nil", err)
	}

	if err = rolledBackTx.Rollback(t.Context()); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}

	afterRollback, err := recorder.List(t.Context(), 10, audit.Cursor{})
	if err != nil {
		t.Fatalf("List() error = %v, want nil", err)
	}

	if len(afterRollback) != 0 {
		t.Fatalf("List() after rollback returned %d events, want 0", len(afterRollback))
	}

	committedTx, err := h.Pool().Begin(t.Context())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}

	if err = recorder.RecordTx(t.Context(), committedTx, audit.Event{
		ActorID:   &actorID,
		Subject:   "user:" + actorID.String(),
		Action:    audit.ActionUserUpdated,
		Outcome:   audit.OutcomeSuccess,
		RequestID: "req-commit",
	}); err != nil {
		t.Fatalf("RecordTx() error = %v, want nil", err)
	}

	if err = committedTx.Commit(t.Context()); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	afterCommit, err := recorder.List(t.Context(), 10, audit.Cursor{})
	if err != nil {
		t.Fatalf("List() error = %v, want nil", err)
	}

	if len(afterCommit) != 1 {
		t.Fatalf("List() after commit returned %d events, want 1", len(afterCommit))
	}

	if afterCommit[0].RequestID != "req-commit" {
		t.Errorf("afterCommit[0].RequestID = %q, want %q", afterCommit[0].RequestID, "req-commit")
	}
}

// TestListPagesAcrossEventsSharingATimestamp covers AC-008.49: List pages
// correctly even when several events share the exact same occurred_at,
// because the compound (occurred_at, id) ordering breaks the tie. This test
// pages by fetching limit+1 rows at a time, the same technique the audit
// list HTTP handler uses: fewer than limit+1 rows back means the page just
// fetched is the last one.
func TestListPagesAcrossEventsSharingATimestamp(t *testing.T) {
	t.Parallel()

	h := storetest.New(t)
	frozen := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	recorder := audit.NewRecorder(h, zap.NewNop(), func() time.Time { return frozen })

	actorID := insertUser(t, h)

	const total = 5

	for i := range total {
		event := audit.Event{
			ActorID:   &actorID,
			Subject:   "user:" + actorID.String(),
			Action:    audit.ActionLogout,
			Outcome:   audit.OutcomeSuccess,
			RequestID: fmt.Sprintf("req-tie-%d", i),
		}
		if err := recorder.Record(t.Context(), event); err != nil {
			t.Fatalf("Record() error = %v, want nil", err)
		}
	}

	const limit = 2

	seen := make(map[uuid.UUID]bool)

	var cursor audit.Cursor

	var lastPageSize int

	for range total + 1 {
		events, err := recorder.List(t.Context(), limit+1, cursor)
		if err != nil {
			t.Fatalf("List() error = %v, want nil", err)
		}

		lastPageSize = len(events)

		fetched := events
		if len(fetched) > limit {
			fetched = fetched[:limit]
		}

		for _, e := range fetched {
			if seen[e.ID] {
				t.Fatalf("List() returned event %v more than once across pages", e.ID)
			}

			seen[e.ID] = true
		}

		if len(events) <= limit {
			break
		}

		last := fetched[len(fetched)-1]
		cursor = audit.Cursor{OccurredAt: last.OccurredAt, ID: last.ID}
	}

	if len(seen) != total {
		t.Fatalf("saw %d distinct events across pages, want %d", len(seen), total)
	}

	if lastPageSize > limit {
		t.Fatalf("final page returned %d rows, want <= %d (fewer than limit+1 marks the last page)", lastPageSize, limit)
	}
}
