package authz

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// recordingHandler is a next handler that records whether it ran and writes a
// distinctive body, so a test can tell whether the middleware invoked it or
// short-circuited before it.
func recordingHandler(ran *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*ran = true
		w.WriteHeader(http.StatusTeapot)

		if _, err := w.Write([]byte("next handler ran")); err != nil {
			panic(err)
		}
	})
}

// decodeErrorDocument unmarshals body as an errorDocument for comparison,
// rather than comparing raw bytes, since WriteError's underlying encoder
// appends a trailing newline that is not part of the JSON value itself.
func decodeErrorDocument(t *testing.T, body []byte) errorDocumentForTest {
	t.Helper()

	var doc errorDocumentForTest
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshaling response body %q: %v", body, err)
	}

	return doc
}

// errorDocumentForTest mirrors server's unexported errorDocument shape so this
// package's tests can decode a response body without importing an unexported
// type.
type errorDocumentForTest struct {
	Errors []errorObjectForTest `json:"errors"`
}

// errorObjectForTest mirrors server's unexported errorObject shape.
type errorObjectForTest struct {
	Status string `json:"status,omitempty"`
	Code   string `json:"code"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
}

// TestRequirePermissionRejectsRequestWithNoSubject covers AC-008.34: an
// unauthenticated request is answered with 401 and the standard
// unauthenticated error body, and the next handler never runs.
func TestRequirePermissionRejectsRequestWithNoSubject(t *testing.T) {
	var ran bool
	handler := RequirePermission("user.read", zap.NewNop())(recordingHandler(&ran))

	req := httptest.NewRequest(http.MethodGet, "/widgets", http.NoBody)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	want := errorDocumentForTest{Errors: []errorObjectForTest{
		{Status: "401", Code: "unauthenticated", Title: "Authentication required"},
	}}
	got := decodeErrorDocument(t, rec.Body.Bytes())

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("body = %+v, want %+v", got, want)
	}

	if ran {
		t.Fatal("next handler ran, want it skipped")
	}
}

// TestRequirePermissionRejectsSubjectWithoutPermission covers AC-008.33: a
// subject lacking the required permission is answered with 403 and the
// standard forbidden error body, and the next handler never runs.
func TestRequirePermissionRejectsSubjectWithoutPermission(t *testing.T) {
	var ran bool
	handler := RequirePermission("user.readall", zap.NewNop())(recordingHandler(&ran))

	subject := Subject{UserID: uuid.New(), SessionPublicID: uuid.New(), Permissions: []string{"user.read"}}
	req := httptest.NewRequest(http.MethodGet, "/widgets", http.NoBody)
	req = req.WithContext(WithSubject(req.Context(), subject))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	want := errorDocumentForTest{Errors: []errorObjectForTest{
		{Status: "403", Code: "forbidden", Title: "Permission denied"},
	}}
	got := decodeErrorDocument(t, rec.Body.Bytes())

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("body = %+v, want %+v", got, want)
	}

	if ran {
		t.Fatal("next handler ran, want it skipped")
	}
}

// TestRequirePermissionRejectsSimilarPrefixPermission covers AC-008.32: a
// subject holding a permission that merely shares a prefix with the required
// one, such as user.read when user.readall is required, is rejected. This
// proves the check is an exact membership test rather than a prefix match.
func TestRequirePermissionRejectsSimilarPrefixPermission(t *testing.T) {
	var ran bool
	handler := RequirePermission("user.readall", zap.NewNop())(recordingHandler(&ran))

	subject := Subject{UserID: uuid.New(), SessionPublicID: uuid.New(), Permissions: []string{"user.read"}}
	req := httptest.NewRequest(http.MethodGet, "/widgets", http.NoBody)
	req = req.WithContext(WithSubject(req.Context(), subject))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	if ran {
		t.Fatal("next handler ran, want it rejected despite the shared prefix")
	}
}

// TestRequirePermissionRunsNextHandlerWhenSubjectHoldsPermission covers
// AC-008.32: a subject holding the required permission reaches the next
// handler, and the middleware writes nothing of its own -- the recorder holds
// only what the next handler wrote.
func TestRequirePermissionRunsNextHandlerWhenSubjectHoldsPermission(t *testing.T) {
	var ran bool
	handler := RequirePermission("user.read", zap.NewNop())(recordingHandler(&ran))

	subject := Subject{UserID: uuid.New(), SessionPublicID: uuid.New(), Permissions: []string{"user.read"}}
	req := httptest.NewRequest(http.MethodGet, "/widgets", http.NoBody)
	req = req.WithContext(WithSubject(req.Context(), subject))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !ran {
		t.Fatal("next handler did not run")
	}

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}

	if got, want := rec.Body.String(), "next handler ran"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

// TestRequirePermissionLogsWarnOnDenial covers AC-008.33: denying a subject
// for lacking a permission logs one warning line carrying the user
// identifier, the permission, and the request path.
func TestRequirePermissionLogsWarnOnDenial(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	logger := zap.New(core)

	subject := Subject{UserID: uuid.New(), SessionPublicID: uuid.New(), Permissions: nil}
	handler := RequirePermission("user.readall", logger)(recordingHandler(new(bool)))

	req := httptest.NewRequest(http.MethodGet, "/widgets", http.NoBody)
	req = req.WithContext(WithSubject(req.Context(), subject))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("logged %d entries, want 1", len(entries))
	}

	entry := entries[0]
	fields := entry.ContextMap()

	if got, want := fields["user_id"], subject.UserID.String(); got != want {
		t.Fatalf("user_id field = %v, want %v", got, want)
	}

	if got, want := fields["permission"], "user.readall"; got != want {
		t.Fatalf("permission field = %v, want %v", got, want)
	}

	if got, want := fields["path"], "/widgets"; got != want {
		t.Fatalf("path field = %v, want %v", got, want)
	}
}
