package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// payload is the request shape the decoding tests target.
type payload struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

// TestWriteJSONEncodesTheValue covers AC-005.1.
func TestWriteJSONEncodesTheValue(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()

	WriteJSON(recorder, zap.NewNop(), http.StatusCreated, payload{Name: "ada", Age: 36})

	if recorder.Code != http.StatusCreated {
		t.Errorf("got status %d, want %d", recorder.Code, http.StatusCreated)
	}

	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("got Content-Type %q, want %q", got, "application/json")
	}

	if diff := cmp.Diff(`{"name":"ada","age":36}`, strings.TrimSpace(recorder.Body.String())); diff != "" {
		t.Errorf("body mismatch (-want +got):\n%s", diff)
	}
}

// TestWriteJSONReportsAnUnencodableValueAsInternal covers AC-005.2.
func TestWriteJSONReportsAnUnencodableValueAsInternal(t *testing.T) {
	t.Parallel()

	core, observed := observer.New(zap.ErrorLevel)
	recorder := httptest.NewRecorder()

	// A channel has no JSON encoding, so Marshal fails before a byte is
	// written: the client must see a complete 500, not a 200 with no body.
	WriteJSON(recorder, zap.New(core), http.StatusOK, make(chan int))

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("got status %d, want %d", recorder.Code, http.StatusInternalServerError)
	}

	wantBody := `{"errors":[{"status":"500","code":"internal","title":"Internal server error"}]}`
	if diff := cmp.Diff(wantBody, strings.TrimSpace(recorder.Body.String())); diff != "" {
		t.Errorf("body mismatch (-want +got):\n%s", diff)
	}

	if observed.FilterMessage("encoding json response").Len() != 1 {
		t.Errorf("got %d log entries about the encoding failure, want 1", observed.FilterMessage("encoding json response").Len())
	}
}

// TestDecodeJSONRequiresAJSONContentType covers AC-005.3.
func TestDecodeJSONRequiresAJSONContentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
		wantErr     bool
	}{
		{name: "missing", contentType: "", wantErr: true},
		{name: "text", contentType: "text/plain", wantErr: true},
		{name: "form", contentType: "application/x-www-form-urlencoded", wantErr: true},
		{name: "json", contentType: "application/json", wantErr: false},
		{name: "json with charset", contentType: "application/json; charset=utf-8", wantErr: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"ada","age":36}`))
			if test.contentType != "" {
				req.Header.Set("Content-Type", test.contentType)
			}

			var got payload

			err := DecodeJSON(req, &got)
			if !test.wantErr {
				if err != nil {
					t.Fatalf("DecodeJSON returned %v, want nil", err)
				}

				return
			}

			clientErr, ok := errors.AsType[*ClientError](err)
			if !ok {
				t.Fatalf("DecodeJSON returned %v, want a *ClientError", err)
			}

			if clientErr.Status != http.StatusUnsupportedMediaType {
				t.Errorf("got status %d, want %d", clientErr.Status, http.StatusUnsupportedMediaType)
			}

			if clientErr.Code != errorCodeUnsupportedMediaType {
				t.Errorf("got code %q, want %q", clientErr.Code, errorCodeUnsupportedMediaType)
			}
		})
	}
}

// TestDecodeJSONNamesWhatIsWrong covers AC-005.4.
func TestDecodeJSONNamesWhatIsWrong(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		body        string
		wantMessage string
	}{
		{name: "empty body", body: "", wantMessage: "request body is empty"},
		{name: "malformed", body: `{"name":`, wantMessage: "malformed JSON: unexpected end of input"},
		{name: "syntax error", body: `{"name" "ada"}`, wantMessage: "malformed JSON at offset 9"},
		{name: "unknown field", body: `{"name":"ada","email":"a@b"}`, wantMessage: `unknown field "email"`},
		{name: "wrong field type", body: `{"name":"ada","age":"old"}`, wantMessage: `field "age" must be a JSON number`},
		{name: "wrong top-level type", body: `[1,2]`, wantMessage: "request body must be a JSON object"},
		{name: "trailing value", body: `{"name":"ada"} {"name":"bob"}`, wantMessage: "request body must contain a single JSON value"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body))
			req.Header.Set("Content-Type", "application/json")

			var got payload

			clientErr, ok := errors.AsType[*ClientError](DecodeJSON(req, &got))
			if !ok {
				t.Fatal("DecodeJSON returned nil or a non-client error, want a *ClientError")
			}

			if clientErr.Status != http.StatusBadRequest {
				t.Errorf("got status %d, want %d", clientErr.Status, http.StatusBadRequest)
			}

			if clientErr.Code != errorCodeInvalidBody {
				t.Errorf("got code %q, want %q", clientErr.Code, errorCodeInvalidBody)
			}

			if clientErr.Message != test.wantMessage {
				t.Errorf("got message %q, want %q", clientErr.Message, test.wantMessage)
			}

			// The message names the problem; the body itself must not be
			// echoed back to the client.
			if test.body != "" && strings.Contains(clientErr.Message, test.body) {
				t.Errorf("message %q echoes the request body", clientErr.Message)
			}
		})
	}
}

// TestDecodeJSONReportsAnOversizedBodyAsTooLarge covers AC-005.5.
func TestDecodeJSONReportsAnOversizedBodyAsTooLarge(t *testing.T) {
	t.Parallel()

	// Through the same middleware the mux applies, so the test proves the two
	// halves agree rather than that DecodeJSON handles a hand-built error.
	var decodeErr error

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got payload

		decodeErr = DecodeJSON(r, &got)
		if decodeErr != nil {
			WriteError(w, r, zap.NewNop(), decodeErr)

			return
		}

		w.WriteHeader(http.StatusOK)
	})

	// A chunked body declares no length, so the Content-Length check passes
	// and MaxBytesReader is what trips.
	body := io.NopCloser(strings.NewReader(`{"name":"` + strings.Repeat("a", 64) + `"}`))
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()

	withRequestBodyLimit(16, zap.NewNop(), inner).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("got status %d, want %d", recorder.Code, http.StatusRequestEntityTooLarge)
	}

	wantBody := `{"errors":[{"status":"413","code":"payload_too_large","title":"Request body too large"}]}`
	if diff := cmp.Diff(wantBody, strings.TrimSpace(recorder.Body.String())); diff != "" {
		t.Errorf("body mismatch (-want +got):\n%s", diff)
	}

	if _, ok := errors.AsType[*http.MaxBytesError](decodeErr); !ok {
		t.Errorf("DecodeJSON returned %v, want an error wrapping *http.MaxBytesError", decodeErr)
	}
}

// TestWriteErrorMapsClientErrorsAndHidesTheRest covers AC-005.6.
func TestWriteErrorMapsClientErrorsAndHidesTheRest(t *testing.T) {
	t.Parallel()

	var secret = errors.New("dial tcp 10.0.0.7:5432: connection refused")

	tests := []struct {
		name         string
		err          error
		wantStatus   int
		wantBody     string
		wantLogLevel string
	}{
		{
			name:       "client error",
			err:        &ClientError{Status: http.StatusConflict, Code: "conflict", Message: "name already taken"},
			wantStatus: http.StatusConflict,
			wantBody:   `{"errors":[{"status":"409","code":"conflict","title":"Request conflicts with current state","detail":"name already taken"}]}`,
		},
		{
			name:       "wrapped client error",
			err:        fmt.Errorf("creating user: %w", &ClientError{Status: http.StatusNotFound, Code: "not_found", Message: "no such user"}),
			wantStatus: http.StatusNotFound,
			wantBody:   `{"errors":[{"status":"404","code":"not_found","title":"Not found","detail":"no such user"}]}`,
		},
		{
			name:       "any other error",
			err:        fmt.Errorf("querying users: %w", secret),
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"errors":[{"status":"500","code":"internal","title":"Internal server error"}]}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			core, observed := observer.New(zap.DebugLevel)
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/users", http.NoBody)

			WriteError(recorder, req, zap.New(core), test.err)

			if recorder.Code != test.wantStatus {
				t.Errorf("got status %d, want %d", recorder.Code, test.wantStatus)
			}

			if diff := cmp.Diff(test.wantBody, strings.TrimSpace(recorder.Body.String())); diff != "" {
				t.Errorf("body mismatch (-want +got):\n%s", diff)
			}

			if strings.Contains(recorder.Body.String(), secret.Error()) {
				t.Errorf("body %q leaks the underlying error", recorder.Body.String())
			}

			if test.wantStatus < http.StatusInternalServerError {
				return
			}

			entries := observed.FilterMessage("handling request").All()
			if len(entries) != 1 {
				t.Fatalf("got %d log entries about the failure, want 1", len(entries))
			}

			if entries[0].Level != zap.ErrorLevel {
				t.Errorf("got log level %v, want %v", entries[0].Level, zap.ErrorLevel)
			}

			if got := entries[0].ContextMap()["error"]; got != test.err.Error() {
				t.Errorf("got logged error %v, want %q", got, test.err.Error())
			}
		})
	}
}

// TestJSONKindNamesTheJSONTypeNotTheGoType covers AC-005.4.
func TestJSONKindNamesTheJSONTypeNotTheGoType(t *testing.T) {
	t.Parallel()

	type object struct{ Name string }

	tests := []struct {
		name  string
		value any
		want  string
	}{
		{name: "struct", value: object{}, want: "object"},
		{name: "pointer to struct", value: &object{}, want: "object"},
		{name: "map", value: map[string]int{}, want: "object"},
		{name: "slice", value: []int{}, want: "array"},
		{name: "array", value: [2]int{}, want: "array"},
		{name: "string", value: "", want: "string"},
		{name: "bool", value: false, want: "boolean"},
		{name: "int", value: 0, want: "number"},
		{name: "uint", value: uint(0), want: "number"},
		{name: "float", value: 0.0, want: "number"},
		{name: "channel has no JSON form", value: make(chan int), want: "value"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := jsonKind(reflect.TypeOf(test.value)); got != test.want {
				t.Errorf("jsonKind(%T) = %q, want %q", test.value, got, test.want)
			}
		})
	}

	// A nil type reaches this only from a malformed error value, and must not
	// panic on the way to a response.
	if got := jsonKind(nil); got != "value" {
		t.Errorf("jsonKind(nil) = %q, want %q", got, "value")
	}
}

// TestWriteErrorReportsEveryJoinedClientError covers AC-002.1 and AC-005.20.
func TestWriteErrorReportsEveryJoinedClientError(t *testing.T) {
	t.Parallel()

	// Reporting one failure per round trip is what the plural document
	// exists to avoid: a handler validating three fields joins three
	// ClientErrors, and the client should learn about all three at once.
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantBody   string
	}{
		{
			name: "several client errors at one status",
			err: errors.Join(
				&ClientError{Status: http.StatusBadRequest, Code: errorCodeInvalidBody, Message: "must be a JSON string", Pointer: "/name"},
				&ClientError{Status: http.StatusBadRequest, Code: errorCodeInvalidBody, Message: "must be a JSON number", Pointer: "/age"},
			),
			wantStatus: http.StatusBadRequest,
			wantBody: `{"errors":[` +
				`{"status":"400","code":"invalid_body","title":"Invalid request body","detail":"must be a JSON string","source":{"pointer":"/name"}},` +
				`{"status":"400","code":"invalid_body","title":"Invalid request body","detail":"must be a JSON number","source":{"pointer":"/age"}}` +
				`]}`,
		},
		{
			// Differing client statuses collapse to the most generally
			// applicable one, which is what JSON:API prescribes.
			name: "client errors at differing statuses",
			err: errors.Join(
				&ClientError{Status: http.StatusConflict, Code: "conflict", Message: "name already taken"},
				&ClientError{Status: http.StatusNotFound, Code: "not_found", Message: "no such team"},
			),
			wantStatus: http.StatusBadRequest,
			wantBody: `{"errors":[` +
				`{"status":"409","code":"conflict","title":"Request conflicts with current state","detail":"name already taken"},` +
				`{"status":"404","code":"not_found","title":"Not found","detail":"no such team"}` +
				`]}`,
		},
		{
			// A server failure among them is not something the client can
			// fix by correcting its input, so the response says so.
			name: "a server error among client errors",
			err: errors.Join(
				&ClientError{Status: http.StatusBadRequest, Code: errorCodeInvalidBody, Message: "must be a JSON string"},
				&ClientError{Status: http.StatusBadGateway, Code: "upstream", Message: "directory unavailable"},
			),
			wantStatus: http.StatusInternalServerError,
			wantBody: `{"errors":[` +
				`{"status":"400","code":"invalid_body","title":"Invalid request body","detail":"must be a JSON string"},` +
				`{"status":"502","code":"upstream","title":"upstream","detail":"directory unavailable"}` +
				`]}`,
		},
		{
			// A join reached through a wrapper is still a join.
			name: "joined client errors behind a wrapper",
			err: fmt.Errorf("creating user: %w", errors.Join(
				&ClientError{Status: http.StatusBadRequest, Code: errorCodeInvalidBody, Message: "must be a JSON string"},
				&ClientError{Status: http.StatusBadRequest, Code: errorCodeInvalidBody, Message: "must be a JSON number"},
			)),
			wantStatus: http.StatusBadRequest,
			wantBody: `{"errors":[` +
				`{"status":"400","code":"invalid_body","title":"Invalid request body","detail":"must be a JSON string"},` +
				`{"status":"400","code":"invalid_body","title":"Invalid request body","detail":"must be a JSON number"}` +
				`]}`,
		},
		{
			// A plain error joined alongside a client error contributes no
			// object of its own: its text is for the log, never the client.
			name: "a plain error joined with a client error",
			err: errors.Join(
				errors.New("dial tcp 10.0.0.7:5432: connection refused"),
				&ClientError{Status: http.StatusBadRequest, Code: errorCodeInvalidBody, Message: "must be a JSON string"},
			),
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"errors":[{"status":"400","code":"invalid_body","title":"Invalid request body","detail":"must be a JSON string"}]}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/users", http.NoBody)

			WriteError(recorder, req, zap.NewNop(), test.err)

			if recorder.Code != test.wantStatus {
				t.Errorf("got status %d, want %d", recorder.Code, test.wantStatus)
			}

			if diff := cmp.Diff(test.wantBody, strings.TrimSpace(recorder.Body.String())); diff != "" {
				t.Errorf("body mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDecodePointerEscapesATypeErrorMemberName covers AC-005.4 for a member
// named by a struct tag. No payload in this package has a tag containing "/"
// or "~", so the error is built directly rather than decoded.
func TestDecodePointerEscapesATypeErrorMemberName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		field string
		want  string
	}{
		{name: "plain", field: "age", want: "/age"},
		{name: "slash", field: "a/b", want: "/a~1b"},
		{name: "tilde", field: "a~b", want: "/a~0b"},
		{name: "nested path", field: "outer.inner", want: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := decodePointer(&json.UnmarshalTypeError{Field: test.field, Type: reflect.TypeFor[int]()})
			if got != test.want {
				t.Errorf("decodePointer() = %q, want %q", got, test.want)
			}
		})
	}
}

// TestDecodeJSONLocatesTheOffendingMember covers AC-005.4.
func TestDecodeJSONLocatesTheOffendingMember(t *testing.T) {
	t.Parallel()

	// source.pointer is what lets a frontend attach the message to the field
	// it is about instead of dropping it at the top of the form.
	tests := []struct {
		name        string
		body        string
		wantPointer string
	}{
		{name: "wrong field type", body: `{"age":"old"}`, wantPointer: "/age"},
		{name: "unknown field", body: `{"email":"a@b"}`, wantPointer: "/email"},
		// RFC 6901 section 3: "~" is written "~0" and "/" is written "~1".
		// "~" is escaped first, or the "~1" written for a "/" would be
		// escaped again; the slash row catches that order.
		{name: "unknown field containing a slash", body: `{"a/b":1}`, wantPointer: "/a~1b"},
		{name: "unknown field containing a tilde", body: `{"a~b":1}`, wantPointer: "/a~0b"},
		{name: "unknown field containing an escape sequence", body: `{"~1":1}`, wantPointer: "/~01"},
		{name: "wrong top-level type", body: `[1,2]`, wantPointer: ""},
		{name: "malformed", body: `{"name":`, wantPointer: ""},
		{name: "empty body", body: "", wantPointer: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body))
			req.Header.Set("Content-Type", "application/json")

			var dst payload

			err := DecodeJSON(req, &dst)

			clientErr, ok := errors.AsType[*ClientError](err)
			if !ok {
				t.Fatalf("DecodeJSON returned %T, want *ClientError", err)
			}

			if clientErr.Pointer != test.wantPointer {
				t.Errorf("got pointer %q, want %q", clientErr.Pointer, test.wantPointer)
			}
		})
	}
}
