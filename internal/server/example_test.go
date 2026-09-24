package server_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"go.uber.org/zap"

	"github.com/uhdaptuhbl/template-go-multi-user-web/internal/server"
)

// These examples cite no criterion. They are documentation that happens to
// execute: their value is the rendered Output block next to each function in
// godoc, and the criteria they touch are already cited by the tests in this
// package.

// user is the request and response shape these examples decode into and
// encode back out.
type user struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

// ExampleDecodeJSON shows the shape of a handler that reads a JSON body:
// decode, and hand any failure straight to WriteError, which already knows how
// to turn a ClientError into the right status and body.
func ExampleDecodeJSON() {
	handler := func(w http.ResponseWriter, r *http.Request) {
		var decoded user

		if err := server.DecodeJSON(r, &decoded); err != nil {
			server.WriteError(w, r, zap.NewNop(), err)

			return
		}

		server.WriteJSON(w, zap.NewNop(), http.StatusOK, decoded)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(`{"name":"ada","age":36}`))
	request.Header.Set("Content-Type", "application/json")

	handler(recorder, request)

	fmt.Println(recorder.Code)
	fmt.Println(strings.TrimSpace(recorder.Body.String()))

	// A body the endpoint did not ask for is rejected, and the error names
	// the member it is about rather than echoing what was sent.
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(`{"name":"ada","nickname":"a"}`))
	request.Header.Set("Content-Type", "application/json")

	handler(recorder, request)

	fmt.Println(recorder.Code)
	fmt.Println(strings.TrimSpace(recorder.Body.String()))

	// Output:
	// 200
	// {"name":"ada","age":36}
	// 400
	// {"errors":[{"status":"400","code":"invalid_body","title":"Invalid request body","detail":"unknown field \"nickname\"","source":{"pointer":"/nickname"}}]}
}

// ExampleWriteJSON shows the success path: a status and a value, encoded
// before anything is written, so a value that cannot be encoded produces a
// well-formed 500 rather than half a body behind a 200 status line.
func ExampleWriteJSON() {
	recorder := httptest.NewRecorder()

	server.WriteJSON(recorder, zap.NewNop(), http.StatusCreated, user{Name: "ada", Age: 36})

	fmt.Println(recorder.Code)
	fmt.Println(recorder.Header().Get("Content-Type"))
	fmt.Println(strings.TrimSpace(recorder.Body.String()))

	// Output:
	// 201
	// application/json
	// {"name":"ada","age":36}
}

// ExampleWriteError shows the three cases a handler hands to WriteError: one
// client error, several joined together, and an error that is nobody's fault
// but the server's.
func ExampleWriteError() {
	write := func(err error) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/users", http.NoBody)

		server.WriteError(recorder, request, zap.NewNop(), err)

		fmt.Println(recorder.Code, strings.TrimSpace(recorder.Body.String()))
	}

	// A ClientError anywhere in the chain supplies the status and code, so
	// wrapping it with context for the log costs nothing.
	write(fmt.Errorf("creating user: %w", &server.ClientError{
		Status:  http.StatusConflict,
		Code:    "conflict",
		Message: "name already taken",
	}))

	// Joined client errors become one error object each, which is how a
	// handler reports every bad field in one response instead of one per
	// round trip.
	write(errors.Join(
		&server.ClientError{Status: http.StatusBadRequest, Code: "invalid_body", Message: "must not be empty", Pointer: "/name"},
		&server.ClientError{Status: http.StatusBadRequest, Code: "invalid_body", Message: "must be positive", Pointer: "/age"},
	))

	// Anything else is a 500 that tells the client nothing. The cause goes
	// to the log and no further.
	write(errors.New("dial tcp 10.0.0.7:5432: connection refused"))

	// Output:
	// 409 {"errors":[{"status":"409","code":"conflict","title":"Request conflicts with current state","detail":"name already taken"}]}
	// 400 {"errors":[{"status":"400","code":"invalid_body","title":"Invalid request body","detail":"must not be empty","source":{"pointer":"/name"}},{"status":"400","code":"invalid_body","title":"Invalid request body","detail":"must be positive","source":{"pointer":"/age"}}]}
	// 500 {"errors":[{"status":"500","code":"internal","title":"Internal server error"}]}
}

// ExampleReadiness_AddCheck shows a dependency registered as a readiness
// check, and what /readyz reports once it starts failing.
//
// A check should name a dependency without which requests cannot be served at
// all. One that is merely slow does not belong here: a shared dependency
// having a bad minute would otherwise pull every replica out of rotation at
// once.
func ExampleReadiness_AddCheck() {
	ready := server.NewReadiness()

	reachable := false

	ready.AddCheck("database", func(context.Context) error {
		if !reachable {
			// The text is logged, never sent: the body names which check
			// failed and nothing about why.
			return errors.New("dial tcp 10.0.0.7:5432: connection refused")
		}

		return nil
	})

	mux := server.NewAdminMux(server.DefaultAdminConfig(), zap.NewNop(), ready, server.ProcessInfo{}, http.NotFoundHandler())

	probe := func() {
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", http.NoBody))

		fmt.Println(recorder.Code, strings.TrimSpace(recorder.Body.String()))
	}

	probe()

	reachable = true

	probe()

	// Output:
	// 503 {"status":"not_ready","failing":["database"]}
	// 200 {"status":"ready"}
}
