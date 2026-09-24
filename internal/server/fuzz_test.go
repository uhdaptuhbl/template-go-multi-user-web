package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// These three targets guard properties that hold for every input, not for the
// inputs someone thought to write down. Each one is a place where attacker
// controlled bytes cross into something that trusts them: a log field, a slice
// index, an error message returned to the client. The table tests next to them
// still carry the criterion citations; these carry the invariant.
//
// Seeds are the interesting rows of those tables. Running the targets needs an
// explicit `go test -fuzz=FuzzName ./internal/server/`; a plain `go test` run
// executes the seed corpus only, which is why there is no CI job for this.

// FuzzValidRequestID checks that no input validRequestID accepts can carry a
// control character or exceed the length bound.
//
// Adopting an identifier puts it verbatim into a response header and into
// every log line about the request. A CR or LF that got through would let a
// client inject a second header or forge a log entry, and an unbounded string
// would let one request write as much of the log as it liked.
func FuzzValidRequestID(f *testing.F) {
	f.Add("")
	f.Add("abc123")
	f.Add("a.b_c-d")
	f.Add("has space")
	f.Add("has\nnewline")
	f.Add("has\rcarriage")
	f.Add(strings.Repeat("a", maxRequestIDLength))
	f.Add(strings.Repeat("a", maxRequestIDLength+1))
	f.Add("\x00")
	f.Add("café")

	f.Fuzz(func(t *testing.T, id string) {
		if !validRequestID(id) {
			return
		}

		if id == "" {
			t.Error("validRequestID accepted the empty string")
		}

		if len(id) > maxRequestIDLength {
			t.Errorf("validRequestID accepted %d bytes, limit is %d", len(id), maxRequestIDLength)
		}

		for i := range len(id) {
			if id[i] < 0x20 || id[i] == 0x7f {
				t.Errorf("validRequestID accepted control byte %#x at index %d", id[i], i)
			}
		}
	})
}

// FuzzForwardedFor checks that forwardedFor returns exactly one address per
// comma-separated entry, parseable or not.
//
// The hop count is the invariant the whole trusted-proxy walk rests on:
// TrustsPeer indexes backwards from the end of this slice to decide which hop
// is the client. An entry silently dropped shifts every index after it, so a
// header the proxy did not write could name whichever address the attacker
// wanted believed.
func FuzzForwardedFor(f *testing.F) {
	f.Add("198.51.100.9")
	f.Add("198.51.100.9, 10.4.5.6")
	f.Add("203.0.113.1, unknown, 10.9.9.9")
	f.Add("::ffff:198.51.100.9")
	f.Add("")
	f.Add(",")
	f.Add(" , , ")
	f.Add("2001:db8::1, , 10.0.0.1,")

	f.Fuzz(func(t *testing.T, value string) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set(forwardedForHeader, value)

		got := forwardedFor(req)

		want := strings.Count(value, ",") + 1
		if len(got) != want {
			t.Errorf("forwardedFor(%q) returned %d addresses, want %d (one per comma-separated entry)",
				value, len(got), want)
		}
	})
}

// FuzzDecodeJSONMessage checks that the message DecodeJSON returns to the
// client is always valid UTF-8 and free of control characters.
//
// The messages name what was wrong with the body, and some of them quote a
// piece of it: an unknown field's name comes straight from the request. A raw
// byte reaching the message reaches the JSON error body, the client, and the
// log line recording the failure.
func FuzzDecodeJSONMessage(f *testing.F) {
	f.Add("")
	f.Add(`{"name":`)
	f.Add(`{"name" "ada"}`)
	f.Add(`{"name":"ada","email":"a@b"}`)
	f.Add(`{"name":"ada","age":"old"}`)
	f.Add(`[1,2]`)
	f.Add(`{"name":"ada"} {"name":"bob"}`)
	f.Add("{\"\x00\":1}")
	f.Add(`{"\ud800":1}`)

	f.Fuzz(func(t *testing.T, body string) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		var dst payload

		err := DecodeJSON(req, &dst)
		if err == nil {
			return
		}

		clientErr, ok := errors.AsType[*ClientError](err)
		if !ok {
			t.Fatalf("DecodeJSON returned %T, want *ClientError", err)
		}

		if !utf8.ValidString(clientErr.Message) {
			t.Errorf("message is not valid UTF-8: %q", clientErr.Message)
		}

		for i, r := range clientErr.Message {
			if r < 0x20 || r == 0x7f {
				t.Errorf("message carries control rune %#x at index %d: %q", r, i, clientErr.Message)
			}
		}
	})
}
