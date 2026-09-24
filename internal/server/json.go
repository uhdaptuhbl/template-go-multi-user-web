package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

// jsonMediaType is the only media type a JSON endpoint accepts in a request
// body.
const jsonMediaType = "application/json"

// errorCodeInvalidBody is reported when a request body cannot be decoded as the
// JSON value the endpoint expects.
const errorCodeInvalidBody = "invalid_body"

// errorCodeUnsupportedMediaType is reported when a request body arrives with a
// Content-Type the endpoint does not accept.
const errorCodeUnsupportedMediaType = "unsupported_media_type"

// ClientError describes a failure the client caused and can act on: the status
// and machine-readable code to respond with, and a message safe to send.
//
// A handler returns one, or an error wrapping one, and WriteError turns it into
// the response. Any other error becomes a 500, so a handler that wants the
// client to learn anything at all about what went wrong has to say so through
// this type. Err is the underlying cause, kept for the log and never sent.
type ClientError struct {
	// Status is the HTTP status the response carries.
	Status int
	// Code is a stable identifier the client may branch on.
	Code string
	// Message is a short description for a human reading a console or a log.
	// It becomes the error object's detail, so it describes this occurrence
	// rather than the kind of failure, which the title already names.
	Message string
	// Pointer is a JSON Pointer (RFC 6901) to the part of the request body
	// the failure is about, empty when it is not about one part in
	// particular. It becomes the error object's source.pointer, which is
	// what lets a frontend attach a message to a field.
	Pointer string
	// Err is the cause, if any. It is logged, never written to the client.
	Err error
}

// errorObject renders e as one member of an error document.
func (e *ClientError) errorObject() errorObject {
	return newErrorObject(e.Status, e.Code, e.Message, e.Pointer)
}

// Error returns the message, followed by the cause when there is one.
func (e *ClientError) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}

	return e.Message
}

// Unwrap returns the underlying cause, so that errors.Is and errors.As reach
// through a ClientError to whatever produced it.
func (e *ClientError) Unwrap() error {
	return e.Err
}

// WriteJSON responds with status and v encoded as JSON.
//
// v is encoded before anything is written, so a value that cannot be encoded
// produces a well-formed 500 rather than a 200 status line followed by half a
// body. The client is told nothing about why; the failure is a programming
// error and goes to the log.
func WriteJSON(w http.ResponseWriter, logger *zap.Logger, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		logger.Error("encoding json response", zap.Error(err), zap.Int("status", status))
		writeJSONError(w, logger, http.StatusInternalServerError, errorCodeInternal, "")

		return
	}

	w.Header().Set("Content-Type", jsonMediaType)
	w.WriteHeader(status)

	if _, writeErr := w.Write(body); writeErr != nil {
		logger.Error("writing json response", zap.Error(writeErr), zap.Int("status", status))
	}
}

// WriteError responds with the JSON error body for err.
//
// A ClientError anywhere in err's chain supplies the status, code, and message.
// Anything else is a 500 carrying only the generic internal message, logged
// here with the request's identity because this is the last point that knows
// both the error and the request. A client error is logged at debug level with
// its cause, so that a 400 that puzzles someone can still be explained.
func WriteError(w http.ResponseWriter, r *http.Request, logger *zap.Logger, err error) {
	logger = logger.With(
		zap.String("method", r.Method),
		zap.String("path", LoggedPath(r)),
		zap.String("request_id", RequestIDFromContext(r.Context())),
	)

	clientErrs := appendClientErrors(nil, err)
	if len(clientErrs) == 0 {
		logger.Error("handling request", zap.Error(err))
		writeJSONError(w, logger, http.StatusInternalServerError, errorCodeInternal, "")

		return
	}

	status := documentStatus(clientErrs)

	objects := make([]errorObject, 0, len(clientErrs))
	codes := make([]string, 0, len(clientErrs))

	for _, clientErr := range clientErrs {
		objects = append(objects, clientErr.errorObject())
		codes = append(codes, clientErr.Code)
	}

	logger.Debug("request rejected", zap.Int("status", status), zap.Strings("codes", codes), zap.Error(err))
	writeErrorDocument(w, logger, status, objects)
}

// appendClientErrors appends every ClientError in err's tree to found, in the
// order the tree holds them.
//
// errors.AsType would find only the first, which is the wrong answer for a
// tree built by errors.Join: a handler that validates several fields joins one
// ClientError per failure, and reporting one of them per round trip is exactly
// what the plural error document exists to avoid. Descent stops at a
// ClientError rather than continuing into its cause, because a cause is the
// underlying failure and not a second thing to tell the client about.
func appendClientErrors(found []*ClientError, err error) []*ClientError {
	if err == nil {
		return found
	}

	//nolint:errorlint // Deliberate: this walks the tree one node at a time,
	// which is the thing errors.As does internally and does not expose. A
	// tree-wide match here would collapse the joined siblings this exists to
	// find.
	if clientErr, ok := err.(*ClientError); ok {
		return append(found, clientErr)
	}

	//nolint:errorlint // Deliberate, for the same reason: the switch is on the
	// unwrap shape, not on a concrete error type, and errors.As offers no way
	// to ask which shape a node has.
	switch unwrapped := err.(type) {
	case interface{ Unwrap() error }:
		return appendClientErrors(found, unwrapped.Unwrap())
	case interface{ Unwrap() []error }:
		for _, joined := range unwrapped.Unwrap() {
			found = appendClientErrors(found, joined)
		}

		return found
	}

	return found
}

// DecodeJSON reads exactly one JSON value from r's body into dst, which must be
// a non-nil pointer.
//
// The body must be declared as application/json, may not contain a field dst
// does not have, and may not be followed by a second value: each of those is a
// request the client got wrong, and each is reported as a ClientError naming
// the problem, so that a caller can hand the error straight to WriteError. A
// body cut off by the request body limit is reported as the same 413 the limit
// middleware itself produces.
//
// The body is read through whatever reader r carries, so the limit applied by
// withRequestBodyLimit still holds.
func DecodeJSON(r *http.Request, dst any) error {
	if err := requireJSONContentType(r); err != nil {
		return err
	}

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		return clientErrorForDecode(err)
	}

	// A second Decode distinguishes "one value, then end of body" from "one
	// value, then more". Anything but EOF here means the client sent more than
	// the endpoint would have read, which is a request that should not be
	// silently half-processed.
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return &ClientError{
			Status:  http.StatusBadRequest,
			Code:    errorCodeInvalidBody,
			Message: "request body must contain a single JSON value",
			Err:     err,
		}
	}

	return nil
}

// requireJSONContentType reports a 415 ClientError unless r declares an
// application/json body. Parameters such as charset are permitted; a missing
// header is not, because a body of unknown type is one the endpoint cannot
// safely interpret.
func requireJSONContentType(r *http.Request) error {
	declared := r.Header.Get("Content-Type")

	mediaType, _, err := mime.ParseMediaType(declared)
	if err != nil || mediaType != jsonMediaType {
		return &ClientError{
			Status:  http.StatusUnsupportedMediaType,
			Code:    errorCodeUnsupportedMediaType,
			Message: "request body must be " + jsonMediaType,
			Err:     fmt.Errorf("content type %q", declared),
		}
	}

	return nil
}

// clientErrorForDecode maps a json.Decoder failure to the ClientError the client
// should see. The message names what is wrong without echoing the body, so a
// client that sent something it should not have does not get it reflected back.
func clientErrorForDecode(err error) error {
	// The body limit surfaces here, not in the limit middleware: MaxBytesReader
	// fails the read, and the decoder reports that failure as its own.
	if maxErr, ok := errors.AsType[*http.MaxBytesError](err); ok {
		return &ClientError{
			Status:  http.StatusRequestEntityTooLarge,
			Code:    errorCodePayloadTooLarge,
			Message: "request body too large",
			Err:     maxErr,
		}
	}

	return &ClientError{
		Status:  http.StatusBadRequest,
		Code:    errorCodeInvalidBody,
		Message: decodeMessage(err),
		Pointer: decodePointer(err),
		Err:     err,
	}
}

// decodePointer returns a JSON Pointer to the member a decode failure is
// about, or the empty string when the failure is about the body as a whole.
//
// Only top-level members are located. encoding/json reports a nested field as
// a dotted path in UnmarshalTypeError.Field, and translating that back into a
// pointer would have to guess where a dot in a member name ends and a
// separator begins. A wrong pointer is worse than none, because a frontend
// attaches the message to the wrong field and the user is told the wrong
// thing. A top-level name is unambiguous whatever it contains, so it is
// escaped rather than dropped.
func decodePointer(err error) string {
	if typeErr, ok := errors.AsType[*json.UnmarshalTypeError](err); ok {
		if typeErr.Field == "" || strings.Contains(typeErr.Field, ".") {
			return ""
		}

		return "/" + escapePointerToken(typeErr.Field)
	}

	name, found := strings.CutPrefix(err.Error(), "json: unknown field ")
	if !found {
		return ""
	}

	unquoted, unquoteErr := strconv.Unquote(name)
	if unquoteErr != nil || unquoted == "" {
		return ""
	}

	return "/" + escapePointerToken(unquoted)
}

// escapePointerToken escapes a member name for use as one JSON Pointer
// reference token, per RFC 6901 section 3: "~" becomes "~0" and "/" becomes
// "~1". The order matters: escaping "/" first would leave a "~1" whose tilde
// the second step escapes again, so "a/b" would come out as "a~01b".
func escapePointerToken(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(name, "~", "~0"), "/", "~1")
}

// decodeMessage describes a json.Decoder failure in terms a client can act on.
func decodeMessage(err error) string {
	if syntaxErr, ok := errors.AsType[*json.SyntaxError](err); ok {
		return fmt.Sprintf("malformed JSON at offset %d", syntaxErr.Offset)
	}

	if typeErr, ok := errors.AsType[*json.UnmarshalTypeError](err); ok {
		if typeErr.Field == "" {
			return "request body must be a JSON " + jsonKind(typeErr.Type)
		}

		return fmt.Sprintf("field %q must be a JSON %s", typeErr.Field, jsonKind(typeErr.Type))
	}

	// encoding/json has no typed error for an unknown field; the prefix is
	// the documented message, and the field name is what a client needs.
	if name, found := strings.CutPrefix(err.Error(), "json: unknown field "); found {
		return "unknown field " + name
	}

	if errors.Is(err, io.EOF) {
		return "request body is empty"
	}

	if errors.Is(err, io.ErrUnexpectedEOF) {
		return "malformed JSON: unexpected end of input"
	}

	return "invalid request body"
}

// jsonKind names the JSON type that values of t are decoded from.
//
// The Go type name is what encoding/json reports and is the wrong thing to
// send: "server.payload" tells a client nothing it can act on and discloses a
// package and type name it has no business knowing.
func jsonKind(t reflect.Type) string {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	if t == nil {
		return "value"
	}

	switch t.Kind() {
	case reflect.Struct, reflect.Map:
		return "object"
	case reflect.Slice, reflect.Array:
		return "array"
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return "number"
	default:
		return "value"
	}
}
