---
status: accepted
date: 2026-09-20
---

# 10. JSON response conventions

## Context and Problem Statement

Every JSON response this server generates today is either a value a handler passed to
`WriteJSON` or the fixed error body `writeJSONError` produces:

```json
{"error": {"code": "internal", "message": "internal server error"}}
```

That shape was chosen for the first error path and never revisited. It has two problems that
only appear once the service has more than one endpoint.

The first is that it holds exactly one error. Validation is the ordinary case where a client
gets several failures at once, and a singular envelope forces a choice between reporting the
first one and inventing a second shape for the plural case. The second is that the member
names are this project's own invention. `code` and `message` are reasonable, but so are
`type` and `detail`, and a reader coming from another service has to read this one's source
to find out which it picked.

There is also nothing written down about the success side at all. Nothing says whether a
top-level array is allowed, whether a response is always an object, or how a client
distinguishes a success body from a failure body without consulting the status line. Every
one of those is a decision a descendant of this codebase inherits by accident if it is not
made deliberately here, which is the whole reason to make it now: this repository is about
to become the starting point for other services.

## Decision Drivers

- **A client should be able to branch on the body alone.** Status codes get rewritten by
  proxies and lost by client libraries; the body should say what it is.
- **Several failures must be reportable at once,** because validation is the common case and
  reporting one error per round trip is a bad API.
- **Borrowed vocabulary beats invented vocabulary.** A member name a reader already knows
  costs nothing and saves a trip to the source.
- **No new dependency and no conformance obligation.** A specification adopted in full brings
  a media type, a content negotiation contract, and a compliance test suite, none of which
  this service needs.
- **The key casing question is genuinely open** and belongs with the frontend stack decision,
  not here.

## Considered Options

- Borrow JSON:API's error member names for a plural `errors` array, without adopting the
  specification
- Adopt JSON:API in full, including its media type and resource model
- RFC 9457 `application/problem+json`
- Keep the singular `{"error": {...}}` envelope and add a plural variant later

## Decision Outcome

Chosen: **borrow JSON:API's document structure for the error side only.** An error response
carries a top-level `errors` array whose members use JSON:API's member names, and the
response keeps the `application/json` media type with no claim of conformance to anything.

```json
{
  "errors": [
    {
      "status": "400",
      "code": "invalid_body",
      "title": "Invalid request body",
      "detail": "field \"age\" must be a JSON number",
      "source": {"pointer": "/age"}
    }
  ]
}
```

Members, all optional except `code` and `title`:

| Member | Meaning |
| --- | --- |
| `status` | The HTTP status as a string, as JSON:API specifies. Present so a body separated from its response still carries it. |
| `code` | The stable identifier a client branches on. Unchanged from the codes in use today. |
| `title` | A short human-readable summary of the kind of problem. The same for every occurrence of one `code`. |
| `detail` | What went wrong with this specific request. Varies per occurrence. |
| `source` | Where in the request the problem is. Only `pointer`, a JSON Pointer into the request body, is used. |

The success side is settled at the same time, since leaving it open is what produced this
problem in the first place:

- **A response body is a JSON object at the top level, never a bare array.** A top-level
  array cannot be extended with metadata later without breaking every client, and it is the
  one shape a client cannot add a member to. A collection is a member of an object.
- **The presence of `errors` is the failure discriminator.** A body carrying `errors` is a
  failure; a body without it is a success. A response never carries both.
- **`WriteJSON` and `WriteError` are the only two doors out.** A handler that writes a body
  by any other route bypasses the conventions above, and the encoding failure handling that
  goes with them.

**Key casing is not decided here.** Whether member names outside this error envelope are
`snake_case` or `camelCase` depends on what consumes them, and the frontend stack is still
open in `docs/adr/0002-frontend-stack.md`. That record is where the question closes. The
error envelope's own member names are fixed by this decision, because they are borrowed
rather than chosen, and JSON:API spells them in lowercase single words where the question
does not arise.

### Consequences

- Good: several failures are reportable in one response without a second shape, which is what
  makes field-level validation errors expressible at all.
- Good: `source.pointer` gives a frontend somewhere to attach a message, which the current
  envelope has no room for.
- Good: a reader who knows JSON:API reads this without reference to any project document, and
  one who does not can look the names up in a public specification.
- Bad: every error body changes shape, so `AC-002.1` is amended and the tests asserting the
  old envelope are rewritten. This is cheap now and will not be once the service has clients.
- Bad: borrowing member names without conforming means a client library written against
  JSON:API will not work here. The media type stays `application/json` precisely so that no
  such library is invited to try.
- Neutral: `title` is new work per error code. There is one per error code.

## Pros and Cons of the Options

### Borrow JSON:API's error member names for a plural `errors` array

- Good: the plural container, the member names, and the `source.pointer` convention are all
  already specified, reviewed, and public.
- Good: no dependency, no media type, no conformance suite, no obligation to implement the
  resource model.
- Good: adopting more of the specification later is additive, since nothing here contradicts
  it.
- Bad: "looks like JSON:API but is not JSON:API" can mislead a reader who assumes the rest
  follows. The `application/json` media type is the mitigation, and it is the signal the
  specification itself uses.

### Adopt JSON:API in full

- Good: an unambiguous contract with a conformance suite and existing client libraries.
- Bad: the resource model, with `type` and `id` on every object and relationships between
  them, is a data model this service does not have and may never have.
- Bad: the `application/vnd.api+json` media type brings content negotiation rules that must
  be implemented correctly or not claimed.
- Bad: it decides the frontend's data access shape as a side effect, which is
  `docs/adr/0002-frontend-stack.md`'s decision to make.

### RFC 9457 `application/problem+json`

- Good: an IETF standard, with `type`, `title`, `detail`, `status`, and `instance` covering
  most of what is needed.
- Good: widely implemented, particularly outside the JavaScript ecosystem.
- Bad: it is singular by construction. Multiple errors go in an extension member the standard
  does not define, which puts this project back to inventing the plural shape.
- Bad: the `application/problem+json` media type means error and success responses carry
  different content types, which complicates every client that parses before branching.
- Bad: `type` is a URI that should resolve to documentation. Either that documentation gets
  hosted, or the field is a URI that lies.

### Keep the singular envelope and add a plural variant later

- Good: no change now, and no tests to rewrite.
- Bad: two shapes forever, and every client must handle both. The cost of changing this grows
  with every client and is lowest today, when there are none.
- Bad: it leaves the success-side conventions unwritten, which is half of what this record
  exists to settle.

## More Information

- JSON:API v1.1, Document Structure: https://jsonapi.org/format/#document-structure
- JSON:API v1.1, Error Objects: https://jsonapi.org/format/#error-objects
- RFC 9457, Problem Details for HTTP APIs: https://www.rfc-editor.org/rfc/rfc9457
- `docs/adr/0002-frontend-stack.md`, where key casing is decided
- `specs/002-server-hardening/requirements.md`, `AC-002.1`
- `specs/005-service-scaffolding/requirements.md`, Story 1
