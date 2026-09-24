package server

import "net/http"

// withSecurityHeaders sets, on every response from the application listener,
// the headers that stop a browser from treating a response as something other
// than what it is.
//
// These cover the API responses and error bodies the frontend handler does not
// serve. They are set before next runs, so a handler with a more specific need,
// such as the frontend's fuller Content-Security-Policy, overrides them by
// setting the same header again rather than fighting a value written after it.
//
// HSTS is absent on purpose: it is the reverse proxy's job under
// docs/adr/0007-deployment-topology.md, and a process that does not terminate
// TLS cannot know whether the connection was secure.
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()

		// A JSON body a browser is told is JSON must not be sniffed into HTML.
		header.Set("X-Content-Type-Options", "nosniff")

		// Both forms, because older browsers honour only the first and the
		// CSP directive is the one the standard now defines.
		header.Set("X-Frame-Options", "DENY")
		header.Set("Content-Security-Policy", "frame-ancestors 'none'")

		next.ServeHTTP(w, r)
	})
}
