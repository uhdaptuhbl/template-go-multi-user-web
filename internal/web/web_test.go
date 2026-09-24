package web

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestEmbeddedAssetsContainIndex cites no criterion: it checks a build
// input, not behaviour. The reasoning is at the assertion.
func TestEmbeddedAssetsContainIndex(t *testing.T) {
	t.Parallel()

	// Guards the go:embed pattern: an empty dist/ fails the build, but a dist/
	// missing index.html would compile and then serve nothing at the root.
	if _, err := fs.Stat(assets, distDir+"/index.html"); err != nil {
		t.Fatalf("index.html missing from embedded assets: %v", err)
	}
}

// TestHandlerServesEmbeddedAssets covers AC-001.7 and AC-001.8.
func TestHandlerServesEmbeddedAssets(t *testing.T) {
	t.Parallel()

	handler, err := Handler()
	if err != nil {
		t.Fatalf("Handler() returned error: %v", err)
	}

	tests := []struct {
		name       string
		target     string
		wantStatus int
	}{
		{name: "root serves index", target: "/", wantStatus: http.StatusOK},
		// net/http canonicalises an explicit index.html back to the directory.
		{name: "index by name redirects to root", target: "/index.html", wantStatus: http.StatusMovedPermanently},
		{name: "missing asset is not found", target: "/does-not-exist.js", wantStatus: http.StatusNotFound},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.target, http.NoBody))

			if recorder.Code != test.wantStatus {
				t.Errorf("GET %s returned status %d, want %d", test.target, recorder.Code, test.wantStatus)
			}
		})
	}
}

// TestHandlerSetsSecurityHeaders covers AC-002.20.
func TestHandlerSetsSecurityHeaders(t *testing.T) {
	t.Parallel()

	handler, err := Handler()
	if err != nil {
		t.Fatalf("Handler() returned error: %v", err)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if got := recorder.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want %q", got, "nosniff")
	}

	if got := recorder.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want %q", got, "no-referrer")
	}

	if got := recorder.Header().Get("Content-Security-Policy"); got == "" {
		t.Error("Content-Security-Policy header is empty, want a policy")
	}
}

// TestHandlerSetsCacheHeaders covers AC-002.19.
func TestHandlerSetsCacheHeaders(t *testing.T) {
	t.Parallel()

	handler, err := Handler()
	if err != nil {
		t.Fatalf("Handler() returned error: %v", err)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if got := recorder.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-cache")
	}

	if got := recorder.Header().Get("ETag"); got == "" {
		t.Error("ETag header is empty, want a validator")
	}
}

// TestHandlerRevalidatesWithETag covers AC-002.18.
func TestHandlerRevalidatesWithETag(t *testing.T) {
	t.Parallel()

	handler, err := Handler()
	if err != nil {
		t.Fatalf("Handler() returned error: %v", err)
	}

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("ETag header is empty, want a validator")
	}

	request := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	request.Header.Set("If-None-Match", etag)

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, request)

	if second.Code != http.StatusNotModified {
		t.Errorf("GET / with If-None-Match returned status %d, want %d", second.Code, http.StatusNotModified)
	}

	if body := second.Body.String(); body != "" {
		t.Errorf("GET / with If-None-Match returned body %q, want empty", body)
	}
}
