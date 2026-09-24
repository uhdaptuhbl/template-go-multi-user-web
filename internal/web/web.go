package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// distDir is the directory the frontend build writes into, relative to this
// package. It must stay in sync with the go:embed pattern below.
const distDir = "dist"

// assets holds the built frontend. The all: prefix keeps files whose names
// begin with a dot or underscore, which embed would otherwise skip and some
// build tools emit.
//
//go:embed all:dist
var assets embed.FS

// contentSecurityPolicy is served with every frontend response. It permits only
// same-origin resources and forbids framing, which is the tightest policy a
// bundled single-page application can run under. Revisit it when
// docs/adr/0002-frontend-stack.md is accepted and the build's actual needs are
// known.
const contentSecurityPolicy = "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'"

// Handler returns a handler serving the embedded frontend. Paths with no
// corresponding file produce a 404; it does not fall back to index.html,
// because whether it should depends on the frontend stack.
func Handler() (http.Handler, error) {
	tree, err := fs.Sub(assets, distDir)
	if err != nil {
		return nil, fmt.Errorf("opening embedded frontend assets under %s: %w", distDir, err)
	}

	tags, err := etags(tree)
	if err != nil {
		return nil, err
	}

	return withAssetHeaders(tags, http.FileServerFS(tree)), nil
}

// etags computes one strong entity tag per embedded file, once, at start-up.
//
// The embedded filesystem reports a zero modification time, so net/http can send
// neither Last-Modified nor a validator of its own, and every asset is refetched
// in full on every load. The content cannot change while the process runs, so
// hashing it once is exact rather than an approximation.
func etags(tree fs.FS) (map[string]string, error) {
	tags := make(map[string]string)

	err := fs.WalkDir(tree, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() {
			return nil
		}

		data, readErr := fs.ReadFile(tree, name)
		if readErr != nil {
			return fmt.Errorf("reading embedded asset %s: %w", name, readErr)
		}

		sum := sha256.Sum256(data)

		// Half the digest: 128 bits of content addressing is far past what a
		// cache validator needs, and a shorter tag costs less on every response.
		tags["/"+name] = `"` + hex.EncodeToString(sum[:16]) + `"`

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("computing embedded asset entity tags: %w", err)
	}

	return tags, nil
}

// withAssetHeaders sets the validator and the security headers before delegating
// to the file server.
//
// The Etag is set before next runs on purpose: http.ServeContent evaluates
// If-None-Match against whatever is already in the header map, so setting it
// here is what turns a repeat request into a 304 without the file server needing
// to know how the tag was computed.
func withAssetHeaders(tags map[string]string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Content-Security-Policy", contentSecurityPolicy)

		// Revalidation rather than a long max-age: the frontend build does not
		// produce content-hashed filenames yet, so an immutable cache entry
		// would pin a stale asset behind a name that never changes.
		header.Set("Cache-Control", "no-cache")

		if tag, ok := tags[assetKey(r.URL.Path)]; ok {
			header.Set("ETag", tag)
		}

		next.ServeHTTP(w, r)
	})
}

// assetKey maps a request path to the key its entity tag is stored under,
// resolving a directory request to the index file the file server would serve
// for it.
func assetKey(urlPath string) string {
	cleaned := path.Clean("/" + urlPath)

	if strings.HasSuffix(urlPath, "/") || cleaned == "/" {
		return path.Join(cleaned, "index.html")
	}

	return cleaned
}
