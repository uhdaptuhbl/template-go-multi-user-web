// Package web serves the built user interface from assets compiled into the
// binary.
//
// The go:embed directive cannot reference paths outside its own package
// directory, so the frontend build must write its output into dist/ here
// rather than anywhere under ui/. That constraint holds for any frontend stack
// and is why this package exists before one has been chosen.
//
// What this package deliberately does not decide: whether unmatched paths fall
// back to index.html for client-side routing. That depends on the frontend
// stack and is settled by docs/adr/0002-frontend-stack.md.
package web
