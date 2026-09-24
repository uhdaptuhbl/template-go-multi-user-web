// Package secret provides a string type that redacts itself in every
// textual, structured logging, and JSON representation. It is a leaf
// package with no dependencies inside this module, so any package may use
// it without creating an import cycle.
package secret
