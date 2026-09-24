// Package server runs the application's HTTP listener.
//
// It owns the http.Server configuration, request logging, the operational
// endpoints that do not belong to any feature, and shutdown sequencing: once
// the supplied context is cancelled, in-flight requests are given a bounded
// window to finish before the listener is closed.
package server
