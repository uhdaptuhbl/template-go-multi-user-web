// Package buildinfo carries the identity of the binary a process is running:
// the version, the commit it was built from, and when it was built.
//
// The values are stamped at link time, so they are supplied by whoever builds
// rather than read from the environment, which is what makes them trustworthy
// as an answer to "which build is this".
package buildinfo
