// Package otp issues and verifies single-use codes delivered by email, the
// fallback login method for an account with neither a provider identity nor a
// passkey. It responds identically whether or not an address is known, so
// that neither a code request nor a failed verification can be used to probe
// which addresses have accounts.
package otp
