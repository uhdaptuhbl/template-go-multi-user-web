package config

import "github.com/uhdaptuhbl/template-go-multi-user-web/internal/secret"

// SecretString holds a sensitive value loaded from configuration. It is an
// alias for secret.String, which lives in a leaf package so that packages
// whose Config this one composes can use the same type without creating an
// import cycle.
type SecretString = secret.String

// redacted is the placeholder text that a SecretString renders as. It mirrors
// secret.Redacted so that this package's tests can assert against it.
const redacted = secret.Redacted
