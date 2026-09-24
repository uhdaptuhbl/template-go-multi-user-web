package passkey

// Config identifies this service to an authenticator.
type Config struct {
	// Enabled registers the passkey routes.
	Enabled bool `json:"enabled"`
	// RPID is the WebAuthn relying party identifier: the registrable domain
	// the credential is scoped to. It defaults to the host of the public
	// origin.
	RPID string `json:"rp_id"`
	// RPDisplayName is shown by the authenticator when a user registers or
	// uses a credential.
	RPDisplayName string `json:"rp_display_name"`
	// RPOrigins are the origins an assertion may come from.
	RPOrigins []string `json:"rp_origins"`
}
