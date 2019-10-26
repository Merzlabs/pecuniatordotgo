package oauth

// State is used to store information about the OAuth flow temporily
type State struct {
	CodeVerifier string
	Consent      *ConsentResponse
	Tokens       *Tokens
}
