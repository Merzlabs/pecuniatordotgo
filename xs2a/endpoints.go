package xs2a

// Endpoints are URL for the API given by the wellknown endpoint
type Endpoints struct {
	Authorization string `json:"authorization_endpoint,omitempty"`
	Token         string `json:"token_endpoint,omitempty"`
	JWKSURI       string `json:"jwks_uri,omitempty"`
}
