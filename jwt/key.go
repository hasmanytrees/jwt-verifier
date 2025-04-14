package jwt

type Key struct {
	Type      string `json:"kty"`
	Exponent  string `json:"e,omitempty"`
	KeyID     string `json:"kid,omitempty"`
	Algorithm string `json:"alg,omitempty"`
	Modulus   string `json:"n,omitempty"`
}
