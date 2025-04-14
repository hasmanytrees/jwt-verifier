package jwt

type Header struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid,omitempty"`
}

type ReservedClaims struct {
	Issuer     string `json:"iss,omitempty"`
	Subscriber string `json:"sub,omitempty"`
	Audience   string `json:"aud,omitempty"`
	ExpiresAt  int64  `json:"exp,omitempty"`
	NotBefore  int64  `json:"nbf,omitempty"`
	IssuedAt   int64  `json:"iat,omitempty"`
	ID         string `json:"jit,omitempty"`
}

type Token struct {
	Header         Header
	ReservedClaims ReservedClaims
	Payload        []byte
	Signature      []byte
}
