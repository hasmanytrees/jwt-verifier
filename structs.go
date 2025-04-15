package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
)

type Header struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid,omitempty"`
}

type Key struct {
	Type      string `json:"kty"`
	Exponent  string `json:"e,omitempty"`
	KeyID     string `json:"kid,omitempty"`
	Algorithm string `json:"alg,omitempty"`
	Modulus   string `json:"n,omitempty"`
}

func (k *Key) PublicKey() (*rsa.PublicKey, error) {
	// Decode the n and e values from base64.
	modulusBytes, err := base64.RawURLEncoding.DecodeString(k.Modulus)
	if err != nil {
		return nil, err
	}

	exponentBytes, err := base64.RawURLEncoding.DecodeString(k.Exponent)
	if err != nil {
		return nil, err
	}

	//Construct a *big.Int from the n bytes.
	n := new(big.Int).SetBytes(modulusBytes)

	// Construct an int from the e bytes.
	e := int(new(big.Int).SetBytes(exponentBytes).Int64())

	// Construct a *rsa.PublicKey from the n and e values.
	pubKey := &rsa.PublicKey{
		N: n,
		E: e,
	}

	return pubKey, nil
}

type KeySet struct {
	Keys []*Key `json:"keys"`
}

type OpenIDConfiguration struct {
	Issuer  string   `json:"issuer"`
	JWKSURI *url.URL `json:"jwks_uri"`
}

func (c *OpenIDConfiguration) UnmarshalJSON(data []byte) error {
	// Define a temporary struct to hold the string value of the URL.
	type Alias OpenIDConfiguration
	aux := &struct {
		URL string `json:"jwks_uri"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}

	// Unmarshal the JSON data into the temporary struct.
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Parse the string URL into a url.URL struct.
	parsedURL, err := url.Parse(aux.URL)
	if err != nil {
		return err
	}

	// Assign the parsed URL to the MyStruct's URL field.
	c.JWKSURI = parsedURL
	return nil
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
