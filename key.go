package main

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

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
