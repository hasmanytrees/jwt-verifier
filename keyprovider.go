package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-jose/go-jose/v4"
)

type KeyProvider struct {
	jwksuri    *url.URL
	keySet     *jose.JSONWebKeySet
	publicKeys map[string]*rsa.PublicKey
}

func NewKeyProvider(jwksuri *url.URL) (*KeyProvider, error) {
	kp := &KeyProvider{
		jwksuri: jwksuri,
		keySet:  &jose.JSONWebKeySet{},
	}

	err := kp.Refresh()
	if err != nil {
		return nil, err
	}

	return kp, nil
}

func (kp *KeyProvider) Refresh() error {
	// Create the HTTP request
	req, err := http.NewRequest(http.MethodGet, kp.jwksuri.String(), nil)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	// Use the default HTTP client to make the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	// Check the HTTP status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad HTTP status: %d", resp.StatusCode)
	}

	// Populate the struct
	err = json.NewDecoder(resp.Body).Decode(&kp.keySet)
	if err != nil {
		return fmt.Errorf("could not decode JSON: %w", err)
	}

	// Populate the public key map
	kp.publicKeys = map[string]*rsa.PublicKey{}
	for _, k := range kp.keySet.Keys {
		kp.publicKeys[k.KeyID] = k.Key.(*rsa.PublicKey)
	}

	return nil
}

func (kp *KeyProvider) Key(kid string) *rsa.PublicKey {
	return kp.publicKeys[kid]
}
