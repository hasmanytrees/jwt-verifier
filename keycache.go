package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v5"
)

type KeyCache struct {
	providers map[string]*KeyProvider
}

func NewKeyCache() *KeyCache {
	kc := &KeyCache{
		providers: map[string]*KeyProvider{},
	}

	return kc
}

func (kc *KeyCache) AddProvider(openIDConfigurationURL *url.URL) error {
	// Use the default HTTP client to make the request
	resp, err := http.DefaultClient.Get(openIDConfigurationURL.String())
	if err != nil {
		return fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	// Check the HTTP status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad HTTP status: %d", resp.StatusCode)
	}

	// Populate the struct
	var config OpenIDConfiguration
	err = json.NewDecoder(resp.Body).Decode(&config)
	if err != nil {
		return fmt.Errorf("could not decode JSON: %w", err)
	}

	// Validate the config has the required fields populated
	if config.Issuer == "" || config.JWKSURI == nil {
		return fmt.Errorf("config is not populated")
	}

	// Creaet the new key provider
	p, err := NewKeyProvider(config.JWKSURI)
	if err != nil {
		return fmt.Errorf("could not create new key provider: %w", err)
	}

	// Register the provider for the issuers in the map
	kc.providers[config.Issuer] = p

	return nil
}

func (kc *KeyCache) Key(issuer string, kid string) (*rsa.PublicKey, error) {
	kp, ok := kc.providers[issuer]
	if !ok {
		return nil, fmt.Errorf("no provider found for issuer: %s", issuer)
	}

	k := kp.Key(kid)

	if k == nil {
		err := kp.Refresh()
		if err != nil {
			return nil, err
		}

		k = kp.Key(kid)
	}

	return k, nil
}

func (kc *KeyCache) KeyFunc(t *jwt.Token) (any, error) {
	issuer, err := t.Claims.GetIssuer()
	if err != nil {
		return nil, err
	}

	kid := t.Header["kid"].(string)
	if len(kid) == 0 {
		return nil, fmt.Errorf("header does not contain a kid")
	}

	pub, err := kc.Key(issuer, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key for issuer: %s with key id: %s: %w", issuer, kid, err)
	}

	return pub, nil
}
