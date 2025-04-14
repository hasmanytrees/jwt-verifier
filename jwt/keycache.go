package jwt

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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
	// Create the HTTP request
	req, err := http.NewRequest(http.MethodGet, openIDConfigurationURL.String(), nil)
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
	var config OpenIDConfiguration
	err = json.NewDecoder(resp.Body).Decode(&config)
	if err != nil {
		return fmt.Errorf("could not decode JSON: %w", err)
	}

	if config.Issuer == "" || config.JWKSURI == nil {
		return fmt.Errorf("config is not populated")
	}

	kc.providers[config.Issuer], err = NewKeyProvider(config.JWKSURI)

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

func (kc *KeyCache) KeyFunc(t *Token) (*rsa.PublicKey, error) {
	issuer := t.ReservedClaims.Issuer
	kid := t.Header.KeyID

	pub, err := kc.Key(issuer, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key for issuer: %s with key id: %s: %w", issuer, kid, err)
	}

	return pub, nil
}
