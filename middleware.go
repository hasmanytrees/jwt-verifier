package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Middleware struct {
	mu                      sync.Mutex
	openIDConfigurationURLs []*url.URL
	keys                    map[string]map[string]*rsa.PublicKey
	withRefresh             bool
}

type MiddlewareOption func(*Middleware)

func WithRefresh(m *Middleware) {
	m.withRefresh = true
}

func NewMiddleware(openIDConfigurationURLs []*url.URL, opts ...MiddlewareOption) (*Middleware, error) {
	m := &Middleware{
		openIDConfigurationURLs: openIDConfigurationURLs,
		keys:                    map[string]map[string]*rsa.PublicKey{},
	}

	err := m.refreshKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to load keys from open id configuration urls: %w", err)
	}

	for _, o := range opts {
		o(m)
	}

	return m, nil
}

func (m *Middleware) Parse(tokenString string) (*Token, error) {
	// Split the token string and verify it has 3 parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token string doesn't contain the required three parts")
	}

	// Decode and unmarshal the header
	decodedHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header Header
	err = json.Unmarshal(decodedHeader, &header)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	// Decode and unmarshal the payload/reserved claims
	decodedPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var reservedClaims ReservedClaims
	err = json.Unmarshal(decodedPayload, &reservedClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	// Decode the signature
	decodedSignature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Create the token
	t := &Token{
		Header:         header,
		ReservedClaims: reservedClaims,
		Payload:        decodedPayload,
		Signature:      decodedSignature,
	}

	now := time.Now().Unix()

	// Verify the token is not expired
	if now > t.ReservedClaims.ExpiresAt {
		return nil, fmt.Errorf("token is expired")
	}

	if now < t.ReservedClaims.NotBefore {
		return nil, fmt.Errorf("token can not be used before: %v", t.ReservedClaims.NotBefore)
	}

	// Get the public key
	pub, err := m.getKey(t)

	if err != nil && m.withRefresh {
		if err = m.refreshKeys(); err == nil {
			pub, err = m.getKey(t)
		}
	}

	if err != nil {
		return nil, err
	}

	// Hash the token header/payload and verify the signature of the token
	hashed := sha256.Sum256([]byte(parts[0] + "." + parts[1]))

	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], decodedSignature)
	if err != nil {
		return nil, fmt.Errorf("could not verify token signature: %w", err)
	}

	return t, nil
}

func (m *Middleware) getKey(t *Token) (*rsa.PublicKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get the public key for the token using our map of cached keys
	keyMap, ok := m.keys[t.ReservedClaims.Issuer]
	if !ok {
		return nil, fmt.Errorf("no keys found for issuer: %s", t.ReservedClaims.Issuer)
	}

	pub, ok := keyMap[t.Header.KeyID]
	if !ok {
		return nil, fmt.Errorf("no key found for kid: %s", t.Header.KeyID)

	}

	return pub, nil
}

func (m *Middleware) refreshKeys() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	clear(m.keys)

	for _, configurationURL := range m.openIDConfigurationURLs {
		var config OpenIDConfiguration
		err := loadStructFromURL(&config, configurationURL)
		if err != nil {
			return err
		}

		var keySet KeySet
		err = loadStructFromURL(&keySet, config.JWKSURI)
		if err != nil {
			return err
		}

		keyMap := map[string]*rsa.PublicKey{}

		for _, k := range keySet.Keys {
			pub, err := k.PublicKey()
			if err != nil {
				return err
			}

			keyMap[k.KeyID] = pub
		}

		m.keys[config.Issuer] = keyMap
	}

	return nil
}

func loadStructFromURL(v any, url *url.URL) error {
	// Use the default HTTP client to make the request
	resp, err := http.DefaultClient.Get(url.String())
	if err != nil {
		return fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	// Check the HTTP status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad HTTP status: %d", resp.StatusCode)
	}

	// Populate the struct
	err = json.NewDecoder(resp.Body).Decode(&v)
	if err != nil {
		return fmt.Errorf("could not decode JSON: %w", err)
	}

	return nil
}
