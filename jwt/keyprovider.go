package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
)

type KeyProvider struct {
	jwksuri    *url.URL
	keySet     *KeySet
	publicKeys map[string]*rsa.PublicKey
}

func NewKeyProvider(jwksuri *url.URL) (*KeyProvider, error) {
	kp := &KeyProvider{
		jwksuri: jwksuri,
		keySet:  &KeySet{},
	}

	err := kp.Refresh()
	if err != nil {
		return nil, err
	}

	return kp, nil
}

func (kp *KeyProvider) Refresh() error {
	// Use the default HTTP client to make the request
	resp, err := http.DefaultClient.Get(kp.jwksuri.String())
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
		pub, err := publicKey(k)
		if err != nil {
			return err
		}

		kp.publicKeys[k.KeyID] = pub
	}

	return nil
}

func (kp *KeyProvider) Key(kid string) *rsa.PublicKey {
	return kp.publicKeys[kid]
}

func publicKey(k *Key) (*rsa.PublicKey, error) {
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
