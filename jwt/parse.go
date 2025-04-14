package jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func Parse(tokenString string, keyFunc func(*Token) (*rsa.PublicKey, error)) (*Token, error) {
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

	// Verify the token is not expired
	if time.Now().Unix() > t.ReservedClaims.ExpiresAt {
		return nil, fmt.Errorf("token is expired")
	}

	// Get the public key for the token using the supplied keyFunc
	pub, err := keyFunc(t)
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
