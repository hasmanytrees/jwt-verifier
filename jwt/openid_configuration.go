package jwt

import (
	"encoding/json"
	"net/url"
)

type OpenIDConfiguration struct {
	Issuer  string   `json:"issuer"`
	JWKSURI *url.URL `json:"jwks_uri"`
	TokenEndpointURI *url.URL `json:"token_endpoint"`
}

func (c *OpenIDConfiguration) UnmarshalJSON(data []byte) error {
	// Define a temporary struct to hold the string value of the URL.
	type Alias OpenIDConfiguration
	aux := &struct {
		jwksURIString string `json:"jwks_uri"`
		tokenEndpointString string `json:"token_endpoint"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}

	// Unmarshal the JSON data into the temporary struct.
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Parse the string URL into a url.URL struct.
	parsedJWKSURL, err := url.Parse(aux.jwksURIString)
	if err != nil {
		return err
	}

	// Assign the parsed URL to the MyStruct's URL field.
	c.JWKSURI = parsedJWKSURL

	parsedTokenEndpointURL, err = url.Parse(aux.tokenEndpointString)
	if err != nil {
		return err
	}
	
	c.TokenEndpointURI = parsedTokenEndpointURL
	
	return nil
}
