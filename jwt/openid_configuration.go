package jwt

import (
	"encoding/json"
	"net/url"
)

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
