package web

import (
	"encoding/json"
	"os"

	jose "github.com/go-jose/go-jose/v3"
)

// LoadJWK loads a JSON encoded JWK specified by filename or returns an error
func LoadJWK(filename string) (*jose.JSONWebKey, error) {
	var jwk jose.JSONWebKey
	if jsonBytes, err := os.ReadFile(filename); err != nil {
		return nil, err
	} else if err = json.Unmarshal(jsonBytes, &jwk); err != nil {
		return nil, err
	}
	return &jwk, nil
}
