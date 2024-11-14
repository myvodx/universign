package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/rs/zerolog/log"
)

type JWSHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// decodeJWSHeader takes a string header and decodes it to extract the JWS header.
//
// The header is expected to be a base64url encoded string.
// The decoded header is then unmarshalled into a JWSHeader struct.
// The function returns a pointer to the JWSHeader and an error.
func decodeJWSHeader(header string) (*JWSHeader, error) {
	decodedHeader, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil, err
	}
	var jwsHeader JWSHeader
	err = json.Unmarshal(decodedHeader, &jwsHeader)
	if err != nil {
		return nil, err
	}
	return &jwsHeader, nil
}

// getPublicKey retrieves the JSON Web Key (JWK) from a JWKS endpoint based on the given key ID (kid).
//
// It fetches the JWKS from the configured Universign base URL, iterates over the keys, and returns
// the key matching the specified kid. If no matching key is found, it returns an error.
func getPublicKey(kid string) (jwk.Key, error) {
	url := "https://api.universign.com/v1/webhooks/jwks.json"

	set, err := jwk.Fetch(context.Background(), url)
	if err != nil {
		log.Error().Err(err).Msg("failed to fetch JWK set")
		return nil, err
	}

	// Iterate over the keys in the JWKS
	for it := set.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)

		// Check if the key has the specified kid
		if key.KeyID() == kid {
			return key, nil
		}
	}

	return nil, fmt.Errorf("no matching key found for kid: %s", kid)
}

// VerifyWebhookSignature verifies the signature of a webhook payload in JWS format
// @see https://apps.universign.com/docs/developer_tools/webhooks/
func VerifyWebhookSignature(jwsSignature string, payload string) error {
	// Split the JWS signature into its components
	jwsParts := strings.Split(jwsSignature, ".")
	if len(jwsParts) != 3 {
		log.Error().Msg("invalid JWS signature format")
		return errors.New("invalid JWS signature format")
	}

	// Decode the JWS header to retrieve the kid
	signHeader, err := decodeJWSHeader(jwsParts[0])
	if err != nil {
		log.Error().Err(err).Msg("failed to decode JWS header")
		return err
	}

	// Retrieve the public key corresponding to the kid
	publicKey, err := getPublicKey(signHeader.Kid)
	if err != nil {
		log.Error().Err(err).Msgf("failed to retrieve public key for kid: %s", signHeader.Kid)
		return err
	}

	// Verify the signature using the public key
	_, err = jws.Verify([]byte(jwsSignature), jwa.PS256, publicKey)
	if err != nil {
		log.Error().Err(err).Msg("signature verification failed")
		return err
	}

	log.Info().Msg("signature verified successfully")
	return nil
}
