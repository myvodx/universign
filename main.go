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
//
// @arg kid The key ID to look for in the JWKS.
// @return jwk.Key The JWK corresponding to the provided kid, or an error if not found or if fetching fails.
func getPublicKey(kid string) (jwk.Key, error) {
	url := "https://api.universign.com/v1/webhooks/jwks.json"

	set, err := jwk.Fetch(context.Background(), url)
	if err != nil {
		log.Printf("failed to parse JWK: %s", err)
		return nil, err
	}

	// Iterate over the keys in the JWKS
	for it := set.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)

		// Check if the key has the specified kid
		if key.KeyID() != kid {
			continue
		}

		return key, nil
	}

	return nil, errors.New("key not found")
}

// VerifyWebhookSignature verifies the signature of a webhook payload in JWS format
// @see https://apps.universign.com/docs/developer_tools/webhooks/
func VerifyWebhookSignature(jwsSignature string, payload string) error {
	jwsParts := strings.Split(jwsSignature, ".")
	if len(jwsParts) != 3 {
		log.Error().Msgf("invalid JWS signature: %v", jwsSignature)
		return errors.New("invalid JWS signature")
	}

	// 0. Base64-Decode the JWS
	signHeader, err := decodeJWSHeader(jwsParts[0])
	if err != nil {
		log.Error().Err(err).Msgf("VerifyWebhookSignature decodeJWSHeader: %v", err)
		return err
	}

	// 1. Retrieve the key ID used by Universign to sign the webhook
	// 2. Retrieve the public key matching this ID
	publicKey, err := getPublicKey(signHeader.Kid)
	if err != nil {
		log.Error().Err(err).Msgf("VerifyWebhookSignature getPublicKey: %v", err)
		return err
	}
	// 3. Reconstruct the signed data: concatenating the base64URL-encoded header and payload
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signedData := fmt.Sprintf("%s.%s", jwsParts[0], encodedPayload)
	signedData += "." + jwsParts[2]
	log.Debug().Msgf("encodedPayload: %v", encodedPayload)

	// 4. Verify the obtained signature value with the public key
	verified, err := jws.Verify([]byte(signedData), jwa.SignatureAlgorithm(signHeader.Alg), publicKey)
	if err != nil {
		log.Printf("failed to verify message: %s", err)
		return err
	}

	log.Debug().Msgf("verified: %v", verified)
	if (string(verified)) == signedData {
		return nil
	}

	return errors.New("invalid signature")
}
