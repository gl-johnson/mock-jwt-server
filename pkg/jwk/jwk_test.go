package jwk

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetJWKS(t *testing.T) {
	// Test GetJWKS for an unsupported algorithm
	jwks, err := GetJWKS("invalid", "INVALID_ALG")
	assert.Nil(t, jwks)
	assert.Equal(t, fmt.Sprintf("unsupported algorithm: '%s', must one of: %v", "INVALID_ALG", supportedAlgorithms), err.Error())

	// Test GetJWKS for a supported algorithm
	jwks, err = GetJWKS("valid", "RS256")
	require.NoError(t, err)
	assert.NotNil(t, jwks)
	assert.Len(t, jwks.Keys, 1)
	assert.Equal(t, jwks.Keys[0].KeyID, "valid")

	// Test GetAllJWKS
	_, err = GetJWKS("another", "RS256")
	require.NoError(t, err)

	jwks = GetAllJWKS()
	assert.NotNil(t, jwks)
	assert.Len(t, jwks.Keys, 2)
	assert.Equal(t, jwks.Keys[0].KeyID, "valid")
	assert.Equal(t, jwks.Keys[1].KeyID, "another")
}

func TestGetOrCreateKey(t *testing.T) {
	keyName := "test-key"
	alg := "RS256"

	// Create a key pair
	key := getOrCreateKey(keyName, alg)
	assert.NotNil(t, key)
	assert.Equal(t, key.KeyID, keyName)
	assert.Equal(t, key.Algorithm, alg)

	// Ensure it doesn't overwrite the existing key pair
	existingKey := getOrCreateKey(keyName, alg)
	assert.Equal(t, existingKey.KeyID, key.KeyID)
	assert.Equal(t, existingKey.Key, key.Key)
}

func TestGenerateKey(t *testing.T) {
	// Test supported algorithms
	algorithms := []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512"}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			key, err := generateKey(alg)
			require.NoError(t, err)
			assert.NotNil(t, key)
		})
	}

	// Test an unsupported algorithm
	alg := "INVALID_ALG"
	key, err := generateKey(alg)
	assert.Error(t, err)
	assert.Nil(t, key)
	assert.Equal(t, fmt.Sprintf("unsupported algorithm: %s", alg), err.Error())
}
