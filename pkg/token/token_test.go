package token

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/gl-johnson/mock-jwt-server/pkg/jwk"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfigDefault(t *testing.T) {
	config := NewConfig()

	assert.Equal(t, "mock-jwt-server", config.Issuer)
	assert.Equal(t, "test-subject", config.Subject)
	assert.Equal(t, "test-audience", config.Audience)
	assert.Equal(t, "test-name", config.Name)
	assert.Equal(t, "test-email", config.Email)
	assert.Empty(t, config.ExtraClaims)
}

func TestNewConfigEnv(t *testing.T) {
	os.Setenv("ISSUER", "custom-issuer")
	os.Setenv("SUBJECT", "custom-subject")
	os.Setenv("AUDIENCE", "custom-audience")
	os.Setenv("NAME", "custom-name")
	os.Setenv("EMAIL", "custom-email")
	os.Setenv("EXTRA_CLAIMS", "custom1=foo;custom2=bar")

	config := NewConfig()

	assert.Equal(t, "custom-issuer", config.Issuer)
	assert.Equal(t, "custom-subject", config.Subject)
	assert.Equal(t, "custom-audience", config.Audience)
	assert.Equal(t, "custom-name", config.Name)
	assert.Equal(t, "custom-email", config.Email)
	assert.Equal(t, "foo", config.ExtraClaims["custom1"])
	assert.Equal(t, "bar", config.ExtraClaims["custom2"])

	os.Unsetenv("ISSUER")
	os.Unsetenv("SUBJECT")
	os.Unsetenv("AUDIENCE")
	os.Unsetenv("NAME")
	os.Unsetenv("EMAIL")
	os.Unsetenv("EXTRA_CLAIMS")
}

func TestIssueToken(t *testing.T) {
	config := NewConfig()

	tokenStr, err := IssueToken("default", "RS256", config)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenStr)

	AssertValidToken(t, tokenStr)
}

func TestSignToken(t *testing.T) {
	// Generate unsigned token
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
	}
	payload := map[string]interface{}{
		"sub":   "test-subject",
		"name":  "test-name",
		"email": "test-email@example.com",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
	}

	headerBytes, _ := json.Marshal(header)
	payloadBytes, _ := json.Marshal(payload)

	unsignedToken := fmt.Sprintf("%s.%s.",
		base64.RawURLEncoding.EncodeToString(headerBytes),
		base64.RawURLEncoding.EncodeToString(payloadBytes),
	)
	signedToken, err := SignToken("default", "RS256", unsignedToken)

	require.NoError(t, err)
	assert.NotEmpty(t, signedToken)

	AssertValidToken(t, signedToken)
}

func TestGetExtraClaims(t *testing.T) {
	testCases := []struct {
		name   string
		env    string
		expect map[string]string
	}{
		{
			name:   "empty",
			env:    "",
			expect: map[string]string{},
		},
		{
			name: "single",
			env:  "claim1=value1",
			expect: map[string]string{
				"claim1": "value1",
			},
		},
		{
			name: "multiple with special characters",
			env:  "claim1=value1;claim2={value2};claim3=value-3",
			expect: map[string]string{
				"claim1": "value1",
				"claim2": "{value2}",
				"claim3": "value-3",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			os.Setenv("EXTRA_CLAIMS", tc.env)
			defer os.Unsetenv("EXTRA_CLAIMS")

			claims := getExtraClaims()
			assert.Equal(t, tc.expect, claims)
		})
	}
}

func AssertValidToken(t *testing.T, tokenStr string) {
	keyfunc := func(t *jwt.Token) (interface{}, error) {
		key, _ := jwk.GetJWKS("default", "RS256")
		privateKey, _ := key.Keys[0].Key.(*rsa.PrivateKey)
		return &privateKey.PublicKey, nil
	}

	parsedToken, err := jwt.Parse(tokenStr, keyfunc)
	require.NoError(t, err)
	assert.True(t, parsedToken.Valid)
}
