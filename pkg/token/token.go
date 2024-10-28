package token

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"os"
	"time"

	"github.com/gl-johnson/mock-jwt-server/pkg/jwk"

	"github.com/golang-jwt/jwt/v4"
)

type Config struct {
	Issuer   string
	Subject  string
	Audience string
	Name     string
	Email    string
}

func NewConfig() Config {
	return Config{
		Issuer:   getEnvOrDefault("ISSUER", "mock-jwt-server"),
		Subject:  getEnvOrDefault("SUBJECT", "test-subject"),
		Audience: getEnvOrDefault("AUDIENCE", "test-audience"),
		Name:     getEnvOrDefault("NAME", "test-name"),
		Email:    getEnvOrDefault("EMAIL", "test-email"),
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func IssueToken(keyName, alg string, config Config) (string, error) {
	key, err := jwk.GetJWKS(keyName, alg)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod(alg), jwt.MapClaims{
		"sub":   config.Subject,
		"name":  config.Name,
		"email": config.Email,
		"iss":   config.Issuer,
		"aud":   config.Audience,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
	})

	token.Header["kid"] = keyName

	var signedToken string

	switch k := key.Keys[0].Key.(type) {
	case *rsa.PrivateKey:
		signedToken, err = token.SignedString(k)
	case *ecdsa.PrivateKey:
		signedToken, err = token.SignedString(k)
	case []byte:
		signedToken, err = token.SignedString(k)
	default:
		return "", fmt.Errorf("unsupported key type")
	}

	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	return signedToken, nil
}

func SignToken(keyName, alg, remoteToken string) (string, error) {
	// Parse the unsigned token to extract claims
	// parser := new(jwt.Parser)
	// parser.SkipClaimsValidation = true // Skip validation since we're dealing with an unsigned token
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	token, _, err := parser.ParseUnverified(remoteToken, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse token: %v", err)
	}

	// Get the claims from the original token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid claims in token")
	}

	// Create a new token with the same claims
	newToken := jwt.NewWithClaims(jwt.GetSigningMethod(alg), claims)

	// Set the header parameters
	newToken.Header["kid"] = keyName

	// Get the signing key
	key, err := jwk.GetJWKS(keyName, alg)
	if err != nil {
		return "", fmt.Errorf("failed to get JWKS: %v", err)
	}

	if len(key.Keys) == 0 {
		return "", fmt.Errorf("no keys found in JWKS")
	}

	// Sign the token based on key type
	var signedToken string
	switch k := key.Keys[0].Key.(type) {
	case *rsa.PrivateKey:
		signedToken, err = newToken.SignedString(k)
	case *ecdsa.PrivateKey:
		signedToken, err = newToken.SignedString(k)
	case []byte:
		signedToken, err = newToken.SignedString(k)
	default:
		return "", fmt.Errorf("unsupported key type")
	}

	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	return signedToken, nil
}
