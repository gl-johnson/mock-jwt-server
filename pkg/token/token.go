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
	token, _, err := new(jwt.Parser).ParseUnverified(remoteToken, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse token: %v", err)
	}

	key, err := jwk.GetJWKS(keyName, alg)
	if err != nil {
		return "", err
	}

	token.Header["alg"] = alg
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
