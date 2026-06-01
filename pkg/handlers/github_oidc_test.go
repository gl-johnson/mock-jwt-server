package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/cyberark/mock-jwt-server/pkg/jwk"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitHubIDTokenHandler(t *testing.T) {
	jwk.GenerateDefaultKeys()
	os.Setenv("ISSUER", "https://token.actions.githubusercontent.com")
	os.Setenv("OIDC_BEARER_TOKEN", "dev-token")
	os.Setenv("GITHUB_REPOSITORY", "octo-org/octo-repo")
	defer func() {
		os.Unsetenv("ISSUER")
		os.Unsetenv("OIDC_BEARER_TOKEN")
		os.Unsetenv("GITHUB_REPOSITORY")
	}()

	req := httptest.NewRequest(http.MethodGet, "/github/actions/idtoken?audience=sigstore", nil)
	req.Header.Set("Authorization", "Bearer dev-token")
	resp := httptest.NewRecorder()

	GitHubIDTokenHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
	value, ok := body["value"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, value)

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(value, jwt.MapClaims{})
	require.NoError(t, err)
	assert.Equal(t, "RS256", token.Header["alg"])
	assert.Equal(t, "default", token.Header["kid"])

	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, "sigstore", claims["aud"])
	assert.Equal(t, "https://token.actions.githubusercontent.com", claims["iss"])
	assert.Equal(t, "repo:octo-org/octo-repo:ref:refs/heads/main", claims["sub"])
	assert.Equal(t, "octo-org", claims["repository_owner"])
}

func TestGitHubIDTokenHandler_environment(t *testing.T) {
	jwk.GenerateDefaultKeys()
	os.Setenv("GITHUB_REPOSITORY", "octo-org/octo-repo")
	os.Setenv("GITHUB_ENVIRONMENT", "prod")
	defer func() {
		os.Unsetenv("GITHUB_REPOSITORY")
		os.Unsetenv("GITHUB_ENVIRONMENT")
	}()

	req := httptest.NewRequest(http.MethodGet, "/github/actions/idtoken?audience=sigstore", nil)
	resp := httptest.NewRecorder()
	GitHubIDTokenHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
	value := body["value"].(string)

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(value, jwt.MapClaims{})
	require.NoError(t, err)
	claims := token.Claims.(jwt.MapClaims)
	assert.Equal(t, "repo:octo-org/octo-repo:environment:prod", claims["sub"])
}
