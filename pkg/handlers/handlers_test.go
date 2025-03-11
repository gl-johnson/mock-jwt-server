package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWKSHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	resp := httptest.NewRecorder()

	JWKSHandler(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	var jwks interface{}
	err := json.Unmarshal(resp.Body.Bytes(), &jwks)
	require.NoError(t, err)
}

func TestOIDCConfigHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	resp := httptest.NewRecorder()

	OIDCConfigHandler(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "application/json", resp.Header().Get("Content-Type"))
	assert.NotEmpty(t, resp.Body.String())
}

func TestTokenHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	resp := httptest.NewRecorder()

	TokenHandler(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	var respBody map[string]string
	err := json.Unmarshal(resp.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Contains(t, respBody, "token")
}

func TestDynamicKeyHandler_Get(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/default/RS256", nil)
	resp := httptest.NewRecorder()

	DynamicKeyHandler(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "application/json", resp.Header().Get("Content-Type"))
}

func TestDynamicKeyHandler_Post(t *testing.T) {
	// Generate unsigned JWT token
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

	req, _ := http.NewRequest("POST", "/default/RS256", strings.NewReader(unsignedToken))
	resp := httptest.NewRecorder()

	DynamicKeyHandler(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	var respBody map[string]string
	err := json.Unmarshal(resp.Body.Bytes(), &respBody)
	require.NoError(t, err)
	assert.Contains(t, respBody, "token")
}
