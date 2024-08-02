package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/gl-johnson/mock-jwt-server/pkg/jwk"
	"github.com/gl-johnson/mock-jwt-server/pkg/token"
)

func JWKSHandler(w http.ResponseWriter, r *http.Request) {
	jwks := jwk.GetAllJWKS()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func TokenHandler(w http.ResponseWriter, r *http.Request) {
	keyName := "default"
	alg := "RS256"

	signedToken, err := token.IssueToken(keyName, alg, token.NewConfig())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": signedToken})
}

func DynamicKeyHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 2 {
		http.Error(w, "Invalid path. Use /<key_name>/<algorithm>", http.StatusBadRequest)
		return
	}

	keyName, alg := parts[0], parts[1]

	switch r.Method {
	case http.MethodGet:
		handleJWKS(w, keyName, alg)
	case http.MethodPost:
		unsignedToken, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		handleTokenSigning(w, keyName, alg, string(unsignedToken))
	case http.MethodDelete:
		handleKeyDelete(w, keyName)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleJWKS(w http.ResponseWriter, keyName, alg string) {
	jwks, err := jwk.GetJWKS(keyName, alg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func handleTokenSigning(w http.ResponseWriter, keyName, alg, remoteToken string) {
	signedToken, err := token.SignToken(keyName, alg, remoteToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": signedToken})
}

func handleKeyDelete(w http.ResponseWriter, keyName string) {
	jwk.DeleteKey(keyName)
	w.Write([]byte("DELETED"))
}
