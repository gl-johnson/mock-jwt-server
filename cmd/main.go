package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/cyberark/mock-jwt-server/pkg/handlers"
)

func main() {
	http.HandleFunc("/.well-known/jwks.json", handlers.JWKSHandler)
	http.HandleFunc("/.well-known/openid-configuration", handlers.OIDCConfigHandler)
	http.HandleFunc("/jwks", handlers.JWKSHandler)
	http.HandleFunc("/token", handlers.TokenHandler)
	http.HandleFunc("/", handlers.DynamicKeyHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf(`
mock-jwt-server usage:

GET /token - Issue token with default key/alg (RS256)
GET /.well-known/jwks.json - Get complete JWKS
GET /<key_id>/<algorithm> - Get/create specified JWKS
POST /<key_id>/<algorithm> - Sign token with specified key/alg
DELETE /<key_id> - Delete key

Listening on port %s.
`, port)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}
