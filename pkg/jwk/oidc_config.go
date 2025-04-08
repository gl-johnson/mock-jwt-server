package jwk

import (
	"fmt"
	"os"
)

var oidcConfigTemplate = `
{
  "jwks_uri": "%s/.well-known/jwks.json",
  "issuer": "%s",
  "id_token_signing_alg_values_supported": [
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "HS256",
    "HS384",
    "HS512"
  ],
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ]
}`

// This is the minimal OIDC configuration required for Conjur to treat this server as an OIDC provider.
// This allows it to be used with the 'provider-uri' option instead of the 'jwks-uri' option if desired.
func GetOIDCConfig() string {
	issuer := os.Getenv("ISSUER")
	return fmt.Sprintf(oidcConfigTemplate, issuer, issuer)
}
