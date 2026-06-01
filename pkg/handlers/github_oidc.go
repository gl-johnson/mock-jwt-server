package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/cyberark/mock-jwt-server/pkg/token"
)

// GitHubIDTokenHandler implements the GitHub Actions OIDC token request API.
// GET /github/actions/idtoken?audience=<aud> with Authorization: Bearer <ACTIONS_ID_TOKEN_REQUEST_TOKEN>
func GitHubIDTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !authorizeGitHubTokenRequest(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	audience := r.URL.Query().Get("audience")
	if audience == "" {
		audience = os.Getenv("AUDIENCE")
	}
	if audience == "" {
		http.Error(w, "missing audience query parameter", http.StatusBadRequest)
		return
	}

	signedToken, err := token.IssueGitHubActionsToken("default", "RS256", audience)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"count": 1,
		"value": signedToken,
	})
}

func authorizeGitHubTokenRequest(r *http.Request) bool {
	expected := os.Getenv("OIDC_BEARER_TOKEN")
	if expected == "" {
		return true
	}
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	return strings.TrimSpace(auth[len(prefix):]) == expected
}
