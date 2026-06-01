package token

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cyberark/mock-jwt-server/pkg/jwk"

	"github.com/golang-jwt/jwt/v4"
)

const (
	defaultGitHubIssuer = "https://token.actions.githubusercontent.com"
	defaultGitHubRef    = "refs/heads/main"
	defaultWorkflowFile = "example-workflow.yml"
	githubTokenTTL      = 900
)

// IssueGitHubActionsToken mints a JWT shaped like GitHub Actions OIDC tokens.
func IssueGitHubActionsToken(keyName, alg, audience string) (string, error) {
	keySet, err := jwk.GetJWKS(keyName, alg)
	if err != nil {
		return "", err
	}
	if len(keySet.Keys) == 0 {
		return "", fmt.Errorf("no keys found for %s", keyName)
	}

	claims := githubActionsClaims(audience)
	token := jwt.NewWithClaims(jwt.GetSigningMethod(alg), claims)
	token.Header["kid"] = keyName

	privateKey := keySet.Keys[0].Key
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		return token.SignedString(k)
	case *ecdsa.PrivateKey:
		return token.SignedString(k)
	default:
		return "", fmt.Errorf("unsupported key type for GitHub OIDC tokens")
	}
}

func githubActionsClaims(audience string) jwt.MapClaims {
	repo := strings.TrimSpace(getEnvOrDefault("GITHUB_REPOSITORY", "octo-org/octo-repo"))
	owner := repoOwner(repo)
	environment := strings.TrimSpace(os.Getenv("GITHUB_ENVIRONMENT"))
	ref := defaultGitHubRef

	subject := fmt.Sprintf("repo:%s:ref:%s", repo, ref)
	if environment != "" {
		subject = fmt.Sprintf("repo:%s:environment:%s", repo, environment)
	}

	now := time.Now().Unix()

	// Defaults mirror GitHub Actions OIDC tokens. Override any claim via EXTRA_CLAIMS
	// (semicolon-separated claim=value pairs), e.g.:
	//   EXTRA_CLAIMS="sha=abc123;workflow=vault-demo.yml;sub=repo:acme/app:ref:refs/heads/main"
	claims := jwt.MapClaims{
		"jti":                        "example-id",
		"sub":                        subject,
		"aud":                        audience,
		"ref":                        ref,
		"sha":                        "example-sha",
		"repository":                 repo,
		"repository_owner":           owner,
		"actor_id":                   "12",
		"repository_visibility":      "private",
		"repository_id":              "74",
		"repository_owner_id":        "65",
		"run_id":                     "example-run-id",
		"run_number":                 "10",
		"run_attempt":                "2",
		"runner_environment":         "github-hosted",
		"actor":                      "octocat",
		"workflow":                   defaultWorkflowFile,
		"head_ref":                   "",
		"base_ref":                   "",
		"event_name":                 "workflow_dispatch",
		"ref_type":                   "branch",
		"job_workflow_ref":           jobWorkflowRef(repo, defaultWorkflowFile, ref),
		"iss":                        getEnvOrDefault("ISSUER", defaultGitHubIssuer),
		"nbf":                        now - 300,
		"iat":                        now,
		"exp":                        now + githubTokenTTL,
		"repo_property_workspace_id": "ws-abc123",
	}
	if environment != "" {
		claims["environment"] = environment
	}

	mergeExtraClaims(claims)
	return claims
}

// mergeExtraClaims applies EXTRA_CLAIMS on top of the token (last wins).
func mergeExtraClaims(claims jwt.MapClaims) {
	for key, value := range getExtraClaims() {
		claims[key] = value
	}
}

func repoOwner(repo string) string {
	if i := strings.Index(repo, "/"); i > 0 {
		return repo[:i]
	}
	return repo
}

func jobWorkflowRef(repo, workflow, ref string) string {
	name := strings.TrimSuffix(workflow, ".yml")
	name = strings.TrimSuffix(name, ".yaml")
	return fmt.Sprintf("%s/.github/workflows/%s.yml@%s", repo, name, ref)
}
