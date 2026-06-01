package token

import (
	"os"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGithubActionsClaims_derivesFromRepository(t *testing.T) {
	os.Setenv("GITHUB_REPOSITORY", "acme/dev-demo")
	defer os.Unsetenv("GITHUB_REPOSITORY")

	claims := githubActionsClaims("sigstore")

	assert.Equal(t, "acme/dev-demo", claims["repository"])
	assert.Equal(t, "acme", claims["repository_owner"])
	assert.Equal(t, "repo:acme/dev-demo:ref:refs/heads/main", claims["sub"])
	assert.Equal(t, "acme/dev-demo/.github/workflows/example-workflow.yml@refs/heads/main", claims["job_workflow_ref"])
	_, hasEnv := claims["environment"]
	assert.False(t, hasEnv)
}

func TestGithubActionsClaims_environmentSubject(t *testing.T) {
	os.Setenv("GITHUB_REPOSITORY", "octo-org/octo-repo")
	os.Setenv("GITHUB_ENVIRONMENT", "prod")
	defer func() {
		os.Unsetenv("GITHUB_REPOSITORY")
		os.Unsetenv("GITHUB_ENVIRONMENT")
	}()

	claims := githubActionsClaims("sigstore")

	assert.Equal(t, "prod", claims["environment"])
	assert.Equal(t, "repo:octo-org/octo-repo:environment:prod", claims["sub"])
}

func TestGithubActionsClaims_extraClaimsOverride(t *testing.T) {
	os.Setenv("GITHUB_REPOSITORY", "acme/dev-demo")
	os.Setenv("EXTRA_CLAIMS", "actor=custom-bot;run_number=99;sha=1234abc;sub=repo:acme/dev-demo:ref:refs/heads/feature")
	defer func() {
		os.Unsetenv("GITHUB_REPOSITORY")
		os.Unsetenv("EXTRA_CLAIMS")
	}()

	claims := githubActionsClaims("sigstore")
	assert.Equal(t, "custom-bot", claims["actor"])
	assert.Equal(t, "99", claims["run_number"])
	assert.Equal(t, "1234abc", claims["sha"])
	assert.Equal(t, "repo:acme/dev-demo:ref:refs/heads/feature", claims["sub"])
}

func TestIssueGitHubActionsToken(t *testing.T) {
	os.Setenv("GITHUB_REPOSITORY", "octo-org/octo-repo")
	defer os.Unsetenv("GITHUB_REPOSITORY")

	tokenStr, err := IssueGitHubActionsToken("default", "RS256", "sigstore")
	require.NoError(t, err)

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	require.NoError(t, err)

	claims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, "repo:octo-org/octo-repo:ref:refs/heads/main", claims["sub"])
}
