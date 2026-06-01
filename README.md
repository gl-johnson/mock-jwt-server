# mock-jwt-server

This is a simple mock JWT issuer that can be used to generate valid JWTs with various algorithms and claims. 
It is intended for testing purposes only.

## Usage

### Running the server
The start script will build and run the JWKS server in a Docker container. 
The server will be available at `http://localhost:8080`, unless otherwise specified via the PORT environment variable.
```bash
./bin/start
```

### Configuration (Generic JWT)

Configurable claims can be modified by environment variables
```bash
export ISSUER="some-issuer"
export SUBJECT="some-subject"
export AUDIENCE="some-audience"
export NAME="Some Name"
export EMAIL="some-email@example.com"
export EXTRA_CLAIMS="some-claim=some-value;another-claim=another-value"

./bin/start
```

Otherwise the claims will be set to the following defaults:
```json
{
  "aud": "test-audience",
  "email": "test-email",
  "exp": time.Now()+24H,
  "iat": time.Now(),
  "iss": "mock-jwt-server",
  "name": "test-name",
  "sub": "test-subject"
}
```

#### GitHub Actions OIDC (`GET /github/actions/idtoken`)

Request a token that mirrors a [GitHub Actions OIDC token](https://docs.github.com/en/actions/concepts/security/openid-connect#understanding-the-oidc-token).

Identity-related claims come from a small set of variables; everything else uses GitHub-like hardcoded defaults (see `pkg/token/github.go`).

| Variable | Purpose |
|----------|---------|
| `GITHUB_REPOSITORY` | `owner/repo` — drives `repository`, `repository_owner`, `sub`, and `job_workflow_ref` |
| `GITHUB_ENVIRONMENT` | Optional — `sub` becomes `repo:OWNER/REPO:environment:NAME` and sets `environment` |
| `EXTRA_CLAIMS` | Override any default claim (`claim=value;…`, applied last). Example: `sha=abc123;workflow=vault-demo.yml;run_id=99` |
| `ISSUER` | Token `iss` (default `https://token.actions.githubusercontent.com`) |
| `JWKS_BASE_URL` | Host published in OIDC discovery `jwks_uri` |

`aud` is taken from the `audience` query parameter. `OIDC_BEARER_TOKEN` optionally requires `Authorization: Bearer`.

### Endpoints

```
GET /token - Issue token with default key/alg (RS256); JSON includes `token` and `value`

GET /github/actions/idtoken?audience=<aud> - GitHub Actions OIDC token API (`{"count":1,"value":"<jwt>"}`)

GET /.well-known/jwks.json - Get complete JWKS
GET /.well-known/openid-configuration - OIDC discovery (issuer + jwks_uri)

GET /<key_id>/<algorithm> - Get/create specified JWKS
POST /<key_id>/<algorithm> - Sign existing token with specified key/alg
DELETE /<key_id> - Delete key
```

### Supported Algorithms
  - RS256 (default)
  - RS384
  - RS512
  - ES256
  - ES384
  - ES512
  - HS256
  - HS384
  - HS512

