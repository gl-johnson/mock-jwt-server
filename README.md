<<<<<<< HEAD
<<<<<<< HEAD
# conjur-template
=======
# mock-jwt-server
>>>>>>> b361af5 (Initial commit)
=======
# mock-jwt-server

This is a simple mock JWT issuer that can be used to generate valid JWTs with various algorithms and claims. 
It is intended for testing purposes only.

## Usage

### Running the server
The start script will build and run the JWKS server in a Docker container. 
The server will be available at `http://localhost:8080`, unless otherwise specified via a parameter.
```bash
# Maps port 8080 on the host
./bin/start

# Maps port 8888 on the host
./bin/start 8888
```

### Configuration
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

### Endpoints

```
GET /token - Issue token with default key/alg (RS256)

GET /.well-known/jwks.json - Get complete JWKS

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
>>>>>>> 38f1789 (Implementation)
