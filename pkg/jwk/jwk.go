package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"sync"

	"gopkg.in/square/go-jose.v2"
)

var (
	keys     = make(map[string]interface{})
	keysLock sync.RWMutex
)

var supportedAlgorithms = []string{
	"RS256",
	"RS384",
	"RS512",
	"ES256",
	"ES384",
	"ES512",
	"HS256",
	"HS384",
	"HS512",
}

func GetAllJWKS() *jose.JSONWebKeySet {
	keysLock.RLock()
	defer keysLock.RUnlock()

	jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
	for name, key := range keys {
		jwk := jose.JSONWebKey{
			Key:   key,
			KeyID: name,
			Use:   "sig",
		}
		jwks.Keys = append(jwks.Keys, jwk)
	}

	return jwks
}

func GetJWKS(keyName, alg string) (*jose.JSONWebKeySet, error) {
	key := getOrCreateKey(keyName, strings.ToUpper(alg))
	if key == nil {
		return nil, fmt.Errorf("unsupported algorithm: '%s', must one of: %v", alg, supportedAlgorithms)
	}

	return &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{*key},
	}, nil
}

func DeleteKey(keyName string) {
	keysLock.Lock()
	delete(keys, keyName)
	keysLock.Unlock()
}

func getOrCreateKey(keyName, alg string) *jose.JSONWebKey {
	keysLock.Lock()
	defer keysLock.Unlock()

	key, exists := keys[keyName]
	if !exists {
		var err error
		key, err = generateKey(alg)
		if err != nil {
			return nil
		}
		keys[keyName] = key
	}

	return &jose.JSONWebKey{
		Key:       key,
		KeyID:     keyName,
		Algorithm: alg,
		Use:       "sig",
	}
}

func generateKey(alg string) (interface{}, error) {
	switch alg {
	case "RS256", "RS384", "RS512":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "ES256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ES384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ES512":
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "HS256", "HS384", "HS512":
		key := make([]byte, 32)
		_, err := rand.Read(key)
		return key, err
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}
