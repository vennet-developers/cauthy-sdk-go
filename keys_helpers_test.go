package cauthy

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
	weakKey *rsa.PrivateKey
)

// now is the instant the tests verify at: 2026-01-01T00:00:00Z.
var now = time.Unix(1767225600, 0)

// testKeys answers a 2048-bit and a 1024-bit key, made once per test run.
func testKeys(t *testing.T) (strong, weak *rsa.PrivateKey) {
	t.Helper()
	keyOnce.Do(func() {
		var err error
		if testKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if weakKey, err = rsa.GenerateKey(rand.Reader, 1024); err != nil {
			panic(err)
		}
	})
	return testKey, weakKey
}

// jwkJSON renders key as a JWKS member with the given fields.
func jwkJSON(key *rsa.PublicKey, kty, use, alg, kid string) string {
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	return fmt.Sprintf(`{"kty":%q,"use":%q,"alg":%q,"kid":%q,"n":%q,"e":%q}`, kty, use, alg, kid, n, e)
}

// setOf is a JWKS of the strong test key under each kid.
func setOf(kids ...string) string {
	members := make([]string, len(kids))
	for i, kid := range kids {
		members[i] = jwkJSON(&testKey.PublicKey, "RSA", "sig", "RS256", kid)
	}
	return `{"keys":[` + strings.Join(members, ",") + `]}`
}
