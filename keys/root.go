// Package keys is where a contracted application keeps its own key, and the
// keys it derives from its one secret, PACT_ROOT_KEY.
//
// Every format here is @cauthyhq/node's, byte for byte: the HKDF labels, the
// sealed private key (JWE dir/A256GCM of the private JWK), the key id (RFC
// 7638 thumbprint) and the table. A Go and a Node instance of one
// application can share one key table and one root key.
package keys

import (
	"crypto/hkdf"
	"crypto/sha256"
	"unicode/utf8"

	"github.com/vennet-developers/cauthy-sdk-go/internal/cfgerr"
)

// MinRootKey is the least a root key may be: 32 characters (counted as
// characters, not bytes), as 32 random
// bytes in base64url are 43.
const MinRootKey = 32

// Rings are the keys a root key (and the one before it, while rotating)
// stand for, one ring per job. The first key of a ring writes; every key of
// it is tried to read.
type Rings struct {
	// Seal seals the application's private key at rest (pact/seal/v1).
	Seal [][]byte
	// Cookie encrypts the session cookie (pact/cookie/v1).
	Cookie [][]byte
	// Flow encrypts what a sign-in carries between its steps (pact/flow/v1).
	Flow [][]byte
}

func derive(root, purpose string) []byte {
	k, err := hkdf.Key(sha256.New, []byte(root), nil, "pact/"+purpose+"/v1", 32)
	if err != nil {
		panic(err) // only for a length HKDF-SHA-256 cannot give; 32 it always can
	}
	return k
}

// Derive is the key rings of root, and of previous while the root is being
// rotated (PACT_ROOT_KEY_PREVIOUS; "" when not).
func Derive(root, previous string) (*Rings, error) {
	if utf8.RuneCountInString(root) < MinRootKey {
		return nil, cfgerr.New("the root key (PACT_ROOT_KEY) must be at least %d characters: 32 random bytes, e.g. openssl rand -base64 32", MinRootKey)
	}
	if previous != "" && utf8.RuneCountInString(previous) < MinRootKey {
		return nil, cfgerr.New("the previous root key (PACT_ROOT_KEY_PREVIOUS) must be at least %d characters", MinRootKey)
	}
	roots := []string{root}
	if previous != "" && previous != root {
		roots = append(roots, previous)
	}
	r := &Rings{}
	for _, rt := range roots {
		r.Seal = append(r.Seal, derive(rt, "seal"))
		r.Cookie = append(r.Cookie, derive(rt, "cookie"))
		r.Flow = append(r.Flow, derive(rt, "flow"))
	}
	return r, nil
}
