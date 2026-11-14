// Package keyring derives the cookie and flow keys from a secret: the secret
// segment of CAUTHY_KEY (key/cauthy-key.md §4), and of CAUTHY_KEY_PREVIOUS
// while rotating.
//
// The HKDF labels are @cauthyhq/node's, byte for byte, so a Go and a Node
// instance of one application open each other's cookies.
package keyring

import (
	"crypto/hkdf"
	"crypto/sha256"
	"unicode/utf8"

	"github.com/vennet-developers/cauthy-sdk-go/internal/cfgerr"
)

// MinSecret is the least a secret may be: 32 characters (counted as
// characters, not bytes), as 32 random bytes in base64url are 43.
const MinSecret = 32

// Rings are the keys a secret (and the one before it, while rotating)
// stands for, one ring per job. The first key of a ring writes; every key of
// it is tried to read.
type Rings struct {
	// Cookie encrypts the session cookie (pact/cookie/v1).
	Cookie [][]byte
	// Flow encrypts what a sign-in carries between its steps (pact/flow/v1).
	Flow [][]byte
}

func derive(secret, purpose string) []byte {
	k, err := hkdf.Key(sha256.New, []byte(secret), nil, "pact/"+purpose+"/v1", 32)
	if err != nil {
		panic(err) // only for a length HKDF-SHA-256 cannot give; 32 it always can
	}
	return k
}

// Derive is the key rings of secret, and of previous while it is being
// rotated ("" when not).
func Derive(secret, previous string) (*Rings, error) {
	if utf8.RuneCountInString(secret) < MinSecret {
		return nil, cfgerr.New("the key's secret must be at least %d characters", MinSecret)
	}
	if previous != "" && utf8.RuneCountInString(previous) < MinSecret {
		return nil, cfgerr.New("the previous key's secret must be at least %d characters", MinSecret)
	}
	secrets := []string{secret}
	if previous != "" && previous != secret {
		secrets = append(secrets, previous)
	}
	r := &Rings{}
	for _, s := range secrets {
		r.Cookie = append(r.Cookie, derive(s, "cookie"))
		r.Flow = append(r.Flow, derive(s, "flow"))
	}
	return r, nil
}
