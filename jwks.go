package cauthy

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

var (
	// ErrUnknownKid: no usable key in the issuer's set has the token's kid.
	ErrUnknownKid = errors.New("cauthy: no signing key with that kid")
	// ErrWeakKey: the key is smaller than MinKeyBits.
	ErrWeakKey = errors.New("cauthy: the signing key is smaller than 2048 bits")
	// ErrNoKeySet: Cauthy's keys have never been fetched (Cauthy unreachable
	// since start). It comes wrapped with ErrUnknownKid; the middleware answers
	// it 503, not 401, so an outage does not sign anybody out.
	ErrNoKeySet = errors.New("cauthy: Cauthy's keys could not be fetched yet")
)

// KeySet answers the public key a token names by its kid. It answers
// ErrUnknownKid or ErrWeakKey (possibly wrapped) when it cannot.
type KeySet interface {
	Key(ctx context.Context, kid string) (*rsa.PublicKey, error)
}

// StaticKeys is a parsed JWK Set.
type StaticKeys struct {
	byKid map[string]*rsa.PublicKey
}

// member reads a string-valued field of a JWK; absent is "", and ok is false
// when the field is present but not a string. Names are exact: Go's struct
// decoding would also match "KID" to "kid".
func member(m map[string]any, name string) (value string, ok bool) {
	raw, present := m[name]
	if !present {
		return "", true
	}
	value, ok = raw.(string)
	return value, ok
}

// verifies reports whether key_ops, when present, allows verification.
func verifies(m map[string]any) bool {
	raw, present := m["key_ops"]
	if !present {
		return true
	}
	ops, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, op := range ops {
		if op == "verify" {
			return true
		}
	}
	return false
}

// ParseJWKS reads a JWK Set. Only keys a Cauthy token can be signed with are
// kept: kty RSA, use sig or absent, alg RS256 or absent, key_ops absent or
// holding verify, a kid, a sound modulus and exponent. A member that is
// anything else, or malformed, is skipped, so a token naming it reads as an
// unknown kid. Two usable keys with one kid, or no usable key, make the set
// invalid (rule K6).
func ParseJWKS(raw []byte) (*StaticKeys, error) {
	// "keys" by its exact name: Go's struct decoding would also take "KEYS".
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("cauthy: JWKS: %w", err)
	}
	var set struct{ Keys []any }
	if err := json.Unmarshal(top["keys"], &set.Keys); err != nil {
		return nil, fmt.Errorf("cauthy: JWKS: keys: %w", err)
	}
	k := &StaticKeys{byKid: map[string]*rsa.PublicKey{}}
	for _, item := range set.Keys {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		kty, ok1 := member(m, "kty")
		use, ok2 := member(m, "use")
		alg, ok3 := member(m, "alg")
		kid, ok4 := member(m, "kid")
		ns, ok5 := member(m, "n")
		es, ok6 := member(m, "e")
		if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) || kty != "RSA" || (use != "" && use != "sig") ||
			(alg != "" && alg != "RS256") || kid == "" || !verifies(m) {
			continue
		}
		n, errN := base64.RawURLEncoding.DecodeString(ns)
		e, errE := base64.RawURLEncoding.DecodeString(es)
		if errN != nil || errE != nil || len(n) == 0 || len(e) == 0 || len(e) > 4 {
			continue
		}
		exp := int(new(big.Int).SetBytes(e).Int64())
		if exp < 3 || exp%2 == 0 {
			continue
		}
		if _, dup := k.byKid[kid]; dup {
			return nil, fmt.Errorf("cauthy: JWKS has two keys with kid %q", kid)
		}
		k.byKid[kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}
	}
	if len(k.byKid) == 0 {
		return nil, errors.New("cauthy: JWKS has no usable key")
	}
	return k, nil
}

// Key answers the key with kid.
func (k *StaticKeys) Key(_ context.Context, kid string) (*rsa.PublicKey, error) {
	key, ok := k.byKid[kid]
	if !ok {
		return nil, ErrUnknownKid
	}
	if key.N.BitLen() < MinKeyBits {
		return nil, ErrWeakKey
	}
	return key, nil
}
