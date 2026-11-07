// Package jose is the little of JOSE the SDK needs, on the standard library
// only: base64url, RS256 compact JWS, JWE compact with alg "dir" and enc
// "A256GCM" (the envelope @cauthyhq/node seals cookies and keys with, byte
// compatible), RSA JWKs and their RFC 7638 thumbprints.
package jose

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
)

var b64 = base64.RawURLEncoding

// Encode is base64url without padding.
func Encode(b []byte) string { return b64.EncodeToString(b) }

// Decode reads base64url without padding, strictly.
func Decode(s string) ([]byte, error) { return b64.Strict().DecodeString(s) }

// SignRS256 writes a compact JWS of claims, signed RS256. header holds every
// header member but alg, which is always RS256.
func SignRS256(key *rsa.PrivateKey, header map[string]any, claims any) (string, error) {
	h := map[string]any{"alg": "RS256"}
	for k, v := range header {
		if k != "alg" {
			h[k] = v
		}
	}
	hj, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	pj, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := Encode(hj) + "." + Encode(pj)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return input + "." + Encode(sig), nil
}

// Compact is a compact JWS split and decoded, not yet verified.
type Compact struct {
	Header  map[string]json.RawMessage
	Payload []byte
	Input   string // the first two segments, as received: what was signed
	Sig     []byte
}

// ParseCompact splits a compact JWS. It checks the shape only, and is not a
// verification path: it reads the SDK's own tokens back in tests and tools.
// A token from outside goes through cauthy.Verifier, which checks every rule
// of verification/rules.md (size, alg, repeated names, dates, kid, signature)
// in order.
func ParseCompact(token string) (*Compact, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jose: not three segments")
	}
	h, err1 := Decode(parts[0])
	p, err2 := Decode(parts[1])
	s, err3 := Decode(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errors.New("jose: a segment is not base64url")
	}
	var header map[string]json.RawMessage
	if json.Unmarshal(h, &header) != nil || header == nil {
		return nil, errors.New("jose: the header is not a JSON object")
	}
	return &Compact{Header: header, Payload: p, Input: parts[0] + "." + parts[1], Sig: s}, nil
}

// VerifyRS256 checks the signature of c with key.
func (c *Compact) VerifyRS256(key *rsa.PublicKey) error {
	digest := sha256.Sum256([]byte(c.Input))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], c.Sig)
}

// dirHeader is the protected header @cauthyhq/node writes: jose's
// JSON.stringify({ alg: 'dir', enc: 'A256GCM' }).
var dirHeader = Encode([]byte(`{"alg":"dir","enc":"A256GCM"}`))

// ErrOpen is every reason a sealed value does not open: a wrong key, a
// tampered value, something that is not a sealed value at all.
var ErrOpen = errors.New("jose: not a value this key sealed")

// Seal encrypts plaintext as a compact JWE, alg "dir", enc "A256GCM", with
// a 32-byte key.
func Seal(plaintext, key []byte) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	out := gcm.Seal(nil, iv, plaintext, []byte(dirHeader))
	ct, tag := out[:len(out)-gcm.Overhead()], out[len(out)-gcm.Overhead():]
	return dirHeader + ".." + Encode(iv) + "." + Encode(ct) + "." + Encode(tag), nil
}

// Open decrypts a compact JWE Seal made, or one jose's CompactEncrypt made
// with { alg: 'dir', enc: 'A256GCM' }.
func Open(token string, key []byte) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 5 || parts[1] != "" {
		return nil, ErrOpen
	}
	raw, err := Decode(parts[0])
	if err != nil {
		return nil, ErrOpen
	}
	var h map[string]json.RawMessage
	if json.Unmarshal(raw, &h) != nil || string(h["alg"]) != `"dir"` || string(h["enc"]) != `"A256GCM"` {
		return nil, ErrOpen
	}
	if _, zip := h["zip"]; zip {
		return nil, ErrOpen
	}
	if _, crit := h["crit"]; crit {
		return nil, ErrOpen
	}
	iv, err1 := Decode(parts[2])
	ct, err2 := Decode(parts[3])
	tag, err3 := Decode(parts[4])
	if err1 != nil || err2 != nil || err3 != nil || len(iv) != 12 || len(tag) != 16 {
		return nil, ErrOpen
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, ErrOpen
	}
	plain, err := gcm.Open(nil, iv, slices.Concat(ct, tag), []byte(parts[0]))
	if err != nil {
		return nil, ErrOpen
	}
	return plain, nil
}

// OpenAny tries every key of ring in order and answers the plaintext and the
// index of the key that opened it.
func OpenAny(token string, ring [][]byte) ([]byte, int, error) {
	for i, key := range ring {
		if plain, err := Open(token, key); err == nil {
			return plain, i, nil
		}
	}
	return nil, -1, ErrOpen
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("jose: A256GCM needs a 32-byte key, not %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func intBytes(i int) []byte { return big.NewInt(int64(i)).Bytes() }

// PublicJWK is the public half of key as a JWK: kty, n, e.
func PublicJWK(key *rsa.PublicKey) map[string]any {
	return map[string]any{"kty": "RSA", "n": Encode(key.N.Bytes()), "e": Encode(intBytes(key.E))}
}

// PrivateJWK is key as a private JWK, the members jose's exportJWK writes.
func PrivateJWK(key *rsa.PrivateKey) map[string]any {
	key.Precompute()
	m := PublicJWK(&key.PublicKey)
	m["d"] = Encode(key.D.Bytes())
	m["p"] = Encode(key.Primes[0].Bytes())
	m["q"] = Encode(key.Primes[1].Bytes())
	m["dp"] = Encode(key.Precomputed.Dp.Bytes())
	m["dq"] = Encode(key.Precomputed.Dq.Bytes())
	m["qi"] = Encode(key.Precomputed.Qinv.Bytes())
	return m
}

func member(m map[string]any, name string) (*big.Int, error) {
	s, ok := m[name].(string)
	if !ok || s == "" {
		return nil, fmt.Errorf("jose: JWK member %q is missing", name)
	}
	b, err := Decode(s)
	if err != nil {
		return nil, fmt.Errorf("jose: JWK member %q is not base64url", name)
	}
	return new(big.Int).SetBytes(b), nil
}

// ParsePublicJWK reads an RSA public JWK.
func ParsePublicJWK(m map[string]any) (*rsa.PublicKey, error) {
	if m["kty"] != "RSA" {
		return nil, errors.New("jose: not an RSA JWK")
	}
	n, err := member(m, "n")
	if err != nil {
		return nil, err
	}
	e, err := member(m, "e")
	if err != nil {
		return nil, err
	}
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
		return nil, errors.New("jose: JWK exponent out of range")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// ParsePrivateJWK reads an RSA private JWK (two primes).
func ParsePrivateJWK(raw []byte) (*rsa.PrivateKey, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("jose: private JWK: %w", err)
	}
	pub, err := ParsePublicJWK(m)
	if err != nil {
		return nil, err
	}
	var parts [3]*big.Int
	for i, name := range []string{"d", "p", "q"} {
		if parts[i], err = member(m, name); err != nil {
			return nil, err
		}
	}
	key := &rsa.PrivateKey{PublicKey: *pub, D: parts[0], Primes: []*big.Int{parts[1], parts[2]}}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("jose: private JWK: %w", err)
	}
	key.Precompute()
	return key, nil
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint of an RSA public key, as
// jose's calculateJwkThumbprint writes it: the key's id.
func Thumbprint(key *rsa.PublicKey) string {
	j := fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, Encode(intBytes(key.E)), Encode(key.N.Bytes()))
	sum := sha256.Sum256([]byte(j))
	return Encode(sum[:])
}
