package jose

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// nodeFixtures was written by @cauthyhq/node's own code (jose 5.10.0): the
// keys HKDF derives from a test root key, values it sealed with them, and a
// key it made and sealed as its key store keeps it.
type nodeFixtures struct {
	Seal, Cookie, Flow, SecretKey string
	CookieSealed                  string `json:"cookieSealed"`
	SecretSealed                  string `json:"secretSealed"`
	StoredKey                     struct {
		Kid       string         `json:"kid"`
		PublicJWK map[string]any `json:"publicJwk"`
		Sealed    string         `json:"sealed"`
	} `json:"storedKey"`
}

func fixtures(t *testing.T) nodeFixtures {
	t.Helper()
	raw, err := os.ReadFile("testdata/node-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f nodeFixtures
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func hexKey(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad key %q", s)
	}
	return b
}

func TestSealRoundTripsAndRefusesAnyOtherKey(t *testing.T) {
	key, other := make([]byte, 32), make([]byte, 32)
	rand.Read(key)
	rand.Read(other)
	sealed, err := Seal([]byte(`{"a":1}`), key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..") {
		t.Fatalf("header: %s", sealed)
	}
	plain, err := Open(sealed, key)
	if err != nil || string(plain) != `{"a":1}` {
		t.Fatalf("%q %v", plain, err)
	}
	if _, err := Open(sealed, other); !errors.Is(err, ErrOpen) {
		t.Fatalf("other key: %v", err)
	}
	// Flip a bit of the tag's first byte: overwriting its last characters
	// is a no-op when the tag happens to end with them already.
	cut := strings.LastIndexByte(sealed, '.') + 1
	tag, _ := Decode(sealed[cut:])
	tag[0] ^= 1
	tampered := sealed[:cut] + Encode(tag)
	if _, err := Open(tampered, key); !errors.Is(err, ErrOpen) {
		t.Fatalf("tampered: %v", err)
	}
	for _, junk := range []string{"", "a.b.c", "x....", sealed + "."} {
		if _, err := Open(junk, key); !errors.Is(err, ErrOpen) {
			t.Fatalf("%q: %v", junk, err)
		}
	}
	plain, i, err := OpenAny(sealed, [][]byte{other, key})
	if err != nil || i != 1 || string(plain) != `{"a":1}` {
		t.Fatalf("OpenAny: %q %d %v", plain, i, err)
	}
}

func TestOpensWhatNodeSealed(t *testing.T) {
	f := fixtures(t)
	for name, c := range map[string]struct{ sealed, key string }{
		"cookie (contract mode)":  {f.CookieSealed, f.Cookie},
		"cookie (variables mode)": {f.SecretSealed, f.SecretKey},
	} {
		plain, err := Open(c.sealed, hexKey(t, c.key))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var v struct {
			AT  string `json:"at"`
			Exp int64  `json:"exp"`
			P   int    `json:"p"`
		}
		if json.Unmarshal(plain, &v) != nil || v.AT != "at-1" || v.Exp != 1767226440 || v.P != 1 {
			t.Fatalf("%s: %s", name, plain)
		}
	}
}

func TestOpensAKeyNodeMadeAndAgreesOnItsId(t *testing.T) {
	f := fixtures(t)
	plain, err := Open(f.StoredKey.Sealed, hexKey(t, f.Seal))
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParsePrivateJWK(plain)
	if err != nil {
		t.Fatal(err)
	}
	if got := Thumbprint(&key.PublicKey); got != f.StoredKey.Kid {
		t.Fatalf("thumbprint %s, Node says %s", got, f.StoredKey.Kid)
	}
	pub, err := ParsePublicJWK(f.StoredKey.PublicJWK)
	if err != nil || pub.N.Cmp(key.N) != 0 {
		t.Fatalf("public half: %v", err)
	}
}

func TestPrivateJWKRoundTripsAndSigns(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(PrivateJWK(key))
	back, err := ParsePrivateJWK(raw)
	if err != nil || back.D.Cmp(key.D) != 0 {
		t.Fatalf("%v", err)
	}
	tok, err := SignRS256(back, map[string]any{"kid": "k", "alg": "none"}, map[string]any{"sub": "x"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCompact(tok)
	if err != nil {
		t.Fatal(err)
	}
	if string(c.Header["alg"]) != `"RS256"` || string(c.Header["kid"]) != `"k"` || string(c.Payload) != `{"sub":"x"}` {
		t.Fatalf("%s %s", c.Header, c.Payload)
	}
	if err := c.VerifyRS256(&key.PublicKey); err != nil {
		t.Fatal(err)
	}
	if PublicJWK(&key.PublicKey)["e"] != "AQAB" {
		t.Fatal("e is not AQAB")
	}
}
