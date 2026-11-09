package cauthykey_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/cauthykey"
)

// pinned is the sha256 of the vendored vectors (scripts/sync-spec.sh copies
// them; a new copy changes this pin in the same commit).
const pinned = "165199405ab31ed72390c4e8eabdc7488bb07a871683341bef25525ee0020522"

// testSecret is the bytes 00..1f: a test value, never a real key.
const testSecret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

type vector struct {
	Name      string            `json:"name"`
	Key       string            `json:"key"`
	Reason    string            `json:"reason"`
	Issuer    string            `json:"issuer"`
	ClientID  string            `json:"client_id"`
	Secret    string            `json:"secret"`
	Derived   map[string]string `json:"derived"`
	PublicJWK map[string]string `json:"public_jwk"`
	KID       string            `json:"kid"`
	Assertion struct {
		TokenEndpoint string `json:"token_endpoint"`
		Jti           string `json:"jti"`
		Iat           int64  `json:"iat"`
		JWS           string `json:"jws"`
	} `json:"assertion"`
}

type vectors struct {
	Valid   []vector `json:"valid"`
	Invalid []vector `json:"invalid"`
}

func load(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("../internal/spec/testdata/cauthy-key.json")
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != pinned {
		t.Fatalf("cauthy-key.json is not the pinned copy: sync it with scripts/sync-spec.sh and update the pin")
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Valid) == 0 || len(v.Invalid) == 0 {
		t.Fatal("no vectors")
	}
	return v
}

func TestParseAndComposeVectors(t *testing.T) {
	v := load(t)
	for _, c := range v.Valid {
		t.Run(c.Name, func(t *testing.T) {
			k, err := cauthykey.Parse(c.Key)
			if err != nil {
				t.Fatal(err)
			}
			if k.Issuer != c.Issuer || k.ClientID != c.ClientID || k.Secret != c.Secret {
				t.Fatalf("Parse = %s %s", k.Issuer, k.ClientID)
			}
			got, err := cauthykey.Compose(c.Issuer, c.ClientID, c.Secret)
			if err != nil || got != strings.Trim(c.Key, " \t\r\n") {
				t.Fatalf("Compose: %v", err)
			}
		})
	}
	for _, c := range v.Invalid {
		t.Run(c.Name, func(t *testing.T) {
			_, err := cauthykey.Parse(c.Key)
			var e *cauthykey.Error
			if !errors.As(err, &e) || e.Reason != c.Reason {
				t.Fatalf("want %s, got %v", c.Reason, err)
			}
			if strings.Contains(err.Error(), testSecret) {
				t.Fatal("the refusal holds the secret")
			}
		})
	}
}
