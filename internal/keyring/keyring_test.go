package keyring

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The keys @cauthyhq/node derives from this secret, in internal/jose/testdata.
func nodeKeys(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../jose/testdata/node-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]any
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return map[string]string{"cookie": f["cookie"].(string), "flow": f["flow"].(string)}
}

const testSecret = "acme-root-key-for-tests-only-0123456789"

func TestDeriveAgreesWithNode(t *testing.T) {
	r, err := Derive(testSecret, "")
	if err != nil {
		t.Fatal(err)
	}
	want := nodeKeys(t)
	for name, ring := range map[string][][]byte{"cookie": r.Cookie, "flow": r.Flow} {
		if len(ring) != 1 || hex.EncodeToString(ring[0]) != want[name] {
			t.Fatalf("%s: %x, Node derives %s", name, ring, want[name])
		}
	}
}

func TestDeriveRotatingAndRefusals(t *testing.T) {
	r, err := Derive("another-secret-for-tests-only-0123456789", testSecret)
	if err != nil || len(r.Cookie) != 2 || hex.EncodeToString(r.Cookie[1]) != nodeKeys(t)["cookie"] {
		t.Fatalf("the previous secret reads second: %v", err)
	}
	if r, _ := Derive(testSecret, testSecret); len(r.Cookie) != 1 {
		t.Fatal("the same secret twice is one key")
	}
	for _, c := range [][2]string{{"short", ""}, {testSecret, "short"}} {
		if _, err := Derive(c[0], c[1]); err == nil {
			t.Fatalf("%q %q: want an error", c[0], c[1])
		}
	}
}

func TestDeriveCountsCharactersNotBytes(t *testing.T) {
	short := strings.Repeat("ñ", 20) // 40 bytes, 20 characters
	if _, err := Derive(short, ""); err == nil {
		t.Fatal("20 characters must be refused, whatever their bytes")
	}
	if _, err := Derive(strings.Repeat("a", 40), short); err == nil {
		t.Fatal("a previous secret of 20 characters must be refused")
	}
	if _, err := Derive(strings.Repeat("ñ", MinSecret), ""); err != nil {
		t.Fatal(err)
	}
}
