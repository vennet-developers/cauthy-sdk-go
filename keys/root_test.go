package keys

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The keys @cauthyhq/node derives from this root, in internal/jose/testdata.
func nodeKeys(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../internal/jose/testdata/node-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]any
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return map[string]string{"seal": f["seal"].(string), "cookie": f["cookie"].(string), "flow": f["flow"].(string)}
}

const testRoot = "acme-root-key-for-tests-only-0123456789"

func TestDeriveAgreesWithNode(t *testing.T) {
	r, err := Derive(testRoot, "")
	if err != nil {
		t.Fatal(err)
	}
	want := nodeKeys(t)
	for name, ring := range map[string][][]byte{"seal": r.Seal, "cookie": r.Cookie, "flow": r.Flow} {
		if len(ring) != 1 || hex.EncodeToString(ring[0]) != want[name] {
			t.Fatalf("%s: %x, Node derives %s", name, ring, want[name])
		}
	}
}

func TestDeriveRotatingAndRefusals(t *testing.T) {
	r, err := Derive("another-root-key-for-tests-only-012345", testRoot)
	if err != nil || len(r.Cookie) != 2 || hex.EncodeToString(r.Cookie[1]) != nodeKeys(t)["cookie"] {
		t.Fatalf("the previous root reads second: %v", err)
	}
	if r, _ := Derive(testRoot, testRoot); len(r.Seal) != 1 {
		t.Fatal("the same root twice is one key")
	}
	for _, c := range [][2]string{{"short", ""}, {testRoot, "short"}} {
		if _, err := Derive(c[0], c[1]); err == nil {
			t.Fatalf("%q %q: want an error", c[0], c[1])
		}
	}
}
