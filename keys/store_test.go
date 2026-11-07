package keys_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/internal/storetest"
	"github.com/vennet-developers/cauthy-sdk-go/keys"
)

func TestMemoryStore(t *testing.T) { storetest.Behaves(t, keys.Memory()) }

func TestFileStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "pact-keys.json")
	storetest.Behaves(t, keys.File(path))
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the file must be the owner's only: %v %v", info.Mode(), err)
	}
	raw, _ := os.ReadFile(path)
	for _, name := range []string{`"kid"`, `"publicJwk"`, `"sealed"`, `"createdAt"`} {
		if !strings.HasPrefix(string(raw), "[") || !strings.Contains(string(raw), name) {
			t.Fatalf("not the file @cauthyhq/node writes: %s", raw)
		}
	}
}
