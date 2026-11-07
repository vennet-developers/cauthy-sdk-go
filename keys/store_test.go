package keys_test

import (
	"fmt"
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

func TestFileStoreNeverWritesThroughAPlantedTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pact-keys.json")
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The name a fixed temp file would have.
	if err := os.Symlink(victim, fmt.Sprintf("%s.%d.tmp", path, os.Getpid())); err != nil {
		t.Fatal(err)
	}
	storetest.Behaves(t, keys.File(path))
	if raw, _ := os.ReadFile(victim); string(raw) != "untouched" {
		t.Fatalf("the store wrote through a planted link: %q", raw)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 3 {
		t.Fatalf("a temp file was left behind: %v", entries)
	}
}
