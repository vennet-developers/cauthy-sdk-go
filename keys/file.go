package keys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
)

// File is a Store in a JSON file only its owner may read: for a developer's
// machine. Production keeps its key in its database, where every instance
// reads the same one. The file is the one @cauthyhq/node's fileKeyStore
// writes.
func File(path string) Store { return &file{path: path} }

type file struct {
	path string
	mu   sync.Mutex
}

func (f *file) read() ([]StoredKey, error) {
	raw, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return []StoredKey{}, nil
	}
	if err != nil {
		return nil, err
	}
	var keys []StoredKey
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, fmt.Errorf("cauthy: key file %s: %w", f.path, err)
	}
	return keys, nil
}

// write changes the file whole: written beside it, then moved over it, so a
// crash never leaves half a file.
func (f *file) write(change func([]StoredKey) []StoredKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys, err := f.read()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(change(keys), "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", f.path, os.Getpid())
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

func (f *file) List(context.Context) ([]StoredKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.read()
}

func has(keys []StoredKey, kid string) bool {
	return slices.ContainsFunc(keys, func(k StoredKey) bool { return k.Kid == kid })
}

func (f *file) Add(_ context.Context, k StoredKey) error {
	return f.write(func(keys []StoredKey) []StoredKey {
		if has(keys, k.Kid) {
			return keys
		}
		return append(keys, k)
	})
}

func (f *file) AddFirst(_ context.Context, k StoredKey) error {
	return f.write(func(keys []StoredKey) []StoredKey {
		if len(keys) > 0 {
			return keys
		}
		return []StoredKey{k}
	})
}

func (f *file) Update(_ context.Context, k StoredKey) error {
	return f.write(func(keys []StoredKey) []StoredKey {
		for i := range keys {
			if keys[i].Kid == k.Kid {
				keys[i] = k
			}
		}
		return keys
	})
}

func (f *file) Remove(_ context.Context, kid string) error {
	return f.write(func(keys []StoredKey) []StoredKey {
		return slices.DeleteFunc(keys, func(k StoredKey) bool { return k.Kid == kid })
	})
}
