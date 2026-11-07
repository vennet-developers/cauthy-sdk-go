package keys

import (
	"context"
	"sync"
)

// StoredKey is a key as a Store keeps it. Nothing in it is secret but sealed.
// The JSON names are @cauthyhq/node's.
type StoredKey struct {
	// Kid is its id, as published: the RFC 7638 thumbprint.
	Kid string `json:"kid"`
	// PublicJWK is its public half, as published.
	PublicJWK map[string]any `json:"publicJwk"`
	// Sealed is its private half, sealed with the key derived from the root key.
	Sealed string `json:"sealed"`
	// CreatedAt is when it was made, UTC, "2006-01-02T15:04:05.000Z". The
	// newest signs.
	CreatedAt string `json:"createdAt"`
}

// Store is where the application keeps its keys: a table, a file.
type Store interface {
	// List answers every key kept.
	List(ctx context.Context) ([]StoredKey, error)
	// Add keeps a new key; a kid already kept is left as it is.
	Add(ctx context.Context, k StoredKey) error
	// AddFirst keeps the key only while the store holds none, in one step,
	// so instances starting together make one key.
	AddFirst(ctx context.Context, k StoredKey) error
	// Update replaces a key's sealed private half (after a root rotation).
	Update(ctx context.Context, k StoredKey) error
	// Remove forgets a key no longer published.
	Remove(ctx context.Context, kid string) error
}

// Memory is a Store in this process's memory: for tests, and for trying
// contract mode out. Gone on restart.
func Memory() Store { return &memory{byKid: map[string]StoredKey{}} }

type memory struct {
	mu    sync.Mutex
	byKid map[string]StoredKey
}

func (m *memory) List(context.Context) ([]StoredKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]StoredKey, 0, len(m.byKid))
	for _, k := range m.byKid {
		out = append(out, k)
	}
	return out, nil
}

func (m *memory) Add(_ context.Context, k StoredKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byKid[k.Kid]; !ok {
		m.byKid[k.Kid] = k
	}
	return nil
}

func (m *memory) AddFirst(_ context.Context, k StoredKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.byKid) == 0 {
		m.byKid[k.Kid] = k
	}
	return nil
}

func (m *memory) Update(_ context.Context, k StoredKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byKid[k.Kid] = k
	return nil
}

func (m *memory) Remove(_ context.Context, kid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byKid, kid)
	return nil
}
