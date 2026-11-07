package keys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/internal/cfgerr"
	"github.com/vennet-developers/cauthy-sdk-go/internal/jose"
)

const (
	// RetireAfter is how long the key before the newest stays published.
	RetireAfter = 24 * time.Hour
	// ForgetAfter is how long a key no longer published is kept before it is
	// removed from the store.
	ForgetAfter = 7 * 24 * time.Hour
	// JWKSMaxAge is how long the published keys may be cached (max-age).
	JWKSMaxAge = 300 * time.Second
	// SignAfter is how long a new key is published before it signs: longer
	// than any cached copy of the keys.
	SignAfter = JWKSMaxAge + time.Minute
	// MaxPublished is how many keys are published at once: Cauthy reads at
	// most two RS256 keys from an application's JWKS during a rotation.
	MaxPublished = 2

	currentTTL  = 5 * time.Minute
	settlingTTL = 5 * time.Second
)

// JWKS is the published key set.
type JWKS struct {
	Keys []map[string]any `json:"keys"`
}

// Keys is the application's own keys: the one that signs its assertions,
// the ones published at its jwks_url, rotating them.
//
// The first key is made by whichever instance needs it first; the store
// keeps it only while it holds none (AddFirst), so instances starting
// together end with one key.
type Keys struct {
	store Store
	seal  [][]byte
	now   func() time.Time

	makeMu     sync.Mutex // one key made at a time in this process
	mu         sync.Mutex
	remembered *signer
}

type signer struct {
	kid   string
	key   *rsa.PrivateKey
	until time.Time
}

// New is the keys kept in store, sealed with the seal ring of the root key
// (Rings.Seal). now nil is time.Now.
func New(store Store, seal [][]byte, now func() time.Time) *Keys {
	if now == nil {
		now = time.Now
	}
	return &Keys{store: store, seal: seal, now: now}
}

func newestFirst(keys []StoredKey) []StoredKey {
	slices.SortFunc(keys, func(a, b StoredKey) int {
		if c := strings.Compare(b.CreatedAt, a.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(b.Kid, a.Kid)
	})
	return keys
}

func at(k StoredKey) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, k.CreatedAt)
	return t
}

// make makes a key, newer than after when given, and keeps it.
func (k *Keys) make(ctx context.Context, after *StoredKey) (StoredKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return StoredKey{}, err
	}
	plain, _ := json.Marshal(jose.PrivateJWK(priv))
	sealed, err := jose.Seal(plain, k.seal[0])
	if err != nil {
		return StoredKey{}, err
	}
	made := k.now().UTC().Truncate(time.Millisecond)
	if after != nil {
		if next := at(*after).Add(time.Millisecond); !made.After(at(*after)) {
			made = next
		}
	}
	sk := StoredKey{Kid: jose.Thumbprint(&priv.PublicKey), PublicJWK: jose.PublicJWK(&priv.PublicKey), Sealed: sealed, CreatedAt: Timestamp(made)}
	if after == nil {
		err = k.store.AddFirst(ctx, sk)
	} else {
		err = k.store.Add(ctx, sk)
	}
	return sk, err
}

// kept is every key kept, newest first; the first is made when there is none.
func (k *Keys) kept(ctx context.Context) ([]StoredKey, error) {
	list, err := k.store.List(ctx)
	if err != nil || len(list) > 0 {
		return newestFirst(list), err
	}
	k.makeMu.Lock()
	defer k.makeMu.Unlock()
	if list, err = k.store.List(ctx); err != nil || len(list) > 0 {
		return newestFirst(list), err
	}
	if _, err := k.make(ctx, nil); err != nil {
		return nil, err
	}
	if list, err = k.store.List(ctx); err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, cfgerr.New("the key store kept no key: check that it writes")
	}
	return newestFirst(list), nil
}

// pick is the key that signs: the newest published long enough. When none
// is (the first minutes of the first key), the oldest, read again shortly
// so every instance lands on the same one.
func (k *Keys) pick(kept []StoredKey) (StoredKey, time.Time) {
	now := k.now()
	for _, key := range kept {
		if now.Sub(at(key)) >= SignAfter {
			until := now.Add(currentTTL)
			// A newer key ripens later: read again then, not after the usual while.
			if ripens := at(kept[0]).Add(SignAfter); key.Kid != kept[0].Kid && ripens.Before(until) {
				until = ripens
			}
			return key, until
		}
	}
	return kept[len(kept)-1], now.Add(settlingTTL)
}

func (k *Keys) open(key StoredKey) (*rsa.PrivateKey, bool, error) {
	plain, i, err := jose.OpenAny(key.Sealed, k.seal)
	if err != nil {
		return nil, false, cfgerr.New("the key %s cannot be opened with the root key (PACT_ROOT_KEY): if the root key was rotated, set the previous one as PACT_ROOT_KEY_PREVIOUS", key.Kid)
	}
	priv, err := jose.ParsePrivateJWK(plain)
	if err != nil {
		return nil, false, fmt.Errorf("cauthy: the key %s: %w", key.Kid, err)
	}
	return priv, i == 0, nil
}

// Current is the key that signs now, made the first time there is none.
func (k *Keys) Current(ctx context.Context) (string, *rsa.PrivateKey, error) {
	k.mu.Lock()
	if r := k.remembered; r != nil && k.now().Before(r.until) {
		k.mu.Unlock()
		return r.kid, r.key, nil
	}
	k.mu.Unlock()
	kept, err := k.kept(ctx)
	if err != nil {
		return "", nil, err
	}
	pick, until := k.pick(kept)
	k.mu.Lock()
	defer k.mu.Unlock()
	if r := k.remembered; r != nil && r.kid == pick.Kid {
		r.until = until
		return r.kid, r.key, nil
	}
	priv, _, err := k.open(pick)
	if err != nil {
		return "", nil, err
	}
	k.remembered = &signer{kid: pick.Kid, key: priv, until: until}
	return pick.Kid, priv, nil
}

// Published is the public keys to publish: the newest, and the one before it
// while the newest is younger than RetireAfter. Never more than
// MaxPublished. A key retired longer than ForgetAfter is removed.
func (k *Keys) Published(ctx context.Context) (JWKS, error) {
	kept, err := k.kept(ctx)
	if err != nil {
		return JWKS{}, err
	}
	now := k.now()
	out := JWKS{Keys: []map[string]any{}}
	for i, key := range kept {
		switch {
		case i == 0 || (i < MaxPublished && now.Sub(at(kept[i-1])) < RetireAfter):
			jwk := map[string]any{"kty": key.PublicJWK["kty"], "n": key.PublicJWK["n"], "e": key.PublicJWK["e"],
				"kid": key.Kid, "alg": "RS256", "use": "sig"}
			out.Keys = append(out.Keys, jwk)
		case now.Sub(at(kept[i-1])) > ForgetAfter:
			if err := k.store.Remove(ctx, key.Kid); err != nil {
				return JWKS{}, err
			}
		}
	}
	return out, nil
}

// Rotate makes a new key, published at once and signing once SignAfter has
// passed. It answers the new key's id.
func (k *Keys) Rotate(ctx context.Context) (string, error) {
	k.makeMu.Lock()
	defer k.makeMu.Unlock()
	list, err := k.store.List(ctx)
	if err != nil {
		return "", err
	}
	var after *StoredKey
	if len(list) > 0 {
		after = &newestFirst(list)[0]
	}
	made, err := k.make(ctx, after)
	if err != nil {
		return "", err
	}
	k.mu.Lock()
	k.remembered = nil
	k.mu.Unlock()
	return made.Kid, nil
}

// Reseal seals every key again with the current root key, after the root
// key was rotated; it answers how many changed.
func (k *Keys) Reseal(ctx context.Context) (int, error) {
	list, err := k.store.List(ctx)
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, key := range list {
		priv, fresh, err := k.open(key)
		if err != nil || fresh {
			continue
		}
		plain, _ := json.Marshal(jose.PrivateJWK(priv))
		if key.Sealed, err = jose.Seal(plain, k.seal[0]); err != nil {
			return changed, err
		}
		if err := k.store.Update(ctx, key); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

// Handler serves the published keys at the application's jwks_url, with
// Cache-Control: public, max-age=300.
func (k *Keys) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		set, err := k.Published(r.Context())
		if err != nil {
			http.Error(w, "the keys are unavailable right now", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(JWKSMaxAge.Seconds())))
		_ = json.NewEncoder(w).Encode(set)
	})
}
