package keys

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/internal/jose"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func sealRing(t *testing.T, root string) [][]byte {
	t.Helper()
	r, err := Derive(root, "")
	if err != nil {
		t.Fatal(err)
	}
	return r.Seal
}

func TestTheFirstKeyIsMadeOnceAndSigns(t *testing.T) {
	clk := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	store := Memory()
	k := New(store, sealRing(t, testRoot), clk.now)
	var wg sync.WaitGroup
	kids := make(chan string, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			kid, key, err := k.Current(context.Background())
			if err != nil || key == nil || kid != jose.Thumbprint(&key.PublicKey) {
				t.Errorf("%s %v", kid, err)
			}
			kids <- kid
		}()
	}
	wg.Wait()
	close(kids)
	first := <-kids
	for kid := range kids {
		if kid != first {
			t.Fatalf("two keys: %s %s", first, kid)
		}
	}
	if list, _ := store.List(context.Background()); len(list) != 1 {
		t.Fatalf("%d keys kept, want 1", len(list))
	}
	set, err := k.Published(context.Background())
	if err != nil || len(set.Keys) != 1 || set.Keys[0]["kid"] != first || set.Keys[0]["alg"] != "RS256" || set.Keys[0]["use"] != "sig" {
		t.Fatalf("%+v %v", set, err)
	}
}

func TestRotationPublishesAtOnceSignsLaterAndKeepsAtMostTwo(t *testing.T) {
	clk := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	k := New(Memory(), sealRing(t, testRoot), clk.now)
	ctx := context.Background()
	old, _, _ := k.Current(ctx)
	clk.add(time.Hour)
	if kid, _, _ := k.Current(ctx); kid != old {
		t.Fatal("the key changed by itself")
	}
	next, err := k.Rotate(ctx)
	if err != nil || next == old {
		t.Fatalf("%s %v", next, err)
	}
	if set, _ := k.Published(ctx); len(set.Keys) != 2 || set.Keys[0]["kid"] != next || set.Keys[1]["kid"] != old {
		t.Fatalf("both published, newest first: %+v", set)
	}
	if kid, _, _ := k.Current(ctx); kid != old {
		t.Fatal("a new key must not sign before SignAfter")
	}
	clk.add(SignAfter)
	if kid, _, _ := k.Current(ctx); kid != next {
		t.Fatal("the new key must sign after SignAfter")
	}
	third, _ := k.Rotate(ctx)
	if set, _ := k.Published(ctx); len(set.Keys) != MaxPublished || set.Keys[0]["kid"] != third || set.Keys[1]["kid"] != next {
		t.Fatalf("at most two, the newest two: %+v", set)
	}
	clk.add(RetireAfter)
	if set, _ := k.Published(ctx); len(set.Keys) != 1 || set.Keys[0]["kid"] != third {
		t.Fatalf("the one before retires after a day: %+v", set)
	}
	clk.add(ForgetAfter)
	k.Published(ctx)
	if list, _ := k.store.List(ctx); len(list) != 1 {
		t.Fatalf("keys retired for a week are forgotten: %d kept, want 1", len(list))
	}
}

func TestReadsAKeyNodeMadeAndResealsAfterARootRotation(t *testing.T) {
	raw, err := os.ReadFile("../internal/jose/testdata/node-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		StoredKey StoredKey `json:"storedKey"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store := Memory()
	store.Add(ctx, f.StoredKey)
	clk := &clock{t: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}
	if kid, _, err := New(store, sealRing(t, testRoot), clk.now).Current(ctx); err != nil || kid != f.StoredKey.Kid {
		t.Fatalf("Node's key: %s %v", kid, err)
	}
	newRoot := "a-new-root-key-for-tests-only-0123456789"
	if _, _, err := New(store, sealRing(t, newRoot), clk.now).Current(ctx); err == nil {
		t.Fatal("a root that cannot open the key must say so")
	}
	rings, _ := Derive(newRoot, testRoot)
	k := New(store, rings.Seal, clk.now)
	if n, err := k.Reseal(ctx); err != nil || n != 1 {
		t.Fatalf("resealed %d, %v", n, err)
	}
	if n, _ := k.Reseal(ctx); n != 0 {
		t.Fatal("a key already sealed with the new root is left alone")
	}
	if kid, _, err := New(store, sealRing(t, newRoot), clk.now).Current(ctx); err != nil || kid != f.StoredKey.Kid {
		t.Fatalf("after reseal the new root alone opens it: %v", err)
	}
}

func TestHandlerServesTheSetCacheable(t *testing.T) {
	k := New(Memory(), sealRing(t, testRoot), nil)
	w := httptest.NewRecorder()
	k.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/pact-jwks.json", nil))
	var set JWKS
	if w.Code != 200 || w.Header().Get("Cache-Control") != "public, max-age=300" || json.Unmarshal(w.Body.Bytes(), &set) != nil || len(set.Keys) != 1 {
		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body)
	}
}
