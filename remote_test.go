package cauthy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// clock is a time the test moves by hand.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// source is a JWKS the test changes, and counts its fetches.
type source struct {
	mu      sync.Mutex
	body    string
	fail    bool
	fetches atomic.Int32
	gate    chan struct{} // when set, a fetch waits for it
}

func (s *source) set(body string, fail bool) { s.mu.Lock(); s.body, s.fail = body, fail; s.mu.Unlock() }

func (s *source) fetch(context.Context) ([]byte, time.Duration, error) {
	s.fetches.Add(1)
	if s.gate != nil {
		<-s.gate
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return nil, 0, errors.New("unreachable")
	}
	return []byte(s.body), time.Hour, nil
}

func TestRemoteKeysFetchOnFirstUseAndKeep(t *testing.T) {
	testKeys(t)
	src, clk := &source{}, &clock{t: now}
	src.set(setOf("a"), false)
	r := NewRemoteKeys(src.fetch, 30*time.Second, clk.now)
	if r.Loaded() {
		t.Fatal("loaded before any fetch")
	}
	for range 3 {
		if _, err := r.Key(context.Background(), "a"); err != nil {
			t.Fatal(err)
		}
	}
	if n := src.fetches.Load(); n != 1 || !r.Loaded() {
		t.Fatalf("%d fetches, want 1", n)
	}
	clk.add(time.Hour)
	if _, err := r.Key(context.Background(), "a"); err != nil || src.fetches.Load() != 2 {
		t.Fatalf("after max-age: err %v, %d fetches, want 2", err, src.fetches.Load())
	}
}

func TestRemoteKeysUnknownKidWaitsForTheCooldown(t *testing.T) {
	testKeys(t)
	src, clk := &source{}, &clock{t: now}
	src.set(setOf("a"), false)
	r := NewRemoteKeys(src.fetch, 30*time.Second, clk.now)
	ctx := context.Background()
	if _, err := r.Key(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	src.set(setOf("a", "b"), false)
	for _, kid := range []string{"forged-1", "forged-2", "b"} {
		if _, err := r.Key(ctx, kid); !errors.Is(err, ErrUnknownKid) {
			t.Fatalf("%s inside the cooldown: want ErrUnknownKid, got %v", kid, err)
		}
	}
	if n := src.fetches.Load(); n != 1 {
		t.Fatalf("%d fetches inside the cooldown, want 1", n)
	}
	clk.add(30 * time.Second)
	if _, err := r.Key(ctx, "b"); err != nil {
		t.Fatalf("b after the cooldown: %v", err)
	}
	if _, err := r.Key(ctx, "forged-3"); !errors.Is(err, ErrUnknownKid) {
		t.Fatalf("forged-3: %v", err)
	}
	if n := src.fetches.Load(); n != 2 {
		t.Fatalf("%d fetches, want 2", n)
	}
}

func TestRemoteKeysFailedFetchKeepsTheLastSet(t *testing.T) {
	testKeys(t)
	src, clk := &source{}, &clock{t: now}
	src.set(setOf("a"), false)
	r := NewRemoteKeys(src.fetch, 30*time.Second, clk.now)
	ctx := context.Background()
	if _, err := r.Key(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	src.set("", true)
	clk.add(2 * time.Hour)
	if _, err := r.Key(ctx, "a"); err != nil {
		t.Fatalf("stale set after a failed fetch: %v", err)
	}
	src.set(`{"keys":[`+jwkJSON(&testKey.PublicKey, "RSA", "sig", "RS256", "x")+`,`+jwkJSON(&testKey.PublicKey, "RSA", "sig", "RS256", "x")+`]}`, false)
	clk.add(time.Minute)
	if _, err := r.Key(ctx, "a"); err != nil {
		t.Fatalf("a set with a duplicate kid must not replace the last good one: %v", err)
	}
}

func TestRemoteKeysNoSetYetIsSaidApart(t *testing.T) {
	testKeys(t)
	src, clk := &source{}, &clock{t: now}
	src.set("", true)
	r := NewRemoteKeys(src.fetch, 30*time.Second, clk.now)
	for range 2 {
		_, err := r.Key(context.Background(), "a")
		if !errors.Is(err, ErrUnknownKid) || !errors.Is(err, ErrNoKeySet) {
			t.Fatalf("want ErrUnknownKid and ErrNoKeySet, got %v", err)
		}
	}
	if n := src.fetches.Load(); n != 1 {
		t.Fatalf("%d fetches, want 1", n)
	}
}

func TestRemoteKeysOneFetchAtATime(t *testing.T) {
	testKeys(t)
	src, clk := &source{gate: make(chan struct{})}, &clock{t: now}
	src.set(setOf("a"), false)
	r := NewRemoteKeys(src.fetch, 30*time.Second, clk.now)
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.Key(context.Background(), "a")
			errs <- err
		}()
	}
	for src.fetches.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(src.gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := src.fetches.Load(); n != 1 {
		t.Fatalf("%d fetches, want 1", n)
	}
}

func TestRemoteKeysCancelledCallerSetsNoCooldown(t *testing.T) {
	testKeys(t)
	src, clk := &source{}, &clock{t: now}
	src.set(setOf("a"), false)
	r := NewRemoteKeys(src.fetch, 30*time.Second, clk.now)
	dead, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Key(dead, "a"); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if n := src.fetches.Load(); n != 0 {
		t.Fatalf("a cancelled caller started %d fetches", n)
	}
	if _, err := r.Key(context.Background(), "a"); err != nil {
		t.Fatalf("the next caller must fetch at once: %v", err)
	}
}

func TestRemoteKeysSurvivesAPanickingFetcher(t *testing.T) {
	testKeys(t)
	clk := &clock{t: now}
	var calls atomic.Int32
	r := NewRemoteKeys(func(context.Context) ([]byte, time.Duration, error) {
		if calls.Add(1) == 1 {
			panic("boom")
		}
		return []byte(setOf("a")), time.Hour, nil
	}, 30*time.Second, clk.now)
	if _, err := r.Key(context.Background(), "a"); !errors.Is(err, ErrUnknownKid) {
		t.Fatalf("want ErrUnknownKid after a panic, got %v", err)
	}
	clk.add(31 * time.Second)
	if _, err := r.Key(context.Background(), "a"); err != nil {
		t.Fatalf("after the cooldown the fetch must work again: %v", err)
	}
}

func TestHTTPFetcher(t *testing.T) {
	testKeys(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/jwks.json":
			w.Header().Set("Cache-Control", "public, max-age=3600")
			w.Write([]byte(setOf("a")))
		case "/moved":
			http.Redirect(w, r, "/.well-known/jwks.json", http.StatusFound)
		case "/huge":
			w.Write([]byte(strings.Repeat(" ", MaxJWKSBytes+1)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	raw, maxAge, err := HTTPFetcher(srv.URL+"/.well-known/jwks.json", nil)(ctx)
	if err != nil || maxAge != time.Hour || !strings.Contains(string(raw), `"kid":"a"`) {
		t.Fatalf("got %q, %s, %v", raw, maxAge, err)
	}
	for _, path := range []string{"/moved", "/huge", "/missing"} {
		if _, _, err := HTTPFetcher(srv.URL+path, srv.Client())(ctx); err == nil {
			t.Errorf("%s: want an error", path)
		}
	}
}

func TestMaxAgeOf(t *testing.T) {
	for cc, want := range map[string]time.Duration{
		"public, max-age=3600": time.Hour,
		"Max-Age=300":          5 * time.Minute,
		"no-store":             0,
		"max-age=nope":         0,
		"":                     0,
	} {
		if got := maxAgeOf(cc); got != want {
			t.Errorf("%q: %s, want %s", cc, got, want)
		}
	}
}

func TestRemoteKeysDeadlineBeforeTheFirstSetIsSaidApart(t *testing.T) {
	testKeys(t)
	src := &source{gate: make(chan struct{})}
	defer close(src.gate)
	src.set(setOf("a"), false)
	r := NewRemoteKeys(src.fetch, 0, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := r.Key(ctx, "a")
	if !errors.Is(err, ErrUnknownKid) || !errors.Is(err, ErrNoKeySet) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want ErrUnknownKid, ErrNoKeySet and the deadline, got %v", err)
	}
	// Once ended, a ctx before any call is the same.
	_, err = r.Key(ctx, "a")
	if !errors.Is(err, ErrNoKeySet) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("an ended ctx before the first set: %v", err)
	}
}

func TestRemoteKeysBoundAFetcherThatIgnoresItsContext(t *testing.T) {
	testKeys(t)
	src := &source{gate: make(chan struct{})}
	defer close(src.gate)
	src.set(setOf("a"), false)
	r := NewRemoteKeys(src.fetch, 0, nil)
	r.timeout = 100 * time.Millisecond
	done := make(chan error, 1)
	go func() { _, err := r.Key(context.Background(), "a"); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNoKeySet) {
			t.Fatalf("want ErrNoKeySet, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a fetcher that ignores its context held the caller past the fetch timeout")
	}
}

func TestHTTPFetcherRefusesAPlainHTTPHost(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer srv.Close()
	for _, url := range []string{"http://auth.example.com/.well-known/jwks.json", "ftp://auth.example.com/jwks", "://bad"} {
		if _, _, err := HTTPFetcher(url, nil)(context.Background()); err == nil || !strings.Contains(err.Error(), "https") {
			t.Errorf("%s: want an https error, got %v", url, err)
		}
	}
	_, _, _ = HTTPFetcher(srv.URL, nil)(context.Background())
	if hits.Load() != 1 {
		t.Fatalf("http on 127.0.0.1 is allowed: %d hits", hits.Load())
	}
}
