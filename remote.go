package cauthy

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultCooldown is the least time between two fetches of the JWKS (K3).
	DefaultCooldown = 30 * time.Second
	// DefaultJWKSAge is how long a set is kept when its answer names no max-age.
	DefaultJWKSAge = 5 * time.Minute
	// MaxJWKSAge caps the max-age a JWKS answer may ask for.
	MaxJWKSAge = time.Hour
	// MaxJWKSBytes is the largest JWKS answer read.
	MaxJWKSBytes = 64 << 10
	// FetchTimeout bounds one fetch of the JWKS.
	FetchTimeout = 5 * time.Second
)

// Fetcher answers the issuer's JWKS and how long it may be kept (zero when
// the answer does not say).
type Fetcher func(ctx context.Context) (jwks []byte, maxAge time.Duration, err error)

// RemoteKeys is the issuer's JWKS, fetched when needed (rules K2–K5):
//
//   - fetched on first use, and again once older than its max-age;
//   - a kid the set does not hold triggers a fetch only when the last fetch
//     started at least the cooldown ago; otherwise it is unknown at once;
//   - one fetch at a time: callers that need one while it runs wait for it;
//   - a failed fetch keeps the last good set.
type RemoteKeys struct {
	fetch    Fetcher
	cooldown time.Duration
	now      func() time.Time

	mu      sync.Mutex
	set     *StaticKeys
	maxAge  time.Duration
	fetched time.Time     // when set arrived
	tried   time.Time     // when the last fetch started
	running chan struct{} // closed when the fetch in flight ends
}

// NewRemoteKeys answers a key set fed by fetch. A cooldown of zero means
// DefaultCooldown; now nil means time.Now.
func NewRemoteKeys(fetch Fetcher, cooldown time.Duration, now func() time.Time) *RemoteKeys {
	if cooldown <= 0 {
		cooldown = DefaultCooldown
	}
	if now == nil {
		now = time.Now
	}
	return &RemoteKeys{fetch: fetch, cooldown: cooldown, now: now}
}

// Loaded reports whether a set has ever been fetched.
func (r *RemoteKeys) Loaded() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.set != nil
}

// Key answers the key with kid, fetching the set when the rules allow. The
// fetch runs on its own context with its own FetchTimeout, so a caller that
// gives up neither aborts it nor sets a cooldown for nothing; every caller
// stops waiting on its own ctx.
func (r *RemoteKeys) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	for {
		if ctx.Err() != nil {
			return nil, r.gaveUp(ctx)
		}
		r.mu.Lock()
		now := r.now()
		if r.set != nil && now.Sub(r.fetched) < r.maxAge {
			if key, err := r.set.Key(ctx, kid); !errors.Is(err, ErrUnknownKid) {
				r.mu.Unlock()
				return key, err
			}
		}
		ch := r.running
		if ch == nil {
			if !r.tried.IsZero() && now.Sub(r.tried) < r.cooldown {
				set := r.set
				r.mu.Unlock()
				if set == nil {
					return nil, fmt.Errorf("%w: %w", ErrUnknownKid, ErrNoKeySet)
				}
				return set.Key(ctx, kid)
			}
			r.tried = now
			ch = make(chan struct{})
			r.running = ch
			go r.refresh(context.WithoutCancel(ctx), ch)
		}
		r.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, r.gaveUp(ctx)
		}
	}
}

// gaveUp is the error of a caller whose ctx ended. Before any set arrived it
// wraps ErrNoKeySet beside ErrUnknownKid: a request deadline that runs out
// while Cauthy has never answered is an outage (503), not a forged kid.
func (r *RemoteKeys) gaveUp(ctx context.Context) error {
	if r.Loaded() {
		return ctx.Err()
	}
	return fmt.Errorf("%w: %w: %w", ErrUnknownKid, ErrNoKeySet, ctx.Err())
}

// refresh fetches and installs the set, then closes ch. A panic in the
// fetcher counts as a failed fetch, so ch always closes.
func (r *RemoteKeys) refresh(ctx context.Context, ch chan struct{}) {
	var (
		set    *StaticKeys
		maxAge time.Duration
	)
	func() {
		defer func() {
			if recover() != nil {
				set = nil
			}
		}()
		ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
		defer cancel()
		raw, age, err := r.fetch(ctx)
		if err != nil {
			return
		}
		if parsed, err := ParseJWKS(raw); err == nil {
			set, maxAge = parsed, age
		}
	}()

	r.mu.Lock()
	defer r.mu.Unlock()
	if set != nil {
		if maxAge <= 0 {
			maxAge = DefaultJWKSAge
		}
		r.set, r.fetched, r.maxAge = set, r.now(), min(maxAge, MaxJWKSAge)
	}
	r.running = nil
	close(ch)
}

// HTTPFetcher fetches the JWKS at url: GET, no redirects, a 200 only, at
// most MaxJWKSBytes, within FetchTimeout; max-age from Cache-Control. A nil
// client is a plain one.
func HTTPFetcher(url string, client *http.Client) Fetcher {
	c := &http.Client{Timeout: FetchTimeout}
	if client != nil {
		copied := *client
		c = &copied
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return func(ctx context.Context) ([]byte, time.Duration, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, 0, err
		}
		res, err := c.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return nil, 0, fmt.Errorf("cauthy: JWKS answered %d", res.StatusCode)
		}
		raw, err := io.ReadAll(io.LimitReader(res.Body, MaxJWKSBytes+1))
		if err != nil {
			return nil, 0, err
		}
		if len(raw) > MaxJWKSBytes {
			return nil, 0, fmt.Errorf("cauthy: JWKS is larger than %d bytes", MaxJWKSBytes)
		}
		return raw, maxAgeOf(res.Header.Get("Cache-Control")), nil
	}
}

// maxAgeOf reads max-age from a Cache-Control value; zero when absent.
func maxAgeOf(cc string) time.Duration {
	for _, part := range strings.Split(cc, ",") {
		if v, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(part)), "max-age="); ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				return time.Duration(n) * time.Second
			}
		}
	}
	return 0
}
