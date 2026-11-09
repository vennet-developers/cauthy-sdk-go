package cauthy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/system"
)

// AppIdentity is who the application is, as Cauthy answers it
// (GET /v1/connect/self, key/cauthy-key.md §7). An application on CAUTHY_KEY
// learns its workspace, system and addresses from it.
type AppIdentity struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	Tenant   struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
	} `json:"tenant"`
	System         string   `json:"system"`
	ClientID       string   `json:"client_id"`
	SignInClientID string   `json:"sign_in_client_id"`
	AppURLs        []string `json:"app_urls"`
	CallbackPath   string   `json:"callback_path"`
	Key            *struct {
		Kid       string  `json:"kid"`
		RetiresAt *string `json:"retires_at"`
	} `json:"key"`
	Contract *struct {
		Link                 string `json:"link"`
		SystemProof          string `json:"system_proof"`
		RequireVerifiedEmail bool   `json:"require_verified_email"`
	} `json:"contract"`
}

// ErrUnavailable is Cauthy not having answered who the application is yet:
// the auth routes answer 503 unavailable until it does.
var ErrUnavailable = errors.New("cauthy: Cauthy cannot be reached yet")

// ErrMisconfigured is Cauthy refusing the application's key: revoked, or
// never registered. The auth routes answer 503 misconfigured.
var ErrMisconfigured = errors.New("cauthy: Cauthy refuses this application's key: make a new one in Cauthy's dashboard")

// revalidateEvery is how often the identity is asked again (If-None-Match).
const revalidateEvery = 5 * time.Minute

// identitySource asks Cauthy who the application is: once at start, retried
// with backoff until answered, then again every five minutes. Cauthy down:
// the last answer stands.
type identitySource struct {
	issuer string
	token  func(ctx context.Context) (string, error) // the system client's
	http   *http.Client
	now    func() time.Time
	retry  []time.Duration
	log    *slog.Logger
	kid    string

	once       sync.Once
	mu         sync.RWMutex
	held       *AppIdentity
	etag       string
	checkedAt  time.Time
	refreshing bool
	refused    bool
	ready      chan struct{} // closed with the first answer or the refusal
}

func newIdentitySource(issuer string, token func(context.Context) (string, error), hc *http.Client, now func() time.Time, log *slog.Logger, kid string) *identitySource {
	return &identitySource{issuer: issuer, token: token, http: hc, now: now, log: log, kid: kid,
		retry: []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second},
		ready: make(chan struct{})}
}

// start asks for the first answer in the background, retrying until Cauthy
// answers or refuses the key. Later calls do nothing.
func (s *identitySource) start() {
	s.once.Do(func() { go s.first() })
}

func (s *identitySource) first() {
	for attempt := 0; ; attempt++ {
		err := s.ask(context.Background())
		if err == nil {
			close(s.ready)
			return
		}
		if refusal(err) {
			s.mu.Lock()
			s.refused = true
			s.mu.Unlock()
			s.log.Error("cauthy: Cauthy refuses this application's key: it was revoked or never registered. Make a new key in Cauthy's dashboard", "kid", s.kid)
			close(s.ready)
			return
		}
		time.Sleep(s.retry[min(attempt, len(s.retry)-1)])
	}
}

// refusal is the token endpoint refusing the key itself.
func refusal(err error) bool {
	var e *system.APIError
	return errors.As(err, &e) && e.Code == "invalid_client"
}

// ask calls /v1/connect/self once and keeps what it answers.
func (s *identitySource) ask(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tok, err := s.token(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.issuer+"/v1/connect/self", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	s.mu.RLock()
	if s.held != nil && s.etag != "" {
		req.Header.Set("If-None-Match", s.etag)
	}
	s.mu.RUnlock()
	res, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotModified {
		s.mu.Lock()
		s.checkedAt = s.now()
		s.mu.Unlock()
		return nil
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("cauthy: Cauthy answered %d to /v1/connect/self", res.StatusCode)
	}
	var body struct {
		Data *AppIdentity `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&body); err != nil || body.Data == nil {
		return errors.New("cauthy: Cauthy's answer to /v1/connect/self is not an identity")
	}
	s.mu.Lock()
	s.held, s.etag, s.checkedAt = body.Data, res.Header.Get("ETag"), s.now()
	s.mu.Unlock()
	return nil
}

// refresh asks again now; any failure keeps the last answer.
func (s *identitySource) refresh(ctx context.Context) {
	_ = s.ask(ctx)
}

// Current is the last answer, or nil before the first.
func (s *identitySource) Current() *AppIdentity {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.held
}

// Wait is the identity, waiting for the first answer until ctx is done:
// ErrMisconfigured when Cauthy refused the key, ErrUnavailable when it has
// not answered yet. An answer older than five minutes is asked again in the
// background.
func (s *identitySource) Wait(ctx context.Context) (*AppIdentity, error) {
	select {
	case <-s.ready:
	case <-ctx.Done():
		return nil, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refused {
		return nil, ErrMisconfigured
	}
	if !s.refreshing && s.now().Sub(s.checkedAt) >= revalidateEvery {
		s.refreshing = true
		go func() {
			s.refresh(context.Background())
			s.mu.Lock()
			s.refreshing = false
			s.mu.Unlock()
		}()
	}
	return s.held, nil
}
