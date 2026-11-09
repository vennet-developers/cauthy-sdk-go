package cauthy

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/system"
)

const testIdentity = `{"issuer":"https://id.test","audience":"https://id.test","tenant":{"id":"t1","slug":"acme"},"system":"acme-crm",
"client_id":"client_x","sign_in_client_id":"client_x","app_urls":["http://localhost:3000"],"callback_path":"/api/auth/callback",
"key":{"kid":"k1","retires_at":null},"contract":null}`

// scripted is a Cauthy that answers /v1/connect/self from a script, one
// answer per call; the last answer repeats.
type scripted struct {
	mu      sync.Mutex
	answers []func(w http.ResponseWriter, r *http.Request)
	seen    []*http.Request
}

func (s *scripted) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.seen = append(s.seen, r.Clone(context.Background()))
	next := s.answers[0]
	if len(s.answers) > 1 {
		s.answers = s.answers[1:]
	}
	s.mu.Unlock()
	next(w, r)
}

func (s *scripted) calls() []*http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*http.Request(nil), s.seen...)
}

func answerIdentity(etag string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if etag != "" {
			w.Header().Set("ETag", etag)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":` + testIdentity + `}`))
	}
}

func answerStatus(code int) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }
}

func identityOf(srv *httptest.Server, change func(*identitySource)) *identitySource {
	s := newIdentitySource(srv.URL, func(context.Context) (string, error) { return "sys-token", nil }, srv.Client(),
		time.Now, slog.New(slog.DiscardHandler), "k1")
	s.retry = []time.Duration{time.Millisecond}
	if change != nil {
		change(s)
	}
	return s
}

func TestIdentityIsAskedWithTheSystemTokenAndKept(t *testing.T) {
	sc := &scripted{answers: []func(http.ResponseWriter, *http.Request){answerIdentity(`"a"`)}}
	srv := httptest.NewServer(sc)
	defer srv.Close()
	s := identityOf(srv, nil)
	s.start()
	id, err := s.Wait(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id.ClientID != "client_x" || id.Tenant.Slug != "acme" || id.Tenant.ID != "t1" || id.System != "acme-crm" ||
		len(id.AppURLs) != 1 || id.Key == nil || id.Key.Kid != "k1" || id.Contract != nil {
		t.Fatalf("%+v", id)
	}
	if _, err := s.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := sc.calls()
	if len(calls) != 1 || calls[0].URL.Path != "/v1/connect/self" || calls[0].Header.Get("Authorization") != "Bearer sys-token" {
		t.Fatalf("%d calls", len(calls))
	}
}

func TestIdentityRevalidatesWithIfNoneMatchAfterFiveMinutes(t *testing.T) {
	sc := &scripted{answers: []func(http.ResponseWriter, *http.Request){answerIdentity(`"a"`), answerStatus(http.StatusNotModified)}}
	srv := httptest.NewServer(sc)
	defer srv.Close()
	var clock atomic.Int64
	clock.Store(time.Now().Unix())
	s := identityOf(srv, func(s *identitySource) { s.now = func() time.Time { return time.Unix(clock.Load(), 0) } })
	s.start()
	if _, err := s.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.Add(int64(revalidateEvery/time.Second) - 1)
	s.Wait(context.Background())
	if len(sc.calls()) != 1 {
		t.Fatal("asked again before five minutes")
	}
	clock.Add(1)
	s.refresh(context.Background())
	calls := sc.calls()
	if len(calls) != 2 || calls[1].Header.Get("If-None-Match") != `"a"` {
		t.Fatalf("%d calls", len(calls))
	}
	if s.Current() == nil || s.Current().ClientID != "client_x" {
		t.Fatal("the answer is lost on 304")
	}
}

func TestIdentityWaitRevalidatesInTheBackground(t *testing.T) {
	sc := &scripted{answers: []func(http.ResponseWriter, *http.Request){answerIdentity(`"a"`), answerStatus(http.StatusNotModified)}}
	srv := httptest.NewServer(sc)
	defer srv.Close()
	var clock atomic.Int64
	clock.Store(time.Now().Unix())
	s := identityOf(srv, func(s *identitySource) { s.now = func() time.Time { return time.Unix(clock.Load(), 0) } })
	s.start()
	s.Wait(context.Background())
	clock.Add(int64(revalidateEvery / time.Second))
	if _, err := s.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(sc.calls()) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(sc.calls()) != 2 {
		t.Fatal("no revalidation")
	}
}

func TestIdentityKeepsTheLastAnswerWhenCauthyIsDown(t *testing.T) {
	sc := &scripted{answers: []func(http.ResponseWriter, *http.Request){answerIdentity("")}}
	srv := httptest.NewServer(sc)
	s := identityOf(srv, nil)
	s.start()
	if _, err := s.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv.Close()
	s.refresh(context.Background())
	if id, err := s.Wait(context.Background()); err != nil || id.ClientID != "client_x" {
		t.Fatalf("%v %v", id, err)
	}
}

func TestIdentityRetriesTheFirstAsk(t *testing.T) {
	sc := &scripted{answers: []func(http.ResponseWriter, *http.Request){answerStatus(500), answerStatus(502), answerIdentity("")}}
	srv := httptest.NewServer(sc)
	defer srv.Close()
	s := identityOf(srv, nil)
	s.start()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if id, err := s.Wait(ctx); err != nil || id.ClientID != "client_x" {
		t.Fatalf("%v %v", id, err)
	}
	if len(sc.calls()) != 3 {
		t.Fatalf("%d calls", len(sc.calls()))
	}
}

func TestIdentityIsUnavailableWhileNotAnswered(t *testing.T) {
	sc := &scripted{answers: []func(http.ResponseWriter, *http.Request){answerStatus(503)}}
	srv := httptest.NewServer(sc)
	defer srv.Close()
	s := identityOf(srv, func(s *identitySource) { s.retry = []time.Duration{time.Hour} })
	s.start()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := s.Wait(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

func TestIdentityRefusedKeyIsMisconfiguredAndNotRetried(t *testing.T) {
	sc := &scripted{answers: []func(http.ResponseWriter, *http.Request){answerIdentity("")}}
	srv := httptest.NewServer(sc)
	defer srv.Close()
	var asked atomic.Int32
	var logs bytes.Buffer
	s := identityOf(srv, func(s *identitySource) {
		s.token = func(context.Context) (string, error) {
			asked.Add(1)
			return "", &system.APIError{Status: 401, Code: "invalid_client", Message: "Cauthy refused the application's own token (401): "}
		}
		s.log = slog.New(slog.NewTextHandler(&logs, nil))
	})
	s.start()
	for range 2 {
		if _, err := s.Wait(context.Background()); !errors.Is(err, ErrMisconfigured) {
			t.Fatalf("want ErrMisconfigured, got %v", err)
		}
	}
	time.Sleep(20 * time.Millisecond)
	if asked.Load() != 1 || len(sc.calls()) != 0 {
		t.Fatalf("asked %d times", asked.Load())
	}
	if strings.Count(logs.String(), "refuses this application's key") != 1 || !strings.Contains(logs.String(), "kid=k1") {
		t.Fatalf("log: %s", logs.String())
	}
}
