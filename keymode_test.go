package cauthy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/cauthykey"
	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
)

// envOf is an environment holding only m.
func envOf(m map[string]string) func(string) string {
	return func(name string) string { return m[name] }
}

// quick makes the waits of key mode short for one test.
func quick(t *testing.T) {
	t.Helper()
	start, request, retry := keyStartWait, keyRequestWait, identityRetry
	keyStartWait, keyRequestWait, identityRetry = 100*time.Millisecond, 100*time.Millisecond, []time.Duration{5 * time.Millisecond}
	t.Cleanup(func() { keyStartWait, keyRequestWait, identityRetry = start, request, retry })
}

// keyAuth is Auth on CAUTHY_KEY alone, issued by f.
func keyAuth(t *testing.T, f *cauthytest.Fake, key string, extra map[string]string) (*Auth, error) {
	t.Helper()
	env := map[string]string{"CAUTHY_KEY": key}
	for k, v := range extra {
		env[k] = v
	}
	return New(Options{Getenv: envOf(env), HTTPClient: f.Client(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
}

func TestKeyModeSignsInWithNothingButTheKey(t *testing.T) {
	f := cauthytest.New()
	a, err := keyAuth(t, f, f.IssueKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Issuer() != f.Issuer || a.ClientID() != f.ClientID || a.tenantSlug() != "acme" || a.systemName() != "acme-crm" {
		t.Fatalf("%s %s %s %s", a.Issuer(), a.ClientID(), a.tenantSlug(), a.systemName())
	}
	b := cauthytest.NewBrowser("http://localhost:3000")
	signIn(t, a, f, b, "u1")
	code, body := status(a, b, "GET", "/api/auth/session", nil)
	if code != 200 || str(at(body, "session", "user", "id")) != "u1" {
		t.Fatalf("%d %v", code, body)
	}
	var exchange *cauthytest.Call
	for _, c := range f.Calls() {
		if c.Path == "/v1/oauth/token" && c.Form.Get("grant_type") == "authorization_code" {
			exchange = &c
		}
	}
	if exchange == nil || exchange.Form.Get("client_assertion_type") != cauthykey.AssertionType || exchange.Form.Get("client_assertion") == "" ||
		exchange.Form.Has("client_secret") || exchange.Header.Get("X-Cauthy-System-Token") == "" {
		t.Fatalf("the exchange: %+v", exchange)
	}
	if exchange.Form.Get("redirect_uri") != "http://localhost:3000/api/auth/callback" {
		t.Fatal(exchange.Form.Get("redirect_uri"))
	}
	id, err := a.Identity(context.Background())
	if err != nil || id.Key == nil || id.Key.Kid != f.RegisteredKids()[0] {
		t.Fatalf("%+v %v", id, err)
	}
	// Signing out revokes with the assertion too.
	b.Send(a, "GET", "/api/auth/logout", nil)
	if len(f.Revoked()) != 1 {
		t.Fatal("not revoked")
	}
}

func TestKeyModeRefusesADamagedKeyNamingTheReasonOnly(t *testing.T) {
	f := cauthytest.New()
	key := f.IssueKey()
	last := "A"
	if strings.HasSuffix(key, "A") {
		last = "B"
	}
	_, err := keyAuth(t, f, key[:len(key)-1]+last, nil)
	var e *cauthykey.Error
	if !errors.As(err, &e) || e.Reason != cauthykey.ReasonChecksum {
		t.Fatalf("want key_checksum, got %v", err)
	}
	k, _ := cauthykey.Parse(key)
	if strings.Contains(err.Error(), k.Secret) || strings.Contains(err.Error(), key[:40]) {
		t.Fatal("the error holds the key")
	}
}

func TestKeyModeRefusesTheOldVariablesBesideIt(t *testing.T) {
	f := cauthytest.New()
	_, err := keyAuth(t, f, f.IssueKey(), map[string]string{"CAUTHY_CLIENT_ID": "x", "CAUTHY_BASE_URL": "http://localhost:3000"})
	if err == nil || !strings.Contains(err.Error(), "CAUTHY_CLIENT_ID, CAUTHY_BASE_URL are also set") {
		t.Fatalf("%v", err)
	}
	_, err = keyAuth(t, f, f.IssueKey(), map[string]string{"CAUTHY_AUDIENCE": "x"})
	if err == nil || !strings.Contains(err.Error(), "CAUTHY_AUDIENCE is also set") {
		t.Fatalf("%v", err)
	}
}

func TestKeyModeRefusesOptionsTheKeyOwns(t *testing.T) {
	f := cauthytest.New()
	_, err := New(Options{Key: f.IssueKey(), ClientID: "x", Getenv: noEnv, HTTPClient: f.Client()})
	if err == nil || !strings.Contains(err.Error(), "ClientID comes from CAUTHY_KEY") {
		t.Fatalf("%v", err)
	}
}

func TestKeyModeAnswersUnavailableUntilCauthyAnswers(t *testing.T) {
	quick(t)
	f := cauthytest.New()
	key := f.IssueKey()
	f.SetDown(true)
	a, err := keyAuth(t, f, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := cauthytest.NewBrowser("http://localhost:3000")
	code, body := status(a, b, "GET", "/api/auth/session", nil)
	if code != 503 || errCode(body) != "unavailable" {
		t.Fatalf("%d %v", code, body)
	}
	f.SetDown(false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.Identity(ctx); err != nil {
		t.Fatal(err)
	}
	if code, body := status(a, b, "GET", "/api/auth/session", nil); code != 200 {
		t.Fatalf("%d %v", code, body)
	}
	if a.tenantSlug() != "acme" {
		t.Fatal("the identity is not adopted")
	}
}

func TestKeyModeARevokedKeyIsMisconfigured(t *testing.T) {
	quick(t)
	f := cauthytest.New()
	key := f.IssueKey()
	f.RevokeKey(f.RegisteredKids()[0])
	if _, err := keyAuth(t, f, key, nil); !errors.Is(err, ErrMisconfigured) {
		t.Fatalf("a refusal at start stops the start: %v", err)
	}

	f = cauthytest.New()
	key = f.IssueKey()
	f.SetDown(true)
	a, err := keyAuth(t, f, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.RevokeKey(f.RegisteredKids()[0])
	f.SetDown(false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.Identity(ctx); !errors.Is(err, ErrMisconfigured) {
		t.Fatalf("want ErrMisconfigured, got %v", err)
	}
	code, body := status(a, cauthytest.NewBrowser("http://localhost:3000"), "GET", "/api/auth/session", nil)
	if code != 503 || errCode(body) != "misconfigured" {
		t.Fatalf("%d %v", code, body)
	}
}

func TestKeyModeBuildsTheRedirectURIFromARegisteredOriginOnly(t *testing.T) {
	f := cauthytest.New()
	f.AppURLs = []string{"http://localhost:3000", "https://crm.example.com"}
	a, err := keyAuth(t, f, f.IssueKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	code, body := status(a, cauthytest.NewBrowser("https://evil.example.com"), "GET", "/api/auth/login", nil)
	if code != 400 || errCode(body) != "unknown_origin" || !strings.Contains(str(at(body, "error", "message")), "https://crm.example.com") {
		t.Fatalf("%d %v", code, body)
	}
	res := cauthytest.NewBrowser("https://crm.example.com").Send(a, "GET", "/api/auth/login", nil)
	loc, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != 302 || loc.Query().Get("redirect_uri") != "https://crm.example.com/api/auth/callback" {
		t.Fatalf("%d %s", res.StatusCode, loc)
	}

	// One address: every request's redirect goes there.
	f = cauthytest.New()
	f.AppURLs = []string{"https://crm.example.com"}
	a, err = keyAuth(t, f, f.IssueKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	res = cauthytest.NewBrowser("http://127.0.0.1:3000").Send(a, "GET", "/api/auth/login", nil)
	loc, _ = url.Parse(res.Header.Get("Location"))
	if res.StatusCode != 302 || loc.Query().Get("redirect_uri") != "https://crm.example.com/api/auth/callback" {
		t.Fatalf("%d %s", res.StatusCode, loc)
	}
}

func TestKeyModeSystemClientSignsWithTheKey(t *testing.T) {
	f := cauthytest.New()
	a, err := keyAuth(t, f, f.IssueKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := a.System().Token(context.Background())
	if err != nil || !strings.HasPrefix(tok, "sys-") {
		t.Fatalf("%s %v", tok, err)
	}
	for _, c := range f.Calls() {
		if c.Form.Get("grant_type") == "client_credentials" && (c.Form.Get("client_assertion") == "" || c.Form.Has("client_secret")) {
			t.Fatalf("%+v", c.Form)
		}
	}
	if s := (*a.signer).String(); strings.Contains(s, string(a.signer.Key)) || !strings.Contains(s, a.signer.KID) {
		t.Fatal(s)
	}
}
