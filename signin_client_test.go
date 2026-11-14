package cauthy

import (
	"context"
	"io"
	"log/slog"
	"net/url"
	"testing"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/cauthykey"
	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
	"github.com/vennet-developers/cauthy-sdk-go/internal/jose"
)

// On CAUTHY_KEY people sign in through the client Cauthy names
// (sign_in_client_id), which is not always the key's: the key may be on a
// service client while the people, and their refresh tokens, are on a
// public sign-in client.

const (
	keyClient    = "acme-crm-service"
	signInClient = "acme-crm-web"
)

// detached is a fake whose key is on keyClient, and which names
// signInClient as the client people sign in through.
func detached() (*cauthytest.Fake, string) {
	f := cauthytest.New()
	f.ClientID = keyClient
	key := f.IssueKey()
	f.SignInClients[f.ClientID] = signInClient
	f.AppURLs = []string{"https://app.test"}
	return f, key
}

func keyAuthAt(t *testing.T, f *cauthytest.Fake, key string, c *clock) *Auth {
	t.Helper()
	a, err := New(Options{Getenv: envOf(map[string]string{"CAUTHY_KEY": key}), HTTPClient: f.Client(), Now: c.now,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func callsOf(f *cauthytest.Fake, path, grant string) []cauthytest.Call {
	var out []cauthytest.Call
	for _, c := range f.Calls() {
		if c.Path == path && (grant == "" || c.Form.Get("grant_type") == grant) {
			out = append(out, c)
		}
	}
	return out
}

func TestSignInClientOtherThanTheKeys(t *testing.T) {
	f, key := detached()
	c := &clock{t: time.Now()}
	a := keyAuthAt(t, f, key, c)
	if a.ClientID() != signInClient {
		t.Fatalf("ClientID %s", a.ClientID())
	}
	b := cauthytest.NewBrowser("https://app.test")
	res := b.Send(a, "GET", "/api/auth/login", nil)
	loc, _ := url.Parse(res.Header.Get("Location"))
	if loc.Query().Get("client_id") != signInClient {
		t.Fatalf("authorize as %s", loc.Query().Get("client_id"))
	}
	signIn(t, a, f, b, "u1")

	// The code exchange: the link's public client, the system's proof, no assertion.
	ex := callsOf(f, "/v1/oauth/token", "authorization_code")
	if len(ex) != 1 || ex[0].Form.Get("client_id") != signInClient || ex[0].Form.Has("client_assertion") ||
		ex[0].Form.Has("client_secret") || ex[0].Header.Get("X-Cauthy-System-Token") == "" {
		t.Fatalf("exchange %+v", ex)
	}
	// The key still proves the key's own client.
	cc := callsOf(f, "/v1/oauth/token", "client_credentials")
	if len(cc) == 0 || cc[0].Form.Get("client_id") != keyClient || cc[0].Form.Get("client_assertion_type") != cauthykey.AssertionType {
		t.Fatalf("credentials %+v", cc)
	}

	// Renewed through the sign-in client, which owns the refresh token.
	c.add(time.Hour)
	code, body := status(a, b, "GET", "/api/auth/session", nil)
	if code != 200 || str(at(body, "status")) != "authenticated" {
		t.Fatalf("%d %v", code, body)
	}
	rf := callsOf(f, "/v1/oauth/token", "refresh_token")
	if len(rf) != 1 || rf[0].Form.Get("client_id") != signInClient || rf[0].Form.Has("client_assertion") {
		t.Fatalf("refresh %+v", rf)
	}

	// Signing out revokes, and leaves Cauthy, as the sign-in client.
	out := b.Send(a, "GET", "/api/auth/logout", nil)
	lo, _ := url.Parse(out.Header.Get("Location"))
	rv := callsOf(f, "/v1/oauth/revoke", "")
	if lo.Query().Get("client_id") != signInClient || len(rv) != 1 || rv[0].Form.Get("client_id") != signInClient ||
		rv[0].Form.Has("client_assertion") || len(f.Revoked()) != 1 {
		t.Fatalf("logout %s %+v", out.Header.Get("Location"), rv)
	}
	acc := b.Send(a, "GET", "/api/auth/account", nil)
	if l, _ := url.Parse(acc.Header.Get("Location")); l.Query().Get("client_id") != signInClient {
		t.Fatalf("account %s", acc.Header.Get("Location"))
	}
}

func TestSignInClientSameAsTheKeysIsUnchanged(t *testing.T) {
	f := cauthytest.New()
	// Renewed at once: an access token shorter than the renewal margin
	// (the clock stays, for the key's assertions).
	f.ExpiresIn = 10
	c := &clock{t: time.Now()}
	a := keyAuthAt(t, f, f.IssueKey(), c)
	b := cauthytest.NewBrowser("http://localhost:3000")
	signIn(t, a, f, b, "u1")
	if code, body := status(a, b, "GET", "/api/auth/session", nil); code != 200 || str(at(body, "status")) != "authenticated" {
		t.Fatalf("%d %v", code, body)
	}
	for _, grant := range []string{"authorization_code", "refresh_token"} {
		got := callsOf(f, "/v1/oauth/token", grant)
		if len(got) != 1 || got[0].Form.Get("client_id") != f.ClientID || got[0].Form.Get("client_assertion") == "" {
			t.Fatalf("%s %+v", grant, got)
		}
	}
}

// Session, outside the handler, waits for Cauthy's answer before renewing:
// a refresh token spent on the key's client would be lost.
func TestSignInClientIsWaitedForBeforeARenewal(t *testing.T) {
	f, key := detached()
	c := &clock{t: time.Now()}
	a := keyAuthAt(t, f, key, c)
	b := cauthytest.NewBrowser("https://app.test")
	signIn(t, a, f, b, "u1")
	again := keyAuthAt(t, f, key, c)
	c.add(time.Hour)
	if s := again.Resolve(b.Request("GET", "/", nil)); s.Session == nil || s.Session.User.ID != "u1" {
		t.Fatalf("%+v", s)
	}
	rf := callsOf(f, "/v1/oauth/token", "refresh_token")
	if len(rf) != 1 || rf[0].Form.Get("client_id") != signInClient {
		t.Fatalf("refresh %+v", rf)
	}
}

// VerifierConfigFromKey names no client: a person's token issued through
// the sign-in client is accepted when the key is another client's.
func TestVerifierFromKeyAcceptsTheSignInClientsTokens(t *testing.T) {
	f, key := detached()
	cfg, err := VerifierConfigFromKey(context.Background(), envOf(map[string]string{"CAUTHY_KEY": key}), f.Client())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientID != "" {
		t.Fatalf("the verifier names a client: %s", cfg.ClientID)
	}
	strong, _ := testKeys(t)
	cfg.Keys = staticKeys("k", &strong.PublicKey)
	v, err := NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jose.SignRS256(strong, map[string]any{"kid": "k", "typ": "JWT"}, map[string]any{
		"iss": cfg.Issuer, "aud": []string{cfg.Audience}, "tid": cfg.Tenant, "sub": "5c1b2f4e-9a3d-4b7e-8c6f-0d1e2f3a4b5c", "azp": signInClient,
		"iat": now.Unix() - 60, "exp": now.Unix() + 840,
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := v.VerifyAt(context.Background(), tok, now)
	if err != nil || id.AuthorizedParty != signInClient {
		t.Fatalf("%+v %v", id, err)
	}
}
