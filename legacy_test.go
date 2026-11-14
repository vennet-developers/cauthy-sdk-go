package cauthy

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/cauthykey"
	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
)

// counted is a logger whose deprecation warnings are counted, with the
// process's "said once" memory forgotten for the test.
type counted struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *counted) logger(t *testing.T) *slog.Logger {
	t.Helper()
	forgetDeprecations()
	t.Cleanup(forgetDeprecations)
	return slog.New(slog.NewTextHandler(lockedWriter{c}, nil))
}

type lockedWriter struct{ c *counted }

func (w lockedWriter) Write(p []byte) (int, error) {
	w.c.mu.Lock()
	defer w.c.mu.Unlock()
	return w.c.buf.Write(p)
}

// deprecations are the deprecation records logged, one per line.
func (c *counted) deprecations() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, l := range strings.Split(c.buf.String(), "\n") {
		if strings.Contains(l, "level=WARN") && strings.Contains(l, "deprecated=true") {
			out = append(out, l)
		}
	}
	return out
}

// sessionUser is who /session says is signed in, "" for nobody.
func sessionUser(a *Auth, b *cauthytest.Browser) string {
	_, body := status(a, b, "GET", "/api/auth/session", nil)
	return str(at(body, "session", "user", "id"))
}

func TestKeyPreviousReadsTheOldSessionsAndWritesWithTheNewKey(t *testing.T) {
	f := cauthytest.New()
	old := f.IssueKey()
	next := otherKey(t, f, old)
	before, err := keyAuth(t, f, old, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := cauthytest.NewBrowser("http://localhost:3000")
	signIn(t, before, f, b, "u1")

	after, err := keyAuth(t, f, next, map[string]string{"CAUTHY_KEY_PREVIOUS": old})
	if err != nil {
		t.Fatal(err)
	}
	if sessionUser(after, b) != "u1" {
		t.Fatal("a session of the previous key is not read")
	}
	// A new session is sealed with the new key alone.
	fresh := cauthytest.NewBrowser("http://localhost:3000")
	signIn(t, after, f, fresh, "u1")
	only, err := keyAuth(t, f, next, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sessionUser(only, fresh) != "u1" || sessionUser(before, fresh) != "" {
		t.Fatal("a new session is not sealed with the new key alone")
	}

	g := cauthytest.New()
	g.ClientID = "another-client"
	_, err = keyAuth(t, f, next, map[string]string{"CAUTHY_KEY_PREVIOUS": g.IssueKey()})
	var e *cauthykey.Error
	if !errors.As(err, &e) || e.Reason != "key_previous_mismatch" {
		t.Fatalf("%v", err)
	}
}

func TestKeyReadsTheSessionsOfCauthySecretWhileMoving(t *testing.T) {
	f := cauthytest.New()
	f.AppURLs = []string{"https://app.test"}
	before := newAuth(t, f, nil)
	b := cauthytest.NewBrowser("")
	signIn(t, before, f, b, "u1")

	var c counted
	after, err := New(Options{Getenv: envOf(map[string]string{"CAUTHY_KEY": f.IssueKey(), "CAUTHY_SECRET": testSecret}), HTTPClient: f.Client(), Logger: c.logger(t)})
	if err != nil {
		t.Fatal(err)
	}
	if sessionUser(after, b) != "u1" {
		t.Fatal("a session of CAUTHY_SECRET is not read")
	}
	if d := c.deprecations(); len(d) != 1 || !strings.Contains(d[0], "CAUTHY_SECRET beside CAUTHY_KEY") {
		t.Fatalf("%v", d)
	}
	if strings.Contains(c.buf.String(), testSecret) {
		t.Fatal("the secret is logged")
	}
}

func TestTheVariablesModeWarnsOncePerProcess(t *testing.T) {
	f := cauthytest.New()
	var c counted
	log := c.logger(t)
	for range 2 {
		a := newAuth(t, f, func(o *Options) { o.Logger = log })
		signIn(t, a, f, cauthytest.NewBrowser(""), "u1")
	}
	if d := c.deprecations(); len(d) != 1 || !strings.Contains(d[0], "CAUTHY_KEY") {
		t.Fatalf("%v", d)
	}
}

// moved is the Auth on CAUTHY_KEY with what env adds beside it.
func moved(t *testing.T, f *cauthytest.Fake, key string, env map[string]string, log *slog.Logger) *Auth {
	t.Helper()
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	all := map[string]string{"CAUTHY_KEY": key}
	for k, v := range env {
		all[k] = v
	}
	a, err := New(Options{Getenv: envOf(all), HTTPClient: f.Client(), Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// sessionCookieSet reports whether the answer to GET /api/auth/session set the session cookie.
func sessionCookieSet(a *Auth, b *cauthytest.Browser) bool {
	res := b.Send(a, "GET", "/api/auth/session", nil)
	for _, c := range res.Header.Values("Set-Cookie") {
		if strings.HasPrefix(c, "cauthy_session.0=") && !strings.HasPrefix(c, "cauthy_session.0=;") {
			return true
		}
	}
	return false
}

func TestKeySealsAgainASessionOfCauthySecret(t *testing.T) {
	f := cauthytest.New()
	f.AppURLs = []string{"https://app.test"}
	before := newAuth(t, f, nil)
	b := cauthytest.NewBrowser("")
	signIn(t, before, f, b, "u1")

	key := f.IssueKey()
	if !sessionCookieSet(moved(t, f, key, map[string]string{"CAUTHY_SECRET": testSecret}, nil), b) {
		t.Fatal("a session of CAUTHY_SECRET is not sealed again with the key when read")
	}
	if sessionUser(moved(t, f, key, nil, nil), b) != "u1" {
		t.Fatal("the session is lost with CAUTHY_SECRET")
	}
}

func TestASessionCookieNoKeyOpensIsSaidOnce(t *testing.T) {
	f := cauthytest.New()
	f.AppURLs = []string{"https://app.test"}
	var c counted
	a := moved(t, f, f.IssueKey(), nil, c.logger(t))
	b := cauthytest.NewBrowser("")
	for range 2 {
		b.Jar["cauthy_session.0"] = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..AAAA.BBBB.CCCC"
		if sessionUser(a, b) != "" || len(b.Jar) != 0 {
			t.Fatalf("%v", b.Jar)
		}
	}
	if n := strings.Count(c.buf.String(), "no key of this application opens"); n != 1 {
		t.Fatalf("said %d times: %s", n, c.buf.String())
	}
	if !strings.Contains(c.buf.String(), "CAUTHY_KEY_PREVIOUS") {
		t.Fatal(c.buf.String())
	}
}

// otherKey is CAUTHY_KEY's issuer and client with another secret, registered.
func otherKey(t *testing.T, f *cauthytest.Fake, key string) string {
	t.Helper()
	k, _ := cauthykey.Parse(key)
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	other, err := cauthykey.Compose(k.Issuer, k.ClientID, base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.RegisterKey(other); err != nil {
		t.Fatal(err)
	}
	return other
}
