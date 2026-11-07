package cauthy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
)

const testSecret = "acme-secret-for-tests-only-0123456789abcdef"

// noEnv is an environment with nothing set.
func noEnv(string) string { return "" }

// newAuth is Auth in variables mode on a fake Cauthy, for the workspace
// "acme" and the client "acme-crm".
func newAuth(t *testing.T, f *cauthytest.Fake, change func(*Options)) *Auth {
	t.Helper()
	o := Options{Issuer: f.Issuer, ClientID: "acme-crm", Secret: testSecret, Tenant: "acme", HTTPClient: f.Client(), Getenv: noEnv,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if change != nil {
		change(&o)
	}
	a, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// signIn signs the browser in through the hosted page as sub.
func signIn(t *testing.T, a *Auth, f *cauthytest.Fake, b *cauthytest.Browser, sub string) {
	t.Helper()
	res := b.Send(a, "GET", "/api/auth/login?return_to=/invoices", nil)
	back, err := f.Authorize(res.Header.Get("Location"), sub)
	if err != nil {
		t.Fatal(err)
	}
	res = b.Send(a, "GET", strings.TrimPrefix(back, b.Origin), nil)
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/invoices" {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("callback: %d %s %s", res.StatusCode, res.Header.Get("Location"), body)
	}
}

// nodeFixture reads one value of internal/jose/testdata/node-fixtures.json.
func nodeFixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile("internal/jose/testdata/node-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m[name].(string)
}

func toJSON(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

const memberPassword = "correct horse battery staple"

// ownAuth is Auth for the own screens, on a fake Cauthy that serves them,
// with member@example.com (u-member) signing in with memberPassword.
func ownAuth(t *testing.T, change func(*Options)) (*Auth, *cauthytest.Fake) {
	t.Helper()
	f := cauthytest.New()
	f.OwnScreens = true
	f.AddUser(cauthytest.User{Sub: "u-member", Email: "member@example.com", Name: "Acme Member", Active: true}, memberPassword)
	return newAuth(t, f, change), f
}

// signInOwn signs the browser in on the own screens.
func signInOwn(t *testing.T, a *Auth, b *cauthytest.Browser) map[string]any {
	t.Helper()
	res := b.Send(a, "POST", "/api/auth/sign-in/email", map[string]any{"email": "member@example.com", "password": memberPassword})
	body := cauthytest.JSON(res)
	if res.StatusCode != 200 || body["status"] != "signed_in" {
		t.Fatalf("sign-in: %d %v", res.StatusCode, body)
	}
	return body
}

// status sends and answers the status and the JSON body.
func status(a *Auth, b *cauthytest.Browser, method, path string, body any) (int, map[string]any) {
	res := b.Send(a, method, path, body)
	return res.StatusCode, cauthytest.JSON(res)
}

// errCode is the code of an error answer.
func errCode(body map[string]any) string { return str(at(body, "error", "code")) }
