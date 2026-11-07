package cauthy

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
)

func TestHostedSignInSessionAndSignOut(t *testing.T) {
	f := cauthytest.New()
	a := newAuth(t, f, nil)
	b := cauthytest.NewBrowser("")

	res := b.Send(a, "GET", "/api/auth/login?return_to=/invoices&prompt=login&locale=es", nil)
	loc, _ := url.Parse(res.Header.Get("Location"))
	q := loc.Query()
	if res.StatusCode != 302 || loc.Host != "id.test" || loc.Path != "/v1/oauth/authorize" || q.Get("redirect_uri") != "https://app.test/api/auth/callback" ||
		q.Get("code_challenge_method") != "S256" || q.Get("prompt") != "login" || q.Get("ui_locales") != "es" || b.Jar["cauthy_session_flow"] == "" ||
		res.Header.Get("Cauthy-Protocol") != "1" || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %s %v", res.StatusCode, loc, res.Header)
	}
	if !strings.Contains(strings.Join(res.Header.Values("Set-Cookie"), ";"), "cauthy_session_flow=") ||
		!strings.Contains(res.Header.Get("Set-Cookie"), "Max-Age=3600; Secure") {
		t.Fatalf("flow cookie: %v", res.Header.Values("Set-Cookie"))
	}
	back, _ := f.Authorize(loc.String(), "u1")
	res = b.Send(a, "GET", strings.TrimPrefix(back, "https://app.test"), nil)
	if res.StatusCode != 302 || res.Header.Get("Location") != "/invoices" || b.Jar["cauthy_session.0"] == "" || b.Jar["cauthy_session_flow"] != "" {
		t.Fatalf("%d %v %v", res.StatusCode, res.Header, b.Jar)
	}

	body := cauthytest.JSON(b.Send(a, "GET", "/api/auth/session/", nil))
	session, _ := body["session"].(map[string]any)
	if body["status"] != "authenticated" || at(session, "user", "email") != "ana@example.com" || session["organizations"] == nil || strings.Contains(toJSON(body), "at-") {
		t.Fatalf("the session, and never a token: %v", body)
	}

	res = b.Send(a, "GET", "/api/auth/logout", nil)
	if !strings.HasPrefix(res.Header.Get("Location"), "https://id.test/v1/oauth/logout?") || b.Jar["cauthy_session.0"] != "" || len(f.Revoked()) != 1 {
		t.Fatalf("%v %v %v", res.Header, b.Jar, f.Revoked())
	}
	if body := cauthytest.JSON(b.Send(a, "GET", "/api/auth/session", nil)); body["status"] != "unauthenticated" || body["session"] != nil {
		t.Fatalf("%v", body)
	}
}

func TestACallbackToAnotherBrowsersQuestionStartsAgainOnce(t *testing.T) {
	f := cauthytest.New()
	a := newAuth(t, f, nil)
	victim := cauthytest.NewBrowser("")
	attacker := cauthytest.NewBrowser("")
	res := attacker.Send(a, "GET", "/api/auth/login", nil)
	back, _ := f.Authorize(res.Header.Get("Location"), "u1")
	path := strings.TrimPrefix(back, "https://app.test")
	res = victim.Send(a, "GET", path, nil)
	if res.StatusCode != 302 || !strings.HasPrefix(res.Header.Get("Location"), "/api/auth/login?return_to=") || victim.Jar["cauthy_session.0"] != "" {
		t.Fatalf("starts again: %d %v", res.StatusCode, res.Header)
	}
	res = victim.Send(a, "GET", path, nil)
	text, _ := io.ReadAll(res.Body)
	if res.StatusCode != 400 || !strings.Contains(string(text), "state_mismatch") || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("then refuses: %d %s", res.StatusCode, text)
	}
}

func TestRefreshAccountAndTheProtocolsEdges(t *testing.T) {
	f := cauthytest.New()
	a := newAuth(t, f, nil)
	b := cauthytest.NewBrowser("")
	if res := b.Send(a, "GET", "/api/auth/refresh?return_to=/x", nil); res.Header.Get("Location") != "/api/auth/login?return_to=%2Fx" {
		t.Fatalf("nobody: to sign in: %v", res.Header)
	}
	res := b.Send(a, "GET", "/api/auth/account?return_to=/settings&locale=es", nil)
	if res.Header.Get("Location") != "https://id.test/v1/oauth/account?client_id=acme-crm&return_to=https%3A%2F%2Fapp.test%2Fsettings&ui_locales=es" {
		t.Fatalf("%v", res.Header.Get("Location"))
	}
	for path, want := range map[string]int{"/api/auth": 404, "/api/auth/nope": 404, "/elsewhere": 404} {
		res := b.Send(a, "GET", path, nil)
		if res.StatusCode != want || res.Header.Get("Cauthy-Protocol") != "1" || res.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %v", path, res.StatusCode, res.Header)
		}
	}
	if res := b.Send(a, "HEAD", "/api/auth/session", nil); res.StatusCode != 200 {
		t.Fatalf("HEAD is GET: %d", res.StatusCode)
	}
	if res := b.Send(a, "POST", "/api/auth/logout", nil); res.StatusCode != http.StatusFound {
		t.Fatalf("a plain form signs out: %d", res.StatusCode)
	}
}

func TestCheckAsksForTheSignedInPerson(t *testing.T) {
	f := cauthytest.New()
	f.SetOrganizations("u1", []map[string]any{{"id": "6f1c1e9e-4a43-4c1b-9f5e-3a1d2b3c4d5e", "system": "acme-crm"}})
	a := newAuth(t, f, func(o *Options) { o.Tenant = "" })
	b := cauthytest.NewBrowser("")
	if res := b.Send(a, "POST", "/api/auth/me/organizations/check", map[string]any{}); res.StatusCode != 401 {
		t.Fatalf("nobody: %d", res.StatusCode)
	}
	signIn(t, a, f, b, "u1")
	ask := map[string]any{"organizationId": "6f1c1e9e-4a43-4c1b-9f5e-3a1d2b3c4d5e", "resource": "invoices", "action": "approve", "attributes": map[string]any{"amount": 500}}
	body := cauthytest.JSON(b.Send(a, "POST", "/api/auth/me/organizations/check", ask))
	if body["status"] != "decided" || body["allowed"] != true || at(body, "rule", "role") != "accountant" {
		t.Fatalf("needs no tenant, only the session: %v", body)
	}
	ask["attributes"] = []any{}
	if res := b.Send(a, "POST", "/api/auth/me/organizations/check", ask); res.StatusCode != 400 {
		t.Fatalf("%d", res.StatusCode)
	}
	if res := b.Send(a, "GET", "/api/auth/me/organizations/check", nil); res.StatusCode != 405 || res.Header.Get("Allow") != "POST" {
		t.Fatalf("%d", res.StatusCode)
	}
}

func TestMountServesBothPaths(t *testing.T) {
	a := newAuth(t, cauthytest.New(), nil)
	mux := http.NewServeMux()
	a.Mount(mux)
	b := cauthytest.NewBrowser("")
	if res := b.Send(mux, "GET", "/api/auth/session", nil); res.StatusCode != 200 {
		t.Fatalf("%d", res.StatusCode)
	}
	if res := b.Send(mux, "GET", DefaultJWKSPath, nil); res.StatusCode != 404 || res.Header.Get("Cauthy-Protocol") != "1" {
		t.Fatalf("no keys published: Auth answers 404 there: %d", res.StatusCode)
	}
}
