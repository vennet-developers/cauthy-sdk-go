package cauthy

import (
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
)

// The gate runs before any own route's handler, so it holds for every route
// of the table, served or not yet.
func TestTheGateOfEveryOwnRoute(t *testing.T) {
	a, _ := ownAuth(t, nil)
	b := cauthytest.NewBrowser("")
	header := cauthytest.NewBrowser("")
	header.NoRequestHeader = true
	if code, body := status(a, header, "POST", "/api/auth/sign-in/email", map[string]any{}); code != 403 || errCode(body) != "csrf_required" {
		t.Fatalf("no X-Cauthy-Request: %d %v", code, body)
	}
	if res := b.Send(a, "GET", "/api/auth/sign-in/email", nil); res.StatusCode != 405 || res.Header.Get("Allow") != "POST" {
		t.Fatalf("GET on a POST route: %d", res.StatusCode)
	}
	r := b.Request("POST", "/api/auth/sign-in/email", map[string]any{"email": "a@example.com", "password": "x"})
	r.Header.Set("Origin", "https://evil.example")
	if res := b.Do(a, r); res.StatusCode != 403 || errCode(cauthytest.JSON(res)) != "cross_site" {
		t.Fatalf("foreign origin: %d", res.StatusCode)
	}
	r = b.Request("POST", "/api/auth/sign-in/email", map[string]any{})
	r.Header.Set("Sec-Fetch-Site", "same-site")
	if res := b.Do(a, r); res.StatusCode != 403 {
		t.Fatalf("Sec-Fetch-Site same-site with no Origin: %d", res.StatusCode)
	}
	for _, body := range []any{"not json", "[]"} {
		if code, got := status(a, b, "POST", "/api/auth/sign-in/email", body); code != 400 || errCode(got) != "bad_request" {
			t.Fatalf("%v: %d %v", body, code, got)
		}
	}
	noTenant := newAuth(t, cauthytest.New(), func(o *Options) { o.Tenant = "" })
	if code, body := status(noTenant, b, "GET", "/api/auth/methods", nil); code != 500 || errCode(body) != "not_configured" {
		t.Fatalf("no tenant: %d %v", code, body)
	}
	if code, body := status(a, b, "POST", "/api/auth/me/password", map[string]any{}); code != 401 || errCode(body) != "unauthenticated" {
		t.Fatalf("a POST under /me runs as the signed-in person: %d %v", code, body)
	}
}
