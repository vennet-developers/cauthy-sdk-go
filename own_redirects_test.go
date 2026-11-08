package cauthy

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
)

func TestGoesToAProviderAndBackForTheBrowserThatLeft(t *testing.T) {
	a, f := ownAuth(t, nil)
	f.On("GET /v1/auth/social/custom:acme", func(c cauthytest.Call) cauthytest.Reply {
		if c.Query.Get("redirect_uri") != "https://app.test/api/auth/callback/custom:acme" || c.Header.Get("X-Cauthy-Link-To") != "https://app.test/api/auth/callback/custom:acme" {
			t.Errorf("names its callback page: %v %v", c.Query, c.Header)
		}
		return cauthytest.Data(map[string]any{"redirect_url": "https://idp.example.com/authorize", "state": "st-1"})
	})
	f.On("GET /v1/auth/social/custom:acme/callback", func(c cauthytest.Call) cauthytest.Reply {
		if c.Query.Get("code") != "c1" || c.Query.Get("state") != "st-1" || c.Header.Get("X-Cauthy-Remember") != "1" {
			t.Errorf("%v %v", c.Query, c.Header)
		}
		return cauthytest.Data(f.Issue("u1"))
	})
	b := cauthytest.NewBrowser("")
	res := b.Send(a, "GET", "/api/auth/sign-in/social/custom%3Aacme?return_to=/invoices&remember=1", nil)
	if res.StatusCode != 302 || res.Header.Get("Location") != "https://idp.example.com/authorize" || b.Jar["cauthy_session_step"] == "" {
		t.Fatalf("%d %v", res.StatusCode, res.Header)
	}
	stranger := cauthytest.NewBrowser("")
	if res := stranger.Send(a, "GET", "/api/auth/callback/custom:acme?code=c1&state=st-1", nil); res.Header.Get("Location") != "/?auth_error=state_mismatch" {
		t.Fatalf("not this browser's question: %v", res.Header.Get("Location"))
	}
	res = b.Send(a, "GET", "/api/auth/callback/custom:acme?code=c1&state=st-1", nil)
	if res.Header.Get("Location") != "/invoices" || b.Jar["cauthy_session.0"] == "" || b.Jar["cauthy_session_step"] != "" {
		t.Fatalf("%v %v", res.Header, b.Jar)
	}
	if res := b.Send(a, "GET", "/api/auth/sign-in/social/Not%20A%20Provider", nil); res.StatusCode != 404 {
		t.Fatalf("a malformed provider is a plain 404: %d", res.StatusCode)
	}
	f.On("GET /v1/auth/social/github", func(cauthytest.Call) cauthytest.Reply {
		return cauthytest.Refuse(404, "provider_unavailable", "not enabled")
	})
	if res := b.Send(a, "GET", "/api/auth/sign-in/social/github?return_to=/x?y=1", nil); res.Header.Get("Location") != "/x?y=1&auth_error=provider_unavailable" {
		t.Fatalf("%v", res.Header.Get("Location"))
	}
}

func TestGoesToTheCompanyAndBackWithTheVerifierOnlyThisBrowserHolds(t *testing.T) {
	a, f := ownAuth(t, nil)
	var challengeSent string
	f.On("POST /v1/auth/sso/start", func(c cauthytest.Call) cauthytest.Reply {
		challengeSent, _ = c.JSON["code_challenge"].(string)
		if c.JSON["email"] != "ana@acme.example.com" || c.JSON["redirect_uri"] != "https://app.test/api/auth/sso/callback" {
			t.Errorf("%v", c.JSON)
		}
		return cauthytest.Data(map[string]any{"redirect_url": "https://okta.example.com/sso"})
	})
	f.On("POST /v1/auth/sso/token", func(c cauthytest.Call) cauthytest.Reply {
		if challenge(c.JSON["code_verifier"].(string)) != challengeSent {
			return cauthytest.Refuse(400, "invalid_grant", "verifier")
		}
		return cauthytest.Data(f.Issue("u1"))
	})
	b := cauthytest.NewBrowser("")
	if res := b.Send(a, "GET", "/api/auth/sign-in/sso?email="+url.QueryEscape("ana@acme.example.com")+"&return_to=/home", nil); res.Header.Get("Location") != "https://okta.example.com/sso" {
		t.Fatalf("%v", res.Header)
	}
	if res := b.Send(a, "GET", "/api/auth/sso/callback?code=xyz", nil); res.Header.Get("Location") != "/home" || b.Jar["cauthy_session.0"] == "" {
		t.Fatalf("%v", res.Header)
	}
	if res := b.Send(a, "GET", "/api/auth/sign-in/sso", nil); res.Header.Get("Location") != "/?auth_error=sso_not_found" {
		t.Fatalf("%v", res.Header)
	}
}

func TestLinksAProviderToTheSignedInAccount(t *testing.T) {
	a, f := ownAuth(t, nil)
	f.On("GET /v1/auth/identities/google/link", func(c cauthytest.Call) cauthytest.Reply {
		if !strings.HasPrefix(c.Header.Get("Authorization"), "Bearer at-") {
			t.Error("as the person")
		}
		return cauthytest.Data(map[string]any{"redirect_url": "https://accounts.example.com/o", "state": "s9"})
	})
	f.On("GET /v1/auth/identities/google/link/callback", func(cauthytest.Call) cauthytest.Reply { return cauthytest.Data(map[string]any{}) })
	b := cauthytest.NewBrowser("")
	if res := b.Send(a, "GET", "/api/auth/me/identities/link/google", nil); res.Header.Get("Location") != "/?auth_error=unauthenticated" {
		t.Fatalf("nobody: %v", res.Header)
	}
	signInOwn(t, a, b)
	b.Send(a, "GET", "/api/auth/me/identities/link/google?return_to=/settings", nil)
	if res := b.Send(a, "GET", "/api/auth/callback/google?code=c&state=s9", nil); res.Header.Get("Location") != "/settings?linked=google" {
		t.Fatalf("%v", res.Header)
	}
}

// renewedCookie is the new session cookie an answer sets, or "".
func renewedCookie(res *http.Response) string {
	for _, c := range res.Header.Values("Set-Cookie") {
		if strings.HasPrefix(c, "cauthy_session.0=") && !strings.HasPrefix(c, "cauthy_session.0=;") {
			return c
		}
	}
	return ""
}

// A session renewed on the way out to a provider, or on the way back, is
// kept even when the provider step fails: the old refresh token is spent.
func TestAJustRenewedSessionSurvivesAFailedProviderStep(t *testing.T) {
	clk := &sessionClock{t: time.Now()}
	a, f := ownAuth(t, func(o *Options) { o.Now = clk.now })
	refuseStart := true
	f.On("GET /v1/auth/identities/google/link", func(cauthytest.Call) cauthytest.Reply {
		if refuseStart {
			return cauthytest.Refuse(409, "identity_taken", "That account is linked elsewhere.")
		}
		return cauthytest.Data(map[string]any{"redirect_url": "https://accounts.example.com/o", "state": "s9"})
	})
	f.On("GET /v1/auth/identities/google/link/callback", func(cauthytest.Call) cauthytest.Reply {
		return cauthytest.Refuse(409, "identity_taken", "That account is linked elsewhere.")
	})
	b := cauthytest.NewBrowser("")
	signInOwn(t, a, b)

	clk.add(time.Hour) // the access token ran out: the next call renews it
	res := b.Send(a, "GET", "/api/auth/me/identities/link/google?return_to=/settings", nil)
	if !strings.Contains(res.Header.Get("Location"), "auth_error=identity_taken") || renewedCookie(res) == "" {
		t.Fatalf("leaving for the provider failed and dropped the renewed session: %v", res.Header)
	}

	refuseStart = false
	b.Send(a, "GET", "/api/auth/me/identities/link/google?return_to=/settings", nil)
	clk.add(time.Hour)
	res = b.Send(a, "GET", "/api/auth/callback/google?code=c&state=s9", nil)
	if !strings.Contains(res.Header.Get("Location"), "auth_error=identity_taken") || renewedCookie(res) == "" {
		t.Fatalf("the provider's answer failed and dropped the renewed session: %v", res.Header)
	}
}
