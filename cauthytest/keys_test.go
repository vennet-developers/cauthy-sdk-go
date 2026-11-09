package cauthytest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/cauthykey"
)

func jti() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func post(t *testing.T, f *Fake, path string, form url.Values) *http.Response {
	t.Helper()
	res, err := f.Client().PostForm(f.Issuer+path, form)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func withAssertion(k *cauthykey.Key, form url.Values) url.Values {
	form.Set("client_id", k.ClientID)
	form.Set("client_assertion_type", cauthykey.AssertionType)
	form.Set("client_assertion", k.Derive().Assertion(k.ClientID, k.Issuer+"/v1/oauth/token", jti(), time.Now()))
	return form
}

func TestAnIssuedKeyBuysATokenThatAnswersWhoTheApplicationIs(t *testing.T) {
	f := New()
	key := f.IssueKey()
	k, err := cauthykey.Parse(key)
	if err != nil {
		t.Fatal(err)
	}
	if k.Issuer != f.Issuer || k.ClientID != f.ClientID {
		t.Fatalf("%s %s", k.Issuer, k.ClientID)
	}
	res := post(t, f, "/v1/oauth/token", withAssertion(k, url.Values{"grant_type": {"client_credentials"}}))
	body := JSON(res)
	tok, _ := body["access_token"].(string)
	if res.StatusCode != 200 || tok == "" {
		t.Fatalf("%d %v", res.StatusCode, body)
	}
	req, _ := http.NewRequest("GET", f.Issuer+"/v1/connect/self", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	res, _ = f.Client().Do(req)
	etag := res.Header.Get("ETag")
	data, _ := JSON(res)["data"].(map[string]any)
	tenant, _ := data["tenant"].(map[string]any)
	key2, _ := data["key"].(map[string]any)
	urls, _ := data["app_urls"].([]any)
	if res.StatusCode != 200 || data["client_id"] != f.ClientID || tenant["slug"] != f.Tenant || data["system"] != f.System ||
		len(urls) != 1 || urls[0] != "http://localhost:3000" || key2["kid"] != k.Derive().KID || data["issuer"] != f.Issuer || etag == "" {
		t.Fatalf("%d %v", res.StatusCode, data)
	}
	req.Header.Set("If-None-Match", etag)
	if res, _ = f.Client().Do(req); res.StatusCode != http.StatusNotModified {
		t.Fatalf("revalidation: %d", res.StatusCode)
	}
	if kids := f.RegisteredKids(); len(kids) != 1 || kids[0] != k.Derive().KID {
		t.Fatalf("%v", kids)
	}
	// Without a system token, nobody is told.
	req.Header.Set("Authorization", "Bearer at-1")
	if res, _ = f.Client().Do(req); res.StatusCode != 401 {
		t.Fatalf("%d", res.StatusCode)
	}
}

func TestAReplayedAssertionAndARevokedKeyAreRefused(t *testing.T) {
	f := New()
	k, _ := cauthykey.Parse(f.IssueKey())
	form := withAssertion(k, url.Values{"grant_type": {"client_credentials"}})
	if res := post(t, f, "/v1/oauth/token", form); res.StatusCode != 200 {
		t.Fatalf("%d", res.StatusCode)
	}
	res := post(t, f, "/v1/oauth/token", form)
	if body := JSON(res); res.StatusCode != 401 || body["error"] != "invalid_client" {
		t.Fatalf("replay: %d %v", res.StatusCode, body)
	}
	f.RevokeKey(k.Derive().KID)
	res = post(t, f, "/v1/oauth/token", withAssertion(k, url.Values{"grant_type": {"client_credentials"}}))
	if body := JSON(res); res.StatusCode != 401 || body["error"] != "invalid_client" {
		t.Fatalf("revoked: %d %v", res.StatusCode, body)
	}
	// An assertion for another audience is refused too.
	other := url.Values{"grant_type": {"client_credentials"}, "client_id": {k.ClientID}, "client_assertion_type": {cauthykey.AssertionType}}
	k2, _ := cauthykey.Parse(f.IssueKey())
	other.Set("client_assertion", k2.Derive().Assertion(k2.ClientID, "https://other.test/v1/oauth/token", jti(), time.Now()))
	if res := post(t, f, "/v1/oauth/token", other); res.StatusCode != 401 {
		t.Fatalf("audience: %d", res.StatusCode)
	}
}

func TestAKeyClientsCodeExchangeNeedsTheAssertion(t *testing.T) {
	f := New()
	k, _ := cauthykey.Parse(f.IssueKey())
	verifier := strings.Repeat("v", 48)
	exchange := func(assert bool) *http.Response {
		loc := f.Issuer + "/v1/oauth/authorize?" + url.Values{"response_type": {"code"}, "client_id": {k.ClientID},
			"redirect_uri": {"http://localhost:3000/api/auth/callback"}, "code_challenge": {challengeOf(verifier)}, "state": {"s"}}.Encode()
		back, err := f.Authorize(loc, "u1")
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(back)
		form := url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "client_id": {k.ClientID},
			"redirect_uri": {"http://localhost:3000/api/auth/callback"}, "code_verifier": {verifier}}
		if assert {
			form = withAssertion(k, form)
		}
		return post(t, f, "/v1/oauth/token", form)
	}
	res := exchange(false)
	if body := JSON(res); res.StatusCode != 401 || body["error"] != "invalid_client" {
		t.Fatalf("without: %d %v", res.StatusCode, body)
	}
	res = exchange(true)
	body := JSON(res)
	if res.StatusCode != 200 || body["refresh_token"] == nil {
		t.Fatalf("with: %d %v", res.StatusCode, body)
	}
	rt := body["refresh_token"].(string)
	if res := post(t, f, "/v1/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {k.ClientID}}); res.StatusCode != 401 {
		t.Fatalf("refresh without: %d", res.StatusCode)
	}
	if res := post(t, f, "/v1/oauth/revoke", url.Values{"token": {rt}, "client_id": {k.ClientID}}); res.StatusCode != 401 {
		t.Fatalf("revoke without: %d", res.StatusCode)
	}
	if res := post(t, f, "/v1/oauth/revoke", withAssertion(k, url.Values{"token": {rt}})); res.StatusCode != 200 || len(f.Revoked()) != 1 {
		t.Fatalf("revoke with: %d", res.StatusCode)
	}
	for _, c := range f.Calls() {
		if c.Form.Get("client_secret") != "" {
			t.Fatal("a secret was sent")
		}
	}
}

func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
