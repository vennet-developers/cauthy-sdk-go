package cauthytest

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestTheFakeSignsAPasswordAccountInAndRenews(t *testing.T) {
	f := New()
	f.OwnScreens = true
	f.AddUser(User{Sub: "u-member", Email: "member@example.com", Name: "Member", Active: true}, "correct horse battery")
	c := f.Client()
	login := func(password string) *http.Response {
		req, _ := http.NewRequest("POST", f.Issuer+"/v1/auth/login", strings.NewReader(`{"email":"member@example.com","password":"`+password+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-Key", "acme")
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := login("wrong"); res.StatusCode != 401 {
		t.Fatalf("%d", res.StatusCode)
	}
	res := login("correct horse battery")
	data := JSON(res)["data"].(map[string]any)
	rt := data["refresh_token"].(string)
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}
	r1, _ := c.PostForm(f.Issuer+"/v1/oauth/token", form)
	r2, _ := c.PostForm(f.Issuer+"/v1/oauth/token", form)
	if r1.StatusCode != 200 || r2.StatusCode != 400 {
		t.Fatalf("a refresh token is used once: %d %d", r1.StatusCode, r2.StatusCode)
	}
	f.On("GET /v1/auth/look/acme-crm", func(Call) Reply { return Data(map[string]any{"brand": "Acme"}) })
	req, _ := http.NewRequest("GET", f.Issuer+"/v1/auth/look/acme-crm", nil)
	res, _ = c.Do(req)
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "Acme") || f.Last("GET /v1/auth/look/acme-crm") == nil {
		t.Fatalf("scripted: %s", body)
	}
	f.Down = true
	if _, err := c.Do(req); err == nil {
		t.Fatal("down must fail")
	}
}

func TestBrowserKeepsAndDropsCookies(t *testing.T) {
	b := NewBrowser("")
	b.Take(http.Header{"Set-Cookie": {"a.0=x; Path=/; HttpOnly", "b=y; Path=/"}})
	b.Take(http.Header{"Set-Cookie": {"b=; Path=/; Max-Age=0"}})
	if len(b.Jar) != 1 || b.Jar["a.0"] != "x" {
		t.Fatalf("%v", b.Jar)
	}
	r := b.Request("POST", "/api/auth/sign-out", map[string]any{})
	if r.Header.Get("X-Cauthy-Request") != "1" || r.Header.Get("Cookie") != "a.0=x" || r.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("%v", r.Header)
	}
}
