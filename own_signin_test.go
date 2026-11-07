package cauthy

import (
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
)

func TestSignsInWithAPasswordAndGivesTheBrowserNoToken(t *testing.T) {
	a, f := ownAuth(t, nil)
	b := cauthytest.NewBrowser("")
	r := b.Request("POST", "/api/auth/sign-in/email", map[string]any{"email": " member@example.com ", "password": memberPassword})
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.2")
	r.Header.Set("Accept-Language", "es")
	res := b.Do(a, r)
	body := cauthytest.JSON(res)
	if res.StatusCode != 200 || body["status"] != "signed_in" || body["next"] != "done" || at(body, "session", "user", "email") != "member@example.com" ||
		strings.Contains(toJSON(body), "at-") || b.Jar["cauthy_session.0"] == "" {
		t.Fatalf("%d %v", res.StatusCode, body)
	}
	login := f.Last("POST /v1/auth/login")
	if login.JSON["email"] != "member@example.com" || login.Header.Get("Accept-Language") != "es" || login.Header.Get("X-Cauthy-Remember") != "" {
		t.Fatalf("%v %v", login.JSON, login.Header)
	}
	if code, m := status(a, b, "POST", "/api/auth/sign-in/email", map[string]any{"email": "member@example.com", "password": "wrong"}); code != 401 || errCode(m) != "invalid_credentials" {
		t.Fatalf("%d %v", code, m)
	}
	if code, m := status(a, b, "POST", "/api/auth/sign-in/email", map[string]any{"email": "not-an-email", "password": "x"}); code != 400 || at(m, "error", "field") != "email" {
		t.Fatalf("%d %v", code, m)
	}
	if code, m := status(a, b, "POST", "/api/auth/sign-out", map[string]any{}); code != 200 || m["status"] != "signed_out" || b.Jar["cauthy_session.0"] != "" {
		t.Fatalf("%d %v %v", code, m, b.Jar)
	}
}

func TestTheSecondStepNeverShowsWhatProvesTheFirst(t *testing.T) {
	a, f := ownAuth(t, nil)
	f.On("POST /v1/auth/login", func(c cauthytest.Call) cauthytest.Reply {
		if c.Header.Get("X-Cauthy-Remember") != "1" {
			t.Error("remember is said to Cauthy")
		}
		return cauthytest.Data(map[string]any{"mfa_required": true, "mfa_token": "mfa-secret", "mfa_method": "email"})
	})
	f.On("POST /v1/auth/mfa/challenge", func(c cauthytest.Call) cauthytest.Reply {
		if c.JSON["mfa_token"] != "mfa-secret" {
			return cauthytest.Refuse(401, "invalid_mfa", "no")
		}
		if c.JSON["code"] != "123456" && c.JSON["push"] != true {
			return cauthytest.Refuse(401, "invalid_code", "That code is not right.")
		}
		return cauthytest.Data(f.Issue("u-member"))
	})
	f.On("POST /v1/auth/mfa/methods", func(cauthytest.Call) cauthytest.Reply {
		return cauthytest.Data(map[string]any{"totp": true, "phone": map[string]any{"number": "+57•••12"}, "push": map[string]any{"devices": 1.0}})
	})
	f.On("POST /v1/auth/mfa/send", func(cauthytest.Call) cauthytest.Reply {
		return cauthytest.Data(map[string]any{"sent_to": "+57•••12", "channel": "whatsapp"})
	})
	f.On("POST /v1/auth/mfa/push", func(cauthytest.Call) cauthytest.Reply { return cauthytest.Data(map[string]any{"number": 42.0}) })
	b := cauthytest.NewBrowser("")
	_, m := status(a, b, "POST", "/api/auth/sign-in/email", map[string]any{"email": "member@example.com", "password": memberPassword, "remember": true})
	if m["status"] != "mfa_required" || m["method"] != "email" || m["next"] != "mfa" || strings.Contains(toJSON(m), "mfa-secret") || b.Jar["cauthy_session_step"] == "" {
		t.Fatalf("%v", m)
	}
	if _, m := status(a, b, "POST", "/api/auth/sign-in/mfa/methods", map[string]any{}); m["totp"] != true || at(m, "phone", "channel") != "sms" || at(m, "push", "devices") != 1.0 || m["email"] != nil {
		t.Fatalf("%v", m)
	}
	if _, m := status(a, b, "POST", "/api/auth/sign-in/mfa/send", map[string]any{}); m["channel"] != "whatsapp" || m["next"] != "mfa" {
		t.Fatalf("%v", m)
	}
	if _, m := status(a, b, "POST", "/api/auth/sign-in/mfa/push", map[string]any{}); m["number"] != 42.0 {
		t.Fatalf("%v", m)
	}
	if code, m := status(a, b, "POST", "/api/auth/sign-in/mfa", map[string]any{"code": "000000"}); code != 401 || at(m, "error", "field") != "code" {
		t.Fatalf("%d %v", code, m)
	}
	if _, m := status(a, b, "POST", "/api/auth/sign-in/mfa", map[string]any{"code": " 123456 "}); m["status"] != "signed_in" || b.Jar["cauthy_session_step"] != "" {
		t.Fatalf("%v %v", m, b.Jar)
	}
	if code, m := status(a, cauthytest.NewBrowser(""), "POST", "/api/auth/sign-in/mfa", map[string]any{"code": "123456"}); code != 400 || errCode(m) != "step_expired" {
		t.Fatalf("another browser has no step: %d %v", code, m)
	}
}

func TestSignUpForgotDiscoverAndGuest(t *testing.T) {
	a, f := ownAuth(t, func(o *Options) { o.Pages.VerifyEmail = "/verify"; o.Pages.ResetPassword = "/reset" })
	f.Settings["password_policy"] = map[string]any{"min_length": 12.0}
	f.On("POST /v1/auth/register", func(c cauthytest.Call) cauthytest.Reply {
		if c.Header.Get("X-Cauthy-Link-To") != "https://app.test/verify" || at(c.JSON, "organization", "name") != "Acme Billing" || c.JSON["accept_legal"] != true {
			t.Errorf("%v %v", c.Header, c.JSON)
		}
		return cauthytest.Data(map[string]any{"verification_required": true})
	})
	b := cauthytest.NewBrowser("")
	if code, m := status(a, b, "POST", "/api/auth/sign-up/email", map[string]any{"email": "new@example.com", "password": "short"}); code != 400 || errCode(m) != "too_short" {
		t.Fatalf("checked against the workspace's rule: %d %v", code, m)
	}
	_, m := status(a, b, "POST", "/api/auth/sign-up/email", map[string]any{"name": "New", "email": "new@example.com", "password": "a long enough password",
		"organization": "Acme Billing", "acceptLegal": true})
	if m["status"] != "verification_required" || m["email"] != "new@example.com" || m["next"] != "verify_email" {
		t.Fatalf("%v", m)
	}
	f.On("POST /v1/auth/password/reset", func(cauthytest.Call) cauthytest.Reply { return cauthytest.Refuse(404, "not_found", "no such account") })
	if _, m := status(a, b, "POST", "/api/auth/forgot-password", map[string]any{"email": "nobody@example.com"}); m["status"] != "sent" {
		t.Fatalf("the same answer for any address: %v", m)
	}
	if f.Last("POST /v1/auth/password/reset").Header.Get("X-Cauthy-Link-To") != "https://app.test/reset" {
		t.Fatal("the link opens the application's page")
	}
	f.On("POST /v1/auth/sso/discover", func(cauthytest.Call) cauthytest.Reply {
		return cauthytest.Data(map[string]any{"connection": map[string]any{"slug": "acme-okta", "display_name": "Acme", "enforced": true}})
	})
	if _, m := status(a, b, "POST", "/api/auth/sign-in/sso/discover", map[string]any{"email": "ana@acme.example.com"}); m["status"] != "found" || at(m, "connection", "id") != "acme-okta" {
		t.Fatalf("%v", m)
	}
	f.On("POST /v1/auth/anonymous", func(cauthytest.Call) cauthytest.Reply {
		f.AddUser(cauthytest.User{Sub: "g1", Name: "Guest", Active: true, Anonymous: true}, "")
		return cauthytest.Data(f.Issue("g1"))
	})
	if _, m := status(a, b, "POST", "/api/auth/sign-in/anonymous", map[string]any{}); m["status"] != "signed_in" || at(m, "session", "user", "isAnonymous") != true {
		t.Fatalf("%v", m)
	}
}

func TestOwnPagesAreRecognizedAndTheValveForOldClients(t *testing.T) {
	a, _ := ownAuth(t, nil)
	b := cauthytest.NewBrowser("")
	r := b.Request("POST", "/api/auth/sign-in/email", map[string]any{"email": "member@example.com", "password": memberPassword})
	r.Header.Set("Origin", "https://app.test")
	if res := b.Do(a, r); res.StatusCode != 200 {
		t.Fatalf("own origin: %d", res.StatusCode)
	}
	proxied := cauthytest.NewBrowser("http://internal:8080")
	r = proxied.Request("POST", "/api/auth/sign-out", map[string]any{})
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Origin", "https://internal:8080")
	if res := proxied.Do(a, r); res.StatusCode != 200 {
		t.Fatalf("a proxy that ends TLS: %d", res.StatusCode)
	}
	old := cauthytest.NewBrowser("")
	old.NoRequestHeader = true
	warn := newAuth(t, cauthytest.New(), func(o *Options) { o.RequestHeader = "warn" })
	if code, _ := status(warn, old, "POST", "/api/auth/sign-out", map[string]any{}); code != 200 {
		t.Fatalf("warn lets it through: %d", code)
	}
}
