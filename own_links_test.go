package cauthy

import (
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
)

func TestWhatAMailedLinkCarriesBack(t *testing.T) {
	a, f := ownAuth(t, nil)
	b := cauthytest.NewBrowser("")
	f.On("POST /v1/auth/password/change", func(c cauthytest.Call) cauthytest.Reply {
		if c.JSON["token"] != "reset-1" {
			return cauthytest.Refuse(422, "invalid_token", "unknown")
		}
		return cauthytest.Reply{Status: 204}
	})
	if code, m := status(a, b, "POST", "/api/auth/reset-password", map[string]any{"token": "", "password": "a long enough password"}); code != 422 || errCode(m) != "invalid_token" {
		t.Fatalf("%d %v", code, m)
	}
	if _, m := status(a, b, "POST", "/api/auth/reset-password", map[string]any{"token": "reset-1", "password": "a long enough password"}); m["status"] != "changed" {
		t.Fatalf("%v", m)
	}
	f.On("POST /v1/auth/email/verify", func(cauthytest.Call) cauthytest.Reply { return cauthytest.Data(f.Issue("u-member")) })
	if _, m := status(a, b, "POST", "/api/auth/verify-email", map[string]any{"token": "v1"}); m["status"] != "signed_in" {
		t.Fatalf("the link proved the address: signed in: %v", m)
	}
	f.On("POST /v1/auth/invitation/accept", func(cauthytest.Call) cauthytest.Reply {
		return cauthytest.Reply{Status: 400, Body: map[string]any{"errors": []any{map[string]any{"code": "weak_password", "message": "weak", "meta": map[string]any{"reasons": []any{"breached"}}}}}}
	})
	code, m := status(a, b, "POST", "/api/auth/invitation/accept", map[string]any{"token": "inv", "password": "a long enough password"})
	if code != 400 || errCode(m) != "weak_password" || at(m, "error", "field") != "password" || len(arr(at(m, "error", "reasons"))) != 1 {
		t.Fatalf("Cauthy's rule passes through: %d %v", code, m)
	}
}

func TestASignInLinkAndItsCode(t *testing.T) {
	a, f := ownAuth(t, func(o *Options) { o.Pages.SignIn = "/sign-in" })
	f.On("POST /v1/auth/magic-link/request", func(c cauthytest.Call) cauthytest.Reply {
		if c.Header.Get("X-Cauthy-Link-To") != "https://app.test/sign-in?remember=1&return_to=%2Finvoices" || c.JSON["create_account"] != true {
			t.Errorf("%v %v", c.Header.Get("X-Cauthy-Link-To"), c.JSON)
		}
		return cauthytest.Reply{Status: 202}
	})
	f.On("POST /v1/auth/magic-link/verify-code", func(c cauthytest.Call) cauthytest.Reply {
		if c.JSON["email"] != "member@example.com" || c.JSON["code"] != "424242" || c.Header.Get("X-Cauthy-Remember") != "1" {
			return cauthytest.Refuse(401, "invalid_code", "no")
		}
		return cauthytest.Data(f.Issue("u-member"))
	})
	b := cauthytest.NewBrowser("")
	if _, m := status(a, b, "POST", "/api/auth/sign-in/magic-link", map[string]any{"email": "member@example.com", "create": true, "returnTo": "/invoices", "remember": true}); m["status"] != "sent" || m["next"] != "code" {
		t.Fatalf("%v", m)
	}
	if _, m := status(a, b, "POST", "/api/auth/sign-in/email-code", map[string]any{"code": "424242"}); m["status"] != "signed_in" || m["returnTo"] != "/invoices" {
		t.Fatalf("%v", m)
	}
	if code, m := status(a, cauthytest.NewBrowser(""), "POST", "/api/auth/sign-in/email-code", map[string]any{"code": "424242"}); code != 400 || errCode(m) != "step_expired" {
		t.Fatalf("not taken from a browser that asked for no link: %d %v", code, m)
	}
	noPage, _ := ownAuth(t, nil)
	if code, m := status(noPage, b, "POST", "/api/auth/sign-in/magic-link", map[string]any{"email": "member@example.com"}); code != 500 || errCode(m) != "not_configured" {
		t.Fatalf("%d %v", code, m)
	}
}

func TestPasskeyAndOneTapCeremonies(t *testing.T) {
	a, f := ownAuth(t, nil)
	f.On("POST /v1/auth/webauthn/login/begin", func(c cauthytest.Call) cauthytest.Reply {
		return cauthytest.Data(map[string]any{"session_id": "wa-1", "options": map[string]any{"publicKey": map[string]any{"challenge": "abc"}}})
	})
	f.On("POST /v1/auth/webauthn/login/finish", func(c cauthytest.Call) cauthytest.Reply {
		if c.JSON["session_id"] != "wa-1" {
			return cauthytest.Refuse(400, "assertion_invalid", "bad")
		}
		return cauthytest.Data(f.Issue("u-member"))
	})
	f.On("POST /v1/auth/google/one-tap/begin", func(cauthytest.Call) cauthytest.Reply {
		return cauthytest.Data(map[string]any{"client_id": "g-client", "nonce": "n-1"})
	})
	b := cauthytest.NewBrowser("")
	if _, m := status(a, b, "POST", "/api/auth/sign-in/passkey/begin", map[string]any{"email": "member@example.com"}); at(m, "options", "challenge") != "abc" || m["next"] != "passkey" || f.Last("POST /v1/auth/webauthn/login/begin").JSON["email"] != "member@example.com" {
		t.Fatalf("%v", m)
	}
	if code, m := status(a, b, "POST", "/api/auth/sign-in/passkey/finish", map[string]any{"credential": "no"}); code != 400 || errCode(m) != "bad_request" {
		t.Fatalf("%d %v", code, m)
	}
	if _, m := status(a, b, "POST", "/api/auth/sign-in/passkey/finish", map[string]any{"credential": map[string]any{"id": "c", "response": map[string]any{}}}); m["status"] != "signed_in" {
		t.Fatalf("%v", m)
	}
	other := cauthytest.NewBrowser("")
	f.On("POST /v1/auth/webauthn/login/begin", func(cauthytest.Call) cauthytest.Reply { return cauthytest.Data(map[string]any{"session_id": "wa-2"}) })
	status(a, other, "POST", "/api/auth/sign-in/passkey/begin", map[string]any{})
	if code, m := status(a, other, "POST", "/api/auth/sign-in/passkey/finish", map[string]any{"credential": map[string]any{"id": "c", "response": map[string]any{}}}); code != 400 || errCode(m) != "passkey_failed" {
		t.Fatalf("which check failed is Cauthy's to log: %d %v", code, m)
	}
	if _, m := status(a, b, "POST", "/api/auth/sign-in/google-one-tap/begin", map[string]any{}); m["clientId"] != "g-client" || m["next"] != "one_tap" {
		t.Fatalf("%v", m)
	}
	if code, m := status(a, b, "POST", "/api/auth/sign-in/google-one-tap", map[string]any{}); code != 400 || errCode(m) != "bad_request" {
		t.Fatalf("%d %v", code, m)
	}
}
