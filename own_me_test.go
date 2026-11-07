package cauthy

import (
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
)

func TestTheAccountIsChangedAsThePerson(t *testing.T) {
	a, f := ownAuth(t, nil)
	b := cauthytest.NewBrowser("")
	if code, m := status(a, b, "POST", "/api/auth/me", map[string]any{"name": "X"}); code != 401 || errCode(m) != "unauthenticated" {
		t.Fatalf("%d %v", code, m)
	}
	signInOwn(t, a, b)
	f.On("PATCH /v1/auth/me", func(c cauthytest.Call) cauthytest.Reply {
		return cauthytest.Data(map[string]any{"id": "u-member", "name": c.JSON["name"]})
	})
	if res := b.Send(a, "POST", "/api/auth/me", map[string]any{"name": " New Name "}); res.StatusCode != 200 || len(res.Header.Values("Set-Cookie")) == 0 {
		t.Fatalf("the cookie says the new name at once: %d %v", res.StatusCode, res.Header)
	}
	f.On("POST /v1/auth/mfa/setup", func(c cauthytest.Call) cauthytest.Reply {
		if c.JSON["password"] == "" {
			return cauthytest.Refuse(401, "step_up_required", "Enter your password.")
		}
		return cauthytest.Data(map[string]any{"secret": "S", "otpauth_uri": "otpauth://x", "qr": "javascript:alert(1)"})
	})
	if code, m := status(a, b, "POST", "/api/auth/me/mfa/setup", map[string]any{}); code != 401 || errCode(m) != "step_up_required" || at(m, "error", "field") != "password" {
		t.Fatalf("%d %v", code, m)
	}
	if _, m := status(a, b, "POST", "/api/auth/me/mfa/setup", map[string]any{"password": memberPassword}); m["status"] != "started" || m["qr"] != "" {
		t.Fatalf("only a PNG data: URI goes to the page: %v", m)
	}
	f.On("POST /v1/auth/me/mfa/recovery-codes", func(cauthytest.Call) cauthytest.Reply {
		return cauthytest.Data(map[string]any{"recovery_codes": []any{"a", "b"}})
	})
	if _, m := status(a, b, "POST", "/api/auth/me/mfa/recovery-codes", map[string]any{"password": "p"}); m["status"] != "renewed" || len(arr(m["recoveryCodes"])) != 2 {
		t.Fatalf("%v", m)
	}
	f.On("POST /v1/auth/me/email", func(cauthytest.Call) cauthytest.Reply { return cauthytest.Refuse(409, "email_taken", "taken") })
	if code, m := status(a, b, "POST", "/api/auth/me/email", map[string]any{"email": "bo@example.com"}); code != 409 || at(m, "error", "field") != "email" {
		t.Fatalf("%d %v", code, m)
	}
	if code, m := status(a, b, "POST", "/api/auth/me/identities/unlink", map[string]any{"provider": "Bad Provider"}); code != 400 || errCode(m) != "invalid_provider" {
		t.Fatalf("%d %v", code, m)
	}
	if code, m := status(a, b, "POST", "/api/auth/me/passkeys/remove", map[string]any{"id": "x"}); code != 400 || errCode(m) != "invalid_passkey" {
		t.Fatalf("%d %v", code, m)
	}
	f.On("POST /v1/auth/me/password", func(cauthytest.Call) cauthytest.Reply { return cauthytest.Data(f.Issue("u-member")) })
	res := b.Send(a, "POST", "/api/auth/me/password", map[string]any{"password": memberPassword, "newPassword": "another long password"})
	m := cauthytest.JSON(res)
	if m["status"] != "changed" || m["signedIn"] != true || b.Jar["cauthy_session.0"] == "" {
		t.Fatalf("a new session for this browser: %v", m)
	}
	if code, m := status(a, b, "POST", "/api/auth/me/nothing-here", map[string]any{}); code != 404 {
		t.Fatalf("%d %v", code, m)
	}
}

func TestAPasskeyIsAddedOnThisPage(t *testing.T) {
	a, f := ownAuth(t, nil)
	b := cauthytest.NewBrowser("")
	signInOwn(t, a, b)
	f.On("POST /v1/auth/webauthn/register/begin", func(c cauthytest.Call) cauthytest.Reply {
		if c.JSON["kind"] != "device" {
			t.Errorf("%v", c.JSON)
		}
		return cauthytest.Data(map[string]any{"session_id": "reg-1", "options": map[string]any{"rp": "acme"}})
	})
	f.On("POST /v1/auth/webauthn/register/finish", func(c cauthytest.Call) cauthytest.Reply {
		if c.JSON["session_id"] != "reg-1" || c.JSON["nickname"] != "Laptop" {
			return cauthytest.Refuse(400, "attestation_invalid", "no")
		}
		return cauthytest.Data(map[string]any{"id": "p1", "nickname": "Laptop", "kind": "device"})
	})
	if _, m := status(a, b, "POST", "/api/auth/me/passkeys/add/begin", map[string]any{"kind": "device"}); m["status"] != "started" || at(m, "options", "rp") != "acme" {
		t.Fatalf("%v", m)
	}
	cred := map[string]any{"id": "c", "response": map[string]any{}}
	if _, m := status(a, b, "POST", "/api/auth/me/passkeys/add/finish", map[string]any{"credential": cred, "name": " Laptop "}); m["status"] != "added" || at(m, "passkey", "kind") != "device" {
		t.Fatalf("%v", m)
	}
	if code, m := status(a, b, "POST", "/api/auth/me/passkeys/add/finish", map[string]any{"credential": cred}); code != 400 || errCode(m) != "step_expired" {
		t.Fatalf("the ceremony is spent: %d %v", code, m)
	}
}
