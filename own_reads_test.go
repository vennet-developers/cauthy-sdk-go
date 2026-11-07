package cauthy

import (
	"io"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
)

func TestTheAccountIsReadAsThePerson(t *testing.T) {
	a, f := ownAuth(t, nil)
	b := cauthytest.NewBrowser("")
	for _, path := range []string{"/me", "/me/organizations", "/me/passkeys", "/me/sessions"} {
		if code, m := status(a, b, "GET", "/api/auth"+path, nil); code != 401 || errCode(m) != "unauthenticated" {
			t.Fatalf("%s without a session: %d %v", path, code, m)
		}
	}
	signInOwn(t, a, b)
	f.On("GET /v1/auth/me", func(cauthytest.Call) cauthytest.Reply {
		return cauthytest.Data(map[string]any{"id": "u-member", "email": "member@example.com", "name": "Acme Member", "has_password": true})
	})
	f.On("GET /v1/auth/me/sessions", func(cauthytest.Call) cauthytest.Reply {
		return cauthytest.Data([]any{map[string]any{"device": "Firefox", "ip": "203.0.113.9", "created_at": "2026-01-01T00:00:00Z"}})
	})
	f.On("GET /v1/auth/me/legal", func(cauthytest.Call) cauthytest.Reply {
		return cauthytest.Data(map[string]any{"pending": []any{map[string]any{"kind": "terms", "version": "3"}}})
	})
	f.On("GET /v1/auth/webauthn/credentials", func(cauthytest.Call) cauthytest.Reply {
		return cauthytest.Data([]any{map[string]any{"id": "p1", "nickname": "Laptop", "kind": "synced", "created_at": "2026-01-01T00:00:00Z"}})
	})
	f.On("GET /v1/auth/me/organizations", func(c cauthytest.Call) cauthytest.Reply {
		return cauthytest.Data([]any{map[string]any{"id": "o1", "name": "Acme", "role": "owner", "can": map[string]any{"manage_members": true}}})
	})
	f.On("GET /v1/auth/me/organizations/6f1c1e9e-4a43-4c1b-9f5e-3a1d2b3c4d5e/members", func(cauthytest.Call) cauthytest.Reply {
		return cauthytest.Data([]any{map[string]any{"user_id": "u2", "email": "bo@example.com", "role": "member", "you": false}})
	})
	f.On("GET /v1/auth/mfa/factors", func(cauthytest.Call) cauthytest.Reply {
		return cauthytest.Data(map[string]any{"totp": true, "phone_channels": []any{"sms", "whatsapp"}})
	})
	if _, m := status(a, b, "GET", "/api/auth/me", nil); at(m, "account", "hasPassword") != true || at(m, "account", "mfaEnabled") != false {
		t.Fatalf("%v", m)
	}
	if _, m := status(a, b, "GET", "/api/auth/me/sessions", nil); at(arr(m["sessions"])[0], "device") != "Firefox" {
		t.Fatalf("%v", m)
	}
	if _, m := status(a, b, "GET", "/api/auth/me/legal", nil); at(arr(m["pending"])[0], "url") != "" {
		t.Fatalf("%v", m)
	}
	if _, m := status(a, b, "GET", "/api/auth/me/passkeys", nil); at(arr(m["passkeys"])[0], "name") != "Laptop" || at(arr(m["passkeys"])[0], "lastUsedAt") != nil {
		t.Fatalf("%v", m)
	}
	if _, m := status(a, b, "GET", "/api/auth/me/organizations", nil); at(arr(m["organizations"])[0], "can", "manageMembers") != true {
		t.Fatalf("%v", m)
	}
	if code, m := status(a, b, "GET", "/api/auth/me/organizations/members?id=nope", nil); code != 400 || errCode(m) != "invalid_organization" {
		t.Fatalf("%d %v", code, m)
	}
	if _, m := status(a, b, "GET", "/api/auth/me/organizations/members?id=6f1c1e9e-4a43-4c1b-9f5e-3a1d2b3c4d5e", nil); at(arr(m["members"])[0], "userId") != "u2" {
		t.Fatalf("%v", m)
	}
	if _, m := status(a, b, "GET", "/api/auth/me/mfa/factors", nil); m["phone"] != nil || len(arr(m["phoneChannels"])) != 2 {
		t.Fatalf("%v", m)
	}
}

func TestThePushApprovalStreamsThrough(t *testing.T) {
	a, f := ownAuth(t, nil)
	f.On("POST /v1/auth/login", func(cauthytest.Call) cauthytest.Reply {
		return cauthytest.Data(map[string]any{"mfa_required": true, "mfa_token": "mfa-1"})
	})
	b := cauthytest.NewBrowser("")
	if code, m := status(a, b, "GET", "/api/auth/sign-in/mfa/push/events", nil); code != 400 || errCode(m) != "step_expired" {
		t.Fatalf("%d %v", code, m)
	}
	status(a, b, "POST", "/api/auth/sign-in/email", map[string]any{"email": "member@example.com", "password": memberPassword})
	f.On("GET /v1/auth/mfa/push/events", func(c cauthytest.Call) cauthytest.Reply {
		if c.Header.Get("X-Mfa-Token") != "mfa-1" {
			return cauthytest.Refuse(401, "invalid_mfa", "no")
		}
		return cauthytest.Reply{Status: 200, Body: "approved"}
	})
	res := b.Send(a, "GET", "/api/auth/sign-in/mfa/push/events", nil)
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "text/event-stream" || string(body) != "\"approved\"\n" {
		t.Fatalf("%d %v %q", res.StatusCode, res.Header, body)
	}
}
