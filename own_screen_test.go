package cauthy

import (
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
)

func TestMethodsSaysWhatTheScreenMayOffer(t *testing.T) {
	a, f := ownAuth(t, func(o *Options) { o.Pages.SignIn = "/sign-in" })
	f.Settings = map[string]any{"allow_password": true, "allow_signup": true, "allow_magic_link": true, "persistent_sessions": true,
		"signup": map[string]any{"organization": map[string]any{"ask": true, "required": true}}, "captcha_enabled": true, "captcha_site_key": "site-key",
		"password_policy": map[string]any{"min_length": 10.0, "requires": []any{"digit"}},
		"legal":           map[string]any{"documents": []any{map[string]any{"kind": "terms", "version": "3", "url": "https://acme.example.com/terms"}}}}
	f.On("GET /v1/auth/social/providers", func(cauthytest.Call) cauthytest.Reply {
		return cauthytest.Data([]any{map[string]any{"provider": "google", "label": "Google", "icon_url": "/v1/icons/google.svg"}, map[string]any{"id": ""}})
	})
	f.On("GET /v1/auth/sso/connections", func(cauthytest.Call) cauthytest.Reply {
		return cauthytest.Data([]any{map[string]any{"discoverable": true}})
	})
	f.On("GET /v1/auth/webauthn/place", func(c cauthytest.Call) cauthytest.Reply {
		if c.Query.Get("origin") != "https://app.test" {
			t.Errorf("origin %q", c.Query.Get("origin"))
		}
		return cauthytest.Data(map[string]any{"here": true})
	})
	code, m := status(a, cauthytest.NewBrowser(""), "GET", "/api/auth/methods", nil)
	providers := arr(m["providers"])
	if code != 200 || len(providers) != 1 || at(providers[0], "iconUrl") != "https://id.test/v1/icons/google.svg" ||
		m["passwordSignIn"] != true || m["signUp"] != true || m["magicLink"] != true || m["passkey"] != true || m["passkeyHere"] != true ||
		m["passkeyOnCauthy"] != false || m["sso"] != true || m["persistentSessions"] != true || m["captchaSiteKey"] != "site-key" ||
		at(m, "organization", "required") != true || at(m, "password", "min") != 10.0 || len(arr(at(m, "legal", "documents"))) != 1 {
		t.Fatalf("%d %v", code, m)
	}
	if c := f.Last("GET /v1/auth/settings"); c.Header.Get("X-Tenant-Key") != "acme" || c.Header.Get("X-Cauthy-Client-Id") != "acme-crm" || c.Header.Get("X-Cauthy-Links") != "hosted" {
		t.Fatalf("the workspace's application asks: %v", c.Header)
	}
	f.Settings = map[string]any{"allow_passkeys": false, "signup": map[string]any{"mode": "invite_only"}}
	_, m = status(a, cauthytest.NewBrowser(""), "GET", "/api/auth/methods", nil)
	if m["passkey"] != false || m["signUp"] != false || m["magicLink"] != false {
		t.Fatalf("%v", m)
	}
}

func TestLookIsKeptAMinuteAndInvitationIsReadWithoutSpendingIt(t *testing.T) {
	a, f := ownAuth(t, nil)
	f.On("GET /v1/auth/look/acme-crm", func(cauthytest.Call) cauthytest.Reply { return cauthytest.Data(map[string]any{"accent": "#123456"}) })
	b := cauthytest.NewBrowser("")
	for range 3 {
		if _, m := status(a, b, "GET", "/api/auth/look", nil); m["accent"] != "#123456" {
			t.Fatalf("%v", m)
		}
	}
	if n := len(callsTo(f, "GET /v1/auth/look/acme-crm")); n != 1 {
		t.Fatalf("%d asks, want 1", n)
	}
	if code, m := status(a, b, "GET", "/api/auth/invitation", nil); code != 422 || errCode(m) != "invalid_token" {
		t.Fatalf("%d %v", code, m)
	}
	f.On("GET /v1/auth/invitation", func(c cauthytest.Call) cauthytest.Reply {
		return cauthytest.Data(map[string]any{"email": "new@example.com", "workspace": "Acme", "organization": "Acme Billing"})
	})
	if _, m := status(a, b, "GET", "/api/auth/invitation?token=tok", nil); m["status"] != "ok" || at(m, "invitation", "organization") != "Acme Billing" {
		t.Fatalf("%v", m)
	}
}
