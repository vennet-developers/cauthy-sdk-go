package cauthy

import (
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
)

const orgID = "6f1c1e9e-4a43-4c1b-9f5e-3a1d2b3c4d5e"
const userID = "0b7c3a2e-1d4f-4e5a-8b6c-7d8e9f0a1b2c"

func TestAMemberAdministersTheirOrganization(t *testing.T) {
	a, f := ownAuth(t, func(o *Options) { o.Pages.AcceptInvite = "/accept-invite" })
	b := cauthytest.NewBrowser("")
	signInOwn(t, a, b)
	base := "/v1/auth/me/organizations/" + orgID
	f.On("POST "+base+"/members", func(c cauthytest.Call) cauthytest.Reply {
		if c.JSON["only_new"] != true || c.JSON["client_id"] != "acme-crm" || c.Header.Get("X-Cauthy-Link-To") != "https://app.test/accept-invite" {
			t.Errorf("%v %v", c.JSON, c.Header)
		}
		if c.JSON["email"] == "ana@example.com" {
			return cauthytest.Refuse(409, "already_member", "already")
		}
		return cauthytest.Data(map[string]any{"user_id": userID, "email": c.JSON["email"], "role": c.JSON["role"], "invited": true})
	})
	f.On("PUT "+base+"/members/"+userID, func(cauthytest.Call) cauthytest.Reply { return cauthytest.Data(map[string]any{}) })
	f.On("DELETE "+base+"/members/"+userID, func(cauthytest.Call) cauthytest.Reply { return cauthytest.Reply{Status: 204} })
	f.On("POST "+base+"/members/"+userID+"/invite", func(cauthytest.Call) cauthytest.Reply { return cauthytest.Reply{Status: 202} })
	f.On("PATCH "+base, func(c cauthytest.Call) cauthytest.Reply {
		return cauthytest.Data(map[string]any{"id": orgID, "name": c.JSON["name"]})
	})
	f.On("POST "+base+"/archive", func(cauthytest.Call) cauthytest.Reply { return cauthytest.Reply{Status: 204} })
	f.On("DELETE "+base, func(cauthytest.Call) cauthytest.Reply { return cauthytest.Reply{Status: 204} })
	f.On("DELETE /v1/auth/me/agents/"+userID, func(cauthytest.Call) cauthytest.Reply { return cauthytest.Reply{Status: 204} })
	f.On("DELETE /v1/auth/me/sessions", func(cauthytest.Call) cauthytest.Reply { return cauthytest.Reply{Status: 204} })

	post := func(path string, body map[string]any) (int, map[string]any) {
		return status(a, b, "POST", "/api/auth/me/organizations"+path, body)
	}
	if code, m := post("/members/add", map[string]any{"organizationId": "nope"}); code != 400 || errCode(m) != "invalid_organization" {
		t.Fatalf("%d %v", code, m)
	}
	if code, m := post("/members/add", map[string]any{"organizationId": orgID, "email": "bo@example.com"}); code != 400 || errCode(m) != "invalid_role" {
		t.Fatalf("%d %v", code, m)
	}
	if _, m := post("/members/add", map[string]any{"organizationId": orgID, "email": "bo@example.com", "role": "member"}); m["status"] != "added" || at(m, "member", "invited") != true {
		t.Fatalf("%v", m)
	}
	if code, m := post("/members/add", map[string]any{"organizationId": orgID, "email": "ana@example.com", "role": "member"}); code != 409 || errCode(m) != "member_exists" {
		t.Fatalf("one code for already a member: %d %v", code, m)
	}
	if code, m := post("/members/role", map[string]any{"organizationId": orgID, "userId": "x", "role": "admin"}); code != 400 || errCode(m) != "invalid_member" {
		t.Fatalf("%d %v", code, m)
	}
	for path, want := range map[string]string{"/members/role": "changed", "/members/remove": "removed", "/members/invite": "sent"} {
		if _, m := post(path, map[string]any{"organizationId": orgID, "userId": userID, "role": "admin"}); m["status"] != want || m["userId"] != userID {
			t.Fatalf("%s: %v", path, m)
		}
	}
	for path, want := range map[string]string{"/rename": "renamed", "/archive": "archived", "/delete": "deleted"} {
		if _, m := post(path, map[string]any{"organizationId": orgID, "name": "Acme Two"}); m["status"] != want {
			t.Fatalf("%s: %v", path, m)
		}
	}
	if _, m := status(a, b, "POST", "/api/auth/me/agents/disconnect", map[string]any{"id": userID}); m["status"] != "disconnected" {
		t.Fatalf("%v", m)
	}
	if _, m := status(a, b, "POST", "/api/auth/me/sessions/end", map[string]any{}); m["status"] != "signed_out" || b.Jar["cauthy_session.0"] != "" {
		t.Fatalf("everywhere is here too: %v %v", m, b.Jar)
	}
}
