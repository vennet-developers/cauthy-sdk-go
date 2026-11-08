package cauthytest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func adminCall(t *testing.T, f *Fake, method, path, body, token string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, f.Issuer+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-Key", "acme")
	req.Header.Set("Content-Type", "application/json")
	res, err := f.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res, JSON(res)
}

func ownCall(t *testing.T, f *Fake, path, body string, headers map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", f.Issuer+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Key", "acme")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := f.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res, JSON(res)
}

func newAdminFake() *Fake {
	f := New()
	f.OwnScreens = true
	f.AdminToken = "admin-token"
	f.AddUser(User{Sub: "u-member", Email: "member@example.com", Name: "Member", Active: true}, "correct horse battery")
	return f
}

func TestTheAdminAPINeedsItsToken(t *testing.T) {
	f := newAdminFake()
	f.SetAdminToken("admin-token")
	if res, _ := adminCall(t, f, "GET", "/v1/settings/auth", "", "wrong"); res.StatusCode != 401 {
		t.Fatalf("%d", res.StatusCode)
	}
	f.AdminToken = ""
	if res, _ := adminCall(t, f, "GET", "/v1/settings/auth", "", ""); res.StatusCode != 401 {
		t.Fatalf("no token set refuses everything: %d", res.StatusCode)
	}
}

func TestTheAdminChangesSettingsAndKeepsOneWayIn(t *testing.T) {
	f := newAdminFake()
	res, body := adminCall(t, f, "PUT", "/v1/settings/auth", `{"allow_signup":true,"allow_magic_link":true,"unknown":1}`, "admin-token")
	if res.StatusCode != 200 || body["data"].(map[string]any)["allow_signup"] != true || f.Setting("unknown") != nil {
		t.Fatalf("%d %v", res.StatusCode, body)
	}
	if res, _ := adminCall(t, f, "PUT", "/v1/settings/auth", `{"allow_magic_link":false,"allow_password":false}`, "admin-token"); res.StatusCode != 409 {
		t.Fatalf("the last way in stays: %d", res.StatusCode)
	}
}

func TestPasswordsAndSignUpsFollowTheSettings(t *testing.T) {
	f := newAdminFake()
	if res, _ := ownCall(t, f, "/v1/auth/register", `{"email":"new@example.com","password":"Long-enough-1"}`, nil); res.StatusCode != 403 {
		t.Fatalf("sign-ups are closed by default: %d", res.StatusCode)
	}
	f.SetSetting("allow_signup", true)
	f.SetSetting("confirm_email", true)
	res, body := ownCall(t, f, "/v1/auth/register", `{"email":"new@example.com","password":"Long-enough-1"}`, nil)
	if res.StatusCode != 201 || body["data"].(map[string]any)["verification_required"] != true {
		t.Fatalf("%d %v", res.StatusCode, body)
	}
	if res, _ := ownCall(t, f, "/v1/auth/login", `{"email":"new@example.com","password":"Long-enough-1"}`, nil); res.StatusCode != 401 {
		t.Fatalf("an unconfirmed account does not sign in: %d", res.StatusCode)
	}
	f.SetSetting("allow_magic_link", true)
	f.SetSetting("allow_password", false)
	res, body = ownCall(t, f, "/v1/auth/login", `{"email":"member@example.com","password":"correct horse battery"}`, nil)
	errs, _ := body["errors"].([]any)
	if res.StatusCode != 403 || len(errs) == 0 || errs[0].(map[string]any)["code"] != "password_disabled" {
		t.Fatalf("%d %v", res.StatusCode, body)
	}
}

func TestTheClientsLongSessions(t *testing.T) {
	f := newAdminFake()
	res, body := adminCall(t, f, "PATCH", "/v1/oauth/clients/acme-crm", `{"allow_persistent_sessions":true}`, "admin-token")
	if res.StatusCode != 200 || body["data"].(map[string]any)["allow_persistent_sessions"] != true {
		t.Fatalf("%d %v", res.StatusCode, body)
	}
	_, list := adminCall(t, f, "GET", "/v1/oauth/clients", "", "admin-token")
	if list["data"].([]any)[0].(map[string]any)["allow_persistent_sessions"] != true {
		t.Fatalf("%v", list)
	}
	_, login := ownCall(t, f, "/v1/auth/login", `{"email":"member@example.com","password":"correct horse battery"}`, map[string]string{"X-Cauthy-Remember": "1"})
	if login["data"].(map[string]any)["persistent"] != true {
		t.Fatalf("%v", login)
	}
}

func TestTheAdminFindsAndDeletesAnAccount(t *testing.T) {
	f := newAdminFake()
	_, found := adminCall(t, f, "GET", "/v1/users?q=member@example.com", "", "admin-token")
	if list := found["data"].([]any); len(list) != 1 || list[0].(map[string]any)["id"] != "u-member" {
		t.Fatalf("%v", found)
	}
	if res, _ := adminCall(t, f, "DELETE", "/v1/users/u-member", "", "admin-token"); res.StatusCode != 204 || f.HasUser("u-member") {
		t.Fatalf("%d", res.StatusCode)
	}
	if res, _ := adminCall(t, f, "DELETE", "/v1/users/u-member", "", "admin-token"); res.StatusCode != 404 {
		t.Fatalf("%d", res.StatusCode)
	}
}

func TestTheFakeServesOverHTTP(t *testing.T) {
	f := newAdminFake()
	srv := httptest.NewServer(f)
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/v1/settings/auth", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	req.Header.Set("X-Tenant-Key", "acme")
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("%v %v", res, err)
	}
}
