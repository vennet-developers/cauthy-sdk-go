package acme

import (
	"net/http"
	"strings"
	"testing"

	cauthy "github.com/vennet-developers/cauthy-sdk-go"
	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
)

func TestAcmeSignsInAndShowsTheInvoices(t *testing.T) {
	f := cauthytest.New()
	f.OwnScreens = true
	f.AddUser(cauthytest.User{Sub: "u-member", Email: "member@example.com", Name: "Acme Member", Active: true}, "correct horse battery staple")
	auth, err := cauthy.New(cauthy.Options{Issuer: f.Issuer, ClientID: "acme-crm", Secret: strings.Repeat("s", 32), Tenant: "acme",
		HTTPClient: f.Client(), Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	app := New(auth)
	if err := auth.CheckMount(app); err != nil {
		t.Fatal(err)
	}
	b := cauthytest.NewBrowser("")
	if res := b.Send(app, "GET", "/api/invoices", nil); res.StatusCode != http.StatusFound {
		t.Fatalf("a page goes to sign in: %d", res.StatusCode)
	}
	res := b.Send(app, "POST", "/api/auth/sign-in/email", map[string]any{"email": "member@example.com", "password": "correct horse battery staple"})
	if res.StatusCode != 200 {
		t.Fatalf("%d", res.StatusCode)
	}
	if body := cauthytest.JSON(b.Send(app, "GET", "/api/invoices", nil)); body["owner"] != "u-member" {
		t.Fatalf("%v", body)
	}
}
