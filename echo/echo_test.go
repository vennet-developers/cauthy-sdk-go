package cauthyecho

import (
	"net/http"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	cauthy "github.com/vennet-developers/cauthy-sdk-go"
	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
)

func TestEchoServesTheProtocolAndProtects(t *testing.T) {
	f := cauthytest.New()
	f.OwnScreens = true
	f.AddUser(cauthytest.User{Sub: "u-member", Email: "member@example.com", Name: "Member", Active: true}, "correct horse battery staple")
	auth, err := cauthy.New(cauthy.Options{Issuer: f.Issuer, ClientID: "acme-crm", Secret: strings.Repeat("s", 32), Tenant: "acme",
		HTTPClient: f.Client(), Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	Mount(e, auth)
	e.GET("/api/invoices", func(c *echo.Context) error {
		s, _ := cauthy.SessionFromContext(c.Request().Context())
		return c.JSON(200, map[string]any{"owner": s.User.ID})
	}, Protect(auth))
	if err := auth.CheckMount(e); err != nil {
		t.Fatal(err)
	}
	b := cauthytest.NewBrowser("")
	if res := b.Send(e, "POST", "/api/auth/sign-in/email", map[string]any{"email": "member@example.com", "password": "correct horse battery staple"}); res.StatusCode != 200 {
		t.Fatalf("%d", res.StatusCode)
	}
	if body := cauthytest.JSON(b.Send(e, "GET", "/api/invoices", nil)); body["owner"] != "u-member" {
		t.Fatalf("%v", body)
	}
	if res := cauthytest.NewBrowser("").Send(e, "GET", "/api/invoices", nil); res.StatusCode != http.StatusFound {
		t.Fatalf("%d", res.StatusCode)
	}
}

func TestEchoRequireRefusesWithoutAToken(t *testing.T) {
	v, _ := cauthy.NewVerifier(cauthy.VerifierConfig{Issuer: "https://id.example.com", Audience: "cauthy", Tenant: "8a6e0804-2bd0-4672-b79a-d97027f5f2a1"})
	e := echo.New()
	e.GET("/api/records", func(c *echo.Context) error { return c.NoContent(204) }, Require(v))
	res := cauthytest.NewBrowser("").Send(e, "GET", "/api/records", nil)
	if res.StatusCode != 401 || cauthytest.JSON(res)["error"] == nil {
		t.Fatalf("%d", res.StatusCode)
	}
}
