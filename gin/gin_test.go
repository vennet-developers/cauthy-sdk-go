package cauthygin

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	cauthy "github.com/vennet-developers/cauthy-sdk-go"
	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
)

func TestGinServesTheProtocolAndProtects(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := cauthytest.New()
	f.OwnScreens = true
	f.AddUser(cauthytest.User{Sub: "u-member", Email: "member@example.com", Name: "Member", Active: true}, "correct horse battery staple")
	auth, err := cauthy.New(cauthy.Options{Issuer: f.Issuer, ClientID: "acme-crm", Secret: strings.Repeat("s", 32), Tenant: "acme",
		HTTPClient: f.Client(), Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	Mount(r, auth)
	r.GET("/api/invoices", Protect(auth), func(c *gin.Context) {
		s, _ := cauthy.SessionFromContext(c.Request.Context())
		c.JSON(200, gin.H{"owner": s.User.ID})
	})
	if err := auth.CheckMount(r); err != nil {
		t.Fatal(err)
	}
	b := cauthytest.NewBrowser("")
	if res := b.Send(r, "GET", "/api/auth/session/", nil); res.StatusCode != 200 || res.Header.Get("Cauthy-Protocol") != "1" {
		t.Fatalf("%d", res.StatusCode)
	}
	if res := b.Send(r, "POST", "/api/auth/sign-in/email", map[string]any{"email": "member@example.com", "password": "correct horse battery staple"}); res.StatusCode != 200 {
		t.Fatalf("%d", res.StatusCode)
	}
	if body := cauthytest.JSON(b.Send(r, "GET", "/api/invoices", nil)); body["owner"] != "u-member" {
		t.Fatalf("%v", body)
	}
	if res := cauthytest.NewBrowser("").Send(r, "GET", "/api/invoices", nil); res.StatusCode != http.StatusFound {
		t.Fatalf("%d", res.StatusCode)
	}
}

func TestGinRequireRefusesWithoutAToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	v, err := cauthy.NewVerifier(cauthy.VerifierConfig{Issuer: "https://id.example.com", Audience: "cauthy", Tenant: "8a6e0804-2bd0-4672-b79a-d97027f5f2a1"})
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.GET("/api/records", Require(v), func(c *gin.Context) { c.Status(204) })
	res := cauthytest.NewBrowser("").Send(r, "GET", "/api/records", nil)
	if res.StatusCode != 401 || res.Header.Get("WWW-Authenticate") != "Bearer" || cauthytest.JSON(res)["error"] == nil {
		t.Fatalf("%d %v", res.StatusCode, res.Header)
	}
}
