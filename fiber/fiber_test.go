package cauthyfiber

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	cauthy "github.com/vennet-developers/cauthy-sdk-go"
	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
)

// handler lets a cauthytest.Browser drive a Fiber app.
type handler struct{ app *fiber.App }

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.app.Test(r, -1)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer res.Body.Close()
	for k, v := range res.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(res.StatusCode)
	_, _ = io.Copy(w, res.Body)
}

func TestFiberServesTheProtocolAndProtects(t *testing.T) {
	f := cauthytest.New()
	f.OwnScreens = true
	f.AddUser(cauthytest.User{Sub: "u-member", Email: "member@example.com", Name: "Member", Active: true}, "correct horse battery staple")
	auth, err := cauthy.New(cauthy.Options{Issuer: f.Issuer, ClientID: "acme-crm", Secret: strings.Repeat("s", 32), Tenant: "acme",
		BaseURL: "https://app.test", HTTPClient: f.Client(), Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	Mount(app, auth)
	app.Get("/api/invoices", Protect(auth), func(c *fiber.Ctx) error {
		s, _ := cauthy.SessionFromContext(c.UserContext())
		return c.JSON(map[string]any{"owner": s.User.ID})
	})
	h := handler{app}
	if err := auth.CheckMount(h); err != nil {
		t.Fatal(err)
	}
	b := cauthytest.NewBrowser("")
	if res := b.Send(h, "POST", "/api/auth/sign-in/email", map[string]any{"email": "member@example.com", "password": "correct horse battery staple"}); res.StatusCode != 200 {
		t.Fatalf("%d", res.StatusCode)
	}
	if body := cauthytest.JSON(b.Send(h, "GET", "/api/invoices", nil)); body["owner"] != "u-member" {
		t.Fatalf("%v", body)
	}
	if res := cauthytest.NewBrowser("").Send(h, "GET", "/api/invoices", nil); res.StatusCode != http.StatusFound {
		t.Fatalf("%d", res.StatusCode)
	}
}

func TestFiberRequireRefusesWithoutAToken(t *testing.T) {
	v, _ := cauthy.NewVerifier(cauthy.VerifierConfig{Issuer: "https://id.example.com", Audience: "cauthy", Tenant: "8a6e0804-2bd0-4672-b79a-d97027f5f2a1"})
	app := fiber.New()
	app.Get("/api/records", Require(v), func(c *fiber.Ctx) error { return c.SendStatus(204) })
	res, err := app.Test(httptest.NewRequest("GET", "/api/records", nil), -1)
	if err != nil || res.StatusCode != 401 {
		t.Fatalf("%v %v", res, err)
	}
}
