// Command conformance-target is Acme CRM on a Cauthy that lives in memory, so
// cauthy-sdk-spec's auth-bff suite runs at level strict with no real Cauthy.
//
//	CONFORMANCE_PASSWORD=… go run ./cmd/conformance-target
//
// One account, member@example.com: a password, MFA off, a verified email,
// no captcha — what the runner signs in as.
//
// With CONFORMANCE_ADMIN_TOKEN set, the in-memory Cauthy also serves its admin
// API on CONFORMANCE_CAUTHY_PORT (default: the target's port + 1), so the
// runner's dashboard-switch checks (level switches) can change its settings.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	cauthy "github.com/vennet-developers/cauthy-sdk-go"
	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
	acme "github.com/vennet-developers/cauthy-sdk-go/examples/acme-crm"
)

func main() {
	port := os.Getenv("CONFORMANCE_PORT")
	if port == "" {
		port = "3999"
	}
	cauthyPort := os.Getenv("CONFORMANCE_CAUTHY_PORT")
	if cauthyPort == "" {
		n, err := strconv.Atoi(port)
		if err != nil {
			fmt.Fprintln(os.Stderr, "CONFORMANCE_PORT is not a number")
			os.Exit(2)
		}
		cauthyPort = strconv.Itoa(n + 1)
	}
	password := os.Getenv("CONFORMANCE_PASSWORD")
	if len(password) < 12 {
		fmt.Fprintln(os.Stderr, "CONFORMANCE_PASSWORD is required (12 characters or more)")
		os.Exit(2)
	}
	fake := cauthytest.New()
	fake.OwnScreens = true
	adminToken := os.Getenv("CONFORMANCE_ADMIN_TOKEN")
	if adminToken != "" {
		// Asked by method: the example's module requires a released
		// cauthy-sdk-go, which may predate the fake's admin API.
		admin, ok := any(fake).(interface{ SetAdminToken(string) })
		if !ok {
			fmt.Fprintln(os.Stderr, "this cauthytest has no admin API: build the target on this checkout (scripts/conformance.sh does)")
			os.Exit(2)
		}
		admin.SetAdminToken(adminToken)
	}
	fake.AddUser(cauthytest.User{Sub: "u-member", Email: "member@example.com", Name: "Acme Member", Active: true}, password)

	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	origin := "http://localhost:" + port
	auth, err := cauthy.New(cauthy.Options{
		Issuer: fake.Issuer, ClientID: "acme-crm", Secret: base64.RawURLEncoding.EncodeToString(secret), Tenant: fake.Tenant,
		BaseURL: origin, HTTPClient: fake.Client(), Getenv: func(string) string { return "" },
		// A sign-in link opens the application's sign-in page.
		Pages: cauthy.Pages{SignIn: "/sign-in"},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	app := acme.New(auth)
	if err := auth.CheckMount(app); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if adminToken != "" {
		go func() {
			log.Fatal(http.ListenAndServe("127.0.0.1:"+cauthyPort, fake))
		}()
		log.Printf("its Cauthy on http://127.0.0.1:%s", cauthyPort)
	}
	log.Printf("conformance target on %s", origin)
	log.Fatal(http.ListenAndServe("127.0.0.1:"+port, app))
}
