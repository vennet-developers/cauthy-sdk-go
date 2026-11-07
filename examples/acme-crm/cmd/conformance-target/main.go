// Command conformance-target is Acme CRM on a Cauthy that lives in memory, so
// cauthy-sdk-spec's auth-bff suite runs at level strict with no real Cauthy.
//
//	CONFORMANCE_PASSWORD=… go run ./cmd/conformance-target
//
// One account, member@example.com: a password, MFA off, a verified email,
// no captcha — what the runner signs in as.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"

	cauthy "github.com/vennet-developers/cauthy-sdk-go"
	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
	acme "github.com/vennet-developers/cauthy-sdk-go/examples/acme-crm"
)

func main() {
	port := os.Getenv("CONFORMANCE_PORT")
	if port == "" {
		port = "3999"
	}
	password := os.Getenv("CONFORMANCE_PASSWORD")
	if len(password) < 12 {
		fmt.Fprintln(os.Stderr, "CONFORMANCE_PASSWORD is required (12 characters or more)")
		os.Exit(2)
	}
	fake := cauthytest.New()
	fake.OwnScreens = true
	fake.AddUser(cauthytest.User{Sub: "u-member", Email: "member@example.com", Name: "Acme Member", Active: true}, password)

	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	origin := "http://localhost:" + port
	auth, err := cauthy.New(cauthy.Options{
		Issuer: fake.Issuer, ClientID: "acme-crm", Secret: base64.RawURLEncoding.EncodeToString(secret), Tenant: fake.Tenant,
		BaseURL: origin, HTTPClient: fake.Client(), Getenv: func(string) string { return "" },
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
	log.Printf("conformance target on %s", origin)
	log.Fatal(http.ListenAndServe("127.0.0.1:"+port, app))
}
