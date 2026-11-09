// Command conformance-target is Acme CRM on a Cauthy that lives in memory, so
// cauthy-sdk-spec's auth-bff suite runs at level strict with no real Cauthy.
//
//	CONFORMANCE_PASSWORD=… go run ./cmd/conformance-target
//
// One account, member@example.com: a password, MFA off, a verified email,
// no captcha — what the runner signs in as.
//
// The application runs on CAUTHY_KEY alone: the in-memory Cauthy issues the
// key, as the dashboard would, for its address on CONFORMANCE_CAUTHY_PORT
// (default: the target's port + 1), where it serves the token endpoint and
// GET /v1/connect/self. With CONFORMANCE_KEY_FILE set the key is written
// there (0600), for the runner's key.* checks (--key-env); it is never
// printed. With CONFORMANCE_ADMIN_TOKEN set, the in-memory Cauthy also serves
// its admin API there, so the runner's dashboard-switch checks (level
// switches) can change its settings.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	cauthy "github.com/vennet-developers/cauthy-sdk-go"
	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
	acme "github.com/vennet-developers/cauthy-sdk-go/examples/acme-crm"
)

// keyFake is what a cauthytest that speaks CAUTHY_KEY adds. Asked by
// method: the example's module requires a released cauthy-sdk-go, which may
// predate it.
type keyFake interface {
	IssueKey() string
	SetAppURLs(urls ...string)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}

func main() {
	port := os.Getenv("CONFORMANCE_PORT")
	if port == "" {
		port = "3999"
	}
	cauthyPort := os.Getenv("CONFORMANCE_CAUTHY_PORT")
	if cauthyPort == "" {
		n, err := strconv.Atoi(port)
		if err != nil {
			fail("CONFORMANCE_PORT is not a number")
		}
		cauthyPort = strconv.Itoa(n + 1)
	}
	password := os.Getenv("CONFORMANCE_PASSWORD")
	if len(password) < 12 {
		fail("CONFORMANCE_PASSWORD is required (12 characters or more)")
	}
	fake := cauthytest.New()
	fake.OwnScreens = true
	adminToken := os.Getenv("CONFORMANCE_ADMIN_TOKEN")
	if adminToken != "" {
		admin, ok := any(fake).(interface{ SetAdminToken(string) })
		if !ok {
			fail("this cauthytest has no admin API: build the target on this checkout (scripts/conformance.sh does)")
		}
		admin.SetAdminToken(adminToken)
	}
	fake.AddUser(cauthytest.User{Sub: "u-member", Email: "member@example.com", Name: "Acme Member", Active: true}, password)

	keyed, ok := any(fake).(keyFake)
	if !ok {
		fail("this cauthytest does not speak CAUTHY_KEY: build the target on this checkout (scripts/conformance.sh does)")
	}
	origin := "http://localhost:" + port
	// The key names the in-memory Cauthy where the runner reaches it too.
	fake.Issuer = "http://127.0.0.1:" + cauthyPort
	keyed.SetAppURLs(origin)
	key := keyed.IssueKey()
	if file := os.Getenv("CONFORMANCE_KEY_FILE"); file != "" {
		if err := os.WriteFile(file, []byte(key), 0o600); err != nil {
			fail("the key could not be written to CONFORMANCE_KEY_FILE")
		}
	}
	go func() {
		log.Fatal(http.ListenAndServe("127.0.0.1:"+cauthyPort, fake))
	}()

	auth, err := cauthy.New(cauthy.Options{
		HTTPClient: fake.Client(), Getenv: func(name string) string {
			if name == "CAUTHY_KEY" {
				return key
			}
			return ""
		},
		// A sign-in link opens the application's sign-in page.
		Pages: cauthy.Pages{SignIn: "/sign-in"},
	})
	if err != nil {
		fail(err.Error())
	}
	app := acme.New(auth)
	if err := auth.CheckMount(app); err != nil {
		fail(err.Error())
	}
	log.Printf("its Cauthy on http://127.0.0.1:%s", cauthyPort)
	log.Printf("conformance target on %s", origin)
	log.Fatal(http.ListenAndServe("127.0.0.1:"+port, app))
}
