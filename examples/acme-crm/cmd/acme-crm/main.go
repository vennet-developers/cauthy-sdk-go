// Command acme-crm is Acme CRM as a deployment runs it: on CAUTHY_KEY, the one
// variable Cauthy's dashboard makes for the application. The variables of
// 1.1 still work until 2.0, with a deprecation warning.
//
//	CAUTHY_KEY=cauthy1.… go run ./cmd/acme-crm
package main

import (
	"log"
	"net/http"
	"os"

	cauthy "github.com/vennet-developers/cauthy-sdk-go"
	acme "github.com/vennet-developers/cauthy-sdk-go/examples/acme-crm"
)

func main() {
	auth, err := cauthy.New(cauthy.Options{}) // reads CAUTHY_KEY
	if err != nil {
		log.Fatal(err) // a missing or damaged key: never start without sign-in
	}
	app := acme.New(auth)
	if err := auth.CheckMount(app); err != nil {
		log.Fatal(err)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Fatal(http.ListenAndServe(":"+port, app))
}
