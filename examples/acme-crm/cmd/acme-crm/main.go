// Command acme-crm is Acme CRM as a deployment runs it: on CAUTHY_KEY, the one
// variable Cauthy's dashboard makes for the application. With
// contracts/graph.json there, it runs by contract on the same key (no key
// store); the variables of 1.1 and PACT_ROOT_KEY still work until 2.0, with
// a deprecation warning.
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
	var o cauthy.Options // reads CAUTHY_KEY
	if graph, err := os.ReadFile("contracts/graph.json"); err == nil {
		o.Contract = &cauthy.Contract{Graph: graph, System: "acme-crm"}
	}
	auth, err := cauthy.New(o)
	if err != nil {
		log.Fatal(err) // the key or the contract is wrong: never start without sign-in
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
