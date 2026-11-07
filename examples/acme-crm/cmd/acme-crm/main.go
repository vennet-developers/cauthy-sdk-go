// Command acme-crm is Acme CRM as a deployment runs it: by contract when
// contracts/graph.json is there (the only secret PACT_ROOT_KEY, the key in a
// file for development), otherwise by the CAUTHY_* variables.
package main

import (
	"log"
	"net/http"
	"os"

	cauthy "github.com/vennet-developers/cauthy-sdk-go"
	acme "github.com/vennet-developers/cauthy-sdk-go/examples/acme-crm"
	"github.com/vennet-developers/cauthy-sdk-go/keys"
)

func main() {
	var o cauthy.Options
	if graph, err := os.ReadFile("contracts/graph.json"); err == nil {
		// Production keeps the key in its database: keys.Postgres(db).
		o = cauthy.Options{Contract: &cauthy.Contract{Graph: graph, System: "acme-crm"}, Keys: keys.File(".cauthy/pact-keys.json")}
	}
	auth, err := cauthy.New(o)
	if err != nil {
		log.Fatal(err) // the contract or the environment is wrong: never start without sign-in
	}
	app := acme.New(auth)
	if err := auth.CheckMount(app); err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.ListenAndServe(":8080", app))
}
