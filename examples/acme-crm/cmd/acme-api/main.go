// Command acme-api is an API behind a backend that already signs people in
// (a Node BFF on @cauthyhq/node, say): it verifies Cauthy's access tokens and
// nothing else. No secret, no call to Cauthy per request.
//
// By contract (contracts/graph.json present) the issuer, audience and
// workspace come from the application's link; otherwise from
// CAUTHY_ISSUER, CAUTHY_AUDIENCE and CAUTHY_TENANT_ID.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	cauthy "github.com/vennet-developers/cauthy-sdk-go"
	"github.com/vennet-developers/cauthy-sdk-go/contract"
)

func config() (cauthy.VerifierConfig, error) {
	graph, err := os.ReadFile("contracts/graph.json")
	if os.IsNotExist(err) {
		return cauthy.VerifierConfigFromEnv(nil)
	}
	if err != nil {
		return cauthy.VerifierConfig{}, err
	}
	link, err := contract.Read(contract.Options{Graph: graph, System: "acme-crm"})
	if err != nil {
		return cauthy.VerifierConfig{}, err
	}
	return cauthy.VerifierConfigFromContract(link)
}

func main() {
	cfg, err := config()
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := cauthy.NewVerifier(cfg)
	if err != nil {
		log.Fatal(err) // never start without a safe verifier
	}
	r := chi.NewRouter()
	r.With(verifier.Require).Get("/api/records", func(w http.ResponseWriter, r *http.Request) {
		id, _ := cauthy.FromContext(r.Context())
		// The person is id.Subject. Their business role is the
		// application's own record, never id.Roles (identity/rules.md).
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"owner": id.Subject, "records": []any{}})
	})
	log.Fatal(http.ListenAndServe(":8081", r))
}
