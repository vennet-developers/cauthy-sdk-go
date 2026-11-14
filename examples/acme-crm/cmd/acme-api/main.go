// Command acme-api is an API behind a backend that already signs people in
// (a Node BFF on @cauthyhq/node, say): it verifies Cauthy's access tokens and
// nothing else. No secret, no call to Cauthy per request.
//
// The issuer, audience and workspace come from CAUTHY_KEY alone: the API
// asks Cauthy once at start who the application is.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	cauthy "github.com/vennet-developers/cauthy-sdk-go"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg, err := cauthy.VerifierConfigFromKey(ctx, nil, nil)
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
