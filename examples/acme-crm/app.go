// Package acme is Acme CRM, the example application: a chi router with
// Cauthy's routes at /api/auth, a page anyone sees, and invoices only a
// signed-in person reaches. The conformance target serves it.
package acme

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"

	"github.com/go-chi/chi/v5"
	cauthy "github.com/vennet-developers/cauthy-sdk-go"
)

// New is Acme CRM's router.
func New(auth *cauthy.Auth) http.Handler {
	r := chi.NewRouter()
	// What `cauthy init` writes for chi: r.Handle("/api/auth/*", auth) and
	// r.Handle(auth.JWKSPath(), auth). MountRouter does both, and the bare
	// /api/auth too.
	auth.MountRouter(r)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if s := auth.Session(w, r); s != nil {
			fmt.Fprintf(w, `<p>Signed in as %s. <a href="%s">Sign out</a></p>`, html.EscapeString(s.User.Email), auth.SignOutURL())
			return
		}
		fmt.Fprintf(w, `<p><a href="%s">Sign in</a></p>`, auth.SignInURL("/"))
	})
	r.With(auth.Protect).Get("/api/invoices", func(w http.ResponseWriter, r *http.Request) {
		s, _ := cauthy.SessionFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{"owner": s.User.ID, "invoices": []any{}})
	})
	return r
}
