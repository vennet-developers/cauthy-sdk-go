package cauthy_test

import (
	"context"
	"database/sql"
	"net/http"
	"testing"

	cauthy "github.com/vennet-developers/cauthy-sdk-go"
	"github.com/vennet-developers/cauthy-sdk-go/keys"
)

// newFromTemplate is, name for name, what `cauthy init` writes into a Go
// application (cauthy-cli, internal/scaffold/golang.go): the names are a
// contract between the CLI and this module. If this stops compiling, the
// CLI's template must change in the same release.
func newFromTemplate(db *sql.DB, graph []byte) (*cauthy.Auth, error) {
	return cauthy.New(cauthy.Options{
		Contract: &cauthy.Contract{Graph: graph, System: "acme-crm"},
		Keys:     keys.Postgres(db),
	})
}

func TestTheNamesTheCLITemplateUses(t *testing.T) {
	_ = newFromTemplate
	var auth *cauthy.Auth
	var _ http.Handler = auth
	mount := func(auth *cauthy.Auth) {
		mux := http.NewServeMux()
		mux.Handle("/api/auth/", auth)
		mux.Handle(auth.JWKSPath(), auth)
	}
	rotate := func(ctx context.Context, auth *cauthy.Auth) {
		_, _ = auth.Pact().Keys().Rotate(ctx)
		_, _ = auth.Pact().Keys().Reseal(ctx)
	}
	_, _ = mount, rotate
}
