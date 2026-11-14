package cauthy_test

import (
	"net/http"
	"testing"

	cauthy "github.com/vennet-developers/cauthy-sdk-go"
)

// newFromTemplate is, name for name, what `cauthy init` writes into a Go
// application (cauthy-cli, internal/scaffold/golang.go): the names are a
// promise between the CLI and this module. If this stops compiling, the
// CLI's template must change in the same release.
func newFromTemplate() (*cauthy.Auth, error) {
	return cauthy.New(cauthy.Options{})
}

func TestTheNamesTheCLITemplateUses(t *testing.T) {
	_ = newFromTemplate
	var auth *cauthy.Auth
	var _ http.Handler = auth
	mount := func(auth *cauthy.Auth) {
		mux := http.NewServeMux()
		auth.Mount(mux)
		mux.Handle("/api/auth/", auth)
	}
	_ = mount
}
