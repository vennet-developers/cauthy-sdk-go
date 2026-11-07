package cauthy

import (
	"context"
	"net/http"

	"github.com/vennet-developers/cauthy-sdk-go/contract"
	"github.com/vennet-developers/cauthy-sdk-go/keys"
	"github.com/vennet-developers/cauthy-sdk-go/system"
)

// Pact is a contracted application's view of its contract: what its link
// says, its own keys, and how it stands against the contract in Cauthy.
type Pact struct{ auth *Auth }

// Pact is the application's contract, or nil when it runs by variables or
// its link gives it no identity of its own (no service block).
func (a *Auth) Pact() *Pact { return a.pact }

// Contract is what the link in the graph says.
func (p *Pact) Contract() *contract.Resolved { return p.auth.contract }

// Keys are the application's own keys: Current, Published, Rotate, Reseal.
func (p *Pact) Keys() *keys.Keys { return p.auth.ownKeys }

// JWKS serves the published keys (Auth serves them at JWKSPath too).
func (p *Pact) JWKS() http.Handler { return p.auth.ownKeys.Handler() }

// Status is how the system stands against its contract, as Cauthy checks it
// now. For a health endpoint.
func (p *Pact) Status(ctx context.Context) (*system.PactStatus, error) {
	return p.auth.sys.PactStatus(ctx, p.auth.contract.System)
}

// DefaultJWKSPath is what JWKSPath answers when the application publishes no
// keys: a path the handler answers 404, safe to mount.
const DefaultJWKSPath = "/.well-known/pact-jwks.json"

// JWKSPath is the path the application publishes its keys at (its contract's
// jwks_url), or DefaultJWKSPath when it publishes none. Mount Auth there too.
func (a *Auth) JWKSPath() string {
	if a.pact != nil {
		return a.contract.JWKSPath
	}
	return DefaultJWKSPath
}
