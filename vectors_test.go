package cauthy_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	cauthy "github.com/vennet-developers/cauthy-sdk-go"
	"github.com/vennet-developers/cauthy-sdk-go/internal/spec"
)

// TestVectors runs every vector of cauthy-sdk-spec against the verifier: the
// verdict and the reason must match exactly, all 108 of them.
func TestVectors(t *testing.T) {
	f, jwks, err := spec.Vectors()
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) != 108 {
		t.Fatalf("%d vectors, want 108: sync testdata with scripts/sync-spec.sh", len(f.Cases))
	}
	if time.Duration(f.LeewaySeconds)*time.Second != cauthy.DefaultLeeway || f.MaxTokenBytes != cauthy.MaxTokenBytes {
		t.Fatalf("the vectors assume leeway %ds and %d bytes", f.LeewaySeconds, f.MaxTokenBytes)
	}
	keys, err := cauthy.ParseJWKS(jwks)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			v, err := cauthy.NewVerifier(cauthy.VerifierConfig{
				Issuer: c.Config.Issuer, Issuers: c.Config.Issuers, Audience: c.Config.Audience, Tenant: c.Config.Tenant,
				AllowAnonymous: c.Config.AllowAnonymous, AllowClientTokens: c.Config.AllowClientTokens, ClientID: c.Config.ClientID, Keys: keys,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = v.VerifyAt(context.Background(), c.Token, time.Unix(c.Now, 0))
			switch c.Expect {
			case "valid":
				if err != nil {
					t.Fatalf("%s: want valid, got %v", c.Description, err)
				}
			case "invalid":
				var e *cauthy.TokenError
				if !errors.As(err, &e) || string(e.Reason) != c.Reason {
					t.Fatalf("%s: want %s, got %v", c.Description, c.Reason, err)
				}
				if !slices.Contains(cauthy.Reasons, e.Reason) {
					t.Fatalf("%s is not in the closed list", e.Reason)
				}
			default:
				t.Fatalf("expect is %q", c.Expect)
			}
		})
	}
}
