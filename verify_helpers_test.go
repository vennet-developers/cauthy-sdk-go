package cauthy

import (
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/internal/jose"
)

var goodConfig = VerifierConfig{
	Issuer:   "https://auth.example.com",
	Audience: "cauthy",
	Tenant:   "8a6e0804-2bd0-4672-b79a-d97027f5f2a1",
}

func staticKeys(kid string, key *rsa.PublicKey) *StaticKeys {
	k := &StaticKeys{byKid: map[string]*rsa.PublicKey{}}
	if key != nil {
		k.byKid[kid] = key
	}
	return k
}

func verifier(t *testing.T, change func(*VerifierConfig)) *Verifier {
	t.Helper()
	strong, _ := testKeys(t)
	cfg := goodConfig
	cfg.Keys = staticKeys("k", &strong.PublicKey)
	if change != nil {
		change(&cfg)
	}
	v, err := NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// token signs claims over a person's token as Cauthy issues it; a nil value
// removes the claim.
func token(t *testing.T, claims map[string]any) string {
	t.Helper()
	strong, _ := testKeys(t)
	base := map[string]any{
		"iss": goodConfig.Issuer, "aud": []string{goodConfig.Audience}, "tid": goodConfig.Tenant,
		"sub": "5c1b2f4e-9a3d-4b7e-8c6f-0d1e2f3a4b5c", "iat": now.Unix() - 60, "exp": now.Unix() + 840,
		"email": "ada@example.com", "roles": []string{"member", "billing"},
	}
	for k, v := range claims {
		if v == nil {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	tok, err := jose.SignRS256(strong, map[string]any{"kid": "k", "typ": "JWT"}, base)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func reasonOf(err error) Reason {
	var e *TokenError
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}
