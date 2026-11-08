package cauthy

import (
	"os"
	"strings"

	"github.com/vennet-developers/cauthy-sdk-go/contract"
	"github.com/vennet-developers/cauthy-sdk-go/internal/cfgerr"
)

// VerifierConfigFromEnv reads a verifier's configuration from the variables
// @cauthyhq/node's verifyToken reads: CAUTHY_ISSUER, CAUTHY_AUDIENCE and
// CAUTHY_TENANT_ID. getenv nil is os.Getenv.
func VerifierConfigFromEnv(getenv func(string) string) (VerifierConfig, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	cfg := VerifierConfig{
		Issuer:   strings.TrimRight(getenv("CAUTHY_ISSUER"), "/"),
		Audience: getenv("CAUTHY_AUDIENCE"),
		Tenant:   getenv("CAUTHY_TENANT_ID"),
	}
	for name, v := range map[string]string{"CAUTHY_ISSUER": cfg.Issuer, "CAUTHY_AUDIENCE": cfg.Audience, "CAUTHY_TENANT_ID": cfg.Tenant} {
		if v == "" {
			return VerifierConfig{}, cfgerr.New("%s is not set", name)
		}
	}
	return cfg, nil
}

// VerifierConfigFromContract is a verifier's configuration from the
// application's link in the Pact graph: Cauthy's address, the workspace, the
// audience and algorithm of the capability the link uses, and the link's
// sign-in client (a person's token issued through another is refused with
// wrong_client).
func VerifierConfigFromContract(c *contract.Resolved) (VerifierConfig, error) {
	if c.Audience == "" {
		return VerifierConfig{}, cfgerr.New("the link %s uses a capability that names no token audience: set VerifierConfig.Audience", c.Link)
	}
	if c.TokenAlgorithm != "" && c.TokenAlgorithm != "RS256" {
		return VerifierConfig{}, cfgerr.New("the link %s signs tokens with %q: Cauthy's tokens are RS256", c.Link, c.TokenAlgorithm)
	}
	return VerifierConfig{Issuer: c.Issuer, Audience: c.Audience, Tenant: c.TenantID, ClientID: c.ClientID}, nil
}
