package cauthy

import (
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/contract"
)

func TestVerifierConfigFromEnv(t *testing.T) {
	env := map[string]string{"CAUTHY_ISSUER": "https://id.example.com/", "CAUTHY_AUDIENCE": "cauthy", "CAUTHY_TENANT_ID": goodConfig.Tenant}
	cfg, err := VerifierConfigFromEnv(func(k string) string { return env[k] })
	if err != nil || cfg.Issuer != "https://id.example.com" || cfg.Audience != "cauthy" || cfg.Tenant != goodConfig.Tenant {
		t.Fatalf("%+v %v", cfg, err)
	}
	delete(env, "CAUTHY_AUDIENCE")
	if _, err := VerifierConfigFromEnv(func(k string) string { return env[k] }); err == nil || !strings.Contains(err.Error(), "CAUTHY_AUDIENCE") {
		t.Fatalf("%v", err)
	}
}

func TestVerifierConfigFromContract(t *testing.T) {
	c := &contract.Resolved{Link: "acme-crm-signs-in-with-cauthy", Issuer: "https://id.example.com", TenantID: goodConfig.Tenant, Audience: "cauthy", TokenAlgorithm: "RS256"}
	cfg, err := VerifierConfigFromContract(c)
	if err != nil || cfg.Issuer != c.Issuer || cfg.Tenant != c.TenantID || cfg.Audience != "cauthy" {
		t.Fatalf("%+v %v", cfg, err)
	}
	if _, err := NewVerifier(cfg); err != nil {
		t.Fatal(err)
	}
	c.TokenAlgorithm = "HS256"
	if _, err := VerifierConfigFromContract(c); err == nil {
		t.Fatal("HS256: want an error")
	}
	c.TokenAlgorithm, c.Audience = "", ""
	if _, err := VerifierConfigFromContract(c); err == nil {
		t.Fatal("no audience: want an error")
	}
}
