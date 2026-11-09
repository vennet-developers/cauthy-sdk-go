package cauthy

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
	"github.com/vennet-developers/cauthy-sdk-go/contract"
	"github.com/vennet-developers/cauthy-sdk-go/internal/jose"
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
	c := &contract.Resolved{Link: "acme-crm-signs-in-with-cauthy", Issuer: "https://id.example.com", TenantID: goodConfig.Tenant, Audience: "cauthy", TokenAlgorithm: "RS256",
		ClientID: "pact.acme-crm-signs-in-with-cauthy"}
	cfg, err := VerifierConfigFromContract(c)
	// The link's sign-in client: a person's token issued through another is refused (R15).
	if err != nil || cfg.Issuer != c.Issuer || cfg.Tenant != c.TenantID || cfg.Audience != "cauthy" || cfg.ClientID != c.ClientID {
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

func TestVerifierConfigFromKey(t *testing.T) {
	f := cauthytest.New()
	key := f.IssueKey()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg, err := VerifierConfigFromKey(ctx, envOf(map[string]string{"CAUTHY_KEY": key}), f.Client())
	if err != nil || cfg.Issuer != f.Issuer || cfg.Audience != f.Issuer || cfg.Tenant != cauthytest.TenantID {
		t.Fatalf("%+v %v", cfg, err)
	}
	// A token Cauthy issued for this workspace verifies with it.
	strong, _ := testKeys(t)
	cfg.Keys = staticKeys("k", &strong.PublicKey)
	v, err := NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := jose.SignRS256(strong, map[string]any{"kid": "k", "typ": "JWT"}, map[string]any{"iss": f.Issuer, "aud": []string{f.Issuer}, "tid": cauthytest.TenantID,
		"sub": "5c1b2f4e-9a3d-4b7e-8c6f-0d1e2f3a4b5c", "iat": now.Unix() - 60, "exp": now.Unix() + 840})
	if id, err := v.VerifyAt(ctx, tok, now); err != nil || id.Subject != "5c1b2f4e-9a3d-4b7e-8c6f-0d1e2f3a4b5c" {
		t.Fatalf("%v %v", id, err)
	}

	if _, err := VerifierConfigFromKey(ctx, envOf(map[string]string{"CAUTHY_KEY": key, "CAUTHY_AUDIENCE": "x"}), f.Client()); err == nil ||
		!strings.Contains(err.Error(), "CAUTHY_AUDIENCE") {
		t.Fatalf("a second source: %v", err)
	}
	if _, err := VerifierConfigFromKey(ctx, noEnv, f.Client()); err == nil || !strings.Contains(err.Error(), "CAUTHY_KEY") {
		t.Fatalf("no key: %v", err)
	}
	f.RevokeKey(f.RegisteredKids()[0])
	if _, err := VerifierConfigFromKey(ctx, envOf(map[string]string{"CAUTHY_KEY": key}), f.Client()); !errors.Is(err, ErrMisconfigured) {
		t.Fatalf("revoked: %v", err)
	}
	f = cauthytest.New()
	key = f.IssueKey()
	f.SetDown(true)
	short, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stop()
	if _, err := VerifierConfigFromKey(short, envOf(map[string]string{"CAUTHY_KEY": key}), f.Client()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("down: %v", err)
	}
}

func TestVerifierConfigFromEnvWarnsOnce(t *testing.T) {
	var c counted
	before := slog.Default()
	slog.SetDefault(c.logger(t))
	defer slog.SetDefault(before)
	env := map[string]string{"CAUTHY_ISSUER": "https://id.example.com", "CAUTHY_AUDIENCE": "cauthy", "CAUTHY_TENANT_ID": goodConfig.Tenant}
	for range 2 {
		if _, err := VerifierConfigFromEnv(envOf(env)); err != nil {
			t.Fatal(err)
		}
	}
	if d := c.deprecations(); len(d) != 1 || !strings.Contains(d[0], "VerifierConfigFromKey") {
		t.Fatalf("%v", d)
	}
}
