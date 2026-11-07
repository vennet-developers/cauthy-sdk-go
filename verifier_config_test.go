package cauthy

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewVerifierRefusesBadConfig(t *testing.T) {
	cases := map[string]func(*VerifierConfig){
		"issuer missing":         func(c *VerifierConfig) { c.Issuer = "" },
		"issuer http":            func(c *VerifierConfig) { c.Issuer = "http://auth.example.com" },
		"issuer trailing slash":  func(c *VerifierConfig) { c.Issuer = "https://auth.example.com/" },
		"issuer with query":      func(c *VerifierConfig) { c.Issuer = "https://auth.example.com?x=1" },
		"issuers entry http":     func(c *VerifierConfig) { c.Issuers = []string{"http://login.acme.example"} },
		"issuers entry slash":    func(c *VerifierConfig) { c.Issuers = []string{"https://login.acme.example/"} },
		"issuers entry empty":    func(c *VerifierConfig) { c.Issuers = []string{""} },
		"audience missing":       func(c *VerifierConfig) { c.Audience = "" },
		"tenant missing":         func(c *VerifierConfig) { c.Tenant = "" },
		"tenant upper case":      func(c *VerifierConfig) { c.Tenant = strings.ToUpper(c.Tenant) },
		"tenant nil":             func(c *VerifierConfig) { c.Tenant = nilUUID },
		"leeway negative":        func(c *VerifierConfig) { c.Leeway = LeewayOf(-time.Second) },
		"leeway over 60 seconds": func(c *VerifierConfig) { c.Leeway = LeewayOf(61 * time.Second) },
	}
	for name, change := range cases {
		cfg := goodConfig
		change(&cfg)
		_, err := NewVerifier(cfg)
		var ce *ConfigError
		if !errors.As(err, &ce) {
			t.Errorf("%s: want a *ConfigError, got %v", name, err)
		}
	}
}

func TestNewVerifierAcceptsLocalhostOverHTTPAndNoLookalike(t *testing.T) {
	for _, iss := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://auth.localhost:8080", "http://cauthy.test", "https://auth.example.com"} {
		cfg := goodConfig
		cfg.Issuer = iss
		if _, err := NewVerifier(cfg); err != nil {
			t.Errorf("%s: %v", iss, err)
		}
	}
	for _, iss := range []string{"http://notlocalhost", "http://localhost.example.com", "http://attacker.test.example.com", "http://test"} {
		cfg := goodConfig
		cfg.Issuer = iss
		if _, err := NewVerifier(cfg); err == nil {
			t.Errorf("%s: want an error", iss)
		}
	}
}

func TestVerifierLeewayDefaultsAndZeroIsConfigurable(t *testing.T) {
	v, err := NewVerifier(goodConfig)
	if err != nil || v.leeway != DefaultLeeway {
		t.Fatalf("%v %v", v, err)
	}
	cfg := goodConfig
	cfg.Leeway = LeewayOf(0)
	if v, err = NewVerifier(cfg); err != nil || v.leeway != 0 {
		t.Fatalf("an explicit zero leeway: %v %v", v, err)
	}
	if _, ok := v.keys.(*RemoteKeys); !ok {
		t.Fatalf("no Keys must mean Cauthy's published set, got %T", v.keys)
	}
}

func TestJWKSURLIsDerivedFromTheIssuer(t *testing.T) {
	got, err := JWKSURL(goodConfig.Issuer)
	if err != nil || got != "https://auth.example.com/.well-known/jwks.json" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := JWKSURL("http://auth.example.com"); err == nil {
		t.Error("http for a public host: want an error")
	}
}
