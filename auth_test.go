package cauthy

import (
	"errors"
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
)

func TestNewRefusesAnUnsafeConfiguration(t *testing.T) {
	f := cauthytest.New()
	cases := map[string]struct {
		change func(*Options)
		says   string
	}{
		"no issuer":       {func(o *Options) { o.Issuer = "id.example.com" }, "issuer"},
		"no client":       {func(o *Options) { o.ClientID = "" }, "CAUTHY_CLIENT_ID"},
		"short secret":    {func(o *Options) { o.Secret = "short" }, "at least 32"},
		"bad base URL":    {func(o *Options) { o.BaseURL = "https://app.example.com/path" }, "public origin"},
		"bad header mode": {func(o *Options) { o.RequestHeader = "maybe" }, "requestHeader"},
	}
	for name, c := range cases {
		o := Options{Issuer: f.Issuer, ClientID: "acme-crm", Secret: testSecret, Getenv: noEnv}
		c.change(&o)
		_, err := New(o)
		var ce *ConfigError
		if !errors.As(err, &ce) || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: want a config error saying %q, got %v", name, c.says, err)
		}
	}
}

func TestNewReadsTheVariables(t *testing.T) {
	env := map[string]string{"CAUTHY_ISSUER": "https://id.example.com/", "CAUTHY_CLIENT_ID": "acme-crm", "CAUTHY_SECRET": testSecret, "CAUTHY_TENANT": "acme"}
	a, err := New(Options{Getenv: func(k string) string { return env[k] }, BasePath: "auth/"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Issuer() != "https://id.example.com" || a.ClientID() != "acme-crm" || a.tenant != "acme" || a.BasePath() != "/auth" ||
		a.JWKSPath() != DefaultJWKSPath || a.Pact() != nil || a.SignInURL("/x") != "/auth/login?return_to=%2Fx" {
		t.Fatalf("%+v", a)
	}
}
