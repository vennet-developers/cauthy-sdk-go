package cauthy

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/internal/cfgerr"
	"github.com/vennet-developers/cauthy-sdk-go/system"
)

// VerifierConfigFromKey is a verifier's configuration from CAUTHY_KEY alone:
// the application proves itself with the key and asks Cauthy who it is
// (GET /v1/connect/self); the issuer, audience and workspace are Cauthy's
// answer. It waits for Cauthy until ctx is done: ErrUnavailable when Cauthy
// has not answered, ErrMisconfigured when it refuses the key. None of
// KeyReplaces may be set beside the key.
//
// It names no ClientID: a person's token is accepted whichever of the
// workspace's clients issued it, the key's or the sign-in client Cauthy names
// for it (sign_in_client_id), which may be another than the key's own.
// getenv nil is os.Getenv; hc nil a plain client.
func VerifierConfigFromKey(ctx context.Context, getenv func(string) string, hc *http.Client) (VerifierConfig, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	k, err := byKey(Options{}, getenv)
	if err != nil {
		return VerifierConfig{}, err
	}
	if k == nil {
		return VerifierConfig{}, cfgerr.New("CAUTHY_KEY is not set: make it on the application's card in Cauthy's dashboard")
	}
	if hc == nil {
		hc = &http.Client{}
	}
	d := k.key.Derive()
	sys, err := system.New(system.Options{Issuer: k.key.Issuer, ClientID: k.key.ClientID, HTTPClient: hc,
		Signer: &system.Signer{ClientID: k.key.ClientID, KID: d.KID, Key: d.Private}})
	if err != nil {
		return VerifierConfig{}, err
	}
	s := newIdentitySource(k.key.Issuer, sys.Token, hc, time.Now, slog.Default(), d.KID)
	for attempt := 0; ; attempt++ {
		err := s.ask(ctx)
		if err == nil {
			break
		}
		if refusal(err) {
			return VerifierConfig{}, ErrMisconfigured
		}
		select {
		case <-ctx.Done():
			return VerifierConfig{}, ErrUnavailable
		case <-time.After(s.retry[min(attempt, len(s.retry)-1)]):
		}
	}
	id := s.Current()
	return VerifierConfig{Issuer: withoutTrailingSlashes(id.Issuer), Audience: id.Audience, Tenant: id.Tenant.ID}, nil
}

// VerifierConfigFromEnv reads a verifier's configuration from the variables
// @cauthyhq/node's verifyToken reads: CAUTHY_ISSUER, CAUTHY_AUDIENCE and
// CAUTHY_TENANT_ID. getenv nil is os.Getenv.
//
// Deprecated: use VerifierConfigFromKey, which reads CAUTHY_KEY alone. The
// three variables leave in 2.0.
func VerifierConfigFromEnv(getenv func(string) string) (VerifierConfig, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	deprecated(slog.Default(), "Verifying with CAUTHY_ISSUER, CAUTHY_AUDIENCE and CAUTHY_TENANT_ID", "Use CAUTHY_KEY and VerifierConfigFromKey.")
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
