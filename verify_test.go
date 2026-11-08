package cauthy

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestVerifyAnswersWhoTheTokenIsFor(t *testing.T) {
	tok := token(t, nil)
	id, err := verifier(t, nil).VerifyAt(context.Background(), tok, now)
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "5c1b2f4e-9a3d-4b7e-8c6f-0d1e2f3a4b5c" || id.Tenant != goodConfig.Tenant || id.Email != "ada@example.com" ||
		!slices.Equal(id.Roles, []string{"member", "billing"}) || id.Anonymous || id.Token != tok ||
		!id.ExpiresAt.Equal(now.Add(840*time.Second)) || id.ExpiresAt.Location() != time.UTC {
		t.Fatalf("identity: %+v", id)
	}
}

func TestVerifyUsesTheConfiguredClock(t *testing.T) {
	v := verifier(t, func(c *VerifierConfig) { c.Now = func() time.Time { return now } })
	if _, err := v.Verify(context.Background(), token(t, nil)); err != nil {
		t.Fatal(err)
	}
	if id, err := v.Verify(context.Background(), token(t, map[string]any{"roles": nil})); err != nil || id.Roles == nil {
		t.Fatalf("absent roles must be an empty list: %+v %v", id, err)
	}
}

func TestVerifyUsesTheConfiguredLeeway(t *testing.T) {
	tok := token(t, map[string]any{"exp": now.Unix() - 10})
	if _, err := verifier(t, nil).VerifyAt(context.Background(), tok, now); err != nil {
		t.Fatalf("default leeway: %v", err)
	}
	strict := verifier(t, func(c *VerifierConfig) { c.Leeway = LeewayOf(5 * time.Second) })
	if _, err := strict.VerifyAt(context.Background(), tok, now); reasonOf(err) != Expired {
		t.Fatalf("5s leeway: want expired, got %v", err)
	}
	none := verifier(t, func(c *VerifierConfig) { c.Leeway = LeewayOf(0) })
	if _, err := none.VerifyAt(context.Background(), token(t, map[string]any{"exp": now.Unix()}), now); reasonOf(err) != Expired {
		t.Fatalf("exp is now: want expired, got %v", err)
	}
}

func TestVerifyAllowsGuestsAndSystemsOnlyWhenTold(t *testing.T) {
	guest := token(t, map[string]any{"anon": true, "email": nil})
	if _, err := verifier(t, nil).VerifyAt(context.Background(), guest, now); reasonOf(err) != AnonymousToken {
		t.Fatalf("want anonymous_token, got %v", err)
	}
	id, err := verifier(t, func(c *VerifierConfig) { c.AllowAnonymous = true }).VerifyAt(context.Background(), guest, now)
	if err != nil || !id.Anonymous {
		t.Fatalf("allowed: %+v, %v", id, err)
	}
	sys := token(t, map[string]any{"sys": "acme-billing", "email": nil})
	if _, err := verifier(t, nil).VerifyAt(context.Background(), sys, now); reasonOf(err) != SystemToken {
		t.Fatalf("want system_token, got %v", err)
	}
	id, err = verifier(t, func(c *VerifierConfig) { c.AllowSystem = true }).VerifyAt(context.Background(), sys, now)
	if err != nil || id.System != "acme-billing" {
		t.Fatalf("allowed: %+v, %v", id, err)
	}
	for _, mark := range []any{false, 0} {
		if _, err := verifier(t, nil).VerifyAt(context.Background(), token(t, map[string]any{"sys": mark}), now); reasonOf(err) != SystemToken {
			t.Fatalf("sys=%v: its presence is the mark, got %v", mark, err)
		}
	}
}

func TestVerifyAcceptsEveryListedIssuerAndNoOther(t *testing.T) {
	const custom = "https://login.acme.example"
	listed := verifier(t, func(c *VerifierConfig) { c.Issuers = []string{custom} })
	for _, iss := range []string{goodConfig.Issuer, custom} {
		if _, err := listed.VerifyAt(context.Background(), token(t, map[string]any{"iss": iss}), now); err != nil {
			t.Errorf("%s: %v", iss, err)
		}
	}
	for _, iss := range []string{custom + "/", "https://Login.acme.example", "https://attacker.example.com"} {
		if _, err := listed.VerifyAt(context.Background(), token(t, map[string]any{"iss": iss}), now); reasonOf(err) != WrongIssuer {
			t.Errorf("%s: want wrong_issuer, got %v", iss, err)
		}
	}
}

func TestRefusalNeverQuotesTheToken(t *testing.T) {
	tok := token(t, map[string]any{"tid": "3f2a9c41-7d4b-4e8a-a1c2-5b6d7e8f9a0b"})
	_, err := verifier(t, nil).VerifyAt(context.Background(), tok, now)
	if reasonOf(err) != WrongTenant {
		t.Fatalf("want wrong_tenant, got %v", err)
	}
	if strings.Contains(err.Error(), strings.Split(tok, ".")[2]) {
		t.Fatal("the error quotes the token")
	}
}

func TestVerifyReportsEmailVerified(t *testing.T) {
	id, err := verifier(t, nil).VerifyAt(context.Background(), token(t, map[string]any{"email_verified": true}), now)
	if err != nil || !id.EmailVerified {
		t.Fatalf("%+v, %v", id, err)
	}
	id, err = verifier(t, nil).VerifyAt(context.Background(), token(t, nil), now)
	if err != nil || id.EmailVerified {
		t.Fatalf("absent must read false: %+v, %v", id, err)
	}
}

func TestAKeySetNeverFetchedIsSaidApart(t *testing.T) {
	v := verifier(t, func(c *VerifierConfig) {
		c.Keys = NewRemoteKeys(func(context.Context) ([]byte, time.Duration, error) {
			return nil, 0, errors.New("unreachable")
		}, 0, nil)
	})
	_, err := v.VerifyAt(context.Background(), token(t, nil), now)
	if reasonOf(err) != UnknownKid || !errors.Is(err, ErrNoKeySet) {
		t.Fatalf("want unknown_kid wrapping ErrNoKeySet, got %v", err)
	}
}

func TestVerifyWithAllowSystemWantsANamedSystem(t *testing.T) {
	allow := verifier(t, func(c *VerifierConfig) { c.AllowSystem = true })
	for _, mark := range []any{false, 0, "", []string{"acme-billing"}, map[string]any{}} {
		tok := token(t, map[string]any{"sys": mark, "email": nil})
		if _, err := allow.VerifyAt(context.Background(), tok, now); reasonOf(err) != InvalidClaim {
			t.Errorf("sys=%v: want invalid_claim, got %v", mark, err)
		}
	}
	id, err := allow.VerifyAt(context.Background(), token(t, map[string]any{"sys": "acme-billing", "email": nil}), now)
	if err != nil || !id.IsSystem || id.System != "acme-billing" {
		t.Fatalf("%+v %v", id, err)
	}
	id, err = allow.VerifyAt(context.Background(), token(t, nil), now)
	if err != nil || id.IsSystem || id.System != "" {
		t.Fatalf("a person's token: %+v %v", id, err)
	}
}

func TestVerifyRefusesAClientsOwnTokenUnlessTold(t *testing.T) {
	// A client_credentials token: token_use "client", the client's public id,
	// no email. The presence of token_use is the mark, whatever its value.
	for _, use := range []string{"client", "", "person"} {
		tok := token(t, map[string]any{"token_use": use, "client_id": "acme-billing", "email": nil})
		if _, err := verifier(t, nil).VerifyAt(context.Background(), tok, now); reasonOf(err) != ClientToken {
			t.Errorf("token_use %q: want client_token, got %v", use, err)
		}
	}
	tok := token(t, map[string]any{"token_use": "client", "client_id": "acme-billing", "email": nil})
	id, err := verifier(t, func(c *VerifierConfig) { c.AllowClientTokens = true }).VerifyAt(context.Background(), tok, now)
	if err != nil || id.ClientID != "acme-billing" || id.AuthorizedParty != "" {
		t.Fatalf("allowed: %+v, %v", id, err)
	}
	// A system's own token is refused as a system's, even with token_use.
	both := token(t, map[string]any{"sys": "acme-crm", "token_use": "client"})
	if _, err := verifier(t, func(c *VerifierConfig) { c.AllowClientTokens = true }).VerifyAt(context.Background(), both, now); reasonOf(err) != SystemToken {
		t.Fatalf("sys and token_use: want system_token, got %v", err)
	}
}

func TestVerifyTypesTokenUseAndAzp(t *testing.T) {
	for _, claims := range []map[string]any{
		{"token_use": json.RawMessage("null")},
		{"token_use": 1},
		{"azp": json.RawMessage("null")},
		{"azp": []string{"acme-web"}},
	} {
		v := verifier(t, func(c *VerifierConfig) { c.AllowClientTokens = true })
		if _, err := v.VerifyAt(context.Background(), token(t, claims), now); reasonOf(err) != InvalidClaim {
			t.Errorf("%v: want invalid_claim, got %v", claims, err)
		}
	}
}

func TestVerifyReportsTheAuthorizedParty(t *testing.T) {
	id, err := verifier(t, nil).VerifyAt(context.Background(), token(t, map[string]any{"azp": "acme-web"}), now)
	if err != nil || id.AuthorizedParty != "acme-web" || id.ClientID != "" {
		t.Fatalf("%+v, %v", id, err)
	}
}
