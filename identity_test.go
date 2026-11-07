package cauthy

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/internal/jose"
)

func TestIdentityNamesItsIssuerAndNeverPrintsItsToken(t *testing.T) {
	tok := token(t, nil)
	id, err := verifier(t, nil).VerifyAt(context.Background(), tok, now)
	if err != nil {
		t.Fatal(err)
	}
	if id.Issuer != goodConfig.Issuer || id.Token != tok {
		t.Fatalf("issuer %q, token kept: %v", id.Issuer, id.Token == tok)
	}
	sig := strings.Split(tok, ".")[2]
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("signed in", "identity", id)
	slog.New(slog.NewTextHandler(&buf, nil)).Info("signed in", "identity", *id)
	for _, out := range []string{fmt.Sprint(id), fmt.Sprintf("%v %+v %#v %s", id, *id, id, *id), buf.String()} {
		if strings.Contains(out, sig) {
			t.Fatalf("the token is printed: %s", out)
		}
		if !strings.Contains(out, id.Subject) {
			t.Fatalf("the subject is missing: %s", out)
		}
	}
}

func TestATokenErrorCapsTheKidItQuotes(t *testing.T) {
	strong, _ := testKeys(t)
	kid := strings.Repeat("k", 500)
	tok, err := jose.SignRS256(strong, map[string]any{"kid": kid}, map[string]any{"sub": "x"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier(t, nil).VerifyAt(context.Background(), tok, now)
	if reasonOf(err) != UnknownKid {
		t.Fatalf("want unknown_kid, got %v", err)
	}
	if strings.Contains(err.Error(), strings.Repeat("k", 65)) || !strings.Contains(err.Error(), strings.Repeat("k", 64)) {
		t.Fatalf("the kid is not capped at 64 characters: %s", err)
	}
}
