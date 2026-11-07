package cauthy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParseJWKSKeepsOnlyUsableKeys(t *testing.T) {
	strong, weak := testKeys(t)
	set, err := ParseJWKS([]byte(`{"keys":[` +
		jwkJSON(&strong.PublicKey, "RSA", "sig", "RS256", "good") + `,` +
		jwkJSON(&strong.PublicKey, "RSA", "", "", "bare") + `,` +
		jwkJSON(&strong.PublicKey, "RSA", "enc", "RS256", "enc") + `,` +
		jwkJSON(&strong.PublicKey, "RSA", "sig", "RS384", "rs384") + `,` +
		jwkJSON(&strong.PublicKey, "EC", "sig", "RS256", "ec") + `,` +
		jwkJSON(&strong.PublicKey, "RSA", "sig", "RS256", "") + `,` +
		jwkJSON(&weak.PublicKey, "RSA", "sig", "RS256", "weak") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, kid := range []string{"good", "bare"} {
		if k, err := set.Key(ctx, kid); err != nil || k.N.Cmp(strong.N) != 0 {
			t.Errorf("%s: %v", kid, err)
		}
	}
	for _, kid := range []string{"enc", "rs384", "ec", "", "absent"} {
		if _, err := set.Key(ctx, kid); !errors.Is(err, ErrUnknownKid) {
			t.Errorf("%s: want ErrUnknownKid, got %v", kid, err)
		}
	}
	if _, err := set.Key(ctx, "weak"); !errors.Is(err, ErrWeakKey) {
		t.Errorf("weak: want ErrWeakKey, got %v", err)
	}
}

func TestParseJWKSRefusesBadSets(t *testing.T) {
	strong, _ := testKeys(t)
	dup := jwkJSON(&strong.PublicKey, "RSA", "sig", "RS256", "same")
	for name, raw := range map[string]string{
		"not json":        `nope`,
		"no keys":         `{}`,
		"duplicate kid":   `{"keys":[` + dup + `,` + dup + `]}`,
		"empty array":     `{"keys":[]}`,
		"only unusable":   `{"keys":[{"kty":"EC"}]}`,
		"keys not a list": `{"keys":{}}`,
	} {
		if _, err := ParseJWKS([]byte(raw)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestParseJWKSSkipsMalformedMembersAndHonoursKeyOps(t *testing.T) {
	strong, _ := testKeys(t)
	n := base64.RawURLEncoding.EncodeToString(strong.N.Bytes())
	good := jwkJSON(&strong.PublicKey, "RSA", "sig", "RS256", "good")
	m := func(extra string) string {
		return fmt.Sprintf(`{"kty":"RSA","kid":"k","n":%q,"e":"AQAB"%s}`, n, extra)
	}
	raw := `{"keys":[` + good + `,"not an object",{"kty":7},` +
		strings.Replace(m(``), `"k"`, `"upper"`, 1) + `,` +
		`{"KTY":"RSA","KID":"loud","n":"` + n + `","e":"AQAB"},` +
		strings.Replace(m(`,"key_ops":["sign"]`), `"k"`, `"signonly"`, 1) + `,` +
		strings.Replace(m(`,"key_ops":["verify"]`), `"k"`, `"verifyonly"`, 1) + `,` +
		strings.Replace(m(`,"kid":1`), `"k"`, `"dupe"`, 1) + `]}`
	set, err := ParseJWKS([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, kid := range []string{"good", "upper", "verifyonly"} {
		if _, err := set.Key(ctx, kid); err != nil {
			t.Errorf("%s: %v", kid, err)
		}
	}
	for _, kid := range []string{"loud", "signonly", "dupe", "k"} {
		if _, err := set.Key(ctx, kid); !errors.Is(err, ErrUnknownKid) {
			t.Errorf("%s: want ErrUnknownKid, got %v", kid, err)
		}
	}
}

func TestParseJWKSReadsKeysByItsExactName(t *testing.T) {
	testKeys(t)
	for _, raw := range []string{`{"KEYS":[` + setOf("a")[9:], `{"Keys":[` + setOf("a")[9:]} {
		if _, err := ParseJWKS([]byte(raw)); err == nil {
			t.Errorf("%.12s…: want an error", raw)
		}
	}
	if _, err := ParseJWKS([]byte(setOf("a"))); err != nil {
		t.Fatal(err)
	}
}
