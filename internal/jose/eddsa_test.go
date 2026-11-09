package jose

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/cauthykey"
)

// SignEdDSA writes the spec's assertion byte for byte: it is what the system
// client sends.
func TestSignEdDSAIsTheVectorsAssertion(t *testing.T) {
	raw, err := os.ReadFile("../spec/testdata/cauthy-key.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Valid []struct {
			Key       string `json:"key"`
			ClientID  string `json:"client_id"`
			Assertion struct {
				TokenEndpoint string `json:"token_endpoint"`
				Jti           string `json:"jti"`
				Iat           int64  `json:"iat"`
				JWS           string `json:"jws"`
			} `json:"assertion"`
		} `json:"valid"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || len(v.Valid) == 0 {
		t.Fatal("no vectors", err)
	}
	for _, c := range v.Valid {
		k, err := cauthykey.Parse(c.Key)
		if err != nil {
			t.Fatal(err)
		}
		d := k.Derive()
		iat := time.Unix(c.Assertion.Iat, 0).Unix()
		got, err := SignEdDSA(d.Private, d.KID, cauthykey.Claims{Iss: c.ClientID, Sub: c.ClientID, Aud: c.Assertion.TokenEndpoint,
			Jti: c.Assertion.Jti, Iat: iat, Exp: iat + 120})
		if err != nil || got != c.Assertion.JWS {
			t.Fatalf("SignEdDSA differs: %v\n%s\n%s", err, got, c.Assertion.JWS)
		}
	}
}
