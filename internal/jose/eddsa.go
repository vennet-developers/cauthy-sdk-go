package jose

import (
	"crypto/ed25519"
	"encoding/json"
)

// SignEdDSA signs a compact JWS with header {"alg":"EdDSA","kid":kid} and the
// given claims, serialized as json.Marshal writes them (struct field order):
// the client assertion of key/cauthy-key.md §6, byte for byte.
func SignEdDSA(key ed25519.PrivateKey, kid string, claims any) (string, error) {
	h, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}{"EdDSA", kid})
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	si := Encode(h) + "." + Encode(c)
	return si + "." + Encode(ed25519.Sign(key, []byte(si))), nil
}
