// Copied from cauthy-sdk-spec conformance/cauthykey/key.go; do not edit here (make key-reference).
// Package cauthykey is the reference implementation of CAUTHY_KEY
// (key/cauthy-key.md): parsing, composing, deriving and signing. Standard
// library only, so the Go SDK can copy this file as it is.
package cauthykey

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Prefix is the version this package reads and writes.
const Prefix = "cauthy1"

// MaxLen is the longest key accepted, after trimming.
const MaxLen = 512

// The reasons a key is refused (key/cauthy-key.md §3).
const (
	ReasonFormat   = "key_format"
	ReasonVersion  = "key_version"
	ReasonChecksum = "key_checksum"
	ReasonIssuer   = "key_issuer"
	ReasonClient   = "key_client"
	ReasonSecret   = "key_secret"
)

// The HKDF labels (§4).
const (
	LabelCookie = "pact/cookie/v1"
	LabelFlow   = "pact/flow/v1"
	LabelSeal   = "pact/seal/v1"
	LabelSign   = "cauthy/sign/v1"
)

// AssertionType is RFC 7523's client assertion type.
const AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// Error is a refused key. It never holds the key or its secret.
type Error struct {
	Reason string
	Msg    string
}

func (e *Error) Error() string { return e.Msg }

func refuse(reason, msg string) error { return &Error{Reason: reason, Msg: "CAUTHY_KEY: " + msg} }

// Key is a parsed CAUTHY_KEY.
type Key struct {
	Issuer   string // an origin, e.g. https://cauthy.api.example.com
	ClientID string
	Secret   string // the 43-character segment: the HKDF input, as text
}

var (
	b64      = base64.RawURLEncoding.Strict()
	clientRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	prefixRe = regexp.MustCompile(`^cauthy[0-9]+$`)
)

// Parse reads a key, refusing it with the first rule of §3 it breaks.
func Parse(s string) (*Key, error) {
	s = strings.Trim(s, " \t\r\n")
	if s == "" || len(s) > MaxLen || !printableASCII(s) {
		return nil, refuse(ReasonFormat, "not a Cauthy key (copy it again from the dashboard)")
	}
	head, _, _ := strings.Cut(s, ".")
	if head != Prefix {
		if prefixRe.MatchString(head) {
			return nil, refuse(ReasonVersion, "this key is for a newer SDK ("+head+"): update the SDK")
		}
		return nil, refuse(ReasonFormat, "not a Cauthy key (copy it again from the dashboard)")
	}
	parts := strings.Split(s, ".")
	if len(parts) != 5 || slicesHasEmpty(parts) {
		return nil, refuse(ReasonFormat, "not a Cauthy key (copy it again from the dashboard)")
	}
	if subtle.ConstantTimeCompare([]byte(checksum(strings.Join(parts[:4], "."))), []byte(parts[4])) != 1 {
		return nil, refuse(ReasonChecksum, "the key is damaged (part of it is missing or changed): copy it again from the dashboard")
	}
	issuer, err := b64.DecodeString(parts[1])
	if err != nil || !ValidIssuer(string(issuer)) {
		return nil, refuse(ReasonIssuer, "the key names no valid Cauthy address")
	}
	client, err := b64.DecodeString(parts[2])
	if err != nil || !clientRe.Match(client) {
		return nil, refuse(ReasonClient, "the key names no valid client")
	}
	if len(parts[3]) != 43 {
		return nil, refuse(ReasonSecret, "the key's secret is not 32 bytes")
	}
	if raw, err := b64.DecodeString(parts[3]); err != nil || len(raw) != 32 {
		return nil, refuse(ReasonSecret, "the key's secret is not 32 bytes")
	}
	return &Key{Issuer: string(issuer), ClientID: string(client), Secret: parts[3]}, nil
}

// Compose writes a key, refusing values Parse would refuse.
func Compose(issuer, clientID, secret string) (string, error) {
	k, err := Parse(composeUnchecked(issuer, clientID, secret))
	if err != nil {
		return "", err
	}
	return composeUnchecked(k.Issuer, k.ClientID, k.Secret), nil
}

// composeUnchecked writes a key with a correct checksum around any values;
// the vectors use it to build keys that fail a later rule.
func composeUnchecked(issuer, clientID, secret string) string {
	body := Prefix + "." + b64.EncodeToString([]byte(issuer)) + "." + b64.EncodeToString([]byte(clientID)) + "." + secret
	return body + "." + checksum(body)
}

// ComposeUnchecked writes a key with a correct checksum around any values.
// For vectors and tests only: a real key is made with Compose.
func ComposeUnchecked(issuer, clientID, secret string) string {
	return composeUnchecked(issuer, clientID, secret)
}

func checksum(body string) string {
	sum := sha256.Sum256([]byte(body))
	return b64.EncodeToString(sum[:6])
}

// ValidIssuer accepts an origin as §3 rule 5 says.
func ValidIssuer(s string) bool {
	if !printableASCII(s) {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" || u.User != nil || u.Path != "" || u.RawPath != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Host == "" || u.String() != s {
		return false
	}
	if strings.ToLower(u.Host) != u.Host {
		return false
	}
	// A WHATWG URL drops the default port; keeping it would make the browser
	// and Node read another origin than Go.
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		return false
	}
	if !canonicalPort(u) || !canonicalHost(u.Hostname()) {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}

// canonicalPort accepts no port, or one a WHATWG URL keeps as written:
// decimal, no leading zero, at most 65535. "host:" and "host:0443" are
// refused because a browser would read them as another origin.
func canonicalPort(u *url.URL) bool {
	rest := u.Host
	if i := strings.LastIndex(rest, "]"); i >= 0 {
		rest = rest[i+1:]
	}
	if !strings.Contains(rest, ":") {
		return true
	}
	p := u.Port()
	if p == "" || len(p) > 5 || (len(p) > 1 && p[0] == '0') {
		return false
	}
	n, err := strconv.Atoi(p)
	return err == nil && n <= 65535
}

// canonicalHost refuses the IP addresses a WHATWG URL would rewrite:
// IPv4 not in dotted-decimal form (127.1, 0x7f.0.0.1, 1.2.3.04), IPv6 not in
// RFC 5952 form, and IPv4-mapped IPv6 (serialized differently by Go and
// WHATWG, and never a Cauthy address).
func canonicalHost(h string) bool {
	if strings.Contains(h, ":") {
		a, err := netip.ParseAddr(h)
		return err == nil && a.Is6() && !a.Is4In6() && a.Zone() == "" && a.String() == h
	}
	labels := strings.Split(strings.TrimSuffix(h, "."), ".")
	last := labels[len(labels)-1]
	if last == "" || !numericLabel(last) {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.Is4() && a.String() == h
}

// numericLabel says whether WHATWG's host parser would read the label as a
// number, making the whole host an IPv4 address.
func numericLabel(l string) bool {
	if strings.HasPrefix(l, "0x") || strings.HasPrefix(l, "0X") {
		return true
	}
	for i := 0; i < len(l); i++ {
		if l[i] < '0' || l[i] > '9' {
			return false
		}
	}
	return true
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func slicesHasEmpty(parts []string) bool {
	for _, p := range parts {
		if p == "" {
			return true
		}
	}
	return false
}

// Derived is everything a key stands for.
type Derived struct {
	Labels  map[string][]byte // LabelCookie, LabelFlow, LabelSeal, LabelSign -> 32 bytes
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
	X       string // the public key, b64u
	KID     string // RFC 7638 thumbprint
}

// Derive computes §4 and §5.
func (k *Key) Derive() *Derived {
	d := &Derived{Labels: map[string][]byte{}}
	for _, l := range []string{LabelCookie, LabelFlow, LabelSeal, LabelSign} {
		b, err := hkdf.Key(sha256.New, []byte(k.Secret), nil, l, 32)
		if err != nil {
			panic(err) // 32 bytes is always within HKDF-SHA-256's reach
		}
		d.Labels[l] = b
	}
	d.Private = ed25519.NewKeyFromSeed(d.Labels[LabelSign])
	d.Public = d.Private.Public().(ed25519.PublicKey)
	d.X = b64.EncodeToString(d.Public)
	d.KID = Thumbprint(d.X)
	return d
}

// PublicJWK is the public key as Cauthy registers it.
func (d *Derived) PublicJWK() map[string]string {
	return map[string]string{"kty": "OKP", "crv": "Ed25519", "x": d.X}
}

// Thumbprint is RFC 7638's for an Ed25519 public key given by its x.
func Thumbprint(x string) string {
	sum := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`))
	return b64.EncodeToString(sum[:])
}

// Claims of an assertion, in the member order §6 fixes.
type Claims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Jti string `json:"jti"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// Assertion signs §6's client assertion. jti must be a fresh UUID v4.
func (d *Derived) Assertion(clientID, tokenEndpoint, jti string, now time.Time) string {
	header := `{"alg":"EdDSA","kid":"` + d.KID + `"}`
	body, err := json.Marshal(Claims{Iss: clientID, Sub: clientID, Aud: tokenEndpoint, Jti: jti, Iat: now.Unix(), Exp: now.Unix() + 120})
	if err != nil {
		panic(err)
	}
	si := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString(body)
	return si + "." + b64.EncodeToString(ed25519.Sign(d.Private, []byte(si)))
}

// VerifyAssertion checks the signature and returns the claims. It checks
// nothing else: times, audience and replay are the caller's.
func VerifyAssertion(pub ed25519.PublicKey, jws string) (*Claims, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a compact JWS")
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &h) != nil || h.Alg != "EdDSA" {
		return nil, errors.New("the header is not EdDSA")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, errors.New("the signature does not verify")
	}
	cb, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("the claims are not base64url")
	}
	var c Claims
	if err := json.Unmarshal(cb, &c); err != nil {
		return nil, errors.New("the claims are not JSON")
	}
	return &c, nil
}
