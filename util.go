package cauthy

import (
	"crypto/rand"
	"crypto/sha256"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// withoutTrailingSlashes is s without its trailing slashes.
func withoutTrailingSlashes(s string) string { return strings.TrimRight(s, "/") }

// localPath is candidate when it is a path of this application and nothing
// else (never another site, never //host, no control characters, no
// backslash), else fallback.
func localPath(candidate, fallback string) string {
	if candidate == "" || !strings.HasPrefix(candidate, "/") || strings.HasPrefix(candidate, "//") || strings.Contains(candidate, `\`) {
		return fallback
	}
	for i := 0; i < len(candidate); i++ {
		if c := candidate[i]; c < 0x20 || c == 0x7f {
			return fallback
		}
	}
	u, err := url.Parse("http://x" + candidate)
	if err != nil || u.Host != "x" {
		return fallback
	}
	return candidate
}

// withQuery appends name=value to a local path, with ? or &.
func withQuery(path, name, value string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + name + "=" + url.QueryEscape(value)
}

// providerRE is a provider's id: google, linkedin_oidc, or custom:<slug>.
var providerRE = regexp.MustCompile(`^(custom:)?[a-z0-9_-]{1,40}$`)

// providerIn is the provider named in a route segment, as written or
// percent-encoded (custom%3Aacme); "" when it does not decode.
func providerIn(segment string) string {
	p, err := url.PathUnescape(segment)
	if err != nil {
		return ""
	}
	return p
}

// looseUUID is a UUID in either case, as the own screens accept one.
var looseUUID = regexp.MustCompile(`(?i)^[0-9a-f-]{36}$`)

// ownNetwork reports whether address is a loopback, private or link-local
// address: a network's own hop, never a person.
func ownNetwork(address string) bool {
	a := strings.ToLower(address)
	for _, p := range []string{"127.", "10.", "192.168.", "169.254.", "0.", "::ffff:127."} {
		if strings.HasPrefix(a, p) {
			return true
		}
	}
	if strings.HasPrefix(a, "172.") {
		if second, _, ok := strings.Cut(a[4:], "."); ok {
			if n, err := strconv.Atoi(second); err == nil && n >= 16 && n <= 31 {
				return true
			}
		}
	}
	return a == "::1" || a == "localhost" || strings.HasPrefix(a, "fc") || strings.HasPrefix(a, "fd") ||
		strings.HasPrefix(a, "fe8") || strings.HasPrefix(a, "fe9") || strings.HasPrefix(a, "fea") || strings.HasPrefix(a, "feb")
}

// random is n random bytes in base64url.
func random(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b64.EncodeToString(b)
}

// challenge is the PKCE S256 challenge of a verifier.
func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return b64.EncodeToString(sum[:])
}

// wants is a form's yes: true, "1", "on" or "true".
func wants(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "1" || x == "on" || x == "true"
	}
	return false
}

// isoUTC is t as JavaScript's toISOString writes it.
func isoUTC(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// ── Reading Cauthy's JSON answers, as loosely as @cauthyhq/node does ──────

// obj is v as a JSON object, or nil.
func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// at walks objects by name: at(v, "a", "b") is v.a.b, or nil.
func at(v any, path ...string) any {
	for _, p := range path {
		m := obj(v)
		if m == nil {
			return nil
		}
		v = m[p]
	}
	return v
}

// str is JavaScript's String(v ?? ”): a string as it is, a number or a
// boolean written out, anything else "".
func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return ""
}

// strOr is str(v), or fallback when v is null or absent.
func strOr(v any, fallback string) string {
	if v == nil {
		return fallback
	}
	return str(v)
}

// yes is v === true.
func yes(v any) bool { b, _ := v.(bool); return b }

// arr is v as a JSON array, or empty.
func arr(v any) []any {
	a, _ := v.([]any)
	return a
}

// num is Number(v ?? 0) for a number, else 0.
func num(v any) float64 {
	f, _ := v.(float64)
	return f
}

// strs is every element of v as a string (String(x)), or an empty list.
func strs(v any) []string {
	out := []string{}
	for _, x := range arr(v) {
		out = append(out, str(x))
	}
	return out
}

// timeAfter is time.After, a variable so a test may shorten it.
var timeAfter = time.After

// urlQueryEscape is url.QueryEscape, as JavaScript's encodeURIComponent
// writes a path: a space as %20.
func urlQueryEscape(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }

// cut is s at most n bytes long, cut on a character boundary: text that is
// reflected back is never left as broken UTF-8.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
