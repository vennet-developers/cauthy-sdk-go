package cauthy

import (
	"net/http"
	"strconv"
	"strings"
)

// partSize is the most characters one cookie part holds (auth-bff.md, Cookies).
const partSize = 3500

// readCookies is every cookie the request carries, by name; a later one of
// the same name wins.
func readCookies(r *http.Request) map[string]string {
	out := map[string]string{}
	for _, header := range r.Header.Values("Cookie") {
		for _, pair := range strings.Split(header, ";") {
			if i := strings.Index(pair, "="); i > 0 {
				out[strings.TrimSpace(pair[:i])] = strings.TrimSpace(pair[i+1:])
			}
		}
	}
	return out
}

// readParts joins name.0, name.1… in order until the first missing index;
// false when there is nothing.
func readParts(c map[string]string, name string) (string, bool) {
	var b strings.Builder
	for i := 0; ; i++ {
		part, ok := c[name+"."+strconv.Itoa(i)]
		if !ok {
			break
		}
		b.WriteString(part)
	}
	return b.String(), b.Len() > 0
}

// cookieAttrs are a cookie's attributes: Secure on an https origin, and a
// Max-Age when it has one (none: the cookie ends with the browser session).
type cookieAttrs struct {
	secure    bool
	maxAge    int
	hasMaxAge bool
}

// age is the same attributes with Max-Age seconds; 0 deletes.
func (a cookieAttrs) age(seconds int) cookieAttrs {
	a.maxAge, a.hasMaxAge = seconds, true
	return a
}

// writeCookie is one Set-Cookie value: Path=/; HttpOnly; SameSite=Lax, as
// @cauthyhq/node writes it.
func writeCookie(name, value string, a cookieAttrs) string {
	var b strings.Builder
	b.WriteString(name + "=" + value + "; Path=/; HttpOnly; SameSite=Lax")
	if a.hasMaxAge {
		b.WriteString("; Max-Age=" + strconv.Itoa(a.maxAge))
	}
	if a.secure {
		b.WriteString("; Secure")
	}
	return b.String()
}

// writeParts stores value in parts of partSize, always at least .0, and
// deletes the parts a longer earlier value left behind.
func writeParts(name, value string, a cookieAttrs, had map[string]string) []string {
	var out []string
	n := 0
	for i := 0; i < len(value); i += partSize {
		out = append(out, writeCookie(name+"."+strconv.Itoa(n), value[i:min(i+partSize, len(value))], a))
		n++
	}
	for i := n; ; i++ {
		if _, ok := had[name+"."+strconv.Itoa(i)]; !ok {
			break
		}
		out = append(out, writeCookie(name+"."+strconv.Itoa(i), "", a.age(0)))
	}
	return out
}

// clearParts deletes every part the request carries, and .0 always.
func clearParts(name string, a cookieAttrs, had map[string]string) []string {
	var out []string
	for i := 0; ; i++ {
		key := name + "." + strconv.Itoa(i)
		if _, ok := had[key]; !ok && i > 0 {
			break
		}
		out = append(out, writeCookie(key, "", a.age(0)))
	}
	return out
}
