package cauthytest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
)

// Browser is a browser as far as cookies go: it keeps what it is told to and
// sends it back, and on every mutation sends X-Cauthy-Request: 1, as a
// protocol-1 client does.
type Browser struct {
	// Origin is the page's origin: https://app.test by default.
	Origin string
	// NoRequestHeader leaves X-Cauthy-Request out, as cauthy-auth 0.42's client.
	NoRequestHeader bool
	Jar             map[string]string
}

// NewBrowser is a browser on origin ("" is https://app.test).
func NewBrowser(origin string) *Browser {
	if origin == "" {
		origin = "https://app.test"
	}
	return &Browser{Origin: origin, Jar: map[string]string{}}
}

// Request builds a request to path. body nil sends none, a string is sent as
// it is, anything else as JSON.
func (b *Browser) Request(method, path string, body any) *http.Request {
	var reader io.Reader
	contentType := ""
	switch v := body.(type) {
	case nil:
	case string:
		reader, contentType = strings.NewReader(v), "application/json"
	default:
		raw, _ := json.Marshal(v)
		reader, contentType = bytes.NewReader(raw), "application/json"
	}
	r := httptest.NewRequest(method, b.Origin+path, reader)
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if len(b.Jar) > 0 {
		var pairs []string
		for k, v := range b.Jar {
			pairs = append(pairs, k+"="+v)
		}
		r.Header.Set("Cookie", strings.Join(pairs, "; "))
	}
	if method != http.MethodGet && method != http.MethodHead && !b.NoRequestHeader {
		r.Header.Set("X-Cauthy-Request", "1")
	}
	return r
}

// Take keeps the cookies of an answer, as a browser would.
func (b *Browser) Take(h http.Header) {
	for _, c := range h.Values("Set-Cookie") {
		parts := strings.Split(c, "; ")
		name, value, _ := strings.Cut(parts[0], "=")
		gone := value == ""
		for _, a := range parts[1:] {
			if a == "Max-Age=0" {
				gone = true
			}
		}
		if gone {
			delete(b.Jar, name)
		} else {
			b.Jar[name] = value
		}
	}
}

// Do sends a request to h and keeps the cookies of its answer.
func (b *Browser) Do(h http.Handler, r *http.Request) *http.Response {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	res := w.Result()
	b.Take(res.Header)
	return res
}

// Send is Do of Request(method, path, body).
func (b *Browser) Send(h http.Handler, method, path string, body any) *http.Response {
	return b.Do(h, b.Request(method, path, body))
}

// JSON reads an answer's JSON object body; nil when it is not one.
func JSON(res *http.Response) map[string]any {
	defer res.Body.Close()
	var m map[string]any
	if json.NewDecoder(res.Body).Decode(&m) != nil {
		return nil
	}
	return m
}
