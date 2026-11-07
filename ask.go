package cauthy

import (
	"encoding/json"
	"net/http"
	"time"
)

// asked is Cauthy's answer to an own-screens call: its status and what it
// put under data, or the error it gave.
type asked struct {
	status int
	data   any
	err    *askError
}

type askError struct {
	code, message string
	reasons       []string
}

// askOpts are what an own-screens call says besides its payload.
type askOpts struct {
	// page is the application's own page a link Cauthy mails opens; "" is
	// Cauthy's own page.
	page string
	// bearer is the person's access token, for a call about their account.
	bearer string
	// remember says the person asked to stay signed in.
	remember bool
}

// ask calls Cauthy's own API as this workspace's application: the
// workspace, the client, the system's proof, and what the browser said of
// language, captcha and agent.
func (a *Auth) ask(r *http.Request, method, path string, payload any, o askOpts) asked {
	h := http.Header{"X-Tenant-Key": {a.tenant}, "Accept": {"application/json"}}
	if o.page != "" {
		h.Set("X-Cauthy-Link-To", a.originOf(r)+o.page)
	} else {
		h.Set("X-Cauthy-Links", "hosted")
	}
	h.Set("X-Cauthy-Client-Id", a.clientID)
	for k, v := range a.passedOn(r) {
		h[k] = v
	}
	if o.bearer != "" {
		h.Set("Authorization", "Bearer "+o.bearer)
	}
	if o.remember {
		h.Set("X-Cauthy-Remember", "1")
	}
	for from, to := range map[string]string{"X-Cauthy-Captcha": "X-Captcha-Token", "Accept-Language": "Accept-Language",
		"X-Cauthy-Locale": "X-Cauthy-Locale", "User-Agent": "User-Agent"} {
		if v := r.Header.Get(from); v != "" {
			h.Set(to, v)
		}
	}
	var body []byte
	if payload != nil {
		body, _ = json.Marshal(payload)
		h.Set("Content-Type", "application/json")
	}
	n := a.fetch(r.Context(), method, a.issuer+path, h, body)
	if n.err != nil {
		return asked{status: 503, err: &askError{code: "unavailable", message: "Sign-in is unavailable right now. Try again in a moment."}}
	}
	if n.ok() {
		if n.status == 202 || n.status == 204 {
			return asked{status: n.status}
		}
		if d, has := obj(n.body)["data"]; has && d != nil {
			return asked{status: n.status, data: d}
		}
		return asked{status: n.status, data: n.body}
	}
	var first map[string]any
	if list := arr(at(n.body, "errors")); len(list) > 0 {
		first = obj(list[0])
	}
	e := &askError{code: strOr(first["code"], "error"), message: strOr(first["message"], "The request could not be completed.")}
	if reasons, ok := at(first, "meta", "reasons").([]any); ok {
		e.reasons = strs(reasons)
	}
	return asked{status: n.status, err: e}
}

// passedOn is what proves the application to Cauthy on a person's behalf:
// its own token, its origin, and the person's address. Nothing when the
// application is no system or Cauthy could not give it a token; then it is
// not asked again for 30 seconds.
func (a *Auth) passedOn(r *http.Request) http.Header {
	a.cacheMu.Lock()
	wait := a.now().Before(a.noProofTill)
	a.cacheMu.Unlock()
	if wait {
		return nil
	}
	tok, err := a.sys.Token(r.Context())
	if err != nil {
		a.cacheMu.Lock()
		a.noProofTill = a.now().Add(30 * time.Second)
		a.cacheMu.Unlock()
		return nil
	}
	h := http.Header{"X-Cauthy-System-Token": {tok}, "X-Cauthy-App-Origin": {a.originOf(r)}}
	if ip := a.clientIP(r); ip != "" {
		h.Set("X-Cauthy-Client-Ip", ip)
	}
	return h
}

// refusedWith is Cauthy's refusal passed on, with the field at fault.
func refusedWith(n asked, field string, h http.Header) *reply {
	return problem(n.status, n.err.code, n.err.message, field, h, n.err.reasons)
}
