package cauthy

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// ProtocolVersion is the auth-bff protocol version Auth serves, at level
// strict. Every answer carries it as Cauthy-Protocol.
const ProtocolVersion = "1"

// NextStep is what the page does after a sign-in answer (auth-bff.md,
// "Sign-in answers").
type NextStep string

const (
	NextDone        NextStep = "done"
	NextMFA         NextStep = "mfa"
	NextVerifyEmail NextStep = "verify_email"
	NextCode        NextStep = "code"
	NextPasskey     NextStep = "passkey"
	NextOneTap      NextStep = "one_tap"
	NextRedirect    NextStep = "redirect"
)

// signInRoutes are the routes whose answers are sign-in answers.
var signInRoutes = map[string]bool{
	"/sign-in/email": true, "/sign-in/mfa": true, "/sign-in/mfa/send": true, "/sign-in/mfa/email": true, "/sign-in/mfa/push": true,
	"/sign-in/mfa/push/finish": true, "/sign-up/email": true, "/invitation/accept": true, "/sign-in/magic-link": true,
	"/sign-in/email-code": true, "/sign-in/magic-link/verify": true, "/sign-in/passkey/begin": true, "/sign-in/passkey/finish": true,
	"/sign-in/google-one-tap/begin": true, "/sign-in/google-one-tap": true, "/sign-in/anonymous": true, "/me/upgrade": true,
}

// nextOf is the step after a sign-in answer of route with status, or "".
func nextOf(route, status string) NextStep {
	switch status {
	case "signed_in":
		return NextDone
	case "mfa_required":
		return NextMFA
	case "verification_required":
		return NextVerifyEmail
	case "sent":
		if strings.HasPrefix(route, "/sign-in/mfa") {
			return NextMFA
		}
		return NextCode
	case "started":
		if route == "/sign-in/google-one-tap/begin" {
			return NextOneTap
		}
		return NextPasskey
	}
	return ""
}

// reply is an answer before it is sent: send gives it the protocol's
// headers and, on a sign-in answer, next.
type reply struct {
	status int
	header http.Header
	body   []byte
	stream io.ReadCloser // an event stream, copied as it arrives
}

// with adds Set-Cookie values.
func (r *reply) with(cookies ...string) *reply {
	for _, c := range cookies {
		r.header.Add("Set-Cookie", c)
	}
	return r
}

func newReply(status int, h http.Header) *reply {
	if h == nil {
		h = http.Header{}
	} else {
		h = h.Clone()
	}
	return &reply{status: status, header: h}
}

// jsonReply is v as JSON with status; h carries cookies to send along.
func jsonReply(status int, v any, h http.Header) *reply {
	r := newReply(status, h)
	r.header.Set("Content-Type", "application/json; charset=utf-8")
	r.header.Set("Cache-Control", "no-store")
	r.body, _ = json.Marshal(v)
	return r
}

// ok is a 200 JSON answer.
func ok(v any, h http.Header) *reply { return jsonReply(http.StatusOK, v, h) }

// problem is an error answer: {"error":{"code","message","field"?,"reasons"?}}.
func problem(status int, code, message, field string, h http.Header, reasons []string) *reply {
	e := map[string]any{"code": code, "message": message}
	if field != "" {
		e["field"] = field
	}
	if len(reasons) > 0 {
		e["reasons"] = reasons
	}
	return jsonReply(status, map[string]any{"error": e}, h)
}

// invalid is a 400 for a field of the form.
func invalid(p *fieldProblem) *reply {
	return problem(http.StatusBadRequest, p.code, p.message, p.field, nil, nil)
}

// redirect is a 302 to location.
func redirect(location string, cookies ...string) *reply {
	r := newReply(http.StatusFound, nil)
	r.header.Set("Location", location)
	r.header.Set("Cache-Control", "no-store")
	return r.with(cookies...)
}

// text is a plain-text answer.
func text(status int, message string) *reply {
	r := newReply(status, nil)
	r.header.Set("Content-Type", "text/plain; charset=utf-8")
	r.body = []byte(message)
	return r
}

func notFound() *reply { return text(http.StatusNotFound, "Not found") }

func methodNotAllowed() *reply {
	r := text(http.StatusMethodNotAllowed, "Method not allowed")
	r.header.Set("Allow", "POST")
	return r
}

// send writes rep as protocol version 1 sends every answer: Cauthy-Protocol
// always, Cache-Control: no-store unless cacheable (the published keys), and
// next on a successful JSON answer of a sign-in route.
func send(w http.ResponseWriter, route string, rep *reply, cacheable bool) {
	h := w.Header()
	for k, v := range rep.header {
		h[k] = v
	}
	h.Set("Cauthy-Protocol", ProtocolVersion)
	if !cacheable && !strings.Contains(h.Get("Cache-Control"), "no-store") {
		h.Set("Cache-Control", "no-store")
	}
	body := rep.body
	if signInRoutes[route] && rep.status >= 200 && rep.status < 300 && strings.HasPrefix(h.Get("Content-Type"), "application/json") {
		var parsed map[string]json.RawMessage
		if json.Unmarshal(body, &parsed) == nil && parsed != nil {
			var status string
			_ = json.Unmarshal(parsed["status"], &status)
			if next := nextOf(route, status); next != "" {
				parsed["next"], _ = json.Marshal(next)
				body, _ = json.Marshal(parsed)
			}
		}
	}
	if rep.stream != nil {
		defer rep.stream.Close()
		w.WriteHeader(rep.status)
		flusher, _ := w.(http.Flusher)
		buf := make([]byte, 4096)
		for {
			n, err := rep.stream.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			if err != nil {
				return
			}
		}
	}
	w.WriteHeader(rep.status)
	_, _ = w.Write(body)
}
