package cauthy

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/cauthykey"
	"github.com/vennet-developers/cauthy-sdk-go/internal/cfgerr"
)

// KeyReplaces are the variables CAUTHY_KEY replaces (key/cauthy-key.md §10):
// set beside it, they are a second source of the same thing, and New
// refuses to start.
var KeyReplaces = []string{"CAUTHY_ISSUER", "CAUTHY_CLIENT_ID", "CAUTHY_CLIENT_SECRET", "CAUTHY_SYSTEM", "CAUTHY_TENANT",
	"CAUTHY_SYSTEM_KEY", "CAUTHY_SYSTEM_KEY_ID", "CAUTHY_BASE_URL", "CAUTHY_AUDIENCE", "CAUTHY_TENANT_ID"}

// How long key mode waits for Cauthy to say who the application is: at
// start (then it starts anyway, answering 503 unavailable until it knows),
// and per request on the auth routes. Variables so tests can shorten them.
var (
	keyStartWait   = 10 * time.Second
	keyRequestWait = 5 * time.Second
)

// keyed is a parsed CAUTHY_KEY and the key it replaces, while rotating.
type keyed struct {
	key, previous *cauthykey.Key
}

// byKey reads CAUTHY_KEY (Options.Key first). nil when there is none.
func byKey(o Options, getenv func(string) string) (*keyed, error) {
	text := o.Key
	if text == "" {
		text = getenv("CAUTHY_KEY")
	}
	if text == "" {
		return nil, nil
	}
	var set []string
	for _, name := range KeyReplaces {
		if getenv(name) != "" {
			set = append(set, name)
		}
	}
	switch len(set) {
	case 0:
	case 1:
		return nil, cfgerr.New("the application runs on CAUTHY_KEY, and %s is also set: remove it from the environment. Everything comes from the key.", set[0])
	default:
		return nil, cfgerr.New("the application runs on CAUTHY_KEY, and %s are also set: remove them from the environment. Everything comes from the key.", strings.Join(set, ", "))
	}
	for _, opt := range []struct {
		name string
		set  bool
	}{{"Issuer", o.Issuer != ""}, {"ClientID", o.ClientID != ""}, {"ClientSecret", o.ClientSecret != ""}, {"Secret", o.Secret != ""},
		{"System", o.System != ""}, {"Tenant", o.Tenant != ""}, {"SystemKey", o.SystemKey != nil}, {"RootKey", o.RootKey != ""},
		{"RootKeyPrevious", o.RootKeyPrevious != ""}} {
		if opt.set {
			return nil, cfgerr.New("with CAUTHY_KEY, %s comes from CAUTHY_KEY: do not pass it", opt.name)
		}
	}
	k, err := cauthykey.Parse(text)
	if err != nil {
		return nil, err
	}
	out := &keyed{key: k}
	prev := o.KeyPrevious
	if prev == "" {
		prev = getenv("CAUTHY_KEY_PREVIOUS")
	}
	if prev != "" {
		p, err := cauthykey.Parse(prev)
		if err != nil {
			var e *cauthykey.Error
			if errors.As(err, &e) {
				return nil, &cauthykey.Error{Reason: e.Reason, Msg: strings.Replace(e.Msg, "CAUTHY_KEY:", "CAUTHY_KEY_PREVIOUS:", 1)}
			}
			return nil, err
		}
		if p.Issuer != k.Issuer || p.ClientID != k.ClientID {
			return nil, &cauthykey.Error{Reason: "key_previous_mismatch", Msg: "CAUTHY_KEY_PREVIOUS: it names another Cauthy or client than CAUTHY_KEY"}
		}
		out.previous = p
	}
	return out, nil
}

// adopt takes what Cauthy says the application is: its workspace and system.
func (a *Auth) adopt(id *AppIdentity) {
	a.idMu.Lock()
	defer a.idMu.Unlock()
	if id != nil && a.adopted != id {
		a.tenant, a.system, a.adopted = id.Tenant.Slug, id.System, id
	}
}

// tenantSlug is the workspace's slug.
func (a *Auth) tenantSlug() string {
	a.idMu.RLock()
	defer a.idMu.RUnlock()
	return a.tenant
}

// systemName is the application's system.
func (a *Auth) systemName() string {
	a.idMu.RLock()
	defer a.idMu.RUnlock()
	return a.system
}

// Identity is who the application is. On CAUTHY_KEY it is Cauthy's answer
// (GET /v1/connect/self), waiting for the first one until ctx is done:
// ErrUnavailable while Cauthy has not answered, ErrMisconfigured when it
// refuses the key. Otherwise it is what is configured, with no Key.
func (a *Auth) Identity(ctx context.Context) (*AppIdentity, error) {
	if a.identity == nil {
		id := &AppIdentity{Issuer: a.issuer, ClientID: a.clientID, SignInClientID: a.clientID, System: a.systemName(),
			CallbackPath: a.basePath + "/callback", AppURLs: []string{}}
		id.Tenant.Slug = a.tenantSlug()
		if a.contract != nil {
			id.Tenant.ID = a.contract.TenantID
		}
		if a.baseURL != "" {
			id.AppURLs = []string{a.baseURL}
		}
		return id, nil
	}
	id, err := a.identity.Wait(ctx)
	if err != nil {
		return nil, err
	}
	a.adopt(id)
	return id, nil
}

// identified answers 503 on the auth routes while the application on
// CAUTHY_KEY does not know who it is, and 400 unknown_origin for a request
// from an address Cauthy does not list for it. nil lets the request through.
func (a *Auth) identified(r *http.Request) *reply {
	ctx, cancel := context.WithTimeout(r.Context(), keyRequestWait)
	defer cancel()
	id, err := a.identity.Wait(ctx)
	switch {
	case errors.Is(err, ErrMisconfigured):
		return problem(http.StatusServiceUnavailable, "misconfigured", "Cauthy refuses this application's key: make a new one in Cauthy's dashboard.", "", nil, nil)
	case err != nil:
		return problem(http.StatusServiceUnavailable, "unavailable", "Cauthy cannot be reached yet. Try again in a moment.", "", nil, nil)
	}
	a.adopt(id)
	if a.baseURL == "" {
		if _, ok := a.registeredOrigin(requestOrigin(r)); !ok {
			return problem(http.StatusBadRequest, "unknown_origin", "This address is not one of the application's in Cauthy ("+
				strings.Join(id.AppURLs, ", ")+"): open the application at one of them, or add this one on its card in Cauthy's dashboard.", "", nil, nil)
		}
	}
	return nil
}

// registeredOrigin is the origin a request on CAUTHY_KEY is answered for:
// its own when Cauthy lists it, else the only one Cauthy lists. ok is false
// when neither.
func (a *Auth) registeredOrigin(asked string) (string, bool) {
	id := a.identity.Current()
	if id == nil {
		return asked, false
	}
	urls := make([]string, 0, len(id.AppURLs))
	for _, u := range id.AppURLs {
		urls = append(urls, withoutTrailingSlashes(u))
	}
	if slices.Contains(urls, asked) {
		return asked, true
	}
	if len(urls) == 1 {
		return urls[0], true
	}
	return asked, false
}

// requestOrigin is the request's own origin, with the scheme a
// TLS-terminating proxy names.
func requestOrigin(r *http.Request) string {
	proto := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]))
	if proto != "https" && proto != "http" {
		proto = "http"
		if r.TLS != nil {
			proto = "https"
		}
	}
	return proto + "://" + r.Host
}
