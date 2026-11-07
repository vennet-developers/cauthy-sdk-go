// Package contract reads an application's link with Cauthy from the Pact
// context graph (core-contracts' graph.json, as `cauthy contracts pull`
// writes it), by the rules of cauthy-sdk-spec's contract/pact.md, the same
// way @cauthyhq/node's readContract does.
package contract

import (
	"encoding/json"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/vennet-developers/cauthy-sdk-go/internal/cfgerr"
)

// Options is what the application says of its contract.
type Options struct {
	// Graph is contracts/graph.json, as read from disk or embedded.
	Graph []byte
	// System is this application's system id in the graph: "acme-crm".
	System string
	// Link names the link to read when the system has several with Cauthy.
	Link string
	// Provider is Cauthy's system id in the graph. Default "cauthy".
	Provider string
}

// Resolved is what an application reads of its contract.
type Resolved struct {
	System string
	Link   string
	// Issuer is Cauthy's public address, without a trailing slash.
	Issuer string
	// TenantID is the workspace's id; Tenant its slug.
	TenantID string
	Tenant   string
	// ClientID is the public client people sign in with: pact.<link>.
	ClientID     string
	RedirectURIs []string
	// RequireSystemProof is SystemProof == "required".
	RequireSystemProof bool
	// SystemProof is off, auto or required.
	SystemProof          string
	RequireVerifiedEmail bool
	PersistentSessions   bool
	// ServiceClientID is the system's own client (pact.<link>.service), when
	// the link has a service block; JWKSURL and JWKSPath are where it
	// publishes its keys.
	ServiceClientID string
	JWKSURL         string
	JWKSPath        string
	// EventsURL is where the system receives Cauthy's events, when it says.
	EventsURL string
	// Audience and TokenAlgorithm are the token audience and algorithm of the
	// capability the link uses (cauthy.identity.v1), when the graph says.
	Audience       string
	TokenAlgorithm string
}

// StandardVariables are the variables of variables mode. With a contract
// none may be set: two sources of the same thing is how a system ends up
// signing people in through a client nobody meant.
var StandardVariables = []string{
	"CAUTHY_ISSUER", "CAUTHY_CLIENT_ID", "CAUTHY_CLIENT_SECRET", "CAUTHY_SECRET",
	"CAUTHY_SYSTEM", "CAUTHY_TENANT", "CAUTHY_SYSTEM_KEY", "CAUTHY_SYSTEM_KEY_ID",
}

// FailClosed refuses to run by contract with a variable of variables mode
// set, and names it.
func FailClosed(getenv func(string) string) error {
	var set []string
	for _, name := range StandardVariables {
		if getenv(name) != "" {
			set = append(set, name)
		}
	}
	switch len(set) {
	case 0:
		return nil
	case 1:
		return cfgerr.New("the application runs by contract, and %s is also set: remove it from the environment. Everything comes from the contract.", set[0])
	default:
		return cfgerr.New("the application runs by contract, and %s are also set: remove them from the environment. Everything comes from the contract.", strings.Join(set, ", "))
	}
}

var (
	slugRE = regexp.MustCompile(`^[a-z0-9]+(?:[-_][a-z0-9]+)*$`)
	uuidRE = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

const nilUUID = "00000000-0000-0000-0000-000000000000"

// The graph is read as plain JSON values, member names exact (Go's struct
// decoding would also take "URL" for "url"), and a member of the wrong type
// reads as absent: like @cauthyhq/node, a malformed node or edge elsewhere
// in the graph never rejects it.
type obj = map[string]any

// object is v when it is a JSON object, else nil (which reads as empty).
func object(v any) obj {
	m, _ := v.(map[string]any)
	return m
}

// list is v when it is a JSON array, else nil.
func list(v any) []any {
	l, _ := v.([]any)
	return l
}

// text is v when it is a string, else "".
func text(v any) string {
	s, _ := v.(string)
	return s
}

// truthy is JavaScript's truthiness, which @cauthyhq/node tests sign_in and
// service with: false, 0, "" and null are absent.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x != ""
	default:
		return true
	}
}

// httpsAddress refuses an address that is not https (http only for
// localhost and 127.0.0.1).
func httpsAddress(raw, what string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, cfgerr.New("the contract's %s is not an address: %q", what, raw)
	}
	host := strings.ToLower(u.Hostname())
	local := host == "localhost" || host == "127.0.0.1"
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return nil, cfgerr.New("the contract's %s must be https: %s", what, raw)
	}
	// As a WHATWG URL writes it: the host in lower case, the scheme's default
	// port dropped.
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	u.Host = host
	if port != "" {
		u.Host += ":" + port
	}
	return u, nil
}

// Read reads what the graph says of the system's link with Cauthy, and
// refuses what contract/pact.md says an SDK refuses.
func Read(o Options) (*Resolved, error) {
	provider := o.Provider
	if provider == "" {
		provider = "cauthy"
	}
	if !slugRE.MatchString(o.System) {
		return nil, cfgerr.New(`contract.System must be the system's id in the graph, e.g. "acme-crm"`)
	}
	var g obj
	if err := json.Unmarshal(o.Graph, &g); err != nil || list(g["nodes"]) == nil || list(g["edges"]) == nil {
		return nil, cfgerr.New("contract.Graph is not a context graph: pass the graph.json that `cauthy contracts pull` writes")
	}
	nodes, edges := list(g["nodes"]), list(g["edges"])
	find := func(id, typ string) obj {
		for _, n := range nodes {
			if m := object(n); text(m["type"]) == typ && text(m["id"]) == id {
				return m
			}
		}
		return nil
	}
	own := find(o.System, "system")
	if own == nil {
		return nil, cfgerr.New("the graph has no system %q", o.System)
	}
	cauthy := find(provider, "system")
	if cauthy == nil {
		return nil, cfgerr.New("the graph has no system %q", provider)
	}

	var links []obj
	for _, raw := range edges {
		e := object(raw)
		if text(e["relation"]) == "links" && text(e["from"]) == o.System && text(e["to"]) == provider && truthy(e["sign_in"]) &&
			(o.Link == "" || text(e["link"]) == o.Link) {
			links = append(links, e)
		}
	}
	if len(links) == 0 {
		if o.Link != "" {
			return nil, cfgerr.New("the graph has no link %q from %s to %s with sign_in", o.Link, o.System, provider)
		}
		return nil, cfgerr.New("no link of the graph signs %s's people in with %s: merge one in the contracts repository, then pull the graph again", o.System, provider)
	}
	if len(links) > 1 {
		names := make([]string, len(links))
		for i, l := range links {
			names[i] = text(l["link"])
		}
		return nil, cfgerr.New("%s has %d links to %s: name the one to read (contract.Link): %s", o.System, len(links), provider, strings.Join(names, ", "))
	}
	e := links[0]
	link := text(e["link"])

	identity := object(e["identity"])
	named, pinned := text(identity["tenant"]), text(identity["tenant_id"])
	createTenant := identity["create_tenant"] == true
	if named == nilUUID || pinned == nilUUID {
		return nil, cfgerr.New("the link %s names the nil UUID as its workspace: name the workspace by its slug", link)
	}
	var tenantID, tenant string
	if uuidRE.MatchString(named) {
		if pinned != "" && !strings.EqualFold(pinned, named) {
			return nil, cfgerr.New("the link %s names the workspace %s and its tenant_id %s does not match: pull the graph again", link, named, pinned)
		}
		tenantID = named
		for _, t := range list(cauthy["tenants"]) {
			if m := object(t); text(m["id"]) == named {
				tenant = text(m["slug"])
				break
			}
		}
		if tenant == "" {
			return nil, cfgerr.New("the graph does not name the slug of the workspace %s that the link %s uses", named, link)
		}
	} else {
		if !slugRE.MatchString(named) {
			return nil, cfgerr.New("the link %s names no workspace: identity.tenant is a UUID or a slug", link)
		}
		if !uuidRE.MatchString(pinned) {
			if createTenant {
				return nil, cfgerr.New("the link %s asks Cauthy for a new workspace %q, and the graph has no tenant_id for it yet: once Cauthy has created it and core-contracts lists it, pull the graph again", link, named)
			}
			return nil, cfgerr.New("the link %s names the workspace %q by its slug, and the graph carries no tenant_id for it: pull the graph again", link, named)
		}
		tenantID, tenant = pinned, named
	}

	iu, err := httpsAddress(text(cauthy["url"]), "address of "+provider)
	if err != nil {
		return nil, err
	}
	si := object(e["sign_in"])
	clientID := text(si["client_id"])
	if clientID == "" {
		clientID = "pact." + link
	}
	var redirects []string
	for _, v := range list(si["redirect_uris"]) {
		if s := text(v); s != "" {
			redirects = append(redirects, s)
		}
	}
	if len(redirects) == 0 {
		return nil, cfgerr.New("the link %s names no redirect URI", link)
	}

	// Present and null is refused too, as @cauthyhq/node refuses it.
	proofValue, proofSet := si["system_proof"]
	proof := text(proofValue)
	if proofSet && !slices.Contains([]string{"off", "auto", "required"}, proof) {
		raw, _ := json.Marshal(proofValue)
		return nil, cfgerr.New("the link %s has system_proof %s: it is off, auto or required. Update cauthy-sdk-go, or pull the graph again", link, raw)
	}
	if proof == "" {
		proof = "off"
		if si["require_system_proof"] == true {
			proof = "required"
		}
	}
	if proof != "off" && !truthy(e["service"]) {
		return nil, cfgerr.New("the link %s asks for the system's proof (%s) and gives %s no identity to make it with: it needs a service block", link, proof, o.System)
	}

	out := &Resolved{
		System: o.System, Link: link, Issuer: strings.TrimRight(iu.String(), "/"), TenantID: tenantID, Tenant: tenant,
		ClientID: clientID, RedirectURIs: redirects, RequireSystemProof: proof == "required", SystemProof: proof,
		RequireVerifiedEmail: si["require_verified_email"] == true, PersistentSessions: si["persistent_sessions"] == true,
	}
	if truthy(e["service"]) {
		svc := object(e["service"])
		out.ServiceClientID = text(svc["client_id"])
		if out.ServiceClientID == "" {
			out.ServiceClientID = "pact." + link + ".service"
		}
		jwks := text(svc["jwks_url"])
		if jwks == "" {
			jwks = text(own["jwks_url"])
		}
		if jwks == "" {
			return nil, cfgerr.New("the link %s gives %s its own identity, and %s names no jwks_url", link, o.System, o.System)
		}
		ju, err := httpsAddress(jwks, "jwks_url")
		if err != nil {
			return nil, err
		}
		out.JWKSURL = ju.String()
		out.JWKSPath = ju.EscapedPath()
		if out.JWKSPath == "" {
			out.JWKSPath = "/"
		}
	}
	if ev := text(own["events_url"]); ev != "" {
		eu, err := httpsAddress(ev, "events_url")
		if err != nil {
			return nil, err
		}
		out.EventsURL = eu.String()
	}
	if c := text(e["capability"]); c != "" {
		if token := object(find(c, "capability")["token"]); token != nil {
			out.Audience = text(token["audience"])
			out.TokenAlgorithm = text(token["algorithm"])
		}
	}
	return out, nil
}
