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

type node struct {
	ID        any `json:"id"`
	Type      any `json:"type"`
	URL       any `json:"url"`
	EventsURL any `json:"events_url"`
	JWKSURL   any `json:"jwks_url"`
	Tenants   []struct {
		ID   any `json:"id"`
		Slug any `json:"slug"`
	} `json:"tenants"`
	Token *struct {
		Algorithm any `json:"algorithm"`
		Audience  any `json:"audience"`
	} `json:"token"`
}

type edge struct {
	From       any `json:"from"`
	Relation   any `json:"relation"`
	To         any `json:"to"`
	Link       any `json:"link"`
	Capability any `json:"capability"`
	Identity   *struct {
		Tenant       any `json:"tenant"`
		TenantID     any `json:"tenant_id"`
		CreateTenant any `json:"create_tenant"`
	} `json:"identity"`
	SignIn  json.RawMessage `json:"sign_in"`
	Service json.RawMessage `json:"service"`
}

type signIn struct {
	ClientID             any `json:"client_id"`
	RedirectURIs         any `json:"redirect_uris"`
	RequireSystemProof   any `json:"require_system_proof"`
	SystemProof          any `json:"system_proof"`
	RequireVerifiedEmail any `json:"require_verified_email"`
	PersistentSessions   any `json:"persistent_sessions"`
}

type service struct {
	ClientID any `json:"client_id"`
	JWKSURL  any `json:"jwks_url"`
}

// text is v when it is a string, else "".
func text(v any) string {
	s, _ := v.(string)
	return s
}

// present reports whether a raw JSON member is there and not null.
func present(raw json.RawMessage) bool { return len(raw) > 0 && string(raw) != "null" }

// httpsAddress refuses an address that is not https (http only for
// localhost and 127.0.0.1).
func httpsAddress(raw, what string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, cfgerr.New("the contract's %s is not an address: %q", what, raw)
	}
	host := u.Hostname()
	local := host == "localhost" || host == "127.0.0.1"
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return nil, cfgerr.New("the contract's %s must be https: %s", what, raw)
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
	var g struct {
		Nodes []node `json:"nodes"`
		Edges []edge `json:"edges"`
	}
	if err := json.Unmarshal(o.Graph, &g); err != nil || g.Nodes == nil || g.Edges == nil {
		return nil, cfgerr.New("contract.Graph is not a context graph: pass the graph.json that `cauthy contracts pull` writes")
	}
	find := func(id, typ string) *node {
		for i := range g.Nodes {
			if text(g.Nodes[i].Type) == typ && text(g.Nodes[i].ID) == id {
				return &g.Nodes[i]
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

	var links []edge
	for _, e := range g.Edges {
		if text(e.Relation) == "links" && text(e.From) == o.System && text(e.To) == provider && present(e.SignIn) &&
			(o.Link == "" || text(e.Link) == o.Link) {
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
			names[i] = text(l.Link)
		}
		return nil, cfgerr.New("%s has %d links to %s: name the one to read (contract.Link): %s", o.System, len(links), provider, strings.Join(names, ", "))
	}
	e := links[0]
	link := text(e.Link)

	var named, pinned string
	createTenant := false
	if e.Identity != nil {
		named, pinned = text(e.Identity.Tenant), text(e.Identity.TenantID)
		createTenant = e.Identity.CreateTenant == true
	}
	if named == nilUUID || pinned == nilUUID {
		return nil, cfgerr.New("the link %s names the nil UUID as its workspace: name the workspace by its slug", link)
	}
	var tenantID, tenant string
	if uuidRE.MatchString(named) {
		if pinned != "" && !strings.EqualFold(pinned, named) {
			return nil, cfgerr.New("the link %s names the workspace %s and its tenant_id %s does not match: pull the graph again", link, named, pinned)
		}
		tenantID = named
		for _, t := range cauthy.Tenants {
			if text(t.ID) == named {
				tenant = text(t.Slug)
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

	iu, err := httpsAddress(text(cauthy.URL), "address of "+provider)
	if err != nil {
		return nil, err
	}
	var si signIn
	_ = json.Unmarshal(e.SignIn, &si)
	clientID := text(si.ClientID)
	if clientID == "" {
		clientID = "pact." + link
	}
	var redirects []string
	if list, ok := si.RedirectURIs.([]any); ok {
		for _, v := range list {
			if s := text(v); s != "" {
				redirects = append(redirects, s)
			}
		}
	}
	if len(redirects) == 0 {
		return nil, cfgerr.New("the link %s names no redirect URI", link)
	}

	proof := text(si.SystemProof)
	if si.SystemProof != nil && !slices.Contains([]string{"off", "auto", "required"}, proof) {
		raw, _ := json.Marshal(si.SystemProof)
		return nil, cfgerr.New("the link %s has system_proof %s: it is off, auto or required. Update cauthy-sdk-go, or pull the graph again", link, raw)
	}
	if proof == "" {
		proof = "off"
		if si.RequireSystemProof == true {
			proof = "required"
		}
	}
	if proof != "off" && !present(e.Service) {
		return nil, cfgerr.New("the link %s asks for the system's proof (%s) and gives %s no identity to make it with: it needs a service block", link, proof, o.System)
	}

	out := &Resolved{
		System: o.System, Link: link, Issuer: strings.TrimRight(iu.String(), "/"), TenantID: tenantID, Tenant: tenant,
		ClientID: clientID, RedirectURIs: redirects, RequireSystemProof: proof == "required", SystemProof: proof,
		RequireVerifiedEmail: si.RequireVerifiedEmail == true, PersistentSessions: si.PersistentSessions == true,
	}
	if present(e.Service) {
		var svc service
		_ = json.Unmarshal(e.Service, &svc)
		out.ServiceClientID = text(svc.ClientID)
		if out.ServiceClientID == "" {
			out.ServiceClientID = "pact." + link + ".service"
		}
		jwks := text(svc.JWKSURL)
		if jwks == "" {
			jwks = text(own.JWKSURL)
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
	if ev := text(own.EventsURL); ev != "" {
		eu, err := httpsAddress(ev, "events_url")
		if err != nil {
			return nil, err
		}
		out.EventsURL = eu.String()
	}
	if c := text(e.Capability); c != "" {
		if cap := find(c, "capability"); cap != nil && cap.Token != nil {
			out.Audience = text(cap.Token.Audience)
			out.TokenAlgorithm = text(cap.Token.Algorithm)
		}
	}
	return out, nil
}
