package cauthy

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/cauthykey"
	"github.com/vennet-developers/cauthy-sdk-go/contract"
	"github.com/vennet-developers/cauthy-sdk-go/internal/cfgerr"
	"github.com/vennet-developers/cauthy-sdk-go/keys"
	"github.com/vennet-developers/cauthy-sdk-go/system"
)

// Contract is how an application runs by contract: its Pact graph and its
// system id in it (contract.Options).
type Contract = contract.Options

// Pages are the application's own pages for what Cauthy mails: a link opens
// the page named here, with a token to give back; with none, Cauthy's own.
type Pages struct {
	// SignIn is where the sign-in form is: a sign-in link opens it.
	SignIn        string
	ResetPassword string
	VerifyEmail   string
	// AcceptInvite is where an invitation opens.
	AcceptInvite string
}

// Timeouts bound every call to Cauthy.
type Timeouts struct {
	// System bounds the application's own calls (Auth.System, and the proof
	// its sign-ins carry). Default 2 s.
	System time.Duration
	// Request bounds the sign-in screens' calls and the code, refresh and
	// userinfo calls of a session. Default 5 s. The push-approval event
	// stream has none past its first answer.
	Request time.Duration
}

// Options configure Auth. On CAUTHY_KEY (Key, or the variable) everything
// else comes from the key and from Cauthy, and none of KeyReplaces may be
// set. In variables mode every field left empty is read from its CAUTHY_*
// variable; in contract mode (Contract set) the issuer, the workspace and
// the clients come from the contract, and none of the CAUTHY_* variables may
// be set.
type Options struct {
	// Key is the application's CAUTHY_KEY, made in Cauthy's dashboard.
	// Default: the CAUTHY_KEY variable. With it, nothing else is read.
	Key string
	// KeyPrevious is the key being replaced, while rotating. Default:
	// CAUTHY_KEY_PREVIOUS. Its sessions are read, never written.
	KeyPrevious string
	// Issuer is Cauthy's address, e.g. https://id.example.com. CAUTHY_ISSUER.
	Issuer string
	// ClientID is the application's OAuth client. CAUTHY_CLIENT_ID.
	ClientID string
	// ClientSecret is its secret, when the client is confidential. CAUTHY_CLIENT_SECRET.
	ClientSecret string
	// Secret encrypts the session cookie: 32 characters or more. CAUTHY_SECRET.
	Secret string
	// System is the application's system, whose organizations a session
	// lists. CAUTHY_SYSTEM.
	System string
	// Tenant is the workspace's slug, which the own screens need. CAUTHY_TENANT.
	Tenant string
	// BasePath is where the routes are. Default /api/auth.
	BasePath string
	// RequestHeader is what a POST without X-Cauthy-Request: 1 gets:
	// "required" (default) answers 403 csrf_required, as level strict asks;
	// "warn" lets it through and says so once, for the deploy that moves a
	// page still on cauthy-auth 0.42's client. Removed in 2.0.
	RequestHeader string
	// BaseURL is the application's public origin. CAUTHY_BASE_URL. Default:
	// each request's origin, with the scheme X-Forwarded-Proto names.
	BaseURL string
	// AfterSignIn and AfterSignOut are where a person lands. Default /.
	AfterSignIn  string
	AfterSignOut string
	// CookieName names the session cookie. Default cauthy_session.
	CookieName string
	// SystemKey is a key the application proves itself with instead of its
	// secret. CAUTHY_SYSTEM_KEY and CAUTHY_SYSTEM_KEY_ID.
	SystemKey *system.Key
	Pages     Pages
	// ClientIP is the address of the person a request comes from, passed on
	// to Cauthy with the system's proof. Default: the last address in
	// X-Forwarded-For that is not the network's own.
	ClientIP func(*http.Request) string
	// HTTPClient reaches Cauthy. Default: a plain client.
	HTTPClient *http.Client
	Timeouts   Timeouts
	// Contract runs the application by contract.
	Contract *Contract
	// Keys is where the application keeps its own key, by contract
	// (keys.Postgres(db)). Required when the link has a service block.
	Keys keys.Store
	// RootKey is the one secret of a contracted application. PACT_ROOT_KEY.
	RootKey string
	// RootKeyPrevious is the root key before it, while rotating. PACT_ROOT_KEY_PREVIOUS.
	RootKeyPrevious string
	// WebhookReplay remembers deliveries Auth.Webhook took. Default: memory.
	WebhookReplay ReplayStore
	// Getenv reads the environment. Default os.Getenv.
	Getenv func(string) string
	// Logger receives the warnings said once. Default slog.Default().
	Logger *slog.Logger
	// Now is the clock. Default time.Now.
	Now func() time.Time
}

// Auth serves the auth-bff protocol at level strict under its base path, and
// the application's published keys at its JWKS path when it runs by
// contract. It is an http.Handler: mount it at both (Mount does).
type Auth struct {
	issuer, clientID, clientSecret, system, tenant  string
	basePath, afterSignIn, afterSignOut             string
	cookieName, flowCookie, againCookie, stepCookie string
	requestHeader, baseURL                          string
	pages                                           Pages
	cookieRing, flowRing                            [][]byte
	contract                                        *contract.Resolved
	ownKeys                                         *keys.Keys
	sys                                             *system.Client
	http                                            *http.Client
	requestTimeout                                  time.Duration
	clientIP                                        func(*http.Request) string
	log                                             *slog.Logger
	replay                                          ReplayStore
	now                                             func() time.Time
	pact                                            *Pact

	// CAUTHY_KEY (keymode.go)
	keyed    *keyed
	signer   *system.Signer
	identity *identitySource
	idMu     sync.RWMutex // guards tenant and system on CAUTHY_KEY, and adopted
	adopted  *AppIdentity

	renewMu  sync.Mutex
	renewing map[string]*renewal

	orgMu    sync.Mutex
	orgCache map[string]orgEntry

	cacheMu     sync.Mutex
	look        *timed
	policy      *timed
	noProofTill time.Time

	told sync.Map // warnings said once
}

var baseURLRE = regexp.MustCompile(`^https?://[^/]+/*$`)

// New makes Auth. It refuses to start, with a *ConfigError, on anything
// contract/pact.md lists, a missing variable, or an unsafe option.
func New(o Options) (*Auth, error) {
	getenv := o.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	or := func(v, name string) string {
		if v != "" {
			return v
		}
		return getenv(name)
	}
	a := &Auth{renewing: map[string]*renewal{}, orgCache: map[string]orgEntry{}, now: o.Now, log: o.Logger, replay: o.WebhookReplay}
	if a.now == nil {
		a.now = time.Now
	}
	if a.log == nil {
		a.log = slog.Default()
	}
	if a.replay == nil {
		a.replay = MemoryReplay(a.now)
	}

	k, err := byKey(o, getenv)
	if err != nil {
		return nil, err
	}
	if k != nil {
		a.keyed = k
		a.issuer, a.clientID = k.key.Issuer, k.key.ClientID
	}

	var root, previous string
	if o.Contract != nil {
		// On CAUTHY_KEY, byKey refused the variables the key replaces.
		if a.keyed == nil {
			if err := contract.FailClosed(getenv); err != nil {
				return nil, err
			}
		}
		for name, v := range map[string]bool{"ClientID": o.ClientID != "", "ClientSecret": o.ClientSecret != "", "Secret": o.Secret != "",
			"System": o.System != "", "Tenant": o.Tenant != "", "SystemKey": o.SystemKey != nil} {
			if v {
				return nil, cfgerr.New("with a contract, %s comes from the contract: do not pass it", name)
			}
		}
		c, err := contract.Read(*o.Contract)
		if err != nil {
			return nil, err
		}
		a.contract = c
		if a.keyed != nil {
			// The key names the graph's Cauthy; which client it may prove is
			// Cauthy's to decide (the link's service client, or one adopted).
			if a.keyed.key.Issuer != c.Issuer {
				return nil, &cauthykey.Error{Reason: "key_contract_issuer", Msg: "CAUTHY_KEY: the key names " + a.keyed.key.Issuer + ", the contract's Cauthy is " + c.Issuer}
			}
		} else {
			deprecated(a.log, "PACT_ROOT_KEY", "Generate CAUTHY_KEY on the application's card in Cauthy's dashboard, and remove PACT_ROOT_KEY and the key store.")
			root, previous = or(o.RootKey, "PACT_ROOT_KEY"), or(o.RootKeyPrevious, "PACT_ROOT_KEY_PREVIOUS")
			if root == "" {
				return nil, cfgerr.New("CAUTHY_KEY is required with a contract: make it on the application's card in Cauthy's dashboard (or, until 2.0, RootKey: PACT_ROOT_KEY)")
			}
			if c.ServiceClientID != "" && o.Keys == nil {
				return nil, cfgerr.New("the link %s gives %s its own identity: pass Keys, where its key is kept (keys.Postgres(db)), or move to CAUTHY_KEY, which needs none", c.Link, c.System)
			}
		}
		a.issuer, a.clientID, a.system, a.tenant = withoutTrailingSlashes(o.Issuer), c.ClientID, c.System, c.Tenant
		if a.issuer == "" {
			a.issuer = c.Issuer
		}
	} else if a.keyed == nil {
		deprecated(a.log, "Variables mode (the CAUTHY_* variables)", "Connect the application in Cauthy's dashboard and use the one variable CAUTHY_KEY.")
		a.issuer = withoutTrailingSlashes(or(o.Issuer, "CAUTHY_ISSUER"))
		a.clientID = or(o.ClientID, "CAUTHY_CLIENT_ID")
		a.clientSecret = or(o.ClientSecret, "CAUTHY_CLIENT_SECRET")
		a.system = or(o.System, "CAUTHY_SYSTEM")
		a.tenant = or(o.Tenant, "CAUTHY_TENANT")
	}
	if !strings.HasPrefix(a.issuer, "https://") && !strings.HasPrefix(a.issuer, "http://") {
		return nil, cfgerr.New("issuer (CAUTHY_ISSUER) must be Cauthy's address, e.g. https://id.example.com")
	}
	if a.clientID == "" {
		return nil, cfgerr.New("clientId (CAUTHY_CLIENT_ID) is required")
	}
	if a.keyed == nil && o.Contract != nil {
		rings, err := keys.Derive(root, previous)
		if err != nil {
			return nil, err
		}
		a.cookieRing, a.flowRing = rings.Cookie, rings.Flow
		if o.Keys != nil {
			a.ownKeys = keys.New(o.Keys, rings.Seal, a.now)
		}
	} else if a.keyed != nil {
		// The secret segment is the root of the cookie and flow keys
		// (key/cauthy-key.md §4); the previous key's are read, never written.
		prev := ""
		if a.keyed.previous != nil {
			prev = a.keyed.previous.Secret
		}
		rings, err := keys.Derive(a.keyed.key.Secret, prev)
		if err != nil {
			return nil, err
		}
		a.cookieRing, a.flowRing = rings.Cookie, rings.Flow
		// While moving to CAUTHY_KEY, the sessions of the secret it replaces
		// are read (never written: the first key of a ring writes).
		if secret := getenv("CAUTHY_SECRET"); secret != "" {
			sum := sha256.Sum256([]byte(secret))
			a.cookieRing, a.flowRing = append(a.cookieRing, sum[:]), append(a.flowRing, sum[:])
			deprecated(a.log, "CAUTHY_SECRET beside CAUTHY_KEY", "It is read only for sessions made before the move: remove it after the rotation window.")
		}
		if root := getenv("PACT_ROOT_KEY"); root != "" {
			// With PACT_ROOT_KEY_PREVIOUS when a root rotation was still open:
			// the sessions of both roots are read.
			old, err := keys.Derive(root, getenv("PACT_ROOT_KEY_PREVIOUS"))
			if err != nil {
				return nil, err
			}
			a.cookieRing, a.flowRing = append(a.cookieRing, old.Cookie...), append(a.flowRing, old.Flow...)
			if o.Keys != nil {
				// Its stored keys stay published beside the key's until removed.
				a.ownKeys = keys.New(o.Keys, old.Seal, a.now)
			}
			deprecated(a.log, "PACT_ROOT_KEY beside CAUTHY_KEY", "It is read only for sessions made before the move: remove it, the key store and its table after the rotation window.")
		} else if o.Keys != nil {
			return nil, cfgerr.New("Keys is the key store of PACT_ROOT_KEY, which opens it: on CAUTHY_KEY remove Keys (no key store is needed), or keep PACT_ROOT_KEY beside the key while moving")
		}
		// The key proves the key's client; by contract, the link's service
		// client (none without a service block).
		proves := a.clientID
		if a.contract != nil {
			proves = a.contract.ServiceClientID
		}
		if proves != "" {
			d := a.keyed.key.Derive()
			a.signer = &system.Signer{ClientID: proves, KID: d.KID, Key: d.Private}
		}
	} else {
		secret := or(o.Secret, "CAUTHY_SECRET")
		if len(secret) < 32 {
			return nil, cfgerr.New("secret (CAUTHY_SECRET) must be at least 32 characters: it encrypts the session cookie")
		}
		k := sha256.Sum256([]byte(secret))
		a.cookieRing = [][]byte{k[:]}
		a.flowRing = a.cookieRing
	}

	a.baseURL = or(o.BaseURL, "CAUTHY_BASE_URL")
	if a.baseURL != "" && !baseURLRE.MatchString(a.baseURL) {
		return nil, cfgerr.New("baseURL (CAUTHY_BASE_URL) must be the application's public origin, e.g. https://app.example.com")
	}
	a.baseURL = withoutTrailingSlashes(a.baseURL)
	bp := o.BasePath
	if bp == "" {
		bp = "/api/auth"
	}
	a.basePath = "/" + strings.Trim(bp, "/")
	a.requestHeader = o.RequestHeader
	if a.requestHeader == "" {
		a.requestHeader = "required"
	}
	if a.requestHeader != "required" && a.requestHeader != "warn" {
		return nil, cfgerr.New(`requestHeader must be "required" or "warn"`)
	}
	a.afterSignIn, a.afterSignOut = localPath(o.AfterSignIn, "/"), localPath(o.AfterSignOut, "/")
	a.cookieName = o.CookieName
	if a.cookieName == "" {
		a.cookieName = "cauthy_session"
	}
	a.flowCookie, a.againCookie, a.stepCookie = a.cookieName+"_flow", a.cookieName+"_again", a.cookieName+"_step"
	sysTimeout, reqTimeout := o.Timeouts.System, o.Timeouts.Request
	if sysTimeout < 0 || reqTimeout < 0 {
		return nil, cfgerr.New("timeouts must be positive durations")
	}
	if sysTimeout == 0 {
		sysTimeout = 2 * time.Second
	}
	if reqTimeout == 0 {
		reqTimeout = 5 * time.Second
	}
	a.requestTimeout = reqTimeout
	page := func(p string) string {
		if p == "" {
			return ""
		}
		return localPath(p, "/")
	}
	a.pages = Pages{SignIn: page(o.Pages.SignIn), ResetPassword: page(o.Pages.ResetPassword), VerifyEmail: page(o.Pages.VerifyEmail), AcceptInvite: page(o.Pages.AcceptInvite)}
	// Calls to Cauthy never follow a redirect off its host: the tokens,
	// codes and secrets they carry go to Cauthy and nowhere else. The
	// application's client is copied, never changed.
	hc := &http.Client{}
	if o.HTTPClient != nil {
		copied := *o.HTTPClient
		hc = &copied
	}
	issuerHost := ""
	if u, err := url.Parse(a.issuer); err == nil {
		issuerHost = u.Host
	}
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != issuerHost || len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}
	a.http = hc
	a.clientIP = o.ClientIP
	if a.clientIP == nil {
		a.clientIP = forwardedFor
	}

	so := system.Options{Issuer: a.issuer, ClientID: a.clientID, ClientSecret: a.clientSecret, System: a.system, HTTPClient: a.http, Timeout: sysTimeout, Now: a.now,
		// A change the application makes to who belongs where empties the
		// organizations read: a person added a moment ago sees it on the next page.
		Changed: func() { a.forgetOrganizations("") }}
	if a.signer != nil {
		so.Signer, so.SystemOf = a.signer, a.systemName
	} else if o.Contract == nil {
		so.Key = o.SystemKey
		if so.Key == nil && getenv("CAUTHY_SYSTEM_KEY") != "" {
			so.Key = &system.Key{PrivateKey: getenv("CAUTHY_SYSTEM_KEY"), KeyID: getenv("CAUTHY_SYSTEM_KEY_ID")}
		}
	}
	if a.baseURL != "" && a.pages.AcceptInvite != "" {
		so.AcceptInviteURL = a.baseURL + a.pages.AcceptInvite
	}
	if a.ownKeys != nil && a.keyed == nil {
		so.Keys, so.KeysClientID = a.ownKeys, a.contract.ServiceClientID
	}
	sys, err := system.New(so)
	if err != nil {
		return nil, err
	}
	a.sys = sys

	if a.ownKeys != nil && a.keyed == nil {
		// contract/pact.md, rule 10: a store that keeps no key, or a key the
		// root cannot open, stops the start.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, _, err := a.ownKeys.Current(ctx); err != nil {
			return nil, err
		}
		a.pact = &Pact{auth: a}
	}
	if a.keyed != nil && a.contract != nil && a.contract.JWKSPath != "" {
		a.pact = &Pact{auth: a}
	}

	if a.keyed != nil && a.contract == nil {
		// Who the application is, asked of Cauthy with its own token.
		a.identity = newIdentitySource(a.issuer, a.sys.Token, a.http, a.now, a.log, a.signer.KID)
		a.identity.start()
		ctx, cancel := context.WithTimeout(context.Background(), keyStartWait)
		defer cancel()
		id, err := a.identity.Wait(ctx)
		switch {
		case errors.Is(err, ErrMisconfigured):
			// A refusal is a configuration error: starting would only answer 503.
			return nil, fmt.Errorf("%w (kid %s)", ErrMisconfigured, a.signer.KID)
		case err != nil:
			a.log.Warn("cauthy: Cauthy cannot be reached yet; " + a.basePath + " answers 503 until it can")
		default:
			a.adopt(id)
		}
	}
	return a, nil
}

// forwardedFor is the last address in X-Forwarded-For that is not the
// network's own: the one the proxy in front of the application wrote.
func forwardedFor(r *http.Request) string {
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		if a := strings.TrimSpace(parts[i]); a != "" && !ownNetwork(a) {
			return a
		}
	}
	return ""
}

// BasePath is where the routes are: /api/auth by default.
func (a *Auth) BasePath() string { return a.basePath }

// Issuer is Cauthy's address.
func (a *Auth) Issuer() string { return a.issuer }

// ClientID is the client people sign in with.
func (a *Auth) ClientID() string { return a.clientID }

// System is the application acting on its own.
func (a *Auth) System() *system.Client { return a.sys }

// timed is a value kept until a moment.
type timed struct {
	until time.Time
	value any
}

// originOf is the application's public origin: BaseURL, or the request's
// own with the scheme a TLS-terminating proxy names.
// On CAUTHY_KEY, without BaseURL, it is one of the addresses Cauthy lists
// for the application (registeredOrigin).
func (a *Auth) originOf(r *http.Request) string {
	if a.baseURL != "" {
		return a.baseURL
	}
	asked := requestOrigin(r)
	if a.identity != nil {
		origin, _ := a.registeredOrigin(asked)
		return origin
	}
	return asked
}

// attrs are the cookie attributes for r: Secure on an https origin.
func (a *Auth) attrs(r *http.Request) cookieAttrs {
	return cookieAttrs{secure: strings.HasPrefix(a.originOf(r), "https://")}
}

// warnOnce logs message the first time key is seen.
func (a *Auth) warnOnce(key, message string) {
	if _, said := a.told.LoadOrStore(key, true); !said {
		a.log.Warn(message)
	}
}
