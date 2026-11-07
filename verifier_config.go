package cauthy

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/internal/cfgerr"
)

// VerifierConfig is what a verifier checks tokens against.
type VerifierConfig struct {
	// Issuer is Cauthy's issuer exactly as Cauthy writes it: https (http only
	// for localhost, 127.0.0.1, *.localhost and *.test), no trailing slash, no
	// query or fragment. The keys are fetched from <Issuer>/.well-known/jwks.json.
	Issuer string
	// Issuers are further issuers a token may name (a workspace's custom
	// domain). Their keys are Issuer's; none of them is fetched.
	Issuers []string
	// Audience is the audience Cauthy's tokens carry. Required.
	Audience string
	// Tenant is the workspace's id, a lowercase UUID. Required: a token of
	// any other workspace is refused.
	Tenant string
	// AllowAnonymous lets a guest's token through (rule R14). Off by default.
	AllowAnonymous bool
	// AllowSystem lets a system's own token through (rule R13), for an
	// endpoint another system calls. Off by default: a system never stands
	// for a person.
	AllowSystem bool
	// Leeway is the clock tolerance: nil is DefaultLeeway, a pointer to zero
	// is none, at most MaxLeeway. LeewayOf makes the pointer.
	Leeway *time.Duration
	// Keys is where the signing keys come from. Nil: Cauthy's published set,
	// fetched from Issuer under rules K1–K6.
	Keys KeySet
	// HTTPClient fetches the keys when Keys is nil. Nil: a plain client.
	HTTPClient *http.Client
	// Now is the clock. Nil: time.Now.
	Now func() time.Time
	// Logger receives one debug line per refused token, with its reason.
	// Nil: slog.Default().
	Logger *slog.Logger
}

// LeewayOf is a VerifierConfig.Leeway of d.
func LeewayOf(d time.Duration) *time.Duration { return &d }

// Verifier checks Cauthy access tokens against one configuration.
type Verifier struct {
	cfg    VerifierConfig
	leeway time.Duration
	keys   KeySet
	now    func() time.Time
	log    *slog.Logger
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

const nilUUID = "00000000-0000-0000-0000-000000000000"

// localHost reports whether host may be reached over plain http.
func localHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".test")
}

// checkIssuer refuses an issuer that is not an https origin without a
// trailing slash, query or fragment.
func checkIssuer(name, iss string) error {
	u, err := url.Parse(iss)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(iss, "?") || strings.HasSuffix(iss, "#") {
		return cfgerr.New("%s %q is not an absolute URL without query or fragment", name, iss)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && localHost(u.Hostname())) {
		return cfgerr.New("%s %q must be https (http only for localhost, *.localhost and *.test)", name, iss)
	}
	if strings.HasSuffix(iss, "/") {
		return cfgerr.New("%s %q must not end in /", name, iss)
	}
	return nil
}

// JWKSURL is where an issuer publishes its keys. It is derived from the
// configured issuer, never read from a token.
func JWKSURL(issuer string) (string, error) {
	if err := checkIssuer("issuer", issuer); err != nil {
		return "", err
	}
	return issuer + "/.well-known/jwks.json", nil
}

// NewVerifier checks the configuration and answers a verifier. A
// configuration it refuses is a *ConfigError at start, never a reason at
// request time.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if err := checkIssuer("issuer", cfg.Issuer); err != nil {
		return nil, err
	}
	for _, iss := range cfg.Issuers {
		if err := checkIssuer("issuers entry", iss); err != nil {
			return nil, err
		}
	}
	if cfg.Audience == "" {
		return nil, cfgerr.New("audience is required: without it a token issued for another application would be accepted")
	}
	if !uuidRE.MatchString(cfg.Tenant) || cfg.Tenant == nilUUID {
		return nil, cfgerr.New("tenant %q is not the workspace's id, a lowercase UUID that is not the nil UUID", cfg.Tenant)
	}
	leeway := DefaultLeeway
	if cfg.Leeway != nil {
		leeway = *cfg.Leeway
	}
	if leeway < 0 || leeway > MaxLeeway {
		return nil, cfgerr.New("leeway %s is outside 0..%s", leeway, MaxLeeway)
	}
	keys := cfg.Keys
	if keys == nil {
		u, _ := JWKSURL(cfg.Issuer)
		keys = NewRemoteKeys(HTTPFetcher(u, cfg.HTTPClient), DefaultCooldown, nil)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Verifier{cfg: cfg, leeway: leeway, keys: keys, now: now, log: log}, nil
}

// String names the verifier's issuer and tenant, for logs.
func (v *Verifier) String() string {
	return fmt.Sprintf("cauthy.Verifier{issuer: %s, tenant: %s}", v.cfg.Issuer, v.cfg.Tenant)
}
