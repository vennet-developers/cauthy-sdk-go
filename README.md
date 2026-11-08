# cauthy-sdk-go

Cauthy for Go backends: verify Cauthy's access tokens, serve the auth-bff
protocol (version 1, level strict) and act as a system under a Pact contract.
The core module has no dependency outside the standard library.

```
go get github.com/vennet-developers/cauthy-sdk-go
```

It meets [cauthy-sdk-spec](https://github.com/vennet-developers/cauthy-sdk-spec)
at `conformance/v0.4.0`: every token vector, and `cauthy-conformance --level switches`
against the Acme CRM example, in CI on every commit.

Locally, the dashboard switches too (the in-memory Cauthy serves its admin API):

    SPEC_DIR=../cauthy-sdk-spec LEVEL=switches sh scripts/conformance.sh

## An API behind another backend: verify tokens

```go
cfg, err := cauthy.VerifierConfigFromEnv(nil) // CAUTHY_ISSUER, CAUTHY_AUDIENCE, CAUTHY_TENANT_ID
if err != nil {
	log.Fatal(err)
}
verifier, err := cauthy.NewVerifier(cfg)
if err != nil {
	log.Fatal(err) // a verifier without issuer, audience and workspace never starts
}
r := chi.NewRouter()
r.With(verifier.Require).Get("/api/records", func(w http.ResponseWriter, r *http.Request) {
	id, _ := cauthy.FromContext(r.Context())
	// id.Subject is the person. id.Roles are workspace roles, never a business role.
})
```

By contract, `contract.Read` the graph and pass it to `cauthy.VerifierConfigFromContract`;
it names the link's sign-in client (`ClientID`), and a person's token issued through
another client is refused (`wrong_client`; a token with no `azp` passes).
A system's own token (`sys`), a client's own token (`token_use`, from a
`client_credentials` grant: reason `client_token`) and a guest's token are refused
where a person is expected. An endpoint that machines call sets
`AllowClientTokens: true`; `id.ClientID` is then the client's public id (and
`id.Subject` its internal id). `id.AuthorizedParty` is the token's `azp`, the
client a person's token was issued through.
Every refused token answers the same `401 unauthenticated`; while Cauthy's keys
have never been fetched, `503 unavailable`, so an outage signs nobody out.

## The whole backend: serve the auth-bff protocol

```go
graph, err := os.ReadFile("contracts/graph.json")
if err != nil {
	log.Fatal(err)
}
auth, err := cauthy.New(cauthy.Options{
	Contract: &cauthy.Contract{Graph: graph, System: "acme-crm"},
	Keys:     keys.Postgres(db), // the cauthy_pact_keys table
})
if err != nil {
	log.Fatal(err) // refuses to start on anything contract/pact.md lists
}
mux.Handle("/api/auth/", auth)
mux.Handle(auth.JWKSPath(), auth)
if err := auth.CheckMount(mux); err != nil {
	log.Fatal(err) // something else answers under /api/auth
}
```

The only secret is `PACT_ROOT_KEY`. Without a contract, `cauthy.New(cauthy.Options{})`
reads `CAUTHY_ISSUER`, `CAUTHY_CLIENT_ID`, `CAUTHY_SECRET`, `CAUTHY_TENANT` and the
rest; the two modes never mix.

| Router | Mounting |
| --- | --- |
| `net/http` | `mux.Handle("/api/auth/", auth)` and `mux.Handle(auth.JWKSPath(), auth)`, or `auth.Mount(mux)` |
| chi | `r.Handle("/api/auth/*", auth)` and `r.Handle(auth.JWKSPath(), auth)`, or `auth.MountRouter(r)` |
| Gin | `cauthygin.Mount(r, auth)` — `go get github.com/vennet-developers/cauthy-sdk-go/gin` |
| Echo v5 | `cauthyecho.Mount(e, auth)` — `go get github.com/vennet-developers/cauthy-sdk-go/echo` |
| Fiber | `cauthyfiber.Mount(app, auth)` — `go get github.com/vennet-developers/cauthy-sdk-go/fiber` |

The core and the example need Go 1.24 or later; the Echo (Echo v5) and Fiber
adapters Go 1.25, and the Gin adapter Go 1.26 (the golang.org/x/net it pulls
does). Every module is held free of known advisories (govulncheck). Fiber is
fasthttp, and its adaptor buffers an answer whole: the push approval's event
stream arrives at its end, and the page polls `/sign-in/mfa/push/finish`.

A page only a signed-in person sees: `auth.Protect(handler)`, then
`cauthy.SessionFromContext(r.Context())`. Webhooks: `event, err := auth.Webhook(r)`.
Keys: `auth.Pact().Keys().Rotate(ctx)`, and after a root rotation (with
`PACT_ROOT_KEY_PREVIOUS` set) `auth.Pact().Keys().Reseal(ctx)`.

## What a session cookie is

Byte for byte what `@cauthyhq/node` writes, so an application can move between
a Node and a Go backend without signing anybody out:

| Cookie | Holds |
| --- | --- |
| `cauthy_session.0`, `.1`… (≤ 3500 characters each) | JSON `{at, rt, exp, u, tid, roles, p?}`, sealed |
| `cauthy_session_flow` | JSON `{state, verifier, returnTo}`, sealed, 3600 s |
| `cauthy_session_again` | `1`, 120 s |
| `cauthy_session_step` | JSON `{kind, token, provider?, returnTo, remember?}`, sealed, 600 or 300 s |

Sealed is a compact JWE, `alg: dir`, `enc: A256GCM`, protected header exactly
`{"alg":"dir","enc":"A256GCM"}`. The key is SHA-256 of `CAUTHY_SECRET` in variables
mode; by contract, HKDF-SHA-256 of `PACT_ROOT_KEY` with an empty salt and the
label `pact/cookie/v1` (session) or `pact/flow/v1` (flow and step). The private
key in the key store is the same envelope of its private JWK under `pact/seal/v1`,
and its id is the RFC 7638 thumbprint, so Node and Go share one key table. The
published key set holds at most two keys: the newest, and the one before it
for 24 hours.

## Testing your application

`cauthytest.New()` is a Cauthy in memory (`Issuer`, `Client()`, `AddUser`, `On`
to script any route) and `cauthytest.NewBrowser("")` a browser that keeps cookies.
Test-only: it checks nothing a real Cauthy does.

## Security

See [SECURITY.md](SECURITY.md).

## License

See [LICENSE](LICENSE).
