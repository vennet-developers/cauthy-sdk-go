# cauthy-sdk-go

Cauthy for Go backends: verify Cauthy's access tokens, serve the auth-bff
protocol (version 1, level strict) and act as a system under a Pact contract.
The core module has no dependency outside the standard library.

```
go get github.com/vennet-developers/cauthy-sdk-go
```

It meets [cauthy-sdk-spec](https://github.com/vennet-developers/cauthy-sdk-spec):
every token vector, every `CAUTHY_KEY` vector, and `cauthy-conformance --level switches
--key-env` against the Acme CRM example on `CAUTHY_KEY`, in CI on every commit.

Locally, the dashboard switches too (the in-memory Cauthy serves its admin API):

    SPEC_DIR=../cauthy-sdk-spec LEVEL=switches sh scripts/conformance.sh

## Five lines

`.env` holds one line, the key Cauthy's dashboard made for the application
(**Integrate → Applications → Connect an application**):

    CAUTHY_KEY=cauthy1.…

```go
auth, err := cauthy.New(cauthy.Options{}) // reads CAUTHY_KEY
if err != nil {
	log.Fatal(err) // a damaged key, or a variable it replaces set beside it
}
auth.Mount(mux)
```

## CAUTHY_KEY

One value: Cauthy's address, the application's client and a 32-byte secret
(`key/cauthy-key.md` in the spec; the `cauthykey` package reads it). The SDK
derives the session-cookie keys and an Ed25519 key from it, proves itself to
Cauthy with that key (`private_key_jwt`, on every call to the token and revoke
endpoints, never a client secret), and asks Cauthy who it is
(`GET /v1/connect/self`): the workspace, the system and the application's
addresses, revalidated every five minutes. Cauthy keeps only the public half.

- Cauthy unreachable at start: `New` waits up to 10 seconds, then starts
  anyway; the auth routes answer `503 unavailable` until Cauthy answers.
  `auth.Identity(ctx)` waits for it.
- Cauthy refuses the key (revoked, never registered): `New` returns
  `ErrMisconfigured` when it says so at start; after that the auth routes
  answer `503 misconfigured`, and the `kid` is logged once.
- The redirect URI is built from the request's origin when Cauthy lists it for
  the application, else from the only one it lists; otherwise `400 unknown_origin`.
  `BaseURL` still fixes the origin.
- None of `KeyReplaces` (`CAUTHY_ISSUER`, `CAUTHY_CLIENT_ID`, `CAUTHY_BASE_URL`,
  …) may be set beside it: `New` refuses to start and names them. A damaged
  key is refused with a `*cauthykey.Error` naming the reason, never the key.
- Lost or leaked: make a new one on the application's card and revoke the
  old one. Rotating: move the current value to `CAUTHY_KEY_PREVIOUS`, put the
  new one in `CAUTHY_KEY`, deploy, remove `CAUTHY_KEY_PREVIOUS` after the
  window. Sessions of the previous key are read, never written.
- Moving from 1.1: keep `CAUTHY_SECRET` or `PACT_ROOT_KEY` beside the key for
  the window; their sessions are read (one deprecation warning each).

The variables of 1.1 (`CAUTHY_ISSUER`, `CAUTHY_CLIENT_ID`, …) and
`PACT_ROOT_KEY` still work in 1.x with a deprecation warning (`slog`, `Warn`,
`deprecated=true`, once per process) and leave in 2.0.

## An API behind another backend: verify tokens

```go
cfg, err := cauthy.VerifierConfigFromKey(ctx, nil, nil) // CAUTHY_KEY: issuer, audience and workspace from Cauthy
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

`VerifierConfigFromEnv` (`CAUTHY_ISSUER`, `CAUTHY_AUDIENCE`, `CAUTHY_TENANT_ID`)
still works and is deprecated.

## The whole backend: serve the auth-bff protocol

By contract, on the same `CAUTHY_KEY` and no key store:

```go
graph, err := os.ReadFile("contracts/graph.json")
if err != nil {
	log.Fatal(err)
}
auth, err := cauthy.New(cauthy.Options{
	Contract: &cauthy.Contract{Graph: graph, System: "acme-crm"},
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

The only secret is `CAUTHY_KEY`. The key's issuer must be the graph's Cauthy
(`key_contract_issuer`); the key proves the link's service client, and its public
half is published at the contract's `jwks_url` (`{"kty":"OKP","crv":"Ed25519",…,"alg":"EdDSA"}`,
`max-age=300`; the previous key's too while rotating). The legacy contract mode,
`PACT_ROOT_KEY` with `Keys: keys.Postgres(db)`, still works until 2.0.

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
Legacy key store: `auth.Pact().Keys().Rotate(ctx)`, and after a root rotation (with
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
`{"alg":"dir","enc":"A256GCM"}`. On `CAUTHY_KEY` the key is HKDF-SHA-256 of the
key's secret segment (as text) with an empty salt and the label `pact/cookie/v1`
(session) or `pact/flow/v1` (flow and step); with `PACT_ROOT_KEY`, the same of the
root key; in variables mode, SHA-256 of `CAUTHY_SECRET`. The private
key in the key store is the same envelope of its private JWK under `pact/seal/v1`,
and its id is the RFC 7638 thumbprint, so Node and Go share one key table. The
published key set holds at most two keys: the newest, and the one before it
for 24 hours.

## Testing your application

`cauthytest.New()` is a Cauthy in memory (`Issuer`, `Client()`, `AddUser`, `On`
to script any route) and `cauthytest.NewBrowser("")` a browser that keeps cookies.
`f.IssueKey()` makes a `CAUTHY_KEY` as the dashboard would (`f.RevokeKey(kid)`,
`f.AppURLs`, `f.SetDown(true)`); the fake then checks the key's assertions and
answers `/v1/connect/self`:

```go
f := cauthytest.New()
auth, err := cauthy.New(cauthy.Options{Key: f.IssueKey(), HTTPClient: f.Client()})
b := cauthytest.NewBrowser("http://localhost:3000") // the fake's AppURLs
```

Test-only: it checks little of what a real Cauthy does.

## Security

See [SECURITY.md](SECURITY.md).

## License

See [LICENSE](LICENSE).
