# Changelog

## v1.2.0 — CAUTHY_KEY

One variable for every application: `CAUTHY_KEY`, made in Cauthy's dashboard (`key/cauthy-key.md` in cauthy-sdk-spec).

### Added

- **Key mode.** `cauthy.New(cauthy.Options{})` reads `CAUTHY_KEY` (or `Options.Key`) and nothing else: Ed25519 `private_key_jwt` on every call to the token and revoke endpoints (no client secret), the cookie and flow keys derived from the key, and who the application is asked of Cauthy (`GET /v1/connect/self`, revalidated every five minutes). Cauthy unreachable at start: `New` waits 10 seconds, then starts and answers `503 unavailable` on the auth routes until Cauthy answers; a refused key is `ErrMisconfigured` (`503 misconfigured` once running). The redirect URI comes from an origin Cauthy lists for the application (`400 unknown_origin` otherwise).
- **Key + contract.** With a contract, `CAUTHY_KEY` replaces `PACT_ROOT_KEY` and the key store: the key proves the link's service client, and its public half is the JWKS at `jwks_url` (`EdDSA`). A key for another Cauthy is refused (`key_contract_issuer`).
- `CAUTHY_KEY_PREVIOUS` (`Options.KeyPrevious`) for rotations: its sessions are read, never written, and by contract its public key is published too (`key_previous_mismatch` when it names another Cauthy or client).
- `CAUTHY_SECRET` and `PACT_ROOT_KEY` beside `CAUTHY_KEY` are read-only previous keys while moving (one warning each); with `PACT_ROOT_KEY` the stored RS256 keys stay published.
- `VerifierConfigFromKey(ctx, getenv, httpClient)`: a verifier's issuer, audience and workspace from `CAUTHY_KEY`.
- `Auth.Identity(ctx)` and `AppIdentity`; `ErrUnavailable`, `ErrMisconfigured`; `KeyReplaces`.
- Package `cauthykey`: the spec's reference (`Parse`, `Compose`, `Derive`, `Assertion`), byte for byte (`make key-reference`).
- `system.Signer` and `system.Options.Signer` / `SystemOf`.
- `cauthytest`: `Fake.IssueKey`, `RegisterKey`, `RevokeKey`, `RegisteredKids`, `AppURLs`, `System`, `SetAppURLs`, `SetDown`, `TenantID`; the fake checks assertions on every grant of a key client and answers `/v1/connect/self`.
- Conformance runs with `--key-env`: the `key.*` checks pass against the example on `CAUTHY_KEY`.

### Deprecated (removed in 2.0)

- The `CAUTHY_*` variables mode, and the options `Issuer`, `ClientID`, `ClientSecret`, `Secret`, `System`, `Tenant`, `SystemKey`.
- `PACT_ROOT_KEY` / `PACT_ROOT_KEY_PREVIOUS` (`RootKey`, `RootKeyPrevious`) and `Keys` (the key store) by contract.
- `VerifierConfigFromEnv`.

Each logs one warning per process (`slog`, level `Warn`, `deprecated=true`). Nothing else changes for an application that does not move.

### Notes

- With `CAUTHY_KEY` set, any of `CAUTHY_ISSUER`, `CAUTHY_CLIENT_ID`, `CAUTHY_CLIENT_SECRET`, `CAUTHY_SYSTEM`, `CAUTHY_TENANT`, `CAUTHY_SYSTEM_KEY`, `CAUTHY_SYSTEM_KEY_ID`, `CAUTHY_BASE_URL`, `CAUTHY_AUDIENCE`, `CAUTHY_TENANT_ID` stops the start.
- The `gin`, `echo` and `fiber` adapters are unchanged.

## v1.1.0 — security release

Cauthy now marks the tokens a machine holds, and names the client a person's token was issued through. This release makes the verifier use those marks. Refusing a machine's token where a person is expected is a fix, not a break, so it ships as a minor version: upgrade.

### Security

- **A client's own token no longer passes as a person's.** A `client_credentials` token carries `token_use: "client"` and the client's public `client_id`. `Verifier.Verify`, `VerifyRequest` and `Require` now refuse it with `ClientToken` (`client_token`, rule R13 of the spec's `verification/rules.md`), by the claim's presence, whatever its value. In v1.0.0 such a token was accepted as a person whose `Subject` was the client's id.
- **By contract, a person's token issued through another client is refused** with `WrongClient` (`wrong_client`, rule R15): `VerifierConfigFromContract` sets `ClientID` to the link's sign-in client, and a token whose `azp` names another client is refused. A token with no `azp` passes.
- `token_use` and `azp`, when present, must be strings (`invalid_claim` otherwise, rule R8).

### Backends that serve machines

If an endpoint is called by machines with a `client_credentials` token, set `AllowClientTokens` on the verifier that guards it:

```go
cfg.AllowClientTokens = true
machines, err := cauthy.NewVerifier(cfg)
// id.ClientID is the client's public id; id.Subject its internal id.
```

Without it those calls get `401` (`client_token`) after the upgrade.

### Added

- `Identity.AuthorizedParty` (the token's `azp`) and `Identity.ClientID` (its `client_id`).
- `VerifierConfig.AllowClientTokens` (default `false`) and `VerifierConfig.ClientID` (default empty: `azp` is not checked).
- `ClientToken` and `WrongClient` in `Reasons`.

### Notes

- Cauthy now answers its JWKS with `max-age=300` and publishes a key at least that long before it signs with it. Nothing changes here: the set is kept for the answer's `max-age` and fetched again on an unknown `kid` (rules K2 and K3).
- A session that began through a client renews only through it: keep one client id per deployment.
- The `gin`, `echo` and `fiber` adapters take a `*cauthy.Verifier` and are unchanged.

## v1.0.0

First release.
