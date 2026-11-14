# Changelog

## Unreleased

### Removed

- The startup refusal v1.3.0 gave an environment that still carried a contract's root key: it is ignored.

## v1.3.0 — contracts removed

Pact contracts are retired, and contract mode is gone from the SDK. An application runs on its `CAUTHY_KEY` alone, and its people stay signed in.

### Removed

- **Contract mode**: `Options.Contract` and the `Contract` type, the `contract` package (reading the contracts graph), `VerifierConfigFromContract`, `Auth.Pact()` and the `Pact` type (its `Contract`, `Keys`, `JWKS` and `Status`), and `system.Client.PactStatus` / `system.PactStatus`.
- **The key store and the contract root key**: `Options.Keys`, `Options.RootKey`, `Options.RootKeyPrevious`, and the `keys` package (`Store`, `Memory`, `File`, `Postgres`, `TableSQL`, `Keys`, `Derive`, `JWKS`). `system.Options.Keys` and `KeysClientID` go with it; `system.Client.PublicJWKS` now answers a `system.JWKS`.
- **Publishing a JWKS**: `Auth` no longer serves keys, and `Mount`, `MountRouter` and the `gin`, `echo` and `fiber` adapters mount the base path only. `JWKSPath()` and `DefaultJWKSPath` stay, deprecated, so the adapters released before 1.3.0 still compile; `Auth` answers 404 there.
- `AppIdentity.Contract`, and `cauthykey.LabelSeal` (the spec's key reference no longer derives a seal key).
- The SDK's own check of a link's `require_verified_email`. Cauthy enforces it: its `email_not_confirmed` refusal at the token endpoint is still answered as before.

### Changed

- **On `CAUTHY_KEY`, people sign in through the client Cauthy names** (`sign_in_client_id` of `GET /v1/connect/self`). When it is not the key's own, the people, and their refresh tokens, are on that client: the authorize redirect, the code exchange, renewals, revocation, sign-out, the account page, the look and the hosted-page and invitation calls go as that client. It is a public client: the key's assertion is sent for the key's own client only, and the code exchange carries the system's proof (`X-Cauthy-System-Token`). A renewal waits for Cauthy's answer first, so a refresh token is never spent on the wrong client. When the two clients are the same, nothing changes.
- `Auth.ClientID()` is the client people sign in with: on `CAUTHY_KEY`, Cauthy's `sign_in_client_id` once it has answered.
- `VerifierConfigFromKey` names no client, so a person's token issued through the sign-in client is accepted when the key is another client's (now covered by a test).
- `cauthytest`: `Fake.SignInClients` (the key's client → the sign-in client `/v1/connect/self` names). The fake now binds a code to the client that asked for it and a refresh token to the client it was issued to, as Cauthy does.
- The `acme-api` example verifies with `VerifierConfigFromKey`; the `acme-crm` example runs on `CAUTHY_KEY` only.
- **"Keep me signed in" is the workspace's setting**, as in Cauthy: `/methods.persistentSessions` follows `persistent_sessions` of `GET /v1/auth/settings`. `cauthytest`: `PUT /v1/settings/auth` sets `persistent_sessions`; a client update with `allow_persistent_sessions` answers `400 persistent_sessions_moved`, and clients no longer list it.
- Tested against cauthy-sdk-spec `d501e34` (contract removal and the workspace persistent-sessions check).

## v1.2.1 — sessions kept when moving to CAUTHY_KEY

### Fixed

- **Moving to `CAUTHY_KEY`**: a session sealed with `CAUTHY_SECRET`, the contract root key or `CAUTHY_KEY_PREVIOUS` is sealed again with the key on the first request that resolves it (`GET <basePath>/session`, the middleware, `Session(w, r)`), not only when its access token is renewed, so it outlives the old secret's removal.
- the previous contract root key beside `CAUTHY_KEY` and the contract root key is read too: sessions sealed before a root rotation that was still open at the move stay readable. v1.2.0 read the current root only.
- A session cookie that no configured key opens is still cleared, and is now logged once per process (`slog`, `Warn`), naming the secret to keep beside `CAUTHY_KEY` for the window.

## v1.2.0 — CAUTHY_KEY

One variable for every application: `CAUTHY_KEY`, made in Cauthy's dashboard (`key/cauthy-key.md` in cauthy-sdk-spec).

### Added

- **Key mode.** `cauthy.New(cauthy.Options{})` reads `CAUTHY_KEY` (or `Options.Key`) and nothing else: Ed25519 `private_key_jwt` on every call to the token and revoke endpoints (no client secret), the cookie and flow keys derived from the key, and who the application is asked of Cauthy (`GET /v1/connect/self`, revalidated every five minutes). Cauthy unreachable at start: `New` waits 10 seconds, then starts and answers `503 unavailable` on the auth routes until Cauthy answers; a refused key is `ErrMisconfigured` (`503 misconfigured` once running). The redirect URI comes from an origin Cauthy lists for the application (`400 unknown_origin` otherwise).
- **Key + contract.** With a contract, `CAUTHY_KEY` replaces the contract root key and the key store: the key proves the link's service client, and its public half is the JWKS at `jwks_url` (`EdDSA`). A key for another Cauthy is refused (`key_contract_issuer`).
- `CAUTHY_KEY_PREVIOUS` (`Options.KeyPrevious`) for rotations: its sessions are read, never written, and by contract its public key is published too (`key_previous_mismatch` when it names another Cauthy or client).
- `CAUTHY_SECRET` and the contract root key beside `CAUTHY_KEY` are read-only previous keys while moving (one warning each); with the contract root key the stored RS256 keys stay published.
- `VerifierConfigFromKey(ctx, getenv, httpClient)`: a verifier's issuer, audience and workspace from `CAUTHY_KEY`.
- `Auth.Identity(ctx)` and `AppIdentity`; `ErrUnavailable`, `ErrMisconfigured`; `KeyReplaces`.
- Package `cauthykey`: the spec's reference (`Parse`, `Compose`, `Derive`, `Assertion`), byte for byte (`make key-reference`).
- `system.Signer` and `system.Options.Signer` / `SystemOf`.
- `cauthytest`: `Fake.IssueKey`, `RegisterKey`, `RevokeKey`, `RegisteredKids`, `AppURLs`, `System`, `SetAppURLs`, `SetDown`, `TenantID`; the fake checks assertions on every grant of a key client and answers `/v1/connect/self`.
- Conformance runs with `--key-env`: the `key.*` checks pass against the example on `CAUTHY_KEY`.

### Deprecated (removed in 2.0)

- The `CAUTHY_*` variables mode, and the options `Issuer`, `ClientID`, `ClientSecret`, `Secret`, `System`, `Tenant`, `SystemKey`.
- The contract root keys (`RootKey`, `RootKeyPrevious`) and `Keys` (the key store) by contract.
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
