# Changelog

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
