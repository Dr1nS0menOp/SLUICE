# Single sign-on (OIDC)

Facts for `sluice up`'s single sign-on (ADR 0016), verified 2026-10-11 against Keycloak 26.0.7
(`quay.io/keycloak/keycloak:26.0.7`, `start-dev`, a test realm with a public client).

- **Flow:** authorization code with PKCE (`S256`), `state` and `nonce`. A public client needs no
  secret; `client_secret_file` covers providers that require a confidential client.
- **Signatures:** Keycloak signs ID tokens with RS256 by default. Sluice verifies RS256 and ES256
  with `ring` (already in the tree through rustls). `jsonwebtoken` 11 was not used: its two
  crypto backends are `aws-lc-rs` (a C build, awkward for the static musl releases) and
  `rust_crypto`, which pulls in the `rsa` crate with an open advisory (RUSTSEC-2023-0071) that
  cargo-deny refuses.
- **Issuer:** Keycloak's discovery document names the issuer by the host the request used
  (`http://127.0.0.1:8180/realms/sluice`). Configure `issuer` exactly as the provider states it;
  Sluice refuses a discovery document that names another.
- **Name claim:** `email` by default. With Keycloak, `preferred_username` is the login name; with
  Entra ID, `email` needs the optional claim or use `preferred_username` (the UPN).
- **Operators:** only names in `oidc.operators` get a session (compared ignoring case). A valid
  login of anyone else ends in `403 … is not an operator`.
- **Sessions:** a random 32-byte id in `sluice_session` (`HttpOnly`, `SameSite=Strict`, `Secure`
  when the redirect URL is https), held in memory: a restart signs everyone out.
- **Testing over http:** Keycloak marks its own cookies `Secure`; a scripted browser must send
  them over http on localhost anyway (the end-to-end script clears the flag), browsers do so for
  `localhost`.
- **End to end:** alice signed in, `/auth/me` named her, her hold appeared in the history and the
  audit log as `alice@example.org`, sign-out ended the session (401), and mallory, a valid
  Keycloak user but no operator, was refused.
