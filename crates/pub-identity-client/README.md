# pub-identity-client

The `client` library of [identity](https://github.com/public-software/identity), part of Public Software. Kind: `lib`.

The OpenID Connect client core: the client side of the authorization code flow with PKCE as OpenID
Connect Core 1.0, OpenID Connect Discovery 1.0, RFC 6749, RFC 7636, RFC 9207 and RFC 9700 specify
it (listed in the repository's `PROVENANCE.md`), without a transport. It reads the provider's
configuration document (validated for the issuer), builds the authentication request URL with a
PKCE `S256` challenge, state and nonce, checks the authorization response (state, RFC 9207 `iss`,
the provider's error), builds the token request body, reads the token response and parses the ID
token, then validates the ID token's claims against what was sent and the time the caller passes,
naming the rule of Core §3.1.3.7 that fails. The caller supplies the bytes, the random octets and
the clock, and verifies the signature (or relies on TLS to the token endpoint, rule 6). Not yet:
the JWS/JWK verifier, client authentication for confidential clients, the refresh grant, the
UserInfo endpoint (ADR-0001).

```sh
cargo nextest run -p pub-identity-client
```

Its entry in the repository's `CATALOG.toml`:

```toml
[[component]]
crate     = "pub-identity-client"
kind      = "lib"
ledger    = "identity"
readiness = "seed"
effort    = 3
specs     = ["openid-connect-core", "openid-connect-discovery", "rfc6749", "rfc7636"]
provides  = []
requires  = []
```
