# ADR-0001: The OpenID Connect client core carries no transport, no clock and no entropy

- Status: accepted
- Date: 2026-09-03
- Scope: this repository only (cross-repo decisions are RFCs in public-software/rfcs)

## Context

Every application of the suite signs in through OpenID Connect: desktop applications, services, and
plugins running in the WASM host of `plugin-runtime`. Those callers have different HTTP stacks,
different clocks (a plugin gets a WASI clock the host grants), different random sources and
different ways of verifying a signature (a JWK Set from the provider, or trust in the TLS
connection to the token endpoint). The client logic itself is one: build the requests, read the
responses, and check every rule OpenID Connect Core 1.0 §3.1.3.7, OpenID Connect Discovery 1.0
§4.3, RFC 6749 §10.12, RFC 7636 and RFC 9207 put on the client. That logic is where sign-in goes
wrong when it goes wrong, and it is the part worth testing once against fixtures.

The first crate of `identity` therefore has to settle what the client core is and what it is not.

## Decision

1. **`pub-identity-client` is transport-free, clock-free and entropy-free.** The caller fetches
   the bytes (the configuration document, the token response), draws the octets (32 for the PKCE
   verifier, 16 each for state and nonce) and passes the current time as seconds since the epoch.
   The crate builds the authentication request URL and the token request body, parses the
   documents and the responses, and validates. Its dependencies are serde and serde_json.

2. **Signature verification stays out, and the API says so.** `IdToken::parse` yields the header,
   the claims, the signing input and the signature bytes; `validate_claims` checks the claims
   against `Expectations` and names the rule that fails. Verifying the signature with the key the
   header's `kid` names is the caller's, or the caller relies on TLS server validation because the
   token came straight from the token endpoint (Core §3.1.3.7 rule 6). A JWS/JWK verifier is a
   later crate of this repository; it will consume `signing_input()` and `signature()` as they are.

3. **The client is strict where the specifications let it be.** The authorization code flow with
   PKCE `S256` is the only flow (RFC 9700 §2.1.1). The configuration document must carry the
   required members of Discovery §3, an `https` issuer without query or fragment, identical to the
   one the document was fetched for (§4.3). The authorization response is checked in the order
   state (RFC 6749 §10.12), then `iss` (RFC 9207: present it must match, and it must be present
   when the provider announces `authorization_response_iss_parameter_supported`, on error responses
   too), then the provider's error, then the code. The token response must say `Bearer` and carry
   an ID token (Core §3.1.3.3). `alg: none` is never accepted, listed or not.

4. **SHA-256 for the code challenge is implemented in the crate.** The RustCrypto `sha2` tree
   (ten crates on either of its current lines) has no audit in the Mozilla or Google pool at the
   versions Cargo resolves today, and an exemption is not an audit. FIPS 180-4 is one public
   specification with published vectors; the implementation is a page, private to the crate, a hash
   with no key and no secret-dependent branching, and it is tested against the standard's vectors
   and the RFC 7636 appendix B digest. When the organization's vet store covers the RustCrypto
   tree (an org-wide decision, not this repository's) the module can be swapped for `sha2` without
   an API change.

5. **What the flow needs to remember is one serializable value.** `PendingAuthorization` holds the
   issuer, the client id, the redirect URI, the token endpoint, the state, the nonce, the code
   verifier and `max_age`; it derives serde so a web application can keep it in its session store
   across the redirect. The verifier, the authorization code and the tokens do not print in
   `Debug`.

## Consequences

- An application, a service or a plugin uses the same client core, and the transport-specific
  part (HTTP, TLS, session storage, the random source, the clock) is a thin layer each writes for
  itself or takes from `platform`.
- The tests are fixtures and vectors: the RFC 7636 appendix B octets, a configuration document, a
  token response, ID tokens built in the test; no network and no time in CI.
- What is deferred, with its shape: the JWS/JWK verifier (RS256 and ES256 over the JWK Set at
  `jwks_uri`, consuming `signing_input()` and `signature()`); client authentication for
  confidential clients (`client_secret_basic` is an `Authorization` header the caller adds to the
  token request; `client_secret_post` and `private_key_jwt` would add parameters to
  `TokenRequest`); the refresh token grant and the UserInfo endpoint; the pushed authorization
  request (RFC 9126) and the request object (Core §6); a typed error code for `ProviderError`.
- The IdP (`pubd-idp`) needs its own ADR before it is started: the catalog says Kanidm-derived, and
  Kanidm is MPL-2.0, weak copyleft the platform ring cannot take as a dependency; whether
  "derived" means the data model, the protocols or nothing of the source is a decision to record.
