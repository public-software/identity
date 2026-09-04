# Provenance

This repository is a spec-first cleanroom implementation. Record here what was consulted.

## Specifications used
- OpenID Connect Core 1.0 incorporating errata set 2 (https://openid.net/specs/openid-connect-core-1_0.html,
  OpenID Foundation; consulted 2026-09-03): §2 (the ID token claims), §3.1.2.1 (the authentication
  request parameters), §3.1.2.6 (the authentication error codes), §3.1.3.3 (the token response with
  `id_token` and `token_type` Bearer), §3.1.3.7 (the ID token validation rules; `pub-identity-client`
  checks rules 2, 3, 4, 5, 7, 9, 10, 11 and 13 and leaves rule 6, the signature, to the caller),
  §15.5.2 (the nonce).
- OpenID Connect Discovery 1.0 incorporating errata set 2
  (https://openid.net/specs/openid-connect-discovery-1_0.html): §3 (the OpenID Provider Metadata
  members and which are required), §4 (`/.well-known/openid-configuration` appended to the issuer,
  a trailing slash removed first), §4.3 (the issuer in the document identical to the one it was
  fetched for; `https`).
- RFC 6749, The OAuth 2.0 Authorization Framework (https://www.rfc-editor.org/rfc/rfc6749): §4.1.2
  (the authorization response, `code` and `state`), §4.1.2.1 and §5.2 (the error responses and their
  codes), §4.1.3 (the token request), §5.1 (the token response), §10.12 (`state` against CSRF).
- RFC 7636, Proof Key for Code Exchange by OAuth Public Clients
  (https://www.rfc-editor.org/rfc/rfc7636): §4.1 (the code verifier grammar, 43 to 128 unreserved
  characters), §4.2 (`S256`: base64url of the SHA-256 of the ASCII verifier), §4.3 and §4.5 (the
  parameters), appendix A (base64url without padding, the `A-z_4ME` example) and appendix B (the
  octets, verifier, digest and challenge the tests pin).
- RFC 9207, OAuth 2.0 Authorization Server Issuer Identification
  (https://www.rfc-editor.org/rfc/rfc9207): §2 (the `iss` authorization response parameter, on error
  responses too), §2.4 (the client compares it with the issuer and refuses a response without it
  when the server announces support), §3 (`authorization_response_iss_parameter_supported`).
- RFC 9700, Best Current Practice for OAuth 2.0 Security (https://www.rfc-editor.org/rfc/rfc9700):
  §2.1.1 (PKCE with `S256` for every client, the only flow this crate offers), §4.5 (mix-up attacks
  and the `iss` countermeasure).
- RFC 8414, OAuth 2.0 Authorization Server Metadata (https://www.rfc-editor.org/rfc/rfc8414): §2,
  the `code_challenge_methods_supported` member the client reads from the provider metadata.
- RFC 7515, JSON Web Signature (https://www.rfc-editor.org/rfc/rfc7515): §3.1 (the compact
  serialization the ID token uses), §4.1 (`alg`, `kid`, `typ`), §5.1 (the signing input). RFC 7519,
  JSON Web Token (https://www.rfc-editor.org/rfc/rfc7519): §2 (NumericDate).
- RFC 3986, Uniform Resource Identifier: Generic Syntax (https://www.rfc-editor.org/rfc/rfc3986):
  §2.1 and §2.3 (percent-encoding and the unreserved characters).
- FIPS PUB 180-4, Secure Hash Standard (https://doi.org/10.6028/NIST.FIPS.180-4, NIST; public
  domain): §5.1.1 (padding), §6.2 (SHA-256), with the example vectors of NIST's "SHA Examples"
  pages. The crate implements SHA-256 for the PKCE challenge instead of depending on `sha2`, whose
  tree has no audit in the vet pools the organization imports (ADR-0001).

## Behavioural references (cited, not copied)
- None. No OpenID Connect or OAuth library's source or documentation was consulted for
  `pub-identity-client`; the fixtures are the specifications' examples and documents written for
  the tests.

## Copyleft sources
None consulted. Contributors who have studied GPL/AGPL implementations of this domain do not author the corresponding modules (two-team rule; see the Charter §09).

## AI assistance
Prompts point at the specifications and conformance suites above, never at copyleft source. Generated code is reviewed against this list before merge.
