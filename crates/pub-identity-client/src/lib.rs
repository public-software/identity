//! `pub-identity-client` — the OpenID Connect client core of
//! [`identity`](https://github.com/public-software/identity): what every application of the suite
//! signs in with, without a transport.
//!
//! The crate implements the client side of the authorization code flow with PKCE as OpenID Connect
//! Core 1.0, OpenID Connect Discovery 1.0, RFC 6749, RFC 7636, RFC 9207 and RFC 9700 specify it
//! (listed in the repository's `PROVENANCE.md`), and nothing else: no HTTP, no clock, no random
//! numbers, no key handling. The caller fetches the bytes, draws the octets, passes the time and
//! verifies the ID token's signature (or relies on TLS to the token endpoint, Core §3.1.3.7 rule 6);
//! the crate builds the requests, reads the responses and checks every rule the specifications put
//! on the client, naming the rule when one fails.
//!
//! The flow, step by step:
//!
//! ```
//! use pub_identity_client::{
//!     AuthenticationRequest, CodeVerifier, Expectations, IdToken, Nonce, ProviderMetadata, State,
//!     TokenResponse, well_known_url,
//! };
//!
//! # fn main() -> Result<(), pub_identity_client::Error> {
//! // 1. Discovery: fetch the configuration document and validate it for the issuer.
//! let issuer = "https://id.example.org";
//! assert_eq!(well_known_url(issuer), "https://id.example.org/.well-known/openid-configuration");
//! let document = br#"{"issuer":"https://id.example.org",
//!   "authorization_endpoint":"https://id.example.org/authorize",
//!   "token_endpoint":"https://id.example.org/token","jwks_uri":"https://id.example.org/jwks",
//!   "response_types_supported":["code"],"subject_types_supported":["public"],
//!   "id_token_signing_alg_values_supported":["RS256"],
//!   "code_challenge_methods_supported":["S256"]}"#;
//! let provider = ProviderMetadata::parse(issuer, document)?;
//!
//! // 2. The authentication request: PKCE verifier, state and nonce from octets the caller drew.
//! let verifier = CodeVerifier::from_octets(&[7u8; 32])?;
//! let request = AuthenticationRequest::new(
//!     &provider, "app-1", "https://app.example.org/cb", verifier,
//!     State::from_octets(&[1u8; 16]), Nonce::from_octets(&[2u8; 16]),
//! )?.scope("profile");
//! let url = request.url(); // send the user agent here
//! assert!(url.starts_with("https://id.example.org/authorize?response_type=code&client_id=app-1&"));
//! let pending = request.pending(); // keep this (it serializes) until the user comes back
//!
//! // 3. The authorization response: the redirect's query, checked for state and issuer.
//! let query = format!("code=SplxlOBeZQQYbYS6WxSbIA&state={}", pending.state());
//! let code = pending.parse_response(&query)?;
//!
//! // 4. The token request: POST the body to the endpoint, then read the answer.
//! let token_request = pending.token_request(&code);
//! assert_eq!(token_request.endpoint(), "https://id.example.org/token");
//! assert!(token_request.body().starts_with("grant_type=authorization_code&code="));
//! # let _ = TokenResponse::parse;
//! # let _ = IdToken::parse;
//!
//! // 5. The ID token of the token response, validated against what was sent, at the current time.
//! let now = 1_800_000_000;
//! let expectations: Expectations<'_> = pending.expectations(now);
//! assert_eq!(expectations.nonce_expected(), Some(pending.nonce().as_str()));
//! # Ok(()) }
//! ```

#![forbid(unsafe_code)]

mod authorize;
pub mod base64url;
mod discovery;
mod encoding;
mod error;
mod id_token;
mod pkce;
mod sha256;
mod token;

pub use authorize::{AuthenticationRequest, AuthorizationCode, Nonce, PendingAuthorization, State};
pub use discovery::{ProviderMetadata, well_known_url};
pub use error::{Error, ProviderError, Rejection};
pub use id_token::{Claims, Expectations, Header, IdToken};
pub use pkce::{CodeChallenge, CodeVerifier};
pub use token::{TokenRequest, TokenResponse};

/// The crate's name, as `CATALOG.toml` and crates.io know it.
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// The crate's version, as Cargo knows it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_follows_the_naming_rule() {
        assert_eq!(NAME, "pub-identity-client");
        assert!(NAME.starts_with("pub-identity-"));
    }

    #[test]
    fn version_is_semver_shaped() {
        assert_eq!(VERSION.split('.').count(), 3, "{VERSION}");
    }
}
