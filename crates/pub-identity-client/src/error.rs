//! What can go wrong: bytes of the wrong shape, a rule the specification requires that failed, or the
//! provider answering with an error of its own.

use std::fmt;

use serde::{Deserialize, Serialize};

/// An error of the client core.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The bytes do not have the shape the specification gives them. `what` names the document or
    /// value (`provider metadata`, `token response`, `ID token`, `code verifier`, …), `reason` says
    /// what is wrong with it.
    Malformed {
        /// The document or value that is malformed.
        what: &'static str,
        /// What is wrong with it.
        reason: String,
    },
    /// A check the specification requires failed; the [`Rejection`] names the rule.
    Rejected(Rejection),
    /// The provider answered with an error response instead of a code or a token.
    Provider(ProviderError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { what, reason } => write!(f, "malformed {what}: {reason}"),
            Self::Rejected(rejection) => rejection.fmt(f),
            Self::Provider(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

impl From<Rejection> for Error {
    fn from(rejection: Rejection) -> Self {
        Self::Rejected(rejection)
    }
}

impl From<ProviderError> for Error {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

impl Error {
    pub(crate) fn malformed(what: &'static str, reason: impl Into<String>) -> Self {
        Self::Malformed {
            what,
            reason: reason.into(),
        }
    }
}

/// An error response of the provider: the authorization endpoint's (RFC 6749 §4.1.2.1 and
/// OpenID Connect Core 1.0 §3.1.2.6) or the token endpoint's (RFC 6749 §5.2).
///
/// `error` is one of the codes those sections define (`invalid_request`, `unauthorized_client`,
/// `access_denied`, `unsupported_response_type`, `invalid_scope`, `server_error`,
/// `temporarily_unavailable`, `interaction_required`, `login_required`, `account_selection_required`,
/// `consent_required`, `invalid_request_uri`, `invalid_request_object`, `request_not_supported`,
/// `request_uri_not_supported`, `registration_not_supported`, `invalid_client`, `invalid_grant`,
/// `unsupported_grant_type`) or a code an extension defines; the text is kept as the provider sent it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderError {
    /// The error code.
    pub error: String,
    /// Human-readable ASCII text meant for the developer, when the provider sent one.
    pub error_description: Option<String>,
    /// A page with information about the error, when the provider sent one.
    pub error_uri: Option<String>,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.error)?;
        if let Some(description) = &self.error_description {
            write!(f, ": {description}")?;
        }
        if let Some(uri) = &self.error_uri {
            write!(f, " ({uri})")?;
        }
        Ok(())
    }
}

impl std::error::Error for ProviderError {}

/// A rule the specification requires that the input failed. Every variant's text names the section.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rejection {
    /// OpenID Connect Discovery 1.0 §3: the issuer is not an `https` URL without query or fragment.
    IssuerForm {
        /// The issuer as the document states it.
        issuer: String,
    },
    /// The issuer is not the one expected: OpenID Connect Discovery 1.0 §4.3 (the document's `issuer`
    /// against the one the document was fetched for), OpenID Connect Core 1.0 §3.1.3.7 rule 2 (the ID
    /// token's `iss`), RFC 9207 §2.4 (the authorization response's `iss`).
    Issuer {
        /// The issuer expected.
        expected: String,
        /// The issuer found.
        found: String,
    },
    /// RFC 9207 §2.4: the provider announces `authorization_response_iss_parameter_supported` and the
    /// authorization response carries no `iss`.
    IssuerMissing,
    /// RFC 6749 §10.12: the authorization response's `state` is not the one sent.
    State {
        /// The state sent with the authentication request.
        expected: String,
        /// The state in the response, when there was one.
        found: Option<String>,
    },
    /// The provider metadata does not offer what the authorization code flow with PKCE needs.
    Unsupported {
        /// What is missing: `token_endpoint`, `response_type code` or `code_challenge_method S256`.
        feature: &'static str,
        /// What the provider offers instead.
        supported: Vec<String>,
    },
    /// OpenID Connect Core 1.0 §3.1.3.3: the token response's `token_type` is not `Bearer`.
    TokenType {
        /// The token type found.
        found: String,
    },
    /// OpenID Connect Core 1.0 §3.1.3.7 rule 3: the ID token's `aud` does not contain the client.
    Audience {
        /// The client id expected in the audience.
        client_id: String,
        /// The audience found.
        audience: Vec<String>,
    },
    /// OpenID Connect Core 1.0 §3.1.3.7 rules 4 and 5: `aud` has several values and there is no `azp`,
    /// or `azp` is present and is not the client.
    AuthorizedParty {
        /// The client id expected as the authorized party.
        client_id: String,
        /// The `azp` found, when there was one.
        azp: Option<String>,
    },
    /// OpenID Connect Core 1.0 §3.1.3.7 rule 7: the ID token's `alg` is `none` or not one expected.
    Algorithm {
        /// The algorithm in the header.
        alg: String,
        /// The algorithms expected.
        expected: Vec<String>,
    },
    /// OpenID Connect Core 1.0 §3.1.3.7 rule 9: the current time is not before `exp`.
    Expired {
        /// The `exp` claim, in seconds since the epoch.
        exp: u64,
        /// The current time the caller passed, in seconds since the epoch.
        now: u64,
    },
    /// OpenID Connect Core 1.0 §3.1.3.7 rule 10: `iat` is too far from the current time.
    IssuedAt {
        /// The `iat` claim.
        iat: u64,
        /// The current time the caller passed.
        now: u64,
        /// The largest distance accepted, in seconds.
        skew: u64,
    },
    /// OpenID Connect Core 1.0 §3.1.3.7 rule 11: a nonce was sent and the ID token's `nonce` is not it.
    Nonce {
        /// The nonce sent with the authentication request.
        expected: String,
        /// The nonce in the ID token, when there was one.
        found: Option<String>,
    },
    /// OpenID Connect Core 1.0 §3.1.3.7 rule 13: `max_age` was requested and `auth_time` is missing or
    /// older than that.
    AuthTime {
        /// The `max_age` requested, in seconds.
        max_age: u64,
        /// The `auth_time` claim, when there was one.
        auth_time: Option<u64>,
        /// The current time the caller passed.
        now: u64,
    },
}

const CORE: &str = "OpenID Connect Core 1.0 §3.1.3.7";

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IssuerForm { issuer } => write!(
                f,
                "OpenID Connect Discovery 1.0 §3: the issuer `{issuer}` is not an https URL without query or fragment"
            ),
            Self::Issuer { expected, found } => write!(
                f,
                "OpenID Connect Discovery 1.0 §4.3, {CORE} rule 2, RFC 9207 §2.4: the issuer is `{found}`, expected `{expected}`"
            ),
            Self::IssuerMissing => write!(
                f,
                "RFC 9207 §2.4: the provider announces the iss parameter and the authorization response has none"
            ),
            Self::State { expected, found } => match found {
                Some(found) => write!(
                    f,
                    "RFC 6749 §10.12: the state is `{found}`, expected `{expected}`"
                ),
                None => write!(
                    f,
                    "RFC 6749 §10.12: the authorization response has no state, expected `{expected}`"
                ),
            },
            Self::Unsupported { feature, supported } => write!(
                f,
                "the provider does not support {feature} (supported: {})",
                supported.join(", ")
            ),
            Self::TokenType { found } => {
                write!(
                    f,
                    "OpenID Connect Core 1.0 §3.1.3.3: token_type is `{found}`, not Bearer"
                )
            }
            Self::Audience {
                client_id,
                audience,
            } => write!(
                f,
                "{CORE} rule 3: the audience [{}] does not contain the client `{client_id}`",
                audience.join(", ")
            ),
            Self::AuthorizedParty { client_id, azp } => match azp {
                Some(azp) => write!(
                    f,
                    "{CORE} rule 5: the authorized party is `{azp}`, not the client `{client_id}`"
                ),
                None => write!(
                    f,
                    "{CORE} rule 4: the audience has several values and no azp names the client `{client_id}`"
                ),
            },
            Self::Algorithm { alg, expected } => write!(
                f,
                "{CORE} rule 7: the ID token is signed with `{alg}`, expected one of [{}]",
                expected.join(", ")
            ),
            Self::Expired { exp, now } => write!(
                f,
                "{CORE} rule 9: the ID token expired at {exp}, now is {now}"
            ),
            Self::IssuedAt { iat, now, skew } => write!(
                f,
                "{CORE} rule 10: the ID token was issued at {iat}, more than {skew} seconds from now ({now})"
            ),
            Self::Nonce { expected, found } => match found {
                Some(found) => write!(
                    f,
                    "{CORE} rule 11: the nonce is `{found}`, expected `{expected}`"
                ),
                None => write!(
                    f,
                    "{CORE} rule 11: the ID token has no nonce, expected `{expected}`"
                ),
            },
            Self::AuthTime {
                max_age,
                auth_time,
                now,
            } => match auth_time {
                Some(auth_time) => write!(
                    f,
                    "{CORE} rule 13: the authentication at {auth_time} is older than max_age {max_age} seconds (now {now})"
                ),
                None => write!(
                    f,
                    "{CORE} rule 13: max_age {max_age} was requested and the ID token has no auth_time"
                ),
            },
        }
    }
}

impl std::error::Error for Rejection {}
