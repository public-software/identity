//! The token request (RFC 6749 §4.1.3, RFC 7636 §4.5) and the token response (RFC 6749 §5, OpenID
//! Connect Core 1.0 §3.1.3.3).

use std::fmt;

use serde::Deserialize;

use crate::encoding::build_query;
use crate::{Error, IdToken, ProviderError, Rejection};

/// A token request: the endpoint to `POST` to and the `application/x-www-form-urlencoded` body.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenRequest {
    endpoint: String,
    body: String,
}

impl TokenRequest {
    pub(crate) fn new(endpoint: &str, pairs: &[(&str, &str)]) -> Self {
        Self {
            endpoint: endpoint.to_owned(),
            body: build_query(pairs),
        }
    }

    /// The token endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The body: `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`,
    /// `code_verifier`.
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }

    /// The `Content-Type` of the body.
    #[must_use]
    pub const fn content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }
}

impl fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenRequest")
            .field("endpoint", &self.endpoint)
            .field("body", &"..")
            .finish()
    }
}

#[derive(Deserialize)]
struct RawTokenResponse {
    error: Option<String>,
    error_description: Option<String>,
    error_uri: Option<String>,
    access_token: Option<String>,
    token_type: Option<String>,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
    id_token: Option<String>,
}

/// A successful token response (RFC 6749 §5.1 with the `id_token` of Core §3.1.3.3). The access and
/// refresh tokens are credentials: `Debug` does not print them.
#[derive(Clone, PartialEq)]
pub struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
    id_token: IdToken,
}

impl TokenResponse {
    /// Parses the JSON body of the token endpoint's answer, success or error.
    ///
    /// # Errors
    ///
    /// The provider's [`ProviderError`] when the body is an error response (§5.2);
    /// [`Rejection::TokenType`] when `token_type` is not `Bearer` (case-insensitive);
    /// [`Error::Malformed`] (`token response`) when the body is not JSON or lacks `access_token`,
    /// `token_type` or `id_token`, and (`ID token`) when the ID token does not parse.
    pub fn parse(json: &[u8]) -> Result<Self, Error> {
        let malformed = |reason: String| Error::malformed("token response", reason);
        let raw: RawTokenResponse =
            serde_json::from_slice(json).map_err(|e| malformed(e.to_string()))?;
        if let Some(error) = raw.error {
            return Err(ProviderError {
                error,
                error_description: raw.error_description,
                error_uri: raw.error_uri,
            }
            .into());
        }
        let missing = |name: &str| malformed(format!("missing field `{name}`"));
        let access_token = raw.access_token.ok_or_else(|| missing("access_token"))?;
        let token_type = raw.token_type.ok_or_else(|| missing("token_type"))?;
        let id_token = raw.id_token.ok_or_else(|| missing("id_token"))?;
        if !token_type.eq_ignore_ascii_case("bearer") {
            return Err(Rejection::TokenType { found: token_type }.into());
        }
        Ok(Self {
            access_token,
            token_type,
            expires_in: raw.expires_in,
            refresh_token: raw.refresh_token,
            scope: raw.scope,
            id_token: IdToken::parse(&id_token)?,
        })
    }

    /// The access token, for the UserInfo endpoint and the APIs the scope covers.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// The token type as sent; always `Bearer` in some spelling.
    #[must_use]
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// The lifetime of the access token in seconds, when the provider said.
    #[must_use]
    pub const fn expires_in(&self) -> Option<u64> {
        self.expires_in
    }

    /// The refresh token, when the provider issued one.
    #[must_use]
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    /// The scope granted, when it differs from the one requested (§5.1).
    #[must_use]
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    /// The ID token, parsed and not yet validated: see [`IdToken::validate_claims`].
    #[must_use]
    pub const fn id_token(&self) -> &IdToken {
        &self.id_token
    }
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"..")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| ".."))
            .field("scope", &self.scope)
            .field("id_token", &self.id_token)
            .finish()
    }
}
