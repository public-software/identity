//! The authentication request (OpenID Connect Core 1.0 §3.1.2.1, RFC 7636 §4.3), the state the
//! client keeps while the user is at the provider, and the authorization response (RFC 6749 §4.1.2,
//! RFC 9207).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::encoding::{build_query, parse_query};
use crate::{
    CodeVerifier, Error, Expectations, ProviderError, ProviderMetadata, Rejection, TokenRequest,
    base64url,
};

macro_rules! opaque_value {
    ($(#[$doc:meta])* $name:ident, $what:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// The base64url encoding of `octets` the caller drew at random (16 octets are plenty).
            #[must_use]
            pub fn from_octets(octets: &[u8]) -> Self {
                Self(base64url::encode(octets))
            }

            /// A value the caller chose or stored: printable ASCII without spaces, not empty.
            ///
            /// # Errors
            ///
            /// [`Error::Malformed`] otherwise.
            pub fn parse(text: &str) -> Result<Self, Error> {
                if text.is_empty() {
                    return Err(Error::malformed($what, "empty"));
                }
                if let Some(bad) = text.chars().find(|c| !c.is_ascii_graphic()) {
                    return Err(Error::malformed($what, format!("`{}` is not printable ASCII", bad.escape_default())));
                }
                Ok(Self(text.to_owned()))
            }

            /// The value as text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = Error;

            fn try_from(text: String) -> Result<Self, Self::Error> {
                Self::parse(&text)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

opaque_value!(
    /// The `state` parameter (RFC 6749 §4.1.1, §10.12): an opaque value that binds the authorization
    /// response to the request that caused it. Unguessable, one per request.
    State,
    "state"
);

opaque_value!(
    /// The `nonce` parameter (OpenID Connect Core 1.0 §3.1.2.1, §15.5.2): an opaque value that binds
    /// the ID token to the client session. Unguessable, one per request.
    Nonce,
    "nonce"
);

/// An authentication request for the authorization code flow with PKCE, ready to be turned into the
/// URL the user agent is sent to ([`AuthenticationRequest::url`]) and into the state the client keeps
/// meanwhile ([`AuthenticationRequest::pending`]).
#[derive(Debug, Clone)]
pub struct AuthenticationRequest {
    authorization_endpoint: String,
    pending: PendingAuthorization,
    scopes: Vec<String>,
    parameters: Vec<(String, String)>,
}

impl AuthenticationRequest {
    /// A request to `provider` for `client_id`, redirecting to `redirect_uri` (registered with the
    /// provider, matched exactly), with the given PKCE verifier, state and nonce. The scope is `openid`
    /// until [`AuthenticationRequest::scope`] adds more.
    ///
    /// # Errors
    ///
    /// [`Rejection::Unsupported`] when the provider has no token endpoint, does not support the `code`
    /// response type, or lists code challenge methods without `S256`.
    pub fn new(
        provider: &ProviderMetadata,
        client_id: &str,
        redirect_uri: &str,
        code_verifier: CodeVerifier,
        state: State,
        nonce: Nonce,
    ) -> Result<Self, Error> {
        let token_endpoint = provider.code_flow_with_pkce_check()?;
        Ok(Self {
            authorization_endpoint: provider.authorization_endpoint().to_owned(),
            pending: PendingAuthorization {
                issuer: provider.issuer().to_owned(),
                iss_announced: provider.authorization_response_iss_parameter_supported(),
                token_endpoint: token_endpoint.to_owned(),
                client_id: client_id.to_owned(),
                redirect_uri: redirect_uri.to_owned(),
                state,
                nonce,
                code_verifier,
                max_age: None,
            },
            scopes: vec!["openid".to_owned()],
            parameters: Vec::new(),
        })
    }

    /// Adds a scope value (`profile`, `email`, `offline_access`, …); `openid` is always first and a
    /// value is added once.
    #[must_use]
    pub fn scope(mut self, scope: &str) -> Self {
        if !self.scopes.iter().any(|s| s == scope) {
            self.scopes.push(scope.to_owned());
        }
        self
    }

    /// Asks that the user authenticated at most `seconds` ago (`max_age`, Core §3.1.2.1); the ID
    /// token then must carry `auth_time` and the pending authorization's expectations check it
    /// (§3.1.3.7 rule 13).
    #[must_use]
    pub const fn max_age(mut self, seconds: u64) -> Self {
        self.pending.max_age = Some(seconds);
        self
    }

    /// Adds any other parameter of Core §3.1.2.1 (`prompt`, `login_hint`, `display`, `ui_locales`,
    /// `acr_values`, `id_token_hint`, …), sent as given.
    #[must_use]
    pub fn parameter(mut self, name: &str, value: &str) -> Self {
        self.parameters.push((name.to_owned(), value.to_owned()));
        self
    }

    /// The URL to send the user agent to: the authorization endpoint with `response_type=code`,
    /// `client_id`, `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`,
    /// `code_challenge_method=S256`, then `max_age` and the other parameters, all percent-encoded.
    #[must_use]
    pub fn url(&self) -> String {
        let pending = &self.pending;
        let challenge = pending.code_verifier.challenge();
        let scope = self.scopes.join(" ");
        let max_age = pending.max_age.map(|s| s.to_string());
        let mut pairs: Vec<(&str, &str)> = vec![
            ("response_type", "code"),
            ("client_id", &pending.client_id),
            ("redirect_uri", &pending.redirect_uri),
            ("scope", &scope),
            ("state", pending.state.as_str()),
            ("nonce", pending.nonce.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", challenge.method()),
        ];
        if let Some(max_age) = &max_age {
            pairs.push(("max_age", max_age));
        }
        pairs.extend(
            self.parameters
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_str())),
        );
        let separator = if self.authorization_endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        format!(
            "{}{separator}{}",
            self.authorization_endpoint,
            build_query(&pairs)
        )
    }

    /// What the client keeps while the user is at the provider.
    #[must_use]
    pub fn pending(self) -> PendingAuthorization {
        self.pending
    }
}

/// The state of one authentication request between the redirect to the provider and the token
/// response: what the authorization response is checked against and what the token request needs.
/// Serializable, so a web application can keep it in its session store; it holds the code verifier,
/// which `Debug` does not print.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingAuthorization {
    issuer: String,
    iss_announced: bool,
    token_endpoint: String,
    client_id: String,
    redirect_uri: String,
    state: State,
    nonce: Nonce,
    code_verifier: CodeVerifier,
    max_age: Option<u64>,
}

impl PendingAuthorization {
    /// The issuer the request went to.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The client id of the request.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The redirect URI of the request.
    #[must_use]
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// The state sent.
    #[must_use]
    pub const fn state(&self) -> &State {
        &self.state
    }

    /// The nonce sent.
    #[must_use]
    pub const fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// The code verifier the token request will carry.
    #[must_use]
    pub const fn code_verifier(&self) -> &CodeVerifier {
        &self.code_verifier
    }

    /// The `max_age` requested, when one was.
    #[must_use]
    pub const fn max_age(&self) -> Option<u64> {
        self.max_age
    }

    /// Reads the authorization response the user agent came back with: the query string of the
    /// redirect, or the whole redirect URL (its fragment ignored). In order: the `state` must be the
    /// one sent; `iss`, when present, must be the issuer and is required when the provider announces
    /// it (RFC 9207); an `error` becomes [`Error::Provider`]; the `code` is returned.
    ///
    /// # Errors
    ///
    /// [`Rejection::State`], [`Rejection::Issuer`], [`Rejection::IssuerMissing`], the provider's
    /// [`ProviderError`], or [`Error::Malformed`] (`authorization response`) when the query does not
    /// parse or carries neither `code` nor `error`.
    pub fn parse_response(&self, response: &str) -> Result<AuthorizationCode, Error> {
        let query = response
            .split_once('?')
            .map_or(response, |(_, query)| query);
        let query = query.split_once('#').map_or(query, |(query, _)| query);
        let pairs = parse_query(query)
            .map_err(|reason| Error::malformed("authorization response", reason))?;
        let get = |name: &str| {
            pairs
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };

        match get("state") {
            Some(found) if found == self.state.as_str() => {}
            found => {
                return Err(Rejection::State {
                    expected: self.state.as_str().to_owned(),
                    found: found.map(str::to_owned),
                }
                .into());
            }
        }
        match get("iss") {
            Some(found) if found == self.issuer => {}
            Some(found) => {
                return Err(Rejection::Issuer {
                    expected: self.issuer.clone(),
                    found: found.to_owned(),
                }
                .into());
            }
            None if self.iss_announced => return Err(Rejection::IssuerMissing.into()),
            None => {}
        }
        if let Some(error) = get("error") {
            return Err(ProviderError {
                error: error.to_owned(),
                error_description: get("error_description").map(str::to_owned),
                error_uri: get("error_uri").map(str::to_owned),
            }
            .into());
        }
        match get("code") {
            Some(code) if !code.is_empty() => Ok(AuthorizationCode(code.to_owned())),
            _ => Err(Error::malformed(
                "authorization response",
                "neither a code nor an error",
            )),
        }
    }

    /// The token request that redeems `code` (RFC 6749 §4.1.3 with the RFC 7636 §4.5 verifier), for
    /// the provider's token endpoint. A confidential client adds its own authentication (an
    /// `Authorization` header for `client_secret_basic`) when sending it.
    #[must_use]
    pub fn token_request(&self, code: &AuthorizationCode) -> TokenRequest {
        TokenRequest::new(
            &self.token_endpoint,
            &[
                ("grant_type", "authorization_code"),
                ("code", &code.0),
                ("redirect_uri", &self.redirect_uri),
                ("client_id", &self.client_id),
                ("code_verifier", self.code_verifier.as_str()),
            ],
        )
    }

    /// What the ID token of the token response must satisfy, given the current time `now` in seconds
    /// since the epoch: this issuer, this client, the nonce sent, and `max_age` when it was requested.
    /// The skew and the algorithms are the defaults of [`Expectations::new`].
    #[must_use]
    pub fn expectations(&self, now: u64) -> Expectations<'_> {
        let expectations =
            Expectations::new(&self.issuer, &self.client_id, now).nonce(self.nonce.as_str());
        match self.max_age {
            Some(max_age) => expectations.max_age(max_age),
            None => expectations,
        }
    }
}

/// An authorization code (RFC 6749 §4.1.2): single use, short-lived, redeemed at the token endpoint.
/// `Debug` does not print it.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationCode(String);

impl AuthorizationCode {
    /// The code as the provider issued it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AuthorizationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizationCode(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_values_refuse_what_is_not_printable_ascii() {
        assert!(State::parse("tab\there").is_err());
        assert!(Nonce::parse("é").is_err());
        assert_eq!(State::from_octets(&[1, 2, 3, 4]).to_string(), "AQIDBA");
        assert_eq!(
            serde_json::from_str::<State>("\"abc\"").unwrap().as_str(),
            "abc"
        );
        assert!(serde_json::from_str::<State>("\"\"").is_err());
    }

    #[test]
    fn codes_and_pending_state_do_not_print_secrets() {
        let code = AuthorizationCode("secret".into());
        assert_eq!(format!("{code:?}"), "AuthorizationCode(..)");
        let pending = PendingAuthorization {
            issuer: "https://op.example".into(),
            iss_announced: false,
            token_endpoint: "https://op.example/token".into(),
            client_id: "c".into(),
            redirect_uri: "https://app.example/cb".into(),
            state: State::parse("s").unwrap(),
            nonce: Nonce::parse("n").unwrap(),
            code_verifier: "v".repeat(43).parse().unwrap(),
            max_age: None,
        };
        let debug = format!("{pending:?}");
        assert!(debug.contains("CodeVerifier(..)"), "{debug}");
        assert!(!debug.contains(&"v".repeat(43)), "{debug}");
        let json = serde_json::to_string(&pending).unwrap();
        assert_eq!(
            serde_json::from_str::<PendingAuthorization>(&json).unwrap(),
            pending
        );
    }

    #[test]
    fn an_endpoint_with_a_query_is_joined_with_an_ampersand() {
        let json = r#"{"issuer":"https://op.example","authorization_endpoint":"https://op.example/a?tenant=1",
            "token_endpoint":"https://op.example/t","jwks_uri":"https://op.example/jwks",
            "response_types_supported":["code"],"subject_types_supported":["public"],
            "id_token_signing_alg_values_supported":["RS256"]}"#;
        let provider = ProviderMetadata::parse("https://op.example", json.as_bytes()).unwrap();
        let request = AuthenticationRequest::new(
            &provider,
            "c",
            "https://app.example/cb",
            "v".repeat(43).parse().unwrap(),
            State::parse("s").unwrap(),
            Nonce::parse("n").unwrap(),
        )
        .unwrap();
        assert!(
            request
                .url()
                .starts_with("https://op.example/a?tenant=1&response_type=code&"),
            "{}",
            request.url()
        );
    }
}
