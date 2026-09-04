//! OpenID Connect Discovery 1.0: the well-known location of the provider's configuration (§4) and
//! the OpenID Provider Metadata document (§3), validated per §4.3.

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::{Error, Rejection};

/// The URL of the provider's configuration document (§4): `/.well-known/openid-configuration`
/// appended to the issuer, one trailing slash of the issuer removed first.
///
/// ```
/// use pub_identity_client::well_known_url;
/// assert_eq!(well_known_url("https://example.com/issuer1/"),
///            "https://example.com/issuer1/.well-known/openid-configuration");
/// ```
#[must_use]
pub fn well_known_url(issuer: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.strip_suffix('/').unwrap_or(issuer)
    )
}

/// The OpenID Provider Metadata (§3) as the provider published it, validated: the required members
/// present, the issuer an `https` URL without query or fragment, and identical to the one the
/// document was fetched for (§4.3). Members the specification does not name are kept and reachable
/// through [`ProviderMetadata::get`].
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ProviderMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    jwks_uri: String,
    registration_endpoint: Option<String>,
    scopes_supported: Option<Vec<String>>,
    response_types_supported: Vec<String>,
    response_modes_supported: Option<Vec<String>>,
    grant_types_supported: Option<Vec<String>>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
    claims_supported: Option<Vec<String>>,
    /// RFC 8414 §2; absent means the provider says nothing about PKCE.
    code_challenge_methods_supported: Option<Vec<String>>,
    /// RFC 9207 §3; absent means `false`.
    #[serde(default)]
    authorization_response_iss_parameter_supported: bool,
    #[serde(flatten)]
    other: Map<String, Value>,
}

impl ProviderMetadata {
    /// Parses the configuration document fetched from [`well_known_url`]`(issuer)`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] (`provider metadata`) when the bytes are not a JSON object with the
    /// required members of §3; [`Rejection::IssuerForm`] when the issuer is not an `https` URL
    /// without query or fragment; [`Rejection::Issuer`] when it is not `issuer` byte for byte (§4.3).
    pub fn parse(issuer: &str, json: &[u8]) -> Result<Self, Error> {
        let metadata: Self = serde_json::from_slice(json)
            .map_err(|e| Error::malformed("provider metadata", e.to_string()))?;
        let found = &metadata.issuer;
        let host = found.strip_prefix("https://").unwrap_or("");
        if host.is_empty() || host.starts_with('/') || found.contains('?') || found.contains('#') {
            return Err(Rejection::IssuerForm {
                issuer: found.clone(),
            }
            .into());
        }
        if found != issuer {
            return Err(Rejection::Issuer {
                expected: issuer.to_owned(),
                found: found.clone(),
            }
            .into());
        }
        Ok(metadata)
    }

    /// The issuer identifier, the `iss` every ID token of this provider carries.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The authorization endpoint.
    #[must_use]
    pub fn authorization_endpoint(&self) -> &str {
        &self.authorization_endpoint
    }

    /// The token endpoint; a provider that only supports the implicit flow has none.
    #[must_use]
    pub fn token_endpoint(&self) -> Option<&str> {
        self.token_endpoint.as_deref()
    }

    /// The UserInfo endpoint, when the provider has one.
    #[must_use]
    pub fn userinfo_endpoint(&self) -> Option<&str> {
        self.userinfo_endpoint.as_deref()
    }

    /// The JWK Set document with the keys that sign the ID tokens.
    #[must_use]
    pub fn jwks_uri(&self) -> &str {
        &self.jwks_uri
    }

    /// The dynamic client registration endpoint, when the provider has one.
    #[must_use]
    pub fn registration_endpoint(&self) -> Option<&str> {
        self.registration_endpoint.as_deref()
    }

    /// The scope values the provider supports, when it lists them.
    #[must_use]
    pub fn scopes_supported(&self) -> Option<&[String]> {
        self.scopes_supported.as_deref()
    }

    /// The `response_type` values the provider supports.
    #[must_use]
    pub fn response_types_supported(&self) -> &[String] {
        &self.response_types_supported
    }

    /// The `response_mode` values the provider supports, when it lists them.
    #[must_use]
    pub fn response_modes_supported(&self) -> Option<&[String]> {
        self.response_modes_supported.as_deref()
    }

    /// The grant types the provider supports, when it lists them.
    #[must_use]
    pub fn grant_types_supported(&self) -> Option<&[String]> {
        self.grant_types_supported.as_deref()
    }

    /// The subject identifier types the provider supports (`public`, `pairwise`).
    #[must_use]
    pub fn subject_types_supported(&self) -> &[String] {
        &self.subject_types_supported
    }

    /// The JWS algorithms the provider signs ID tokens with.
    #[must_use]
    pub fn id_token_signing_alg_values_supported(&self) -> &[String] {
        &self.id_token_signing_alg_values_supported
    }

    /// The client authentication methods of the token endpoint, when listed; absent means
    /// `client_secret_basic`.
    #[must_use]
    pub fn token_endpoint_auth_methods_supported(&self) -> Option<&[String]> {
        self.token_endpoint_auth_methods_supported.as_deref()
    }

    /// The claim names the provider may supply, when it lists them.
    #[must_use]
    pub fn claims_supported(&self) -> Option<&[String]> {
        self.claims_supported.as_deref()
    }

    /// The PKCE code challenge methods the provider supports (RFC 8414), when it lists them.
    #[must_use]
    pub fn code_challenge_methods_supported(&self) -> Option<&[String]> {
        self.code_challenge_methods_supported.as_deref()
    }

    /// Whether the provider puts `iss` into its authorization responses (RFC 9207 §3). When it does,
    /// a response without one is refused.
    #[must_use]
    pub const fn authorization_response_iss_parameter_supported(&self) -> bool {
        self.authorization_response_iss_parameter_supported
    }

    /// Whether the authorization code flow with PKCE `S256` can be run against this provider: a token
    /// endpoint, `code` among the response types, and `S256` among the code challenge methods when
    /// the provider lists any.
    #[must_use]
    pub fn supports_code_flow_with_pkce(&self) -> bool {
        self.code_flow_with_pkce_check().is_ok()
    }

    pub(crate) fn code_flow_with_pkce_check(&self) -> Result<&str, Rejection> {
        let token_endpoint = self
            .token_endpoint
            .as_deref()
            .ok_or(Rejection::Unsupported {
                feature: "token_endpoint",
                supported: Vec::new(),
            })?;
        if !self.response_types_supported.iter().any(|t| t == "code") {
            return Err(Rejection::Unsupported {
                feature: "response_type code",
                supported: self.response_types_supported.clone(),
            });
        }
        if let Some(methods) = &self.code_challenge_methods_supported
            && !methods.iter().any(|m| m == "S256")
        {
            return Err(Rejection::Unsupported {
                feature: "code_challenge_method S256",
                supported: methods.clone(),
            });
        }
        Ok(token_endpoint)
    }

    /// Any member of the document by name, the ones above included.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Value> {
        match name {
            "issuer" => Some(Value::String(self.issuer.clone())),
            "authorization_endpoint" => Some(Value::String(self.authorization_endpoint.clone())),
            "token_endpoint" => self.token_endpoint.clone().map(Value::String),
            "userinfo_endpoint" => self.userinfo_endpoint.clone().map(Value::String),
            "jwks_uri" => Some(Value::String(self.jwks_uri.clone())),
            "registration_endpoint" => self.registration_endpoint.clone().map(Value::String),
            "scopes_supported" => self.scopes_supported.as_deref().map(strings),
            "response_types_supported" => Some(strings(&self.response_types_supported)),
            "response_modes_supported" => self.response_modes_supported.as_deref().map(strings),
            "grant_types_supported" => self.grant_types_supported.as_deref().map(strings),
            "subject_types_supported" => Some(strings(&self.subject_types_supported)),
            "id_token_signing_alg_values_supported" => {
                Some(strings(&self.id_token_signing_alg_values_supported))
            }
            "token_endpoint_auth_methods_supported" => self
                .token_endpoint_auth_methods_supported
                .as_deref()
                .map(strings),
            "claims_supported" => self.claims_supported.as_deref().map(strings),
            "code_challenge_methods_supported" => self
                .code_challenge_methods_supported
                .as_deref()
                .map(strings),
            "authorization_response_iss_parameter_supported" => Some(Value::Bool(
                self.authorization_response_iss_parameter_supported,
            )),
            other => self.other.get(other).cloned(),
        }
    }
}

fn strings(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"{"issuer":"https://op.example","authorization_endpoint":"https://op.example/a",
        "jwks_uri":"https://op.example/jwks","response_types_supported":["code"],
        "subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],
        "vendor_flag":true}"#;

    #[test]
    fn unknown_members_are_reachable_by_name() {
        let metadata = ProviderMetadata::parse("https://op.example", MINIMAL.as_bytes()).unwrap();
        assert_eq!(metadata.get("vendor_flag"), Some(Value::Bool(true)));
        assert_eq!(
            metadata.get("issuer"),
            Some(Value::String("https://op.example".into()))
        );
        assert_eq!(metadata.get("token_endpoint"), None);
        assert_eq!(metadata.get("nothing"), None);
        assert_eq!(
            metadata.get("response_types_supported"),
            Some(serde_json::json!(["code"]))
        );
        assert_eq!(
            metadata.get("authorization_response_iss_parameter_supported"),
            Some(Value::Bool(false))
        );
    }

    #[test]
    fn issuer_form_rejects_a_bare_scheme() {
        for issuer in ["https://", "https:///path"] {
            let json = format!(
                r#"{{"issuer":"{issuer}","authorization_endpoint":"https://op.example/a",
                "jwks_uri":"https://op.example/jwks","response_types_supported":["code"],
                "subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}}"#
            );
            let error = ProviderMetadata::parse(issuer, json.as_bytes()).unwrap_err();
            assert!(
                matches!(error, Error::Rejected(Rejection::IssuerForm { .. })),
                "{issuer}: {error}"
            );
        }
    }
}
