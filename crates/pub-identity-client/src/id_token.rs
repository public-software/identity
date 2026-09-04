//! The ID token (OpenID Connect Core 1.0 §2) in the JWS compact serialization (RFC 7515 §3.1), its
//! claims, and their validation (§3.1.3.7).

use std::fmt;

use serde_json::{Map, Value};

use crate::{Error, Rejection, base64url};

/// The JOSE header of the ID token (RFC 7515 §4): the algorithm, the key id and the type, plus any
/// other member by name.
#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    alg: String,
    kid: Option<String>,
    typ: Option<String>,
    all: Map<String, Value>,
}

impl Header {
    /// The `alg` the token is signed with (RFC 7518 §3.1: `RS256`, `ES256`, …, or `none`).
    #[must_use]
    pub fn alg(&self) -> &str {
        &self.alg
    }

    /// The `kid` of the signing key, when the header names one.
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The `typ`, when present (`JWT`).
    #[must_use]
    pub fn typ(&self) -> Option<&str> {
        self.typ.as_deref()
    }

    /// Any header member by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.all.get(name)
    }
}

/// The claims of an ID token (Core §2): the required `iss`, `sub`, `aud`, `exp`, `iat`; the
/// conditional `auth_time`, `nonce`, `azp`; the optional `acr`, `amr`; and every other claim by name.
#[derive(Debug, Clone, PartialEq)]
pub struct Claims {
    iss: String,
    sub: String,
    aud: Vec<String>,
    exp: u64,
    iat: u64,
    auth_time: Option<u64>,
    nonce: Option<String>,
    acr: Option<String>,
    amr: Option<Vec<String>>,
    azp: Option<String>,
    all: Map<String, Value>,
}

impl Claims {
    /// The issuer identifier (`iss`).
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.iss
    }

    /// The subject identifier (`sub`): the user, unique at this issuer, never reassigned.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.sub
    }

    /// The audience (`aud`): one or more client ids.
    #[must_use]
    pub fn audience(&self) -> &[String] {
        &self.aud
    }

    /// The expiration time (`exp`), seconds since the epoch.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.exp
    }

    /// The time of issue (`iat`), seconds since the epoch.
    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.iat
    }

    /// The time the user authenticated (`auth_time`), when present.
    #[must_use]
    pub const fn auth_time(&self) -> Option<u64> {
        self.auth_time
    }

    /// The `nonce`, when present.
    #[must_use]
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    /// The Authentication Context Class Reference (`acr`), when present.
    #[must_use]
    pub fn acr(&self) -> Option<&str> {
        self.acr.as_deref()
    }

    /// The Authentication Methods References (`amr`), when present.
    #[must_use]
    pub fn amr(&self) -> Option<&[String]> {
        self.amr.as_deref()
    }

    /// The authorized party (`azp`), when present.
    #[must_use]
    pub fn authorized_party(&self) -> Option<&str> {
        self.azp.as_deref()
    }

    /// Any claim by name, the registered ones included: `email`, `name`, `preferred_username`, …
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.all.get(name)
    }
}

/// An ID token as received: parsed, its signature not verified here. [`IdToken::signing_input`] and
/// [`IdToken::signature`] are what a verifier checks with the key [`Header::kid`] names from the
/// provider's JWK Set; a client that received the token straight from the token endpoint over TLS may
/// rely on the TLS server validation instead (Core §3.1.3.7 rule 6). Either way,
/// [`IdToken::validate_claims`] checks the claims.
#[derive(Clone, PartialEq)]
pub struct IdToken {
    compact: String,
    signing_input_len: usize,
    header: Header,
    claims: Claims,
    signature: Vec<u8>,
}

impl IdToken {
    /// Parses the compact serialization `header.payload.signature`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] (`ID token`) when the segments are not three, not base64url, not JSON
    /// objects, when the header has no `alg`, or when a required claim is missing or of the wrong
    /// type.
    pub fn parse(compact: &str) -> Result<Self, Error> {
        let malformed = |reason: String| Error::malformed("ID token", reason);
        let segments: Vec<&str> = compact.split('.').collect();
        let [header, payload, signature] = segments[..] else {
            return Err(malformed(format!("{} segments, not three", segments.len())));
        };
        let header = object("header", header)?;
        let claims = object("payload", payload)?;
        let signature = segment("signature", signature)?;
        let header = Header {
            alg: string(&header, "alg", "header")?
                .ok_or_else(|| malformed("the header has no alg".into()))?,
            kid: string(&header, "kid", "header")?,
            typ: string(&header, "typ", "header")?,
            all: header,
        };
        let claims = Claims {
            iss: required("iss", string(&claims, "iss", "claim")?)?,
            sub: required("sub", string(&claims, "sub", "claim")?)?,
            aud: required("aud", strings(&claims, "aud")?)?,
            exp: required("exp", time(&claims, "exp")?)?,
            iat: required("iat", time(&claims, "iat")?)?,
            auth_time: time(&claims, "auth_time")?,
            nonce: string(&claims, "nonce", "claim")?,
            acr: string(&claims, "acr", "claim")?,
            amr: strings(&claims, "amr")?,
            azp: string(&claims, "azp", "claim")?,
            all: claims,
        };
        Ok(Self {
            signing_input_len: compact.len() - signature_len(compact),
            compact: compact.to_owned(),
            header,
            claims,
            signature,
        })
    }

    /// The token as received.
    #[must_use]
    pub fn compact(&self) -> &str {
        &self.compact
    }

    /// The header.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// The claims, as parsed; [`IdToken::validate_claims`] checks them.
    #[must_use]
    pub const fn claims(&self) -> &Claims {
        &self.claims
    }

    /// The JWS signing input (RFC 7515 §5.1): `header.payload` as the ASCII bytes a verifier hashes.
    #[must_use]
    pub fn signing_input(&self) -> &[u8] {
        &self.compact.as_bytes()[..self.signing_input_len]
    }

    /// The signature bytes, decoded.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Validates the claims against `expectations` (Core §3.1.3.7): rule 7 (the `alg` is one expected
    /// and never `none`), rule 2 (`iss`), rule 3 (`aud` contains the client), rules 4 and 5 (`azp`),
    /// rule 9 (`exp`), rule 10 (`iat` within the skew), rule 11 (`nonce`, when one was sent) and rule
    /// 13 (`auth_time`, when `max_age` was requested). The first rule that fails is the error.
    ///
    /// Signature verification (rule 6) is not part of this; see the type's documentation.
    ///
    /// # Errors
    ///
    /// The [`Rejection`] naming the rule.
    pub fn validate_claims(&self, expectations: &Expectations<'_>) -> Result<&Claims, Error> {
        let alg = &self.header.alg;
        if alg.eq_ignore_ascii_case("none") || !expectations.algorithms.contains(&alg.as_str()) {
            return Err(Rejection::Algorithm {
                alg: alg.clone(),
                expected: expectations
                    .algorithms
                    .iter()
                    .map(|a| (*a).to_owned())
                    .collect(),
            }
            .into());
        }
        let claims = &self.claims;
        if claims.iss != expectations.issuer {
            return Err(Rejection::Issuer {
                expected: expectations.issuer.to_owned(),
                found: claims.iss.clone(),
            }
            .into());
        }
        let client_id = expectations.client_id;
        if !claims.aud.iter().any(|aud| aud == client_id) {
            return Err(Rejection::Audience {
                client_id: client_id.to_owned(),
                audience: claims.aud.clone(),
            }
            .into());
        }
        match &claims.azp {
            Some(azp) if azp != client_id => {
                return Err(Rejection::AuthorizedParty {
                    client_id: client_id.to_owned(),
                    azp: Some(azp.clone()),
                }
                .into());
            }
            None if claims.aud.len() > 1 => {
                return Err(Rejection::AuthorizedParty {
                    client_id: client_id.to_owned(),
                    azp: None,
                }
                .into());
            }
            _ => {}
        }
        let now = expectations.now;
        if now >= claims.exp {
            return Err(Rejection::Expired {
                exp: claims.exp,
                now,
            }
            .into());
        }
        if claims.iat.abs_diff(now) > expectations.issued_at_skew {
            return Err(Rejection::IssuedAt {
                iat: claims.iat,
                now,
                skew: expectations.issued_at_skew,
            }
            .into());
        }
        if let Some(expected) = expectations.nonce
            && claims.nonce.as_deref() != Some(expected)
        {
            return Err(Rejection::Nonce {
                expected: expected.to_owned(),
                found: claims.nonce.clone(),
            }
            .into());
        }
        if let Some(max_age) = expectations.max_age {
            match claims.auth_time {
                Some(auth_time) if now.saturating_sub(auth_time) <= max_age => {}
                auth_time => {
                    return Err(Rejection::AuthTime {
                        max_age,
                        auth_time,
                        now,
                    }
                    .into());
                }
            }
        }
        Ok(claims)
    }
}

impl fmt::Debug for IdToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdToken")
            .field("header", &self.header)
            .field("claims", &self.claims)
            .finish_non_exhaustive()
    }
}

fn required<T>(name: &str, value: Option<T>) -> Result<T, Error> {
    value.ok_or_else(|| Error::malformed("ID token", format!("missing claim `{name}`")))
}

fn signature_len(compact: &str) -> usize {
    compact
        .rsplit_once('.')
        .map_or(0, |(_, signature)| signature.len() + 1)
}

fn segment(what: &str, text: &str) -> Result<Vec<u8>, Error> {
    base64url::decode(text).map_err(|e| match e {
        Error::Malformed { reason, .. } => {
            Error::malformed("ID token", format!("the {what} segment: {reason}"))
        }
        other => other,
    })
}

fn object(what: &str, text: &str) -> Result<Map<String, Value>, Error> {
    let bytes = segment(what, text)?;
    match serde_json::from_slice(&bytes) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(Error::malformed(
            "ID token",
            format!("the {what} is not a JSON object"),
        )),
        Err(e) => Err(Error::malformed(
            "ID token",
            format!("the {what} is not JSON: {e}"),
        )),
    }
}

fn string(map: &Map<String, Value>, name: &str, kind: &str) -> Result<Option<String>, Error> {
    match map.get(name) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(Error::malformed(
            "ID token",
            format!("the {kind} `{name}` is not a string"),
        )),
    }
}

fn strings(map: &Map<String, Value>, name: &str) -> Result<Option<Vec<String>>, Error> {
    let not_strings = || {
        Error::malformed(
            "ID token",
            format!("the claim `{name}` is not a string or an array of strings"),
        )
    };
    match map.get(name) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(vec![s.clone()])),
        Some(Value::Array(values)) => values
            .iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or_else(not_strings))
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(not_strings()),
    }
}

/// A NumericDate (RFC 7519 §2): a JSON number of seconds since the epoch, whole or not.
fn time(map: &Map<String, Value>, name: &str) -> Result<Option<u64>, Error> {
    let not_a_time = || {
        Error::malformed(
            "ID token",
            format!("the claim `{name}` is not a number of seconds"),
        )
    };
    match map.get(name) {
        None => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .or_else(|| {
                n.as_f64()
                    .filter(|f| f.is_finite() && *f >= 0.0)
                    .map(|f| f as u64)
            })
            .map(Some)
            .ok_or_else(not_a_time),
        Some(_) => Err(not_a_time()),
    }
}

/// What an ID token must satisfy: the issuer and client it is for, the nonce sent, the current time,
/// the skew allowed on `iat`, the signing algorithms accepted, and `max_age` when it was requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectations<'a> {
    issuer: &'a str,
    client_id: &'a str,
    nonce: Option<&'a str>,
    now: u64,
    issued_at_skew: u64,
    algorithms: &'a [&'a str],
    max_age: Option<u64>,
}

impl<'a> Expectations<'a> {
    /// Expectations for `issuer` and `client_id` at time `now` (seconds since the epoch), with no
    /// nonce, a skew of 300 seconds on `iat`, `RS256` as the one algorithm (Core §3.1.3.7 rule 7's
    /// default) and no `max_age`.
    #[must_use]
    pub const fn new(issuer: &'a str, client_id: &'a str, now: u64) -> Self {
        Self {
            issuer,
            client_id,
            nonce: None,
            now,
            issued_at_skew: 300,
            algorithms: &["RS256"],
            max_age: None,
        }
    }

    /// The nonce sent with the authentication request; the token must carry it (rule 11).
    #[must_use]
    pub const fn nonce(mut self, nonce: &'a str) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// The largest distance in seconds between `iat` and `now` accepted (rule 10).
    #[must_use]
    pub const fn issued_at_skew(mut self, seconds: u64) -> Self {
        self.issued_at_skew = seconds;
        self
    }

    /// The signing algorithms accepted (rule 7): those registered for the client, or the provider's
    /// `id_token_signing_alg_values_supported`. `none` is never accepted, listed or not.
    #[must_use]
    pub const fn algorithms(mut self, algorithms: &'a [&'a str]) -> Self {
        self.algorithms = algorithms;
        self
    }

    /// The `max_age` requested; the token must carry an `auth_time` at most that old (rule 13).
    #[must_use]
    pub const fn max_age(mut self, seconds: u64) -> Self {
        self.max_age = Some(seconds);
        self
    }

    /// The issuer expected.
    #[must_use]
    pub const fn issuer(&self) -> &'a str {
        self.issuer
    }

    /// The client id expected in the audience.
    #[must_use]
    pub const fn client_id(&self) -> &'a str {
        self.client_id
    }

    /// The nonce expected, when one was sent.
    #[must_use]
    pub const fn nonce_expected(&self) -> Option<&'a str> {
        self.nonce
    }

    /// The current time the claims are checked against.
    #[must_use]
    pub const fn now(&self) -> u64 {
        self.now
    }

    /// The skew allowed on `iat`, in seconds.
    #[must_use]
    pub const fn issued_at_skew_allowed(&self) -> u64 {
        self.issued_at_skew
    }

    /// The signing algorithms accepted.
    #[must_use]
    pub const fn algorithms_accepted(&self) -> &'a [&'a str] {
        self.algorithms
    }

    /// The `max_age` requested, when one was.
    #[must_use]
    pub const fn max_age_requested(&self) -> Option<u64> {
        self.max_age
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_dates_accept_fractions_and_refuse_negatives() {
        let map = |json: &str| serde_json::from_str::<Map<String, Value>>(json).unwrap();
        assert_eq!(time(&map(r#"{"exp": 10}"#), "exp").unwrap(), Some(10));
        assert_eq!(time(&map(r#"{"exp": 10.9}"#), "exp").unwrap(), Some(10));
        assert_eq!(time(&map(r#"{}"#), "exp").unwrap(), None);
        assert!(time(&map(r#"{"exp": -1}"#), "exp").is_err());
        assert!(time(&map(r#"{"exp": "10"}"#), "exp").is_err());
    }

    #[test]
    fn audience_refuses_a_non_string_member() {
        let map = serde_json::from_str::<Map<String, Value>>(r#"{"aud": ["a", 1]}"#).unwrap();
        assert!(strings(&map, "aud").is_err());
        let map = serde_json::from_str::<Map<String, Value>>(r#"{"aud": 1}"#).unwrap();
        assert!(strings(&map, "aud").is_err());
    }
}
