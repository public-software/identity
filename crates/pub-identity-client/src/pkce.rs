//! Proof Key for Code Exchange (RFC 7636): the code verifier, and the `S256` code challenge derived
//! from it.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{Error, base64url, sha256::sha256};

/// A PKCE code verifier (RFC 7636 §4.1): 43 to 128 characters from the unreserved set of RFC 3986
/// §2.3 (`[A-Za-z0-9]`, `-`, `.`, `_`, `~`). Built from random octets the caller draws (32 octets
/// give the recommended 43 characters), or parsed from text the caller stored.
///
/// It is the secret of the flow: `Debug` does not print it, and it must be kept until the token
/// request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CodeVerifier(String);

impl CodeVerifier {
    /// The base64url encoding of `octets` as the verifier; 32 to 96 octets keep it in the grammar.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] when the encoding is shorter than 43 or longer than 128 characters.
    pub fn from_octets(octets: &[u8]) -> Result<Self, Error> {
        base64url::encode(octets).parse()
    }

    /// The verifier as text, for the `code_verifier` parameter of the token request (§4.5).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The `S256` code challenge of this verifier (§4.2):
    /// `BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`.
    #[must_use]
    pub fn challenge(&self) -> CodeChallenge {
        CodeChallenge(base64url::encode(&sha256(self.0.as_bytes())))
    }
}

impl FromStr for CodeVerifier {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let malformed = |reason: String| Error::malformed("code verifier", reason);
        if !(43..=128).contains(&text.len()) {
            return Err(malformed(format!(
                "{} characters, the grammar allows 43 to 128",
                text.len()
            )));
        }
        if let Some(bad) = text
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')))
        {
            return Err(malformed(format!("`{bad}` is not an unreserved character")));
        }
        Ok(Self(text.to_owned()))
    }
}

impl TryFrom<String> for CodeVerifier {
    type Error = Error;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

impl From<CodeVerifier> for String {
    fn from(verifier: CodeVerifier) -> Self {
        verifier.0
    }
}

impl fmt::Debug for CodeVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CodeVerifier(..)")
    }
}

/// A PKCE code challenge (RFC 7636 §4.2), always of the `S256` method: the only method RFC 9700
/// §2.1.1 lets a client use, since `plain` exposes the verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeChallenge(String);

impl CodeChallenge {
    /// The challenge as text, for the `code_challenge` parameter (§4.3).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The `code_challenge_method` parameter: `S256`.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        "S256"
    }
}

impl fmt::Display for CodeChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_print_the_verifier() {
        let verifier: CodeVerifier = "a".repeat(43).parse().unwrap();
        assert_eq!(format!("{verifier:?}"), "CodeVerifier(..)");
    }

    #[test]
    fn serde_round_trips_and_validates() {
        let verifier: CodeVerifier = "b".repeat(50).parse().unwrap();
        let json = serde_json::to_string(&verifier).unwrap();
        assert_eq!(json, format!("\"{}\"", "b".repeat(50)));
        assert_eq!(
            serde_json::from_str::<CodeVerifier>(&json).unwrap(),
            verifier
        );
        assert!(serde_json::from_str::<CodeVerifier>("\"short\"").is_err());
    }
}
