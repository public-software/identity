//! base64url without padding, the encoding of RFC 4648 §5 with the `=` padding omitted, as RFC 7636
//! appendix A and RFC 7515 §2 use it.

use crate::Error;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encodes `octets` as base64url without padding.
///
/// ```
/// assert_eq!(pub_identity_client::base64url::encode(&[3, 236, 255, 224, 193]), "A-z_4ME");
/// ```
#[must_use]
pub fn encode(octets: &[u8]) -> String {
    let mut out = String::with_capacity(octets.len().div_ceil(3) * 4);
    for chunk in octets.chunks(3) {
        let bits = chunk.iter().enumerate().fold(0u32, |acc, (i, byte)| {
            acc | (u32::from(*byte) << (16 - 8 * i))
        });
        let count = chunk.len() + 1;
        for i in 0..count {
            let index = (bits >> (18 - 6 * i)) & 0x3f;
            out.push(char::from(ALPHABET[index as usize]));
        }
    }
    out
}

/// Decodes base64url without padding. Padding, the standard alphabet's `+` and `/`, whitespace and a
/// length of 1 modulo 4 are refused.
///
/// # Errors
///
/// [`Error::Malformed`] with `what` = `base64url` and the reason.
pub fn decode(text: &str) -> Result<Vec<u8>, Error> {
    let malformed = |reason: String| Error::malformed("base64url", reason);
    if text.len() % 4 == 1 {
        return Err(malformed(format!(
            "a length of {} is not a base64url length",
            text.len()
        )));
    }
    let mut values = Vec::with_capacity(text.len());
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => {
                return Err(malformed(
                    "padding is not part of base64url without padding".into(),
                ));
            }
            b'+' | b'/' => {
                return Err(malformed(format!(
                    "`{}` belongs to the standard alphabet, not base64url",
                    char::from(byte)
                )));
            }
            _ => {
                return Err(malformed(format!(
                    "`{}` is not a base64url character",
                    char::from(byte)
                )));
            }
        };
        values.push(value);
    }
    let mut out = Vec::with_capacity(values.len() * 3 / 4);
    for chunk in values.chunks(4) {
        let bits = chunk.iter().enumerate().fold(0u32, |acc, (i, value)| {
            acc | (u32::from(*value) << (18 - 6 * i))
        });
        for i in 0..chunk.len() - 1 {
            out.push(((bits >> (16 - 8 * i)) & 0xff) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_length() {
        for len in 0..64 {
            let octets: Vec<u8> = (0..len).map(|i| (i * 37 % 256) as u8).collect();
            let text = encode(&octets);
            assert!(!text.contains('='), "{text}");
            assert_eq!(decode(&text).unwrap(), octets, "{len}");
        }
    }

    #[test]
    fn rfc_4648_vectors_without_padding() {
        assert_eq!(encode(b"foob"), "Zm9vYg");
        assert_eq!(encode(b"fooba"), "Zm9vYmE");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(decode("Zm9vYmFy").unwrap(), b"foobar");
    }
}
