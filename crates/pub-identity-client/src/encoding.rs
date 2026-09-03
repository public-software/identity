//! Percent-encoding (RFC 3986 §2) for query and form parameters, and the parsing of a query string or
//! an `application/x-www-form-urlencoded` body.

/// Percent-encodes every byte that is not unreserved (RFC 3986 §2.3: letters, digits, `-`, `.`, `_`,
/// `~`), with uppercase hexadecimal digits.
pub(crate) fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Decodes `%XX` escapes and, as form encoding has it, `+` as a space.
fn percent_decode(input: &str) -> Result<String, String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let digits = bytes
                    .get(i + 1..i + 3)
                    .ok_or_else(|| format!("`{input}` ends inside a percent escape"))?;
                let text = std::str::from_utf8(digits)
                    .map_err(|_| format!("`{input}` has a bad percent escape"))?;
                let value = u8::from_str_radix(text, 16)
                    .map_err(|_| format!("`%{text}` is not a percent escape"))?;
                out.push(value);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| format!("`{input}` does not decode to UTF-8"))
}

/// Parses `name=value&name=value`, decoding both sides; a pair without `=` has an empty value and
/// empty pairs are skipped.
pub(crate) fn parse_query(query: &str) -> Result<Vec<(String, String)>, String> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            Ok((percent_decode(name)?, percent_decode(value)?))
        })
        .collect()
}

/// Joins `name=value` pairs, encoding both sides.
pub(crate) fn build_query(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(name, value)| format!("{}={}", percent_encode(name), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_everything_but_unreserved() {
        assert_eq!(percent_encode("AZaz09-._~"), "AZaz09-._~");
        assert_eq!(
            percent_encode("a b&c=d/e?f#g%h+i"),
            "a%20b%26c%3Dd%2Fe%3Ff%23g%25h%2Bi"
        );
        assert_eq!(percent_encode("é"), "%C3%A9");
    }

    #[test]
    fn decodes_escapes_and_plus() {
        assert_eq!(percent_decode("a%20b+c%C3%A9").unwrap(), "a b cé");
        assert_eq!(percent_decode("%2f%2F").unwrap(), "//");
        assert!(percent_decode("a%2").is_err());
        assert!(percent_decode("a%zz").is_err());
        assert!(percent_decode("%ff").is_err(), "not UTF-8");
    }

    #[test]
    fn parses_and_builds_queries() {
        let pairs = parse_query("a=1&b=two+words&c&&d=%3D").unwrap();
        assert_eq!(
            pairs,
            [("a", "1"), ("b", "two words"), ("c", ""), ("d", "=")]
                .map(|(n, v)| (n.to_string(), v.to_string()))
        );
        assert_eq!(
            build_query(&[("a", "1"), ("b", "two words")]),
            "a=1&b=two%20words"
        );
        assert!(parse_query("a=%").is_err());
    }
}
