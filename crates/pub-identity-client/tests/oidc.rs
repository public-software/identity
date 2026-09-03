//! The OpenID Connect client core against fixtures: RFC 7636 appendix B, an OpenID Provider Metadata
//! document, the authorization response, a token response and an ID token, plus every rule of
//! OpenID Connect Core 1.0 §3.1.3.7 the crate checks.

use pub_identity_client::{
    AuthenticationRequest, Claims, CodeVerifier, Error, Expectations, IdToken, Nonce,
    ProviderMetadata, Rejection, State, TokenResponse, base64url, well_known_url,
};

const PROVIDER: &[u8] = include_bytes!("fixtures/provider.json");
const TOKEN: &[u8] = include_bytes!("fixtures/token.json");
const TOKEN_ERROR: &[u8] = include_bytes!("fixtures/token-error.json");

const ISSUER: &str = "https://id.example.org";
const CLIENT: &str = "app-1";
const REDIRECT: &str = "https://app.example.org/cb?x=1&y=two words";
const NOW: u64 = 1_800_000_000;

/// RFC 7636 appendix B: the 32 octets, the verifier they encode to, the challenge S256 derives.
const APPENDIX_B_OCTETS: [u8; 32] = [
    116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77,
    105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121,
];
const APPENDIX_B_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const APPENDIX_B_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn provider() -> ProviderMetadata {
    ProviderMetadata::parse(ISSUER, PROVIDER).expect("the fixture parses")
}

fn state() -> State {
    State::from_octets(&[7u8; 16])
}

fn nonce() -> Nonce {
    Nonce::from_octets(&[9u8; 16])
}

fn verifier() -> CodeVerifier {
    CodeVerifier::from_octets(&APPENDIX_B_OCTETS).unwrap()
}

fn request() -> AuthenticationRequest {
    AuthenticationRequest::new(&provider(), CLIENT, REDIRECT, verifier(), state(), nonce()).unwrap()
}

/// A compact JWS with the given header and payload objects and a signature nobody verifies here.
fn jws(header: &str, payload: &str) -> String {
    format!(
        "{}.{}.{}",
        base64url::encode(header.as_bytes()),
        base64url::encode(payload.as_bytes()),
        base64url::encode(b"signature-bytes")
    )
}

fn claims_json(extra: &str) -> String {
    let nonce = nonce();
    format!(
        r#"{{"iss":"{ISSUER}","sub":"24400320","aud":"{CLIENT}","exp":{},"iat":{},"nonce":"{}"{}}}"#,
        NOW + 600,
        NOW - 5,
        nonce.as_str(),
        extra
    )
}

fn id_token(extra: &str) -> IdToken {
    IdToken::parse(&jws(
        r#"{"alg":"RS256","kid":"k1","typ":"JWT"}"#,
        &claims_json(extra),
    ))
    .unwrap()
}

fn expectations(nonce: &Nonce) -> Expectations<'_> {
    Expectations::new(ISSUER, CLIENT, NOW).nonce(nonce.as_str())
}

fn rejected(result: Result<impl std::fmt::Debug, Error>) -> Rejection {
    match result.expect_err("expected a rejection") {
        Error::Rejected(rejection) => rejection,
        other => panic!("expected a rejection, got {other}"),
    }
}

// ---- base64url (RFC 7636 appendix A) and PKCE (RFC 7636 §4) ----

#[test]
fn base64url_follows_appendix_a() {
    assert_eq!(base64url::encode(&[3, 236, 255, 224, 193]), "A-z_4ME");
    assert_eq!(
        base64url::decode("A-z_4ME").unwrap(),
        vec![3, 236, 255, 224, 193]
    );
    assert_eq!(base64url::encode(b""), "");
    assert_eq!(base64url::encode(b"f"), "Zg");
    assert_eq!(base64url::encode(b"foo"), "Zm9v");
    for (text, reason) in [
        ("Zg==", "padding"),
        ("Zm9+", "the standard alphabet"),
        ("Zm9v/", "the standard alphabet"),
        ("Z", "a length of 1 mod 4"),
        ("Zm9 v", "a space"),
    ] {
        let error = base64url::decode(text).expect_err(reason);
        assert!(
            matches!(
                error,
                Error::Malformed {
                    what: "base64url",
                    ..
                }
            ),
            "{reason}: {error}"
        );
    }
}

#[test]
fn appendix_b_octets_give_the_verifier_and_the_challenge() {
    let verifier = CodeVerifier::from_octets(&APPENDIX_B_OCTETS).unwrap();
    assert_eq!(verifier.as_str(), APPENDIX_B_VERIFIER);
    let challenge = verifier.challenge();
    assert_eq!(challenge.as_str(), APPENDIX_B_CHALLENGE);
    assert_eq!(challenge.method(), "S256");
    let parsed: CodeVerifier = APPENDIX_B_VERIFIER.parse().unwrap();
    assert_eq!(parsed.challenge().as_str(), APPENDIX_B_CHALLENGE);
}

#[test]
fn verifier_grammar_is_43_to_128_unreserved_characters() {
    assert!(
        CodeVerifier::from_octets(&[0u8; 31]).is_err(),
        "31 octets encode to 42 chars"
    );
    assert!(
        CodeVerifier::from_octets(&[0u8; 96]).is_ok(),
        "96 octets encode to 128 chars"
    );
    assert!(
        CodeVerifier::from_octets(&[0u8; 97]).is_err(),
        "97 octets encode to 130 chars"
    );
    assert!("a".repeat(42).parse::<CodeVerifier>().is_err());
    assert!("a".repeat(43).parse::<CodeVerifier>().is_ok());
    assert!("a".repeat(128).parse::<CodeVerifier>().is_ok());
    assert!("a".repeat(129).parse::<CodeVerifier>().is_err());
    assert!(
        "A-._~z1".repeat(7).parse::<CodeVerifier>().is_ok(),
        "every unreserved character"
    );
    for bad in [
        "a".repeat(42) + "+",
        "a".repeat(42) + "/",
        "a".repeat(42) + "=",
        "a".repeat(42) + " ",
    ] {
        let error = bad
            .parse::<CodeVerifier>()
            .expect_err("a reserved character");
        assert!(
            matches!(
                error,
                Error::Malformed {
                    what: "code verifier",
                    ..
                }
            ),
            "{error}"
        );
    }
}

// ---- Discovery 1.0 ----

#[test]
fn well_known_url_strips_one_trailing_slash() {
    assert_eq!(
        well_known_url("https://example.com"),
        "https://example.com/.well-known/openid-configuration"
    );
    assert_eq!(
        well_known_url("https://example.com/"),
        "https://example.com/.well-known/openid-configuration"
    );
    assert_eq!(
        well_known_url("https://example.com/issuer1"),
        "https://example.com/issuer1/.well-known/openid-configuration"
    );
    assert_eq!(
        well_known_url("https://example.com/issuer1/"),
        "https://example.com/issuer1/.well-known/openid-configuration"
    );
}

#[test]
fn provider_metadata_parses_the_fixture() {
    let provider = provider();
    assert_eq!(provider.issuer(), ISSUER);
    assert_eq!(
        provider.authorization_endpoint(),
        "https://id.example.org/authorize"
    );
    assert_eq!(
        provider.token_endpoint(),
        Some("https://id.example.org/token")
    );
    assert_eq!(
        provider.userinfo_endpoint(),
        Some("https://id.example.org/userinfo")
    );
    assert_eq!(provider.jwks_uri(), "https://id.example.org/jwks");
    assert_eq!(
        provider.response_types_supported(),
        ["code", "id_token", "code id_token"]
    );
    assert_eq!(provider.subject_types_supported(), ["public", "pairwise"]);
    assert_eq!(
        provider.id_token_signing_alg_values_supported(),
        ["RS256", "ES256"]
    );
    assert_eq!(
        provider.scopes_supported(),
        Some(&["openid", "profile", "email", "offline_access"].map(String::from)[..])
    );
    assert_eq!(
        provider.code_challenge_methods_supported(),
        Some(&["S256".to_string()][..])
    );
    assert!(provider.authorization_response_iss_parameter_supported());
    assert_eq!(
        provider.token_endpoint_auth_methods_supported(),
        Some(&["client_secret_basic", "none"].map(String::from)[..])
    );
    assert!(provider.supports_code_flow_with_pkce());
}

#[test]
fn provider_metadata_optional_fields_default() {
    let json =
        br#"{"issuer":"https://id.example.org","authorization_endpoint":"https://id.example.org/a",
        "jwks_uri":"https://id.example.org/jwks","response_types_supported":["code"],
        "subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}"#;
    let provider = ProviderMetadata::parse(ISSUER, json).unwrap();
    assert_eq!(provider.token_endpoint(), None);
    assert_eq!(provider.scopes_supported(), None);
    assert_eq!(provider.code_challenge_methods_supported(), None);
    assert!(
        !provider.authorization_response_iss_parameter_supported(),
        "RFC 9207 §3: default false"
    );
    assert!(
        !provider.supports_code_flow_with_pkce(),
        "no token endpoint"
    );
}

#[test]
fn provider_metadata_refuses_what_discovery_requires() {
    let text = std::str::from_utf8(PROVIDER).unwrap();
    // §3: a required field missing
    let without = text.replacen(r#""jwks_uri": "https://id.example.org/jwks","#, "", 1);
    let error = ProviderMetadata::parse(ISSUER, without.as_bytes()).unwrap_err();
    assert!(
        matches!(error, Error::Malformed { what: "provider metadata", ref reason } if reason.contains("jwks_uri")),
        "{error}"
    );
    // not JSON
    let error = ProviderMetadata::parse(ISSUER, b"<html>").unwrap_err();
    assert!(
        matches!(
            error,
            Error::Malformed {
                what: "provider metadata",
                ..
            }
        ),
        "{error}"
    );
    // §3: the issuer is https without query or fragment
    for issuer in [
        "http://id.example.org",
        "https://id.example.org?x=1",
        "https://id.example.org#frag",
        "id.example.org",
    ] {
        let json = text.replacen(
            r#""issuer": "https://id.example.org""#,
            &format!(r#""issuer": "{issuer}""#),
            1,
        );
        let rejection = rejected(ProviderMetadata::parse(issuer, json.as_bytes()));
        assert!(
            matches!(rejection, Rejection::IssuerForm { issuer: ref found } if found == issuer),
            "{issuer}: {rejection}"
        );
    }
    // §4.3: the issuer is the one the document was fetched for, byte for byte
    let rejection = rejected(ProviderMetadata::parse("https://id.example.org/", PROVIDER));
    assert!(
        matches!(rejection, Rejection::Issuer { ref expected, ref found } if expected == "https://id.example.org/" && found == ISSUER),
        "{rejection}"
    );
    assert!(rejection.to_string().contains("4.3"), "{rejection}");
}

// ---- The authentication request (Core §3.1.2.1, RFC 7636 §4.3) ----

#[test]
fn authentication_request_url_carries_every_parameter() {
    let url = request().url();
    let (endpoint, query) = url.split_once('?').unwrap();
    assert_eq!(endpoint, "https://id.example.org/authorize");
    let parameters: Vec<&str> = query.split('&').collect();
    assert_eq!(parameters[0], "response_type=code");
    assert_eq!(parameters[1], "client_id=app-1");
    assert_eq!(
        parameters[2],
        "redirect_uri=https%3A%2F%2Fapp.example.org%2Fcb%3Fx%3D1%26y%3Dtwo%20words"
    );
    assert_eq!(parameters[3], "scope=openid");
    assert_eq!(parameters[4], format!("state={}", state().as_str()));
    assert_eq!(parameters[5], format!("nonce={}", nonce().as_str()));
    assert_eq!(
        parameters[6],
        format!("code_challenge={APPENDIX_B_CHALLENGE}")
    );
    assert_eq!(parameters[7], "code_challenge_method=S256");
    assert_eq!(parameters.len(), 8);
}

#[test]
fn authentication_request_takes_scopes_and_parameters() {
    let url = request()
        .scope("profile")
        .scope("email")
        .scope("openid")
        .max_age(300)
        .parameter("prompt", "login")
        .parameter("login_hint", "ada@example.org")
        .url();
    assert!(url.contains("&scope=openid%20profile%20email&"), "{url}");
    assert!(url.contains("&max_age=300"), "{url}");
    assert!(url.contains("&prompt=login"), "{url}");
    assert!(url.contains("&login_hint=ada%40example.org"), "{url}");
}

#[test]
fn authentication_request_needs_code_and_s256_and_a_token_endpoint() {
    let text = std::str::from_utf8(PROVIDER).unwrap();
    let no_code = text.replacen(
        r#""response_types_supported": ["code", "id_token", "code id_token"]"#,
        r#""response_types_supported": ["id_token"]"#,
        1,
    );
    let provider = ProviderMetadata::parse(ISSUER, no_code.as_bytes()).unwrap();
    let rejection = rejected(AuthenticationRequest::new(
        &provider,
        CLIENT,
        REDIRECT,
        verifier(),
        state(),
        nonce(),
    ));
    assert!(
        matches!(
            rejection,
            Rejection::Unsupported {
                feature: "response_type code",
                ..
            }
        ),
        "{rejection}"
    );

    let plain_only = text.replacen(
        r#""code_challenge_methods_supported": ["S256"]"#,
        r#""code_challenge_methods_supported": ["plain"]"#,
        1,
    );
    let provider = ProviderMetadata::parse(ISSUER, plain_only.as_bytes()).unwrap();
    let rejection = rejected(AuthenticationRequest::new(
        &provider,
        CLIENT,
        REDIRECT,
        verifier(),
        state(),
        nonce(),
    ));
    assert!(
        matches!(rejection, Rejection::Unsupported { feature: "code_challenge_method S256", ref supported } if supported == &["plain".to_string()]),
        "{rejection}"
    );

    let no_token = text.replacen(
        r#""token_endpoint": "https://id.example.org/token","#,
        "",
        1,
    );
    let provider = ProviderMetadata::parse(ISSUER, no_token.as_bytes()).unwrap();
    let rejection = rejected(AuthenticationRequest::new(
        &provider,
        CLIENT,
        REDIRECT,
        verifier(),
        state(),
        nonce(),
    ));
    assert!(
        matches!(
            rejection,
            Rejection::Unsupported {
                feature: "token_endpoint",
                ..
            }
        ),
        "{rejection}"
    );

    // a metadata document that does not list code_challenge_methods_supported is not a refusal (RFC 8414: optional)
    let unlisted = text.replacen(r#""code_challenge_methods_supported": ["S256"],"#, "", 1);
    let provider = ProviderMetadata::parse(ISSUER, unlisted.as_bytes()).unwrap();
    assert!(
        AuthenticationRequest::new(&provider, CLIENT, REDIRECT, verifier(), state(), nonce())
            .is_ok()
    );
}

#[test]
fn state_and_nonce_are_base64url_of_the_octets() {
    assert_eq!(State::from_octets(&[0, 0, 0]).as_str(), "AAAA");
    assert_eq!(Nonce::from_octets(&[255, 255, 255]).as_str(), "____");
    assert!(State::parse("").is_err(), "empty");
    assert!(
        State::parse("with space").is_err(),
        "not printable ASCII without spaces"
    );
    assert_eq!(State::parse("opaque-1").unwrap().as_str(), "opaque-1");
    assert_eq!(
        Nonce::parse("n-0S6_WzA2Mj").unwrap().as_str(),
        "n-0S6_WzA2Mj"
    );
}

// ---- The authorization response (RFC 6749 §4.1.2, RFC 9207) ----

#[test]
fn authorization_response_yields_the_code_when_state_and_iss_match() {
    let pending = request().pending();
    let query = format!(
        "code=SplxlOBeZQQYbYS6WxSbIA&state={}&iss=https%3A%2F%2Fid.example.org",
        state().as_str()
    );
    let code = pending.parse_response(&query).unwrap();
    assert_eq!(code.as_str(), "SplxlOBeZQQYbYS6WxSbIA");
    // the whole redirect URL is accepted too; a fragment is ignored
    let url = format!("https://app.example.org/cb?x=1&{query}#top");
    assert_eq!(
        pending.parse_response(&url).unwrap().as_str(),
        "SplxlOBeZQQYbYS6WxSbIA"
    );
}

#[test]
fn authorization_response_checks_state() {
    let pending = request().pending();
    let rejection =
        rejected(pending.parse_response("code=abc&state=other&iss=https%3A%2F%2Fid.example.org"));
    assert!(
        matches!(rejection, Rejection::State { ref expected, found: Some(ref found) } if expected == state().as_str() && found == "other"),
        "{rejection}"
    );
    let rejection = rejected(pending.parse_response("code=abc&iss=https%3A%2F%2Fid.example.org"));
    assert!(
        matches!(rejection, Rejection::State { found: None, .. }),
        "{rejection}"
    );
}

#[test]
fn authorization_response_checks_iss_per_rfc_9207() {
    let pending = request().pending();
    let query = format!("code=abc&state={}", state().as_str());
    let rejection = rejected(pending.parse_response(&query));
    assert!(
        matches!(rejection, Rejection::IssuerMissing),
        "the metadata says supported: {rejection}"
    );
    let query = format!(
        "code=abc&state={}&iss=https%3A%2F%2Fevil.example.org",
        state().as_str()
    );
    let rejection = rejected(pending.parse_response(&query));
    assert!(
        matches!(rejection, Rejection::Issuer { ref expected, ref found } if expected == ISSUER && found == "https://evil.example.org"),
        "{rejection}"
    );

    // a provider that does not announce iss support: absent is fine, present must still match
    let text = std::str::from_utf8(PROVIDER).unwrap();
    let unannounced = text.replacen(
        r#""authorization_response_iss_parameter_supported": true,"#,
        "",
        1,
    );
    let provider = ProviderMetadata::parse(ISSUER, unannounced.as_bytes()).unwrap();
    let pending =
        AuthenticationRequest::new(&provider, CLIENT, REDIRECT, verifier(), state(), nonce())
            .unwrap()
            .pending();
    let query = format!("code=abc&state={}", state().as_str());
    assert!(pending.parse_response(&query).is_ok());
    let query = format!(
        "code=abc&state={}&iss=https%3A%2F%2Fevil.example.org",
        state().as_str()
    );
    assert!(matches!(
        rejected(pending.parse_response(&query)),
        Rejection::Issuer { .. }
    ));
}

#[test]
fn authorization_error_response_is_surfaced_with_its_code() {
    let pending = request().pending();
    let query = format!(
        "error=access_denied&error_description=The%20user%20said%20no&state={}&iss=https%3A%2F%2Fid.example.org",
        state().as_str()
    );
    match pending.parse_response(&query).unwrap_err() {
        Error::Provider(error) => {
            assert_eq!(error.error, "access_denied");
            assert_eq!(error.error_description.as_deref(), Some("The user said no"));
            assert_eq!(error.error_uri, None);
            assert_eq!(error.to_string(), "access_denied: The user said no");
        }
        other => panic!("expected the provider's error, got {other}"),
    }
    // an error response with the wrong state is not this request's
    let query = "error=access_denied&state=other";
    assert!(matches!(
        rejected(pending.parse_response(query)),
        Rejection::State { .. }
    ));
    // neither code nor error
    let query = format!(
        "state={}&iss=https%3A%2F%2Fid.example.org",
        state().as_str()
    );
    let error = pending.parse_response(&query).unwrap_err();
    assert!(
        matches!(
            error,
            Error::Malformed {
                what: "authorization response",
                ..
            }
        ),
        "{error}"
    );
    // a broken percent escape
    let error = pending.parse_response("code=ab%2&state=x").unwrap_err();
    assert!(
        matches!(
            error,
            Error::Malformed {
                what: "authorization response",
                ..
            }
        ),
        "{error}"
    );
}

// ---- The token request and response (RFC 6749 §4.1.3, §5; RFC 7636 §4.5; Core §3.1.3.3) ----

#[test]
fn token_request_is_the_form_body_with_the_verifier() {
    let pending = request().pending();
    let query = format!(
        "code=SplxlOBeZQQYbYS6WxSbIA&state={}&iss=https%3A%2F%2Fid.example.org",
        state().as_str()
    );
    let code = pending.parse_response(&query).unwrap();
    let token_request = pending.token_request(&code);
    assert_eq!(token_request.endpoint(), "https://id.example.org/token");
    assert_eq!(
        token_request.content_type(),
        "application/x-www-form-urlencoded"
    );
    assert_eq!(
        token_request.body(),
        format!(
            "grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https%3A%2F%2Fapp.example.org%2Fcb%3Fx%3D1%26y%3Dtwo%20words&client_id=app-1&code_verifier={APPENDIX_B_VERIFIER}"
        )
    );
}

#[test]
fn token_response_parses_the_fixture() {
    let token = id_token("");
    let json = std::str::from_utf8(TOKEN)
        .unwrap()
        .replace("PLACEHOLDER", token.compact());
    let response = TokenResponse::parse(json.as_bytes()).unwrap();
    assert_eq!(response.access_token(), "SlAV32hkKG");
    assert_eq!(response.token_type(), "bearer");
    assert_eq!(response.refresh_token(), Some("8xLOxBtZp8"));
    assert_eq!(response.expires_in(), Some(3600));
    assert_eq!(response.scope(), Some("openid profile"));
    assert_eq!(response.id_token().compact(), token.compact());
}

#[test]
fn token_response_refuses_what_core_requires() {
    let token = id_token("");
    let text = std::str::from_utf8(TOKEN)
        .unwrap()
        .replace("PLACEHOLDER", token.compact());
    let mac = text.replace(r#""token_type": "bearer""#, r#""token_type": "mac""#);
    let rejection = rejected(TokenResponse::parse(mac.as_bytes()));
    assert!(
        matches!(rejection, Rejection::TokenType { ref found } if found == "mac"),
        "{rejection}"
    );
    let no_id_token = text.replace(r#""id_token""#, r#""id_token_""#);
    let error = TokenResponse::parse(no_id_token.as_bytes()).unwrap_err();
    assert!(
        matches!(error, Error::Malformed { what: "token response", ref reason } if reason.contains("id_token")),
        "{error}"
    );
    let error = TokenResponse::parse(b"not json").unwrap_err();
    assert!(
        matches!(
            error,
            Error::Malformed {
                what: "token response",
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn token_error_response_is_surfaced_with_its_code() {
    match TokenResponse::parse(TOKEN_ERROR).unwrap_err() {
        Error::Provider(error) => {
            assert_eq!(error.error, "invalid_grant");
            assert_eq!(
                error.error_description.as_deref(),
                Some("The authorization code has expired.")
            );
            assert_eq!(
                error.error_uri.as_deref(),
                Some("https://id.example.org/docs/errors#invalid_grant")
            );
        }
        other => panic!("expected the provider's error, got {other}"),
    }
}

// ---- The ID token (Core §2, §3.1.3.7; RFC 7515 compact form) ----

#[test]
fn id_token_parses_header_claims_signing_input_and_signature() {
    let compact = jws(
        r#"{"alg":"RS256","kid":"k1","typ":"JWT"}"#,
        &claims_json(
            r#","auth_time":1799999990,"azp":"app-1","amr":["pwd","otp"],"acr":"urn:mace:incommon:iap:silver","email":"ada@example.org""#,
        ),
    );
    let token = IdToken::parse(&compact).unwrap();
    assert_eq!(token.header().alg(), "RS256");
    assert_eq!(token.header().kid(), Some("k1"));
    assert_eq!(token.header().typ(), Some("JWT"));
    let claims: &Claims = token.claims();
    assert_eq!(claims.issuer(), ISSUER);
    assert_eq!(claims.subject(), "24400320");
    assert_eq!(claims.audience(), [CLIENT]);
    assert_eq!(claims.expires_at(), NOW + 600);
    assert_eq!(claims.issued_at(), NOW - 5);
    assert_eq!(claims.auth_time(), Some(1_799_999_990));
    assert_eq!(claims.nonce(), Some(nonce().as_str()));
    assert_eq!(claims.authorized_party(), Some(CLIENT));
    assert_eq!(claims.amr(), Some(&["pwd", "otp"].map(String::from)[..]));
    assert_eq!(claims.acr(), Some("urn:mace:incommon:iap:silver"));
    assert_eq!(
        claims.get("email").and_then(|v| v.as_str()),
        Some("ada@example.org")
    );
    assert_eq!(
        claims.get("iss").and_then(|v| v.as_str()),
        Some(ISSUER),
        "registered claims are reachable too"
    );
    let (signing_input, _) = compact.rsplit_once('.').unwrap();
    assert_eq!(token.signing_input(), signing_input.as_bytes());
    assert_eq!(token.signature(), b"signature-bytes");
    assert_eq!(token.compact(), compact);
}

#[test]
fn id_token_audience_may_be_an_array() {
    let compact = jws(
        r#"{"alg":"RS256"}"#,
        &format!(
            r#"{{"iss":"{ISSUER}","sub":"s","aud":["{CLIENT}","other"],"exp":{},"iat":{},"azp":"{CLIENT}"}}"#,
            NOW + 60,
            NOW
        ),
    );
    let token = IdToken::parse(&compact).unwrap();
    assert_eq!(token.claims().audience(), [CLIENT, "other"]);
    assert!(
        token
            .validate_claims(&Expectations::new(ISSUER, CLIENT, NOW))
            .is_ok()
    );
}

#[test]
fn id_token_refuses_malformed_input() {
    for (compact, reason) in [
        ("a.b".to_string(), "two segments"),
        ("a.b.c.d".to_string(), "four segments"),
        (
            jws("{\"alg\":\"RS256\"}", "{\"iss\":1}"),
            "iss not a string",
        ),
        (jws("{\"alg\":\"RS256\"}", "{}"), "missing required claims"),
        (jws("not json", "{}"), "header not JSON"),
        (jws("{}", &claims_json("")), "header without alg"),
        (
            format!("{}.{}.{}", "Zg==", base64url::encode(b"{}"), "c"),
            "padded segment",
        ),
        (
            jws("{\"alg\":\"RS256\"}", &claims_json(",\"exp\":\"soon\"")),
            "exp not a number",
        ),
    ] {
        let error = IdToken::parse(&compact).expect_err(reason);
        assert!(
            matches!(
                error,
                Error::Malformed {
                    what: "ID token",
                    ..
                }
            ),
            "{reason}: {error}"
        );
    }
}

#[test]
fn id_token_claims_validate_against_the_expectations() {
    let nonce = nonce();
    let token = id_token("");
    let claims = token.validate_claims(&expectations(&nonce)).unwrap();
    assert_eq!(claims.subject(), "24400320");
    // an ES256 token is fine when the expectations say so
    let compact = jws(r#"{"alg":"ES256"}"#, &claims_json(""));
    let token = IdToken::parse(&compact).unwrap();
    assert!(
        token
            .validate_claims(&expectations(&nonce).algorithms(&["RS256", "ES256"]))
            .is_ok()
    );
}

#[test]
fn rule_7_refuses_alg_none_and_an_unexpected_alg() {
    let nonce = nonce();
    for alg in ["none", "NONE", "HS256", "ES256"] {
        let compact = jws(&format!(r#"{{"alg":"{alg}"}}"#), &claims_json(""));
        let token = IdToken::parse(&compact).unwrap();
        let rejection = rejected(token.validate_claims(&expectations(&nonce)));
        assert!(
            matches!(rejection, Rejection::Algorithm { alg: ref found, ref expected } if found == alg && expected == &["RS256".to_string()]),
            "{alg}: {rejection}"
        );
    }
    // none is refused even when listed
    let compact = jws(r#"{"alg":"none"}"#, &claims_json(""));
    let token = IdToken::parse(&compact).unwrap();
    assert!(matches!(
        rejected(token.validate_claims(&expectations(&nonce).algorithms(&["none"]))),
        Rejection::Algorithm { .. }
    ));
}

#[test]
fn rule_2_refuses_another_issuer() {
    let nonce = nonce();
    let rejection = rejected(id_token("").validate_claims(
        &Expectations::new("https://other.example.org", CLIENT, NOW).nonce(nonce.as_str()),
    ));
    assert!(
        matches!(rejection, Rejection::Issuer { ref expected, ref found } if expected == "https://other.example.org" && found == ISSUER),
        "{rejection}"
    );
    assert!(rejection.to_string().contains("3.1.3.7"), "{rejection}");
}

#[test]
fn rule_3_refuses_an_audience_without_the_client() {
    let nonce = nonce();
    let rejection = rejected(
        id_token("")
            .validate_claims(&Expectations::new(ISSUER, "app-2", NOW).nonce(nonce.as_str())),
    );
    assert!(
        matches!(rejection, Rejection::Audience { ref client_id, ref audience } if client_id == "app-2" && audience == &[CLIENT.to_string()]),
        "{rejection}"
    );
}

#[test]
fn rules_4_and_5_check_the_authorized_party() {
    let nonce = nonce();
    // azp present and not the client
    let rejection = rejected(id_token(r#","azp":"app-2""#).validate_claims(&expectations(&nonce)));
    assert!(
        matches!(rejection, Rejection::AuthorizedParty { ref client_id, azp: Some(ref azp) } if client_id == CLIENT && azp == "app-2"),
        "{rejection}"
    );
    // several audiences and no azp
    let compact = jws(
        r#"{"alg":"RS256"}"#,
        &format!(
            r#"{{"iss":"{ISSUER}","sub":"s","aud":["{CLIENT}","other"],"exp":{},"iat":{}}}"#,
            NOW + 60,
            NOW
        ),
    );
    let token = IdToken::parse(&compact).unwrap();
    let rejection = rejected(token.validate_claims(&Expectations::new(ISSUER, CLIENT, NOW)));
    assert!(
        matches!(rejection, Rejection::AuthorizedParty { azp: None, .. }),
        "{rejection}"
    );
}

#[test]
fn rule_9_refuses_an_expired_token() {
    let nonce = nonce();
    let token = id_token("");
    let rejection = rejected(
        token.validate_claims(&Expectations::new(ISSUER, CLIENT, NOW + 600).nonce(nonce.as_str())),
    );
    assert!(
        matches!(rejection, Rejection::Expired { exp, now } if exp == NOW + 600 && now == NOW + 600),
        "exp is not before now: {rejection}"
    );
    assert!(
        token
            .validate_claims(
                &Expectations::new(ISSUER, CLIENT, NOW + 599)
                    .nonce(nonce.as_str())
                    .issued_at_skew(1000)
            )
            .is_ok()
    );
}

#[test]
fn rule_10_bounds_the_issued_at_skew() {
    let nonce = nonce();
    let token = id_token("");
    // the default skew is 300 seconds; the fixture is issued 5 seconds before NOW
    assert!(token.validate_claims(&expectations(&nonce)).is_ok());
    let rejection = rejected(token.validate_claims(&expectations(&nonce).issued_at_skew(4)));
    assert!(
        matches!(rejection, Rejection::IssuedAt { iat, now, skew } if iat == NOW - 5 && now == NOW && skew == 4),
        "{rejection}"
    );
    // a token from the future is bounded the same way
    let future = id_token(&format!(r#","iat":{}"#, NOW + 400));
    assert!(matches!(
        rejected(future.validate_claims(&expectations(&nonce))),
        Rejection::IssuedAt { .. }
    ));
    // the future token within the skew is accepted
    assert!(
        id_token(&format!(r#","iat":{}"#, NOW + 300))
            .validate_claims(&expectations(&nonce))
            .is_ok()
    );
}

#[test]
fn rule_11_refuses_a_mismatched_or_missing_nonce() {
    let nonce = nonce();
    let other = Nonce::from_octets(&[1u8; 16]);
    let rejection = rejected(id_token("").validate_claims(&expectations(&other)));
    assert!(
        matches!(rejection, Rejection::Nonce { ref expected, found: Some(ref found) } if expected == other.as_str() && found == nonce.as_str()),
        "{rejection}"
    );
    let compact = jws(
        r#"{"alg":"RS256"}"#,
        &format!(
            r#"{{"iss":"{ISSUER}","sub":"s","aud":"{CLIENT}","exp":{},"iat":{}}}"#,
            NOW + 60,
            NOW
        ),
    );
    let token = IdToken::parse(&compact).unwrap();
    let rejection = rejected(token.validate_claims(&expectations(&nonce)));
    assert!(
        matches!(rejection, Rejection::Nonce { found: None, .. }),
        "{rejection}"
    );
    // no nonce sent, none expected: a nonce in the token is not an error
    assert!(
        id_token("")
            .validate_claims(&Expectations::new(ISSUER, CLIENT, NOW))
            .is_ok()
    );
}

#[test]
fn rule_13_checks_auth_time_when_max_age_was_requested() {
    let nonce = nonce();
    let with_max_age = expectations(&nonce).max_age(300);
    let rejection = rejected(id_token("").validate_claims(&with_max_age));
    assert!(
        matches!(
            rejection,
            Rejection::AuthTime {
                max_age: 300,
                auth_time: None,
                now: NOW
            }
        ),
        "missing: {rejection}"
    );
    let rejection = rejected(
        id_token(&format!(r#","auth_time":{}"#, NOW - 301)).validate_claims(&with_max_age),
    );
    assert!(
        matches!(rejection, Rejection::AuthTime { max_age: 300, auth_time: Some(t), now: NOW } if t == NOW - 301),
        "too old: {rejection}"
    );
    assert!(
        id_token(&format!(r#","auth_time":{}"#, NOW - 300))
            .validate_claims(&with_max_age)
            .is_ok()
    );
}

#[test]
fn pending_authorization_carries_the_expectations() {
    let pending = request().max_age(120).pending();
    let expectations = pending.expectations(NOW);
    assert_eq!(expectations.issuer(), ISSUER);
    assert_eq!(expectations.client_id(), CLIENT);
    assert_eq!(expectations.nonce_expected(), Some(nonce().as_str()));
    assert_eq!(expectations.now(), NOW);
    assert_eq!(expectations.issued_at_skew_allowed(), 300);
    assert_eq!(expectations.algorithms_accepted(), ["RS256"]);
    assert_eq!(expectations.max_age_requested(), Some(120));
    assert!(
        id_token(&format!(r#","auth_time":{}"#, NOW - 100))
            .validate_claims(&expectations)
            .is_ok()
    );
    assert!(matches!(
        rejected(id_token("").validate_claims(&expectations)),
        Rejection::AuthTime { .. }
    ));
}

#[test]
fn errors_display_what_went_wrong() {
    let error = Error::Malformed {
        what: "ID token",
        reason: "two segments, not three".into(),
    };
    assert_eq!(
        error.to_string(),
        "malformed ID token: two segments, not three"
    );
    let rejection = Rejection::Expired { exp: 10, now: 20 };
    assert_eq!(
        rejection.to_string(),
        "OpenID Connect Core 1.0 §3.1.3.7 rule 9: the ID token expired at 10, now is 20"
    );
    assert_eq!(
        Error::Rejected(rejection).to_string(),
        "OpenID Connect Core 1.0 §3.1.3.7 rule 9: the ID token expired at 10, now is 20"
    );
    assert!(
        std::error::Error::source(&Error::Malformed {
            what: "x",
            reason: String::new()
        })
        .is_none()
    );
}
