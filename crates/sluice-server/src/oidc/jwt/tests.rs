use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::json;

use super::*;

/// A P-256 key and its JWKS, for signing test tokens.
pub(crate) struct TestKey {
    pair: EcdsaKeyPair,
    pub(crate) jwks: Value,
}

impl TestKey {
    pub(crate) fn new(kid: &str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("key");
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .expect("pair");
        let point = pair.public_key().as_ref();
        let jwks = json!({ "keys": [{
            "kty": "EC", "crv": "P-256", "kid": kid, "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
        }]});
        Self { pair, jwks }
    }

    pub(crate) fn sign(&self, header: &Value, claims: &Value) -> String {
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let sig = self
            .pair
            .sign(&SystemRandom::new(), signed.as_bytes())
            .expect("signed");
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
    }
}

fn claims() -> Value {
    json!({ "iss": "https://idp.example", "aud": "sluice", "exp": 2_000, "nonce": "n1",
            "email": "alice@example.org" })
}

fn expected() -> Expected<'static> {
    Expected {
        issuer: "https://idp.example",
        client_id: "sluice",
        nonce: "n1",
        now: 1_000,
    }
}

fn keys(key: &TestKey) -> JwkSet {
    serde_json::from_value(key.jwks.clone()).expect("jwks")
}

#[test]
fn a_valid_token_yields_its_claims() {
    let key = TestKey::new("k1");
    let token = key.sign(&json!({ "alg": "ES256", "kid": "k1" }), &claims());
    let claims = verify(&token, &keys(&key), expected()).expect("valid");
    assert_eq!(claims["email"], "alice@example.org");
}

#[test]
fn every_broken_token_is_refused() {
    let key = TestKey::new("k1");
    let other = TestKey::new("k1");
    let header = json!({ "alg": "ES256", "kid": "k1" });
    let wrong = |change: &dyn Fn(&mut Value)| {
        let mut c = claims();
        change(&mut c);
        verify(&key.sign(&header, &c), &keys(&key), expected())
    };
    assert!(matches!(
        wrong(&|c| c["iss"] = json!("https://evil.example")),
        Err(JwtError::Claim(_))
    ));
    assert!(matches!(
        wrong(&|c| c["aud"] = json!("other")),
        Err(JwtError::Claim(_))
    ));
    assert!(
        wrong(&|c| c["aud"] = json!(["sluice", "x"])).is_ok(),
        "azp is optional"
    );
    assert!(matches!(
        wrong(&|c| {
            c["aud"] = json!(["sluice", "x"]);
            c["azp"] = json!("x");
        }),
        Err(JwtError::Claim(_))
    ));
    assert!(matches!(
        wrong(&|c| c["exp"] = json!(900)),
        Err(JwtError::Claim(_))
    ));
    assert!(matches!(
        wrong(&|c| c["nbf"] = json!(1_100)),
        Err(JwtError::Claim(_))
    ));
    assert!(matches!(
        wrong(&|c| c["nonce"] = json!("replayed")),
        Err(JwtError::Claim(_))
    ));

    let forged = other.sign(&header, &claims());
    assert_eq!(
        verify(&forged, &keys(&key), expected()),
        Err(JwtError::Signature)
    );
    let unknown = key.sign(&json!({ "alg": "ES256", "kid": "k2" }), &claims());
    assert_eq!(
        verify(&unknown, &keys(&key), expected()),
        Err(JwtError::UnknownKey)
    );
    for alg in ["none", "HS256", "RS512"] {
        let token = key.sign(&json!({ "alg": alg, "kid": "k1" }), &claims());
        assert_eq!(
            verify(&token, &keys(&key), expected()),
            Err(JwtError::Algorithm(alg.into()))
        );
    }
    assert_eq!(
        verify("a.b", &keys(&key), expected()),
        Err(JwtError::Malformed)
    );
}

fn with(change: &dyn Fn(&mut Value)) -> Result<Map<String, Value>, JwtError> {
    let key = TestKey::new("k1");
    let mut c = claims();
    change(&mut c);
    verify(
        &key.sign(&json!({ "alg": "ES256", "kid": "k1" }), &c),
        &keys(&key),
        expected(),
    )
}

#[test]
fn the_leeway_is_sixty_seconds_each_way() {
    // now is 1000.
    assert!(with(&|c| c["exp"] = json!(941)).is_ok());
    assert!(with(&|c| c["exp"] = json!(940)).is_err());
    assert!(with(&|c| c["nbf"] = json!(1_060)).is_ok());
    assert!(with(&|c| c["nbf"] = json!(1_061)).is_err());
}

#[test]
fn required_claims_must_be_there_and_of_the_right_type() {
    for claim in ["iss", "aud", "exp", "nonce"] {
        assert!(
            with(&|c| {
                c.as_object_mut().expect("object").remove(claim);
            })
            .is_err(),
            "{claim}"
        );
    }
    assert!(with(&|c| c["exp"] = json!("2000")).is_err(), "a string");
    assert!(with(&|c| c["exp"] = json!(2_000.5)).is_err(), "a float");
    assert!(with(&|c| c["aud"] = json!([1, "x"])).is_err());
    assert!(
        with(&|c| {
            c["aud"] = json!(["sluice"]);
            c["azp"] = json!("x");
        })
        .is_ok(),
        "azp only matters with several audiences"
    );
}

#[test]
fn a_changed_payload_breaks_the_signature() {
    let key = TestKey::new("k1");
    let token = key.sign(&json!({ "alg": "ES256", "kid": "k1" }), &claims());
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    let mut forged = claims();
    forged["email"] = json!("mallory@example.org");
    parts[1] = URL_SAFE_NO_PAD.encode(forged.to_string());
    assert_eq!(
        verify(&parts.join("."), &keys(&key), expected()),
        Err(JwtError::Signature)
    );
    assert_eq!(
        verify(&format!("{token}.extra"), &keys(&key), expected()),
        Err(JwtError::Malformed)
    );
}

#[test]
fn a_key_is_chosen_only_when_exactly_one_fits() {
    let key = TestKey::new("k1");
    let second = TestKey::new("k2");
    let no_kid = key.sign(&json!({ "alg": "ES256" }), &claims());
    assert!(verify(&no_kid, &keys(&key), expected()).is_ok(), "one key");
    let mut both = keys(&key);
    both.keys.extend(keys(&second).keys);
    assert_eq!(
        verify(&no_kid, &both, expected()),
        Err(JwtError::UnknownKey),
        "two keys and no kid: ambiguous"
    );

    let mut encryption = key.jwks.clone();
    encryption["keys"][0]["use"] = json!("enc");
    let encryption: JwkSet = serde_json::from_value(encryption).expect("jwks");
    let token = key.sign(&json!({ "alg": "ES256", "kid": "k1" }), &claims());
    assert_eq!(
        verify(&token, &encryption, expected()),
        Err(JwtError::UnknownKey)
    );

    let rs = key.sign(&json!({ "alg": "RS256", "kid": "k1" }), &claims());
    assert_eq!(
        verify(&rs, &keys(&key), expected()),
        Err(JwtError::UnknownKey),
        "an EC key is never used for RS256"
    );

    let mut other_curve = key.jwks.clone();
    other_curve["keys"][0]["crv"] = json!("P-384");
    let other_curve: JwkSet = serde_json::from_value(other_curve).expect("jwks");
    assert_eq!(
        verify(&token, &other_curve, expected()),
        Err(JwtError::UnknownKey)
    );
}
