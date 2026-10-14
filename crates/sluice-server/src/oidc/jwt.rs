//! ID token verification for single sign-on (ADR 0016): the signature against the provider's
//! published keys (RS256 or ES256, with ring), and the claims the OIDC specification requires a
//! client to check. Anything else is refused: `alg: none`, HMAC, unknown keys, wrong issuer or audience,
//! expired tokens and a nonce that does not match the login.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use serde::Deserialize;
use serde_json::{Map, Value};

/// Seconds of clock difference tolerated between Sluice and the provider.
const LEEWAY: i64 = 60;

/// A provider's published signing key (one entry of its JWKS).
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Jwk {
    kty: String,
    kid: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    n: Option<String>,
    e: Option<String>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

/// A provider's JWKS document.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct JwkSet {
    pub(crate) keys: Vec<Jwk>,
}

/// What the token must say.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Expected<'a> {
    pub(crate) issuer: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) nonce: &'a str,
    pub(crate) now: i64,
}

/// Why a token was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum JwtError {
    /// Not three base64url parts with JSON header and claims.
    #[error("malformed token")]
    Malformed,
    /// An algorithm other than RS256 or ES256.
    #[error("unsupported signing algorithm {0}")]
    Algorithm(String),
    /// No published key fits; the caller may refresh the keys once.
    #[error("no matching signing key")]
    UnknownKey,
    /// The signature does not verify.
    #[error("bad signature")]
    Signature,
    /// A claim does not hold.
    #[error("{0}")]
    Claim(&'static str),
}

/// Verifies `token` and returns its claims.
pub(crate) fn verify(
    token: &str,
    keys: &JwkSet,
    expected: Expected<'_>,
) -> Result<Map<String, Value>, JwtError> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwtError::Malformed);
    };
    let header: Map<String, Value> = json_part(header)?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let kty = match alg {
        "RS256" => "RSA",
        "ES256" => "EC",
        other => return Err(JwtError::Algorithm(other.to_owned())),
    };
    let kid = header.get("kid").and_then(Value::as_str);
    let candidates: Vec<&Jwk> = keys
        .keys
        .iter()
        .filter(|k| k.kty == kty && k.usage.as_deref().is_none_or(|u| u == "sig"))
        .filter(|k| kid.is_none() || k.kid.as_deref() == kid)
        .collect();
    let [key] = candidates.as_slice() else {
        return Err(JwtError::UnknownKey);
    };
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| JwtError::Malformed)?;
    let signed = &token[..header_and_payload_len(token)];
    check_signature(alg, key, signed.as_bytes(), &signature)?;
    let claims: Map<String, Value> = json_part(payload)?;
    check_claims(&claims, expected)?;
    Ok(claims)
}

fn header_and_payload_len(token: &str) -> usize {
    token.rfind('.').unwrap_or(token.len())
}

fn json_part<T: serde::de::DeserializeOwned>(part: &str) -> Result<T, JwtError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| JwtError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| JwtError::Malformed)
}

fn decoded(value: Option<&String>) -> Result<Vec<u8>, JwtError> {
    let value = value.ok_or(JwtError::UnknownKey)?;
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| JwtError::UnknownKey)
}

fn check_signature(alg: &str, key: &Jwk, signed: &[u8], sig: &[u8]) -> Result<(), JwtError> {
    let verified = if alg == "RS256" {
        let n = decoded(key.n.as_ref())?;
        let e = decoded(key.e.as_ref())?;
        RsaPublicKeyComponents { n: &n, e: &e }.verify(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            signed,
            sig,
        )
    } else {
        if key.crv.as_deref() != Some("P-256") {
            return Err(JwtError::UnknownKey);
        }
        let mut point = vec![0x04];
        point.extend(decoded(key.x.as_ref())?);
        point.extend(decoded(key.y.as_ref())?);
        UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point).verify(signed, sig)
    };
    verified.map_err(|_| JwtError::Signature)
}

fn check_claims(claims: &Map<String, Value>, expected: Expected<'_>) -> Result<(), JwtError> {
    if claims.get("iss").and_then(Value::as_str) != Some(expected.issuer) {
        return Err(JwtError::Claim("the token is from another issuer"));
    }
    let audience: Vec<&str> = match claims.get("aud") {
        Some(Value::String(one)) => vec![one.as_str()],
        Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if !audience.contains(&expected.client_id) {
        return Err(JwtError::Claim("the token is for another client"));
    }
    if audience.len() > 1
        && claims
            .get("azp")
            .and_then(Value::as_str)
            .is_some_and(|azp| azp != expected.client_id)
    {
        return Err(JwtError::Claim("the token was issued to another party"));
    }
    let time = |name: &str| claims.get(name).and_then(Value::as_i64);
    match time("exp") {
        Some(exp) if exp + LEEWAY > expected.now => {}
        _ => return Err(JwtError::Claim("the token has expired")),
    }
    if time("nbf").is_some_and(|nbf| nbf - LEEWAY > expected.now) {
        return Err(JwtError::Claim("the token is not valid yet"));
    }
    if claims.get("nonce").and_then(Value::as_str) != Some(expected.nonce) {
        return Err(JwtError::Claim("the token does not belong to this login"));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
