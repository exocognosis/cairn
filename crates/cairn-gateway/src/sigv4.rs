//! Verification of AWS Signature Version 4 on incoming KMS requests.
//!
//! pqc-sidecar's `aws_kms` backend signs every request with SigV4 using whatever credentials
//! its environment provides. Giving `cairn serve-kms` the same access key id and secret makes
//! the endpoint accept only requests signed with them, with no change to the sidecar.
//!
//! This authenticates the caller and the request body. It does not encrypt: put TLS in front,
//! or keep the endpoint on loopback, if the path between sidecar and endpoint is not trusted.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Credentials the endpoint accepts.
#[derive(Clone)]
pub struct KmsAuth {
    pub access_key_id: String,
    pub secret_access_key: String,
    /// How far a request's `x-amz-date` may be from this host's clock.
    pub max_skew: Duration,
}

impl KmsAuth {
    pub fn new(access_key_id: String, secret_access_key: String) -> Self {
        Self {
            access_key_id,
            secret_access_key,
            max_skew: Duration::from_secs(300),
        }
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `YYYYMMDDTHHMMSSZ` to seconds since the epoch.
fn parse_amz_date(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (num(0..4)?, num(4..6)?, num(6..8)?);
    let (hh, mm, ss) = (num(9..11)?, num(11..13)?, num(13..15)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Days from civil (proleptic Gregorian).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hh * 3600 + mm * 60 + ss).ok()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Check a request's SigV4 `Authorization` header. `headers` are (name, value) pairs as
/// received. Returns the reason on failure (for the log, not for the caller).
pub fn verify(
    auth: &KmsAuth,
    method: &str,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    body: &[u8],
    now: SystemTime,
) -> Result<(), &'static str> {
    let header = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim().to_string())
    };
    let authorization = header("authorization").ok_or("no Authorization header")?;
    let rest = authorization
        .strip_prefix("AWS4-HMAC-SHA256")
        .ok_or("not AWS4-HMAC-SHA256")?;
    let (mut credential, mut signed_headers, mut signature) = (None, None, None);
    for part in rest.split(',') {
        match part.trim().split_once('=') {
            Some(("Credential", v)) => credential = Some(v),
            Some(("SignedHeaders", v)) => signed_headers = Some(v),
            Some(("Signature", v)) => signature = Some(v),
            _ => {}
        }
    }
    let (credential, signed_headers, signature) = (
        credential.ok_or("no Credential")?,
        signed_headers.ok_or("no SignedHeaders")?,
        signature.ok_or("no Signature")?,
    );
    let scope: Vec<&str> = credential.split('/').collect();
    let [key_id, date, region, service, terminator] = scope[..] else {
        return Err("malformed credential scope");
    };
    if terminator != "aws4_request" || service != "kms" {
        return Err("credential scope is not for kms");
    }
    if !constant_time_eq(key_id.as_bytes(), auth.access_key_id.as_bytes()) {
        return Err("unknown access key id");
    }
    let amz_date = header("x-amz-date").ok_or("no x-amz-date")?;
    if !amz_date.starts_with(date) {
        return Err("x-amz-date does not match the credential date");
    }
    let stamp = parse_amz_date(&amz_date).ok_or("malformed x-amz-date")?;
    let now = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock before epoch")?
        .as_secs();
    if now.abs_diff(stamp) > auth.max_skew.as_secs() {
        return Err("request timestamp outside the allowed window");
    }
    let names: Vec<&str> = signed_headers.split(';').collect();
    if !names.contains(&"host") || !names.contains(&"x-amz-date") {
        return Err("host and x-amz-date must be signed");
    }
    let mut canonical_headers = String::new();
    for name in &names {
        let value = header(name).ok_or("a signed header is missing")?;
        let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
        canonical_headers.push_str(&format!("{name}:{value}\n"));
    }
    let canonical_request = format!(
        "{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{}",
        hex(&Sha256::digest(body))
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{date}/{region}/{service}/aws4_request\n{}",
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );
    let k_date = hmac(
        format!("AWS4{}", auth.secret_access_key).as_bytes(),
        date.as_bytes(),
    );
    let k_signing = hmac(
        &hmac(&hmac(&k_date, region.as_bytes()), service.as_bytes()),
        b"aws4_request",
    );
    let expected = hex(&hmac(&k_signing, string_to_sign.as_bytes()));
    if constant_time_eq(expected.as_bytes(), signature.as_bytes()) {
        Ok(())
    } else {
        Err("signature mismatch")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(secret: &str, body: &[u8], date: &str) -> (Vec<(String, String)>, SystemTime) {
        // Build a correctly signed request the long way round, then verify it.
        let amz = format!("{date}T120000Z");
        let headers_to_sign = [
            ("host", "127.0.0.1:8200"),
            ("x-amz-date", amz.as_str()),
            ("x-amz-target", "TrentService.Sign"),
        ];
        let canonical_headers: String = headers_to_sign
            .iter()
            .map(|(n, v)| format!("{n}:{v}\n"))
            .collect();
        let signed = "host;x-amz-date;x-amz-target";
        let canonical = format!(
            "POST\n/\n\n{canonical_headers}\n{signed}\n{}",
            hex(&Sha256::digest(body))
        );
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz}\n{date}/us-east-1/kms/aws4_request\n{}",
            hex(&Sha256::digest(canonical.as_bytes()))
        );
        let k = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
        let k = hmac(&hmac(&hmac(&k, b"us-east-1"), b"kms"), b"aws4_request");
        let signature = hex(&hmac(&k, to_sign.as_bytes()));
        let mut headers: Vec<(String, String)> = headers_to_sign
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        headers.push((
            "Authorization".into(),
            format!("AWS4-HMAC-SHA256 Credential=AKIDTEST/{date}/us-east-1/kms/aws4_request, SignedHeaders={signed}, Signature={signature}"),
        ));
        let now = UNIX_EPOCH + Duration::from_secs(parse_amz_date(&amz).unwrap() + 30);
        (headers, now)
    }

    #[test]
    fn dates_parse() {
        assert_eq!(parse_amz_date("19700101T000000Z"), Some(0));
        assert_eq!(parse_amz_date("20150830T123600Z"), Some(1_440_938_160));
        assert_eq!(parse_amz_date("20240229T000000Z"), Some(1_709_164_800));
        assert!(parse_amz_date("2015-08-30T12:36Z").is_none());
    }

    #[test]
    fn accepts_a_signed_request_and_rejects_changes() {
        let auth = KmsAuth::new("AKIDTEST".into(), "secret".into());
        let (headers, now) = request("secret", b"{\"KeyId\":\"k\"}", "20261125");
        assert_eq!(
            verify(&auth, "POST", "/", "", &headers, b"{\"KeyId\":\"k\"}", now),
            Ok(())
        );
        // A different body, secret, key id or a stale clock all fail.
        assert!(verify(&auth, "POST", "/", "", &headers, b"{\"KeyId\":\"x\"}", now).is_err());
        let wrong = KmsAuth::new("AKIDTEST".into(), "other".into());
        assert_eq!(
            verify(&wrong, "POST", "/", "", &headers, b"{\"KeyId\":\"k\"}", now),
            Err("signature mismatch")
        );
        let other_id = KmsAuth::new("AKIDOTHER".into(), "secret".into());
        assert!(verify(
            &other_id,
            "POST",
            "/",
            "",
            &headers,
            b"{\"KeyId\":\"k\"}",
            now
        )
        .is_err());
        let late = now + Duration::from_secs(3600);
        assert_eq!(
            verify(&auth, "POST", "/", "", &headers, b"{\"KeyId\":\"k\"}", late),
            Err("request timestamp outside the allowed window")
        );
        assert!(verify(
            &auth,
            "POST",
            "/",
            "",
            &headers[..3],
            b"{\"KeyId\":\"k\"}",
            now
        )
        .is_err());
    }
}
