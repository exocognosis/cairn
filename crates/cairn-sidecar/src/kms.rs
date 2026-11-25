//! KMS-compatible signing endpoint.
//!
//! pqc-sidecar already has an `aws_kms` signer backend with an endpoint override
//! (`aws_endpoint_url`). This module answers the two KMS JSON-protocol calls that backend makes
//! (`TrentService.GetPublicKey`, `TrentService.Sign` with `MessageType = RAW` and
//! `ML_DSA_SHAKE_256`) from the tower. An unmodified pqc-sidecar pointed at it keeps doing
//! everything it does today (chain watching, finality checks, certificate writing, self-verify)
//! while every signature comes from the committee tower.
//!
//! Requests are not authenticated (SigV4 headers are ignored): bind to loopback or a private
//! interface only.

use crate::certifier::TowerCertifier;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::io::Read as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread::JoinHandle;
use threshold_mldsa::AttemptEngine;
use threshold_mldsa::{PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
use tiny_http::{Header, Response, Server};

/// DER SubjectPublicKeyInfo header for ML-DSA-65 (OID 2.16.840.1.101.3.4.3.18).
pub const SPKI_PREFIX: [u8; 22] = [
    0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
    0x12, 0x03, 0x82, 0x07, 0xa1, 0x00,
];

/// Largest message KMS accepts with `MessageType = RAW`.
pub const MAX_RAW_MESSAGE: usize = 4096;

/// Whatever produces signatures behind the endpoint: the in-process tower or a TCP cluster.
pub trait KmsSigner: Send + 'static {
    fn public_key(&self) -> [u8; PUBLIC_KEY_BYTES];
    fn sign(&mut self, message: &[u8]) -> Result<[u8; SIGNATURE_BYTES], String>;
}

impl<E: AttemptEngine + Send + 'static> KmsSigner for TowerCertifier<E> {
    fn public_key(&self) -> [u8; PUBLIC_KEY_BYTES] {
        *TowerCertifier::public_key(self)
    }

    fn sign(&mut self, message: &[u8]) -> Result<[u8; SIGNATURE_BYTES], String> {
        self.sign_message(message)
            .map(|s| s.signature)
            .map_err(|e| e.to_string())
    }
}

/// Finished signatures by message digest.
type Cache = std::collections::HashMap<[u8; 32], Box<[u8; SIGNATURE_BYTES]>>;
const SIGNATURE_CACHE: usize = 256;

pub struct KmsEndpoint {
    pub addr: SocketAddr,
    server: Arc<Server>,
    worker: Option<JoinHandle<()>>,
}

impl KmsEndpoint {
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Block until the endpoint is shut down.
    pub fn join(mut self) {
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

impl Drop for KmsEndpoint {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

fn handle(
    certifier: &mut dyn KmsSigner,
    cache: &mut Cache,
    target: &str,
    body: &[u8],
) -> (u16, Value) {
    let error = |code: &str, msg: &str| (400, json!({ "__type": code, "message": msg }));
    let req: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let key = req["KeyId"].as_str().unwrap_or("").to_owned();
    match target {
        "TrentService.GetPublicKey" => {
            let der = [SPKI_PREFIX.as_slice(), &certifier.public_key()].concat();
            (
                200,
                json!({
                    "KeyId": key,
                    "PublicKey": B64.encode(der),
                    "KeySpec": "ML_DSA_65",
                    "KeyUsage": "SIGN_VERIFY",
                    "SigningAlgorithms": ["ML_DSA_SHAKE_256"],
                }),
            )
        }
        "TrentService.Sign" => {
            if req["MessageType"] != "RAW" || req["SigningAlgorithm"] != "ML_DSA_SHAKE_256" {
                return error(
                    "ValidationException",
                    "only RAW messages with ML_DSA_SHAKE_256",
                );
            }
            let Some(message) = req["Message"].as_str().and_then(|s| B64.decode(s).ok()) else {
                return error("ValidationException", "Message is not base64");
            };
            if message.len() > MAX_RAW_MESSAGE {
                return error("ValidationException", "Message longer than 4096 bytes");
            }
            // Signing is deterministic, so a finished signature can answer any later request for
            // the same message. pqc-sidecar's KMS client gives up on a call after a few seconds
            // and retries; with a slow MPC backend the retry finds the result here instead of
            // starting the session again.
            let digest: [u8; 32] = Sha3_256::digest(&message).into();
            let signed = match cache.get(&digest) {
                Some(signature) => Ok(**signature),
                None => certifier.sign(&message),
            };
            match signed {
                Ok(signed) => {
                    if cache.len() >= SIGNATURE_CACHE {
                        cache.clear();
                    }
                    cache.insert(digest, Box::new(signed));
                    (
                        200,
                        json!({
                            "KeyId": key,
                            "Signature": B64.encode(signed),
                            "SigningAlgorithm": "ML_DSA_SHAKE_256",
                        }),
                    )
                }
                // The tower could not sign (quorum lost, retries exhausted). Retryable.
                Err(e) => (
                    500,
                    json!({ "__type": "KMSInternalException", "message": e }),
                ),
            }
        }
        _ => error("UnknownOperationException", "unsupported operation"),
    }
}

/// Serve the KMS-compatible API on `listen` (use port 0 for an ephemeral port).
pub fn serve(listen: &str, certifier: impl KmsSigner) -> std::io::Result<KmsEndpoint> {
    serve_with(listen, certifier, None)
}

/// Serve the KMS-compatible API. With `auth`, every request must carry a valid AWS SigV4
/// signature for those credentials. Without it, the endpoint refuses to bind anywhere but
/// loopback: an unauthenticated signing endpoint must not be reachable from another machine.
pub fn serve_with(
    listen: &str,
    mut certifier: impl KmsSigner,
    auth: Option<crate::sigv4::KmsAuth>,
) -> std::io::Result<KmsEndpoint> {
    let server = Arc::new(Server::http(listen).map_err(std::io::Error::other)?);
    let addr = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| std::io::Error::other("not an IP listener"))?;
    if auth.is_none() && !addr.ip().is_loopback() {
        return Err(std::io::Error::other(
            "refusing to serve unauthenticated KMS requests on a non-loopback address; \
             configure credentials (--access-key-id) or bind to 127.0.0.1",
        ));
    }
    let worker = {
        let server = server.clone();
        std::thread::spawn(move || {
            let mut cache = Cache::new();
            for mut request in server.incoming_requests() {
                let target = request
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("x-amz-target"))
                    .map(|h| h.value.as_str().to_owned())
                    .unwrap_or_default();
                let mut body = Vec::new();
                if request
                    .as_reader()
                    .take(64 * 1024)
                    .read_to_end(&mut body)
                    .is_err()
                {
                    continue;
                }
                if let Some(auth) = &auth {
                    let headers: Vec<(String, String)> = request
                        .headers()
                        .iter()
                        .map(|h| {
                            (
                                h.field.as_str().as_str().to_owned(),
                                h.value.as_str().to_owned(),
                            )
                        })
                        .collect();
                    let url = request.url().to_owned();
                    let (path, query) = url.split_once('?').unwrap_or((&url, ""));
                    let method = request.method().as_str().to_owned();
                    if let Err(reason) = crate::sigv4::verify(
                        auth,
                        &method,
                        path,
                        query,
                        &headers,
                        &body,
                        std::time::SystemTime::now(),
                    ) {
                        eprintln!("cairn kms: rejected request ({reason})");
                        let denied = json!({ "__type": "UnrecognizedClientException", "message": "request signature is not valid" });
                        let _ = request.respond(
                            Response::from_string(denied.to_string()).with_status_code(403),
                        );
                        continue;
                    }
                }
                let (status, value) = handle(&mut certifier, &mut cache, &target, &body);
                let header = Header::from_bytes("Content-Type", "application/x-amz-json-1.1")
                    .expect("static header");
                let _ = request.respond(
                    Response::from_string(value.to_string())
                        .with_status_code(status)
                        .with_header(header),
                );
            }
        })
    };
    Ok(KmsEndpoint {
        addr,
        server,
        worker: Some(worker),
    })
}
