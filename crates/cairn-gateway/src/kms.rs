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

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
pub use cairn_core::ThresholdSigner as KmsSigner;
use cairn_core::SIGNATURE_BYTES;
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::io::Read as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use tiny_http::{Header, Response, Server};

/// DER SubjectPublicKeyInfo header for ML-DSA-65 (OID 2.16.840.1.101.3.4.3.18).
pub const SPKI_PREFIX: [u8; 22] = [
    0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
    0x12, 0x03, 0x82, 0x07, 0xa1, 0x00,
];

/// Largest message KMS accepts with `MessageType = RAW`.
pub const MAX_RAW_MESSAGE: usize = 4096;

/// Finished signatures by message digest, with when each was made.
type Cache = std::collections::HashMap<[u8; 32], (std::time::Instant, Box<[u8; SIGNATURE_BYTES]>)>;
const SIGNATURE_CACHE: usize = 256;
/// How long a finished signature answers repeats of its request unless told otherwise.
pub const DEFAULT_CACHE_SECS: u64 = 120;

pub struct KmsEndpoint {
    pub addr: SocketAddr,
    server: Arc<Server>,
    worker: Option<JoinHandle<()>>,
    /// Runs the TLS front when one is configured; dropping it stops the front.
    front: Option<tokio::runtime::Runtime>,
}

/// How the endpoint is exposed.
#[derive(Default)]
pub struct KmsOptions {
    /// AWS SigV4 credentials every request must be signed with.
    pub auth: Option<crate::sigv4::KmsAuth>,
    /// Serve HTTPS on the listen address. The HTTP server itself then binds loopback only.
    pub tls: Option<crate::tls::ServerTls>,
    /// Counters to update, usually also given to [`serve_metrics`].
    pub metrics: Option<Arc<Metrics>>,
    /// For how many seconds a finished signature answers a repeat of its request without the
    /// signers being asked again. `None` is [`DEFAULT_CACHE_SECS`]; 0 asks them every time.
    pub cache_secs: Option<u64>,
}

/// Counters for the KMS endpoint, readable in Prometheus text format.
#[derive(Default)]
pub struct Metrics {
    requests: AtomicU64,
    rejected_auth: AtomicU64,
    signatures: AtomicU64,
    sign_failures: AtomicU64,
    cache_hits: AtomicU64,
    sign_micros: AtomicU64,
    last_sign_unix: AtomicU64,
    started: Option<std::time::Instant>,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            started: Some(std::time::Instant::now()),
            ..Self::default()
        })
    }

    pub fn render(&self) -> String {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        let rows: [(&str, &str, &str, String); 8] = [
            (
                "cairn_kms_requests_total",
                "counter",
                "KMS API requests received",
                get(&self.requests).to_string(),
            ),
            (
                "cairn_kms_rejected_auth_total",
                "counter",
                "Requests refused for a bad SigV4 signature",
                get(&self.rejected_auth).to_string(),
            ),
            (
                "cairn_kms_signatures_total",
                "counter",
                "Signatures produced by the signer (not from cache)",
                get(&self.signatures).to_string(),
            ),
            (
                "cairn_kms_sign_failures_total",
                "counter",
                "Sign requests the signer failed or refused",
                get(&self.sign_failures).to_string(),
            ),
            (
                "cairn_kms_cache_hits_total",
                "counter",
                "Sign requests answered from the signature cache",
                get(&self.cache_hits).to_string(),
            ),
            (
                "cairn_kms_sign_seconds_total",
                "counter",
                "Time spent producing signatures",
                format!("{:.6}", get(&self.sign_micros) as f64 / 1e6),
            ),
            (
                "cairn_kms_last_signature_timestamp_seconds",
                "gauge",
                "Unix time of the last signature, 0 if none",
                get(&self.last_sign_unix).to_string(),
            ),
            (
                "cairn_kms_uptime_seconds",
                "gauge",
                "Seconds since the endpoint started",
                self.started
                    .map_or(0, |s| s.elapsed().as_secs())
                    .to_string(),
            ),
        ];
        rows.iter()
            .map(|(name, kind, help, value)| {
                format!("# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n")
            })
            .collect()
    }
}

/// Serve `/metrics` (Prometheus text) and `/healthz` on `listen`. Plain HTTP with no
/// authentication: bind it to loopback or a private interface.
pub fn serve_metrics(listen: &str, metrics: Arc<Metrics>) -> std::io::Result<SocketAddr> {
    serve_text_metrics(listen, move || metrics.render())
}

/// Serve `/metrics` (whatever `render` returns) and `/healthz` on `listen`.
pub fn serve_text_metrics(
    listen: &str,
    render: impl Fn() -> String + Send + 'static,
) -> std::io::Result<SocketAddr> {
    let server = Server::http(listen).map_err(std::io::Error::other)?;
    let addr = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| std::io::Error::other("not an IP listener"))?;
    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            let response = match request.url() {
                "/metrics" => Response::from_string(render()),
                "/healthz" => Response::from_string("ok\n"),
                _ => Response::from_string("not found\n").with_status_code(404),
            };
            let _ = request.respond(response);
        }
    });
    Ok(addr)
}

impl KmsEndpoint {
    pub fn url(&self) -> String {
        let scheme = if self.front.is_some() {
            "https"
        } else {
            "http"
        };
        format!("{scheme}://{}", self.addr)
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
    cache_ttl: std::time::Duration,
    metrics: &Metrics,
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
            // pqc-sidecar's KMS client gives up on a call after a few seconds and retries; with a
            // slow MPC backend the retry finds the finished signature here instead of starting
            // the session again. An answer from here does not ask the signers' policies, so it
            // is kept only for `cache_ttl`: after that the signers decide again.
            let digest: [u8; 32] = Sha3_256::digest(&message).into();
            cache.retain(|_, (made, _)| made.elapsed() < cache_ttl);
            let signed = match cache.get(&digest) {
                Some((_, signature)) => {
                    metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                    Ok(**signature)
                }
                None => {
                    let started = std::time::Instant::now();
                    let signed = certifier.sign(&message);
                    let outcome = if signed.is_ok() {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_or(0, |d| d.as_secs());
                        metrics.last_sign_unix.store(now, Ordering::Relaxed);
                        metrics
                            .sign_micros
                            .fetch_add(started.elapsed().as_micros() as u64, Ordering::Relaxed);
                        &metrics.signatures
                    } else {
                        &metrics.sign_failures
                    };
                    outcome.fetch_add(1, Ordering::Relaxed);
                    if let (Ok(signed), false) = (&signed, cache_ttl.is_zero()) {
                        if cache.len() >= SIGNATURE_CACHE {
                            cache.clear();
                        }
                        cache.insert(digest, (std::time::Instant::now(), Box::new(*signed)));
                    }
                    signed
                }
            };
            match signed {
                Ok(signed) => (
                    200,
                    json!({
                        "KeyId": key,
                        "Signature": B64.encode(signed),
                        "SigningAlgorithm": "ML_DSA_SHAKE_256",
                    }),
                ),
                // The tower could not sign (quorum lost, retries exhausted). Retryable.
                Err(e) => (
                    500,
                    json!({ "__type": "KMSInternalException", "message": e.to_string() }),
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
    certifier: impl KmsSigner,
    auth: Option<crate::sigv4::KmsAuth>,
) -> std::io::Result<KmsEndpoint> {
    serve_opts(
        listen,
        certifier,
        KmsOptions {
            auth,
            ..KmsOptions::default()
        },
    )
}

/// Serve the KMS-compatible API with every option. With `tls`, `listen` speaks HTTPS and the
/// HTTP server behind it is reachable on loopback only.
pub fn serve_opts(
    listen: &str,
    mut certifier: impl KmsSigner,
    options: KmsOptions,
) -> std::io::Result<KmsEndpoint> {
    let KmsOptions {
        auth,
        tls,
        metrics,
        cache_secs,
    } = options;
    let cache_ttl = std::time::Duration::from_secs(cache_secs.unwrap_or(DEFAULT_CACHE_SECS));
    let metrics = metrics.unwrap_or_else(Metrics::new);
    let inner = if tls.is_some() { "127.0.0.1:0" } else { listen };
    let server = Arc::new(Server::http(inner).map_err(std::io::Error::other)?);
    let mut addr = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| std::io::Error::other("not an IP listener"))?;
    let mut front = None;
    if let Some(tls) = tls {
        let listener = std::net::TcpListener::bind(listen)?;
        listener.set_nonblocking(true)?;
        let backend = addr;
        addr = listener.local_addr()?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;
        runtime.spawn(async move {
            match tokio::net::TcpListener::from_std(listener) {
                Ok(listener) => tls.terminate(listener, backend).await,
                Err(e) => eprintln!("cairn kms: TLS listener: {e}"),
            }
        });
        front = Some(runtime);
    }
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
                metrics.requests.fetch_add(1, Ordering::Relaxed);
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
                        metrics.rejected_auth.fetch_add(1, Ordering::Relaxed);
                        eprintln!("cairn kms: rejected request ({reason})");
                        let denied = json!({ "__type": "UnrecognizedClientException", "message": "request signature is not valid" });
                        let _ = request.respond(
                            Response::from_string(denied.to_string()).with_status_code(403),
                        );
                        continue;
                    }
                }
                let (status, value) = handle(
                    &mut certifier,
                    &mut cache,
                    cache_ttl,
                    &metrics,
                    &target,
                    &body,
                );
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
        front,
    })
}
