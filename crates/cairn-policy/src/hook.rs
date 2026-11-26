//! Policies that ask something outside cairn, and a way to require several at once.
//!
//! cairn carries no code for any particular chain, directory or approval system. A party that
//! needs such a check points one of these at a program or service its operator owns:
//!
//! * [`CommandPolicy`]: run a program, give it the request on standard input, read the answer
//!   from its exit status.
//! * [`WebhookPolicy`]: POST the request to a service on this machine. The request and answer
//!   shapes are the ones Open Policy Agent's data API uses, so OPA works unchanged.
//! * [`AllOf`]: every listed policy must agree.
//!
//! A hook is trusted exactly as much as the party: whoever controls it decides what the party
//! signs. It therefore runs on the party's own machine (a local program, a loopback address),
//! and anything other than a clear yes in time is a refusal.
//!
//! The request, as JSON:
//!
//! ```json
//! { "session": "<hex>", "party": 2, "signers": [1, 2],
//!   "payload_hex": "<hex>", "payload_sha3": "<hex>" }
//! ```

use crate::{PolicyEngine, PolicyError, SignContext};
use sha3::{Digest, Sha3_256};
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Longest refusal reason passed on from a hook.
const MAX_REASON: usize = 200;
/// Most a hook's answer may be.
const MAX_ANSWER: u64 = 64 * 1024;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn request(ctx: &SignContext, payload: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "session": hex(ctx.session),
        "party": ctx.party,
        "signers": ctx.signers,
        "payload_hex": hex(payload),
        "payload_sha3": hex(&Sha3_256::digest(payload)),
    })
}

fn refuse<T>(reason: impl AsRef<str>) -> Result<T, PolicyError> {
    let reason: String = reason
        .as_ref()
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_REASON)
        .collect();
    Err(PolicyError::Refused(reason))
}

/// Every policy must authorize, asked in order; the first refusal is the answer. Put policies
/// that remember what they signed last, so they record only what the others allowed.
pub struct AllOf(pub Vec<Box<dyn PolicyEngine>>);

impl PolicyEngine for AllOf {
    fn authorize_sign(&self, ctx: &SignContext, payload: &[u8]) -> Result<(), PolicyError> {
        self.0
            .iter()
            .try_for_each(|policy| policy.authorize_sign(ctx, payload))
    }
}

/// Ask a program. It gets the request on standard input and allows by exiting with status 0;
/// any other status refuses, with the first line it printed as the reason. No shell is
/// involved: the program is run directly with the given arguments.
pub struct CommandPolicy {
    pub program: String,
    pub args: Vec<String>,
    pub timeout: Duration,
}

impl CommandPolicy {
    /// Split `"program arg arg"` on whitespace.
    pub fn parse(line: &str, timeout: Duration) -> Option<Self> {
        let mut words = line.split_whitespace().map(str::to_owned);
        Some(Self {
            program: words.next()?,
            args: words.collect(),
            timeout,
        })
    }
}

impl PolicyEngine for CommandPolicy {
    fn authorize_sign(&self, ctx: &SignContext, payload: &[u8]) -> Result<(), PolicyError> {
        let hook = &self.program;
        let mut child = match Command::new(hook)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => return refuse(format!("policy command {hook}: {e}")),
        };
        // The request is a few kilobytes: it fits the pipe, so this cannot block on a hook
        // that never reads. A hook that exits without reading is judged by its status.
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(request(ctx, payload).to_string().as_bytes());
        }
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return refuse(format!("policy command {hook}: no answer in time"));
                }
                Err(e) => return refuse(format!("policy command {hook}: {e}")),
            }
        };
        if status.success() {
            return Ok(());
        }
        let mut said = String::new();
        if let Some(stdout) = child.stdout.take() {
            let _ = stdout.take(MAX_ANSWER).read_to_string(&mut said);
        }
        match said.lines().next().map(str::trim).filter(|l| !l.is_empty()) {
            Some(reason) => refuse(reason),
            None => refuse(format!("policy command {hook} refused")),
        }
    }
}

/// Ask a service on this machine: `POST {"input": <request>}` to a loopback HTTP address.
/// It allows with `{"result": true}` or `{"result": {"allow": true}}`; anything else refuses,
/// with `result.reason` as the reason when there is one. Plain HTTP, which is why only
/// loopback addresses are accepted.
pub struct WebhookPolicy {
    addr: SocketAddr,
    path: String,
    timeout: Duration,
}

impl WebhookPolicy {
    /// `http://127.0.0.1:8181/v1/data/cairn/allow`. The host must be a loopback IP address.
    pub fn new(url: &str, timeout: Duration) -> Result<Self, String> {
        let rest = url
            .strip_prefix("http://")
            .ok_or("a policy URL starts with http:// (loopback only)")?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let addr: SocketAddr = authority
            .parse()
            .map_err(|_| format!("policy URL host {authority:?} is not <ip>:<port>"))?;
        if !addr.ip().is_loopback() {
            return Err(format!(
                "policy URL {authority} is not on this machine: a policy service must be local to the party"
            ));
        }
        if path.bytes().any(|b| b.is_ascii_control() || b == b' ') {
            return Err("policy URL path has spaces or control characters".into());
        }
        Ok(Self {
            addr,
            path: path.to_owned(),
            timeout,
        })
    }

    fn ask(&self, body: &str) -> std::io::Result<(u16, Vec<u8>)> {
        let invalid = |what: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, what);
        let deadline = Instant::now() + self.timeout;
        let left = || {
            deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "no answer in time")
                })
        };
        let mut stream = TcpStream::connect_timeout(&self.addr, left()?)?;
        stream.set_write_timeout(Some(left()?))?;
        write!(
            stream,
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.path,
            self.addr,
            body.len()
        )?;
        let mut answer = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            stream.set_read_timeout(Some(left()?))?;
            match stream.read(&mut chunk)? {
                0 => break,
                n => answer.extend_from_slice(&chunk[..n]),
            }
            if answer.len() as u64 > MAX_ANSWER {
                return Err(invalid("answer is too large"));
            }
        }
        let split = answer
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| invalid("not an HTTP answer"))?;
        let head = String::from_utf8_lossy(&answer[..split]).into_owned();
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .ok_or_else(|| invalid("no HTTP status"))?;
        let body = &answer[split + 4..];
        let chunked = head.lines().any(|l| {
            let l = l.to_ascii_lowercase();
            l.starts_with("transfer-encoding:") && l.contains("chunked")
        });
        Ok((
            status,
            if chunked {
                dechunk(body).ok_or_else(|| invalid("bad chunked body"))?
            } else {
                body.to_vec()
            },
        ))
    }
}

/// Decode an HTTP/1.1 chunked body.
fn dechunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = body.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(&body[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(body.get(..size)?);
        body = body.get(size + 2..)?;
    }
}

impl PolicyEngine for WebhookPolicy {
    fn authorize_sign(&self, ctx: &SignContext, payload: &[u8]) -> Result<(), PolicyError> {
        let body = serde_json::json!({ "input": request(ctx, payload) }).to_string();
        let (status, answer) = match self.ask(&body) {
            Ok(answer) => answer,
            Err(e) => return refuse(format!("policy service {}: {e}", self.addr)),
        };
        if status != 200 {
            return refuse(format!("policy service {}: HTTP {status}", self.addr));
        }
        let Ok(answer) = serde_json::from_slice::<serde_json::Value>(&answer) else {
            return refuse(format!("policy service {}: answer is not JSON", self.addr));
        };
        let result = &answer["result"];
        if result == &serde_json::Value::Bool(true)
            || result["allow"] == serde_json::Value::Bool(true)
        {
            return Ok(());
        }
        match result["reason"].as_str() {
            Some(reason) => refuse(reason),
            None => refuse("the policy service did not allow this payload"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Unrestricted;
    use std::net::TcpListener;

    const CTX: SignContext = SignContext {
        session: &[3; 32],
        party: 2,
        signers: &[1, 2],
    };
    const WAIT: Duration = Duration::from_secs(5);

    fn sh(script: &str) -> CommandPolicy {
        CommandPolicy {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            timeout: WAIT,
        }
    }

    fn reason(r: Result<(), PolicyError>) -> String {
        match r {
            Err(PolicyError::Refused(reason)) => reason,
            Ok(()) => panic!("allowed"),
        }
    }

    #[test]
    fn a_command_decides_by_its_exit_status() {
        assert!(sh("cat >/dev/null; exit 0")
            .authorize_sign(&CTX, b"x")
            .is_ok());
        assert_eq!(
            reason(sh("echo 'block is not final'; echo more; exit 1").authorize_sign(&CTX, b"x")),
            "block is not final"
        );
        assert!(reason(sh("exit 3").authorize_sign(&CTX, b"x")).contains("refused"));
        // The request reaches it: allow only the payload "yes" (hex 796573), as party 2.
        let picky = sh(
            r#"r=$(cat); case "$r" in *'"party":2'*'"payload_hex":"796573"'*) exit 0;; esac; exit 1"#,
        );
        assert!(picky.authorize_sign(&CTX, b"yes").is_ok());
        assert!(picky.authorize_sign(&CTX, b"no").is_err());
    }

    #[test]
    fn a_command_that_is_missing_or_slow_refuses() {
        let missing = CommandPolicy::parse("/nonexistent/cairn-hook --flag", WAIT).unwrap();
        assert_eq!(missing.args, ["--flag"]);
        assert!(reason(missing.authorize_sign(&CTX, b"x")).contains("/nonexistent/cairn-hook"));
        let slow = CommandPolicy {
            timeout: Duration::from_millis(100),
            ..sh("sleep 5")
        };
        let started = Instant::now();
        assert!(reason(slow.authorize_sign(&CTX, b"x")).contains("no answer in time"));
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(CommandPolicy::parse("   ", WAIT).is_none());
    }

    /// A one-request HTTP server answering with `answer`; returns its URL and what it was sent.
    fn serve(answer: &'static str) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "http://{}/v1/data/cairn/allow",
            listener.local_addr().unwrap()
        );
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut got = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = stream.read(&mut chunk).unwrap();
                got.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&got).into_owned();
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    if body.len() >= length {
                        stream.write_all(answer.as_bytes()).unwrap();
                        return text;
                    }
                }
            }
        });
        (url, handle)
    }

    fn webhook(answer: &'static str) -> (Result<(), PolicyError>, String) {
        let (url, server) = serve(answer);
        let verdict = WebhookPolicy::new(&url, WAIT)
            .unwrap()
            .authorize_sign(&CTX, b"yes");
        (verdict, server.join().unwrap())
    }

    #[test]
    fn a_local_service_decides_in_the_shape_open_policy_agent_uses() {
        let ok = |body: &str| -> &'static str {
            Box::leak(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .into_boxed_str(),
            )
        };
        let (verdict, sent) = webhook(ok(r#"{"result":true}"#));
        assert!(verdict.is_ok());
        assert!(sent.starts_with("POST /v1/data/cairn/allow HTTP/1.1\r\n"));
        assert!(sent.contains(r#"{"input":{"#) && sent.contains(r#""payload_hex":"796573""#));

        assert!(webhook(ok(r#"{"result":{"allow":true}}"#)).0.is_ok());
        assert!(webhook("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n{\"result\r\n7\r\n\":true}\r\n0\r\n\r\n").0.is_ok());
        assert_eq!(
            reason(
                webhook(ok(
                    r#"{"result":{"allow":false,"reason":"over the limit"}}"#
                ))
                .0
            ),
            "over the limit"
        );
        // An undefined rule (OPA answers `{}`), false, a non-200, and nonsense all refuse.
        for answer in [
            ok("{}"),
            ok(r#"{"result":false}"#),
            ok(r#"{"result":"true"}"#),
            ok("not json"),
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 15\r\n\r\n{\"result\":true}",
            "garbage",
        ] {
            assert!(webhook(answer).0.is_err(), "{answer}");
        }
    }

    #[test]
    fn a_service_that_is_remote_absent_or_silent_refuses() {
        assert!(WebhookPolicy::new("http://10.0.0.5:8181/allow", WAIT).is_err());
        assert!(WebhookPolicy::new("https://127.0.0.1:8181/allow", WAIT).is_err());
        assert!(WebhookPolicy::new("http://localhost:8181/allow", WAIT).is_err());
        assert!(WebhookPolicy::new("http://[::1]:8181", WAIT).is_ok());

        let free = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let absent = WebhookPolicy::new(&format!("http://{free}/"), WAIT).unwrap();
        assert!(reason(absent.authorize_sign(&CTX, b"x")).contains("policy service"));

        // Accepts the connection and never answers.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let silent = WebhookPolicy::new(
            &format!("http://{}/", listener.local_addr().unwrap()),
            Duration::from_millis(150),
        )
        .unwrap();
        let started = Instant::now();
        assert!(silent.authorize_sign(&CTX, b"x").is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn all_of_needs_every_policy_and_stops_at_the_first_refusal() {
        let all = |scripts: &[&str]| {
            AllOf(
                scripts
                    .iter()
                    .map(|s| Box::new(sh(s)) as Box<dyn PolicyEngine>)
                    .chain([Box::new(Unrestricted) as Box<dyn PolicyEngine>])
                    .collect(),
            )
        };
        assert!(all(&["exit 0", "exit 0"])
            .authorize_sign(&CTX, b"x")
            .is_ok());
        assert_eq!(
            reason(
                all(&["exit 0", "echo second; exit 1", "echo third; exit 1"])
                    .authorize_sign(&CTX, b"x")
            ),
            "second"
        );
        assert!(AllOf(vec![]).authorize_sign(&CTX, b"x").is_ok());
    }
}
