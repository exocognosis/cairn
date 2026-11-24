//! Framed request/reply transport over mutually authenticated TLS with wall-clock deadlines.
//!
//! An exchange is one request frame and one reply frame under a `tokio::time::timeout`, on a
//! connection that is kept and reused for later exchanges with the same node. A peer that is down fails fast (connection refused); a peer that
//! accepts and never answers costs the full deadline. `delay` injects one-way latency on both
//! directions (round trip = `2 * delay`) to emulate a WAN link on one machine.
//!
//! Links are TLS 1.3 with client certificates ([`crate::tls`]). The caller only talks to the
//! node it addressed; the server learns the caller's node id from its certificate and discards
//! a frame whose `from` says otherwise.

use crate::tls::TlsIdentity;
use crate::wire::{Frame, MAX_FRAME};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone)]
pub struct Link {
    /// Deadline for one request/reply exchange.
    pub timeout: Duration,
    /// Injected one-way latency.
    pub delay: Duration,
    /// This node's certificate and its view of the cluster's.
    pub tls: Arc<TlsIdentity>,
    /// Idle connections this node keeps to its peers.
    pub pool: Arc<Pool>,
}

impl Link {
    pub fn new(timeout: Duration, delay: Duration, tls: Arc<TlsIdentity>) -> Self {
        Self {
            timeout,
            delay,
            tls,
            pool: Arc::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CallError {
    #[error("no reply within the deadline")]
    Timeout,
    #[error("unreachable: {0}")]
    Unreachable(String),
    #[error("protocol error: {0}")]
    Protocol(String),
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    frame: &Frame,
) -> std::io::Result<usize> {
    let bytes = bincode::serialize(frame).map_err(std::io::Error::other)?;
    // One buffer, one write: a separate 4-byte length write can sit behind Nagle's algorithm
    // (or a tunnel's) for a whole round trip.
    let mut out = Vec::with_capacity(bytes.len() + 4);
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&bytes);
    w.write_all(&out).await?;
    w.flush().await?;
    Ok(bytes.len() + 4)
}

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<(Frame, usize)> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame length out of range",
        ));
    }
    let mut bytes = vec![0u8; len];
    r.read_exact(&mut bytes).await?;
    let frame = bincode::deserialize(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok((frame, len + 4))
}

/// Reply and the bytes sent and received.
pub struct Exchange {
    pub reply: Frame,
    pub sent: usize,
    pub received: usize,
}

type ClientStream = tokio_rustls::client::TlsStream<TcpStream>;

/// Idle authenticated connections, by `(address, node)`. Reusing one saves the TCP and TLS
/// handshakes, which on a WAN are two of the three round trips of an exchange.
#[derive(Default)]
pub struct Pool(
    std::sync::Mutex<std::collections::HashMap<(String, crate::wire::NodeId), Vec<ClientStream>>>,
);

impl Pool {
    fn take(&self, key: &(String, crate::wire::NodeId)) -> Option<ClientStream> {
        self.0.lock().expect("pool").get_mut(key).and_then(Vec::pop)
    }

    fn put(&self, key: (String, crate::wire::NodeId), stream: ClientStream) {
        let mut pool = self.0.lock().expect("pool");
        let idle = pool.entry(key).or_default();
        if idle.len() < 4 {
            idle.push(stream);
        }
    }
}

async fn exchange_on(stream: &mut ClientStream, frame: &Frame) -> Result<Exchange, CallError> {
    let sent = write_frame(stream, frame)
        .await
        .map_err(|e| CallError::Unreachable(e.to_string()))?;
    let (reply, received) = read_frame(stream)
        .await
        .map_err(|e| CallError::Protocol(e.to_string()))?;
    if reply.session != frame.session || reply.from != frame.to {
        return Err(CallError::Protocol(
            "reply does not match the request".into(),
        ));
    }
    Ok(Exchange {
        reply,
        sent,
        received,
    })
}

/// Send `frame` to `addr` and wait for the reply, all within `link.timeout`.
///
/// An idle pooled connection to that node is reused when there is one; if it turns out to be
/// dead the exchange is retried once on a fresh connection. A connection is returned to the
/// pool only after a complete exchange, so a timed-out or failed one is never reused.
pub async fn call(addr: &str, link: &Link, frame: &Frame) -> Result<Exchange, CallError> {
    let key = (addr.to_string(), frame.to);
    let exchange = async {
        tokio::time::sleep(link.delay).await;
        if let Some(mut stream) = link.pool.take(&key) {
            if let Ok(done) = exchange_on(&mut stream, frame).await {
                link.pool.put(key.clone(), stream);
                return Ok(done);
            }
        }
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| CallError::Unreachable(e.to_string()))?;
        tcp.set_nodelay(true).ok();
        // Handshake: fails unless the peer holds the certificate of the node we addressed.
        let mut stream = link
            .tls
            .connector()
            .connect(TlsIdentity::server_name(frame.to), tcp)
            .await
            .map_err(|e| CallError::Protocol(format!("TLS: {e}")))?;
        let done = exchange_on(&mut stream, frame).await?;
        link.pool.put(key.clone(), stream);
        Ok(done)
    };
    tokio::time::timeout(link.timeout, exchange)
        .await
        .unwrap_or(Err(CallError::Timeout))
}

pub type Reply<'a> = Pin<Box<dyn Future<Output = Option<Frame>> + Send + 'a>>;

/// A node's request handler. `None` means "never answer" (the caller's deadline will fire).
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, request: Frame) -> Reply<'_>;
}

/// Accept connections forever; each carries any number of request/reply exchanges. A connection is served only if the
/// client's certificate belongs to a cluster node and the frame's `from` is that node.
pub async fn serve<H: Handler>(
    listener: TcpListener,
    handler: Arc<H>,
    delay: Duration,
    tls: Arc<TlsIdentity>,
) {
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        };
        let (handler, tls) = (handler.clone(), tls.clone());
        tokio::spawn(async move {
            tcp.set_nodelay(true).ok();
            let Ok(mut stream) = tls.acceptor().accept(tcp).await else {
                return;
            };
            let Some(peer) = tls.peer(stream.get_ref().1.peer_certificates()) else {
                return;
            };
            // Serve requests on this connection until the peer closes it.
            while let Ok((request, _)) = read_frame(&mut stream).await {
                if request.from != peer {
                    // Authenticated as one node, claiming to be another: no answer.
                    return;
                }
                match handler.handle(request).await {
                    Some(reply) => {
                        tokio::time::sleep(delay).await;
                        if write_frame(&mut stream, &reply).await.is_err() {
                            return;
                        }
                    }
                    // Stalled peer: hold the connection open and say nothing.
                    None => std::future::pending::<()>().await,
                }
            }
        });
    }
}
