//! Framed request/reply transport over TCP with wall-clock deadlines.
//!
//! Every exchange is one connection: the caller writes one frame and reads one frame, under a
//! `tokio::time::timeout`. A peer that is down fails fast (connection refused); a peer that
//! accepts and never answers costs the full deadline. `delay` injects one-way latency on both
//! directions (round trip = `2 * delay`) to emulate a WAN link on one machine.
//!
//! v2 transport is plain TCP: frames are neither encrypted nor authenticated, and a frame's
//! `from` field is a claim. Run it on loopback or inside an encrypted tunnel (DEPLOY_SPLIT.md).

use crate::wire::{Frame, MAX_FRAME};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Clone, Copy)]
pub struct Link {
    /// Deadline for one request/reply exchange.
    pub timeout: Duration,
    /// Injected one-way latency.
    pub delay: Duration,
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
    w.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    w.write_all(&bytes).await?;
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

/// Send `frame` to `addr` and wait for the reply, all within `link.timeout`.
pub async fn call(addr: &str, link: Link, frame: &Frame) -> Result<Exchange, CallError> {
    let exchange = async {
        tokio::time::sleep(link.delay).await;
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| CallError::Unreachable(e.to_string()))?;
        stream.set_nodelay(true).ok();
        let sent = write_frame(&mut stream, frame)
            .await
            .map_err(|e| CallError::Unreachable(e.to_string()))?;
        let (reply, received) = read_frame(&mut stream)
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

/// Accept connections forever, one request per connection.
pub async fn serve<H: Handler>(listener: TcpListener, handler: Arc<H>, delay: Duration) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        };
        let handler = handler.clone();
        tokio::spawn(async move {
            stream.set_nodelay(true).ok();
            let Ok((request, _)) = read_frame(&mut stream).await else {
                return;
            };
            match handler.handle(request).await {
                Some(reply) => {
                    tokio::time::sleep(delay).await;
                    let _ = write_frame(&mut stream, &reply).await;
                }
                // Stalled peer: hold the connection open and say nothing.
                None => std::future::pending::<()>().await,
            }
        });
    }
}
