//! A TCP relay that sends each connection to the first backend that accepts it.
//!
//! It sits between the sidecar and two or more `cairn serve-kms` coordinators and is what
//! turns a standby coordinator into automatic failover. It carries bytes only: TLS and
//! request signatures pass through untouched, so it holds no key and can see nothing the
//! network could not. Run it on the sidecar's own machine, where it fails only when the
//! sidecar's machine does.
//!
//! "Accepts" means the TCP connection opens. A coordinator that is up but cannot sign (its
//! parties are unreachable, say) still receives connections; that case needs the operator.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

/// Relay connections from `listener` until the task is dropped. Backends are tried in order
/// starting from the one that last worked, each for at most `connect_timeout`.
pub async fn relay(listener: TcpListener, backends: Vec<SocketAddr>, connect_timeout: Duration) {
    let backends = Arc::new(backends);
    let preferred = Arc::new(AtomicUsize::new(0));
    loop {
        let Ok((mut client, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let (backends, preferred) = (backends.clone(), preferred.clone());
        tokio::spawn(async move {
            let first = preferred.load(Ordering::Relaxed);
            for step in 0..backends.len() {
                let index = (first + step) % backends.len();
                let attempt =
                    tokio::time::timeout(connect_timeout, TcpStream::connect(backends[index]));
                if let Ok(Ok(mut backend)) = attempt.await {
                    if step != 0 {
                        eprintln!("cairn kms-failover: now using {}", backends[index]);
                    }
                    preferred.store(index, Ordering::Relaxed);
                    client.set_nodelay(true).ok();
                    backend.set_nodelay(true).ok();
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut backend).await;
                    return;
                }
            }
            // No backend accepted: closing the connection lets the caller retry.
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A backend that answers every connection with one byte naming itself.
    async fn backend(tag: u8) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(&[tag]).await;
            }
        });
        (addr, task)
    }

    async fn ask(relay: SocketAddr) -> Option<u8> {
        let mut stream = TcpStream::connect(relay).await.ok()?;
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.ok()?;
        Some(byte[0])
    }

    #[tokio::test]
    async fn connections_move_to_the_backend_that_is_up() {
        let (a, a_task) = backend(b'a').await;
        let (b, b_task) = backend(b'b').await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = listener.local_addr().unwrap();
        tokio::spawn(relay(listener, vec![a, b], Duration::from_millis(500)));

        assert_eq!(ask(front).await, Some(b'a'));
        // The first backend dies: the next connection reaches the second, and stays there.
        a_task.abort();
        let _ = a_task.await;
        assert_eq!(ask(front).await, Some(b'b'));
        assert_eq!(ask(front).await, Some(b'b'));
        // Nothing left: the connection is closed rather than left hanging.
        b_task.abort();
        let _ = b_task.await;
        assert_eq!(ask(front).await, None);
    }
}
