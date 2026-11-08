//! Mixed listener: serves SOCKS5 and HTTP proxy traffic on a single address.
//!
//! The protocol is detected from the first bytes of each connection using
//! `SOCK_STREAM` peek (bytes are not consumed), so the detected protocol
//! handler still sees the full request. Detection logic is ported from
//! ssrlive/anytls-rs.

use crate::client::Client;
use crate::client::http_proxy::handle_http_proxy_connection;
use crate::client::socks5::handle_socks5_connection;
use crate::util::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// Total time allowed to detect the proxy protocol before the connection is dropped.
const DETECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Short pause used while an HTTP method prefix is still incomplete.
const DETECT_RETRY_DELAY: Duration = Duration::from_millis(2);

/// The proxy protocol detected on a mixed listener connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerProtocol {
    Socks5,
    Socks4,
    Http,
}

/// Start a mixed SOCKS5/HTTP proxy server on a single listen address.
pub async fn start_mixed_server(listen_addr: &str, client: Arc<Client>) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;

    tracing::info!("[MIXED] Listening on {}", listen_addr);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let client = Arc::clone(&client);
                tokio::spawn(async move {
                    if let Err(e) = handle_mixed_connection(stream, client).await {
                        tracing::error!("[MIXED] Connection error from {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                tracing::error!("[MIXED] Accept error: {}", e);
            }
        }
    }
}

/// Detect the protocol of a single connection and dispatch it to the matching handler.
async fn handle_mixed_connection(mut stream: TcpStream, client: Arc<Client>) -> Result<()> {
    let peer_addr = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let protocol = match tokio::time::timeout(DETECT_TIMEOUT, detect_listener_protocol(&stream)).await
    {
        Ok(protocol) => protocol?,
        Err(_) => {
            tracing::debug!("[MIXED] Timed out detecting proxy protocol from {}", peer_addr);
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };

    let Some(protocol) = protocol else {
        let mut first_byte = [0u8; 1];
        match stream.peek(&mut first_byte).await {
            Ok(0) => tracing::debug!("[MIXED] Peer closed before sending a request: {}", peer_addr),
            Ok(_) => tracing::warn!(
                "[MIXED] Unknown proxy protocol from {}, first byte: 0x{:02x}",
                peer_addr,
                first_byte[0]
            ),
            Err(e) => tracing::debug!("[MIXED] Failed to peek request from {}: {}", peer_addr, e),
        }
        let _ = stream.shutdown().await;
        return Ok(());
    };

    match protocol {
        ListenerProtocol::Socks5 => {
            tracing::trace!("[MIXED] SOCKS5 client detected from {}", peer_addr);
            handle_socks5_connection(stream, client).await
        }
        ListenerProtocol::Socks4 => {
            tracing::warn!("[MIXED] SOCKS4 is unsupported on the mixed listener: {}", peer_addr);
            let _ = stream.shutdown().await;
            Ok(())
        }
        ListenerProtocol::Http => {
            tracing::trace!("[MIXED] HTTP proxy client detected from {}", peer_addr);
            handle_http_proxy_connection(stream, client).await
        }
    }
}

/// Peek at the beginning of the stream and classify it as SOCKS5, SOCKS4, or HTTP.
///
/// Returns `Ok(None)` when the peer closed the connection or the bytes do not
/// match any supported protocol.
async fn detect_listener_protocol(stream: &TcpStream) -> std::io::Result<Option<ListenerProtocol>> {
    let mut peek_buf = [0u8; 16];
    loop {
        let size = stream.peek(&mut peek_buf).await?;
        if size == 0 {
            return Ok(None);
        }
        let bytes = &peek_buf[..size];
        match bytes[0] {
            0x05 => return Ok(Some(ListenerProtocol::Socks5)),
            0x04 => return Ok(Some(ListenerProtocol::Socks4)),
            _ if is_http_request(bytes) => return Ok(Some(ListenerProtocol::Http)),
            _ if could_be_http_request_prefix(bytes) => {
                tokio::time::sleep(DETECT_RETRY_DELAY).await;
            }
            _ => return Ok(None),
        }
    }
}

fn is_http_request(bytes: &[u8]) -> bool {
    http_methods().iter().any(|method| {
        bytes.get(..method.len()).is_some_and(|prefix| prefix.eq_ignore_ascii_case(method))
            && bytes.get(method.len()) == Some(&b' ')
    })
}

fn could_be_http_request_prefix(bytes: &[u8]) -> bool {
    http_methods().iter().any(|method| {
        let compared_len = bytes.len().min(method.len());
        bytes
            .get(..compared_len)
            .zip(method.get(..compared_len))
            .is_some_and(|(prefix, expected)| prefix.eq_ignore_ascii_case(expected))
            && (bytes.len() <= method.len() || bytes.get(method.len()) == Some(&b' '))
    })
}

fn http_methods() -> &'static [&'static [u8]] {
    const METHODS: &[&[u8]] = &[
        b"CONNECT",
        b"GET",
        b"POST",
        b"HEAD",
        b"PUT",
        b"OPTIONS",
        b"DELETE",
        b"TRACE",
        b"PATCH",
        b"LOCK",
        b"UNLOCK",
        b"PROPFIND",
        b"MKCOL",
        b"COPY",
        b"MOVE",
    ];
    METHODS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_http_request() {
        assert!(is_http_request(b"CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(is_http_request(b"get http://example.com/ HTTP/1.1\r\n"));
        assert!(!is_http_request(b"GARBAGE"));
        // No space after the method yet: not a complete request line.
        assert!(!is_http_request(b"CONNECT"));
    }

    #[test]
    fn test_could_be_http_request_prefix() {
        assert!(could_be_http_request_prefix(b"CONN"));
        assert!(could_be_http_request_prefix(b"GE"));
        assert!(could_be_http_request_prefix(b"connect "));
        assert!(!could_be_http_request_prefix(b"\x05\x01\x00"));
        assert!(!could_be_http_request_prefix(b"XYZ"));
        // A full method followed by a non-space byte cannot be an HTTP prefix.
        assert!(!could_be_http_request_prefix(b"CONNECTX"));
    }
}
