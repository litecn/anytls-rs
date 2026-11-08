//! Forwarding for unauthenticated TLS connections.
//!
//! When a `--forward` target is configured, connections that complete the TLS
//! handshake but fail AnyTLS authentication are relayed verbatim to the target
//! instead of being dropped. This lets the server share a port with an ordinary
//! HTTPS/HTTP service: real AnyTLS clients authenticate and proxy, while probes
//! (browsers, scanners, censors) are transparently forwarded to the decoy.
//!
//! Ported from ssrlive/anytls-rs.

use crate::util::{AnyTlsError, Result};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// The decoy target for unauthenticated connections (http:// or https:// URL).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForwardTarget {
    /// True when the relay to the target must be wrapped in TLS.
    pub https: bool,
    pub host: String,
    pub port: u16,
}

impl ForwardTarget {
    /// Parse and validate an http:// or https:// URL without extra dependencies.
    pub fn parse(url: &str) -> Result<Self> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| AnyTlsError::Config(format!("forward URL must include a scheme: {url}")))?;
        let https = match scheme.to_ascii_lowercase().as_str() {
            "http" => false,
            "https" => true,
            other => {
                return Err(AnyTlsError::Config(format!(
                    "forward URL must be an http:// or https:// URL, got: {other}"
                )));
            }
        };
        // Strip path/query/fragment; only authority is needed.
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        // Strip userinfo if present.
        let authority = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
        if authority.is_empty() {
            return Err(AnyTlsError::Config(format!(
                "forward URL must include a host: {url}"
            )));
        }
        let (host, port) = split_host_port(authority)
            .ok_or_else(|| AnyTlsError::Config(format!("forward URL must include a host: {url}")))?;
        let port = match port {
            Some(port) => port,
            None if https => 443,
            None => 80,
        };
        if host.is_empty() {
            return Err(AnyTlsError::Config(format!(
                "forward URL must include a host: {url}"
            )));
        }
        Ok(Self { https, host, port })
    }
}

fn split_host_port(authority: &str) -> Option<(String, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: [::1]:8443
        let (host, tail) = rest.split_once(']')?;
        let port = match tail {
            "" => None,
            tail => Some(tail.strip_prefix(':')?.parse::<u16>().ok()?),
        };
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host.to_string(), port.parse::<u16>().ok())),
        None => Some((authority.to_string(), None)),
    }
}

/// Outbound leg of a forward relay: plain TCP for http://, TLS for https://.
enum ForwardOutbound {
    Http(TcpStream),
    Https(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for ForwardOutbound {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::pin::Pin;
        match &mut *self {
            Self::Http(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Https(stream) => Pin::new(&mut **stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ForwardOutbound {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        use std::pin::Pin;
        match &mut *self {
            Self::Http(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Https(stream) => Pin::new(&mut **stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::pin::Pin;
        match &mut *self {
            Self::Http(stream) => Pin::new(stream).poll_flush(cx),
            Self::Https(stream) => Pin::new(&mut **stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::pin::Pin;
        match &mut *self {
            Self::Http(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Https(stream) => Pin::new(&mut **stream).poll_shutdown(cx),
        }
    }
}

/// Relay an unauthenticated TLS connection (plus the already-read auth prefix)
/// to the configured forward target.
pub async fn relay_forward_stream<S>(
    peer_addr: &str,
    target: &ForwardTarget,
    inbound: S,
    prefix: Vec<u8>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let tcp = TcpStream::connect((target.host.as_str(), target.port)).await?;
    let mut outbound = if target.https {
        let config = crate::util::create_client_config()
            .map_err(|e| AnyTlsError::Tls(format!("forward TLS config: {e}")))?;
        let connector = tokio_rustls::TlsConnector::from(config);
        let server_name = rustls_server_name(&target.host)?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| AnyTlsError::Tls(format!("forward TLS handshake failed: {e}")))?;
        ForwardOutbound::Https(Box::new(tls))
    } else {
        ForwardOutbound::Http(tcp)
    };
    tracing::trace!(
        "[Forward] Relaying unauthenticated connection from {} to {}:{} ({})",
        peer_addr,
        target.host,
        target.port,
        if target.https { "https" } else { "http" }
    );
    outbound.write_all(&prefix).await?;
    outbound.flush().await?;
    let mut inbound = inbound;
    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
}

fn rustls_server_name(host: &str) -> Result<tokio_rustls::rustls::pki_types::ServerName<'static>> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(tokio_rustls::rustls::pki_types::ServerName::IpAddress(
            ip.into(),
        ));
    }
    tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| AnyTlsError::Config(format!("forward URL host is not a valid DNS name: {host}")))
}

/// Read the AnyTLS auth header (32-byte password digest + 2-byte padding length)
/// from the stream, tolerating early EOF. Returns the bytes actually read.
pub async fn read_auth_prefix<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<(Vec<u8>, usize)> {
    use crate::util::AUTH_HEADER_SIZE;
    let mut data = vec![0u8; AUTH_HEADER_SIZE];
    let mut read = 0usize;
    while read < data.len() {
        let n = reader.read(&mut data[read..]).await?;
        if n == 0 {
            break;
        }
        read += n;
    }
    data.truncate(read);
    Ok((data, read))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn test_parse_forward_target() {
        let target = ForwardTarget::parse("http://example.com").unwrap();
        assert!(!target.https);
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 80);

        let target = ForwardTarget::parse("https://example.com:8443/path?q=1").unwrap();
        assert!(target.https);
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 8443);

        let target = ForwardTarget::parse("https://[::1]:9443").unwrap();
        assert!(target.https);
        assert_eq!(target.host, "::1");
        assert_eq!(target.port, 9443);

        let target = ForwardTarget::parse("https://127.0.0.1").unwrap();
        assert_eq!(target.host, "127.0.0.1");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn test_parse_forward_target_rejects_bad_urls() {
        assert!(ForwardTarget::parse("ftp://example.com").is_err());
        assert!(ForwardTarget::parse("example.com").is_err());
        assert!(ForwardTarget::parse("http://").is_err());
        assert!(ForwardTarget::parse("http:///path").is_err());
    }

    #[tokio::test]
    async fn test_relay_forward_stream_http() {
        // Decoy origin that echoes back whatever it received.
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut conn, _) = origin.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = conn.read(&mut buf).await.unwrap();
            conn.write_all(&buf[..n]).await.unwrap();
            conn.flush().await.unwrap();
        });

        let target = ForwardTarget::parse(&format!("http://{}", origin_addr)).unwrap();
        let (client, server) = tokio::io::duplex(1024);
        let prefix = b"probe-bytes".to_vec();
        let relay = tokio::spawn(async move {
            let _ = relay_forward_stream("test", &target, server, prefix).await;
        });

        let mut client = client;
        let mut buf = [0u8; 16];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"probe-bytes");
        relay.abort();
        echo.abort();
    }

    #[tokio::test]
    async fn test_read_auth_prefix_partial() {
        let mut truncated: &[u8] = &[1, 2, 3];
        let (bytes, read) = read_auth_prefix(&mut truncated).await.unwrap();
        assert_eq!(read, 3);
        assert_eq!(bytes, vec![1, 2, 3]);
    }
}
