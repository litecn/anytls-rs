//! Outbound SOCKS5 proxy support for the AnyTLS server.
//!
//! When `--outbound-proxy` is configured, the server relays its outbound
//! traffic (TCP targets and UDP-over-TCP targets) through an upstream SOCKS5
//! proxy instead of connecting directly. Target hostnames are handed to the
//! proxy unresolved, so DNS is performed by the proxy (socks5h semantics).
//!
//! Ported from ssrlive/anytls-rs commit "add outbound proxy for server",
//! reimplemented without the socks5-impl dependency.

use crate::util::{AnyTlsError, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// SOCKS5 protocol version.
const SOCKS5_VERSION: u8 = 0x05;
/// SOCKS5 authentication methods.
const AUTH_NONE: u8 = 0x00;
const AUTH_USERPASS: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;
/// SOCKS5 username/password auth protocol version (RFC 1929).
const USERPASS_VERSION: u8 = 0x01;
/// SOCKS5 commands.
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
/// SOCKS5 address types.
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// An upstream SOCKS5 proxy: `socks5://[user[:password]@]host:port`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundProxy {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl std::fmt::Display for OutboundProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "socks5://{}:{}", self.host, self.port)
    }
}

impl OutboundProxy {
    /// Parse and validate a `socks5://[user[:password]@]host:port` URL
    /// without extra dependencies.
    pub fn parse(url: &str) -> Result<Self> {
        let (scheme, rest) = url.split_once("://").ok_or_else(|| {
            AnyTlsError::Config(format!(
                "outbound proxy URL must include a scheme (socks5://): {url}"
            ))
        })?;
        if !scheme.eq_ignore_ascii_case("socks5") {
            return Err(AnyTlsError::Config(format!(
                "only SOCKS5 outbound proxies are supported, got: {scheme}"
            )));
        }
        // Strip path/query/fragment; only authority is needed.
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        if authority.is_empty() {
            return Err(AnyTlsError::Config(format!(
                "outbound proxy URL must include host:port: {url}"
            )));
        }
        // Split optional userinfo (user[:password]) from host:port.
        let (userinfo, host_port) = match authority.rsplit_once('@') {
            Some((userinfo, host_port)) => (Some(userinfo), host_port),
            None => (None, authority),
        };
        let (username, password) = match userinfo {
            None | Some("") => (None, None),
            Some(info) => {
                let (user, pass) = match info.split_once(':') {
                    Some((user, pass)) => (user, Some(pass.to_string())),
                    None => (info, None),
                };
                if user.is_empty() {
                    return Err(AnyTlsError::Config(format!(
                        "outbound proxy URL has empty username: {url}"
                    )));
                }
                (Some(user.to_string()), pass)
            }
        };
        let (host, port) = split_host_port(host_port).ok_or_else(|| {
            AnyTlsError::Config(format!("outbound proxy URL must include host:port: {url}"))
        })?;
        if host.is_empty() {
            return Err(AnyTlsError::Config(format!(
                "outbound proxy URL must include a host: {url}"
            )));
        }
        let port = port.ok_or_else(|| {
            AnyTlsError::Config(format!("outbound proxy URL must include a port: {url}"))
        })?;
        Ok(Self {
            host,
            port,
            username,
            password,
        })
    }

    /// Connect to the proxy and perform the method-selection handshake
    /// (plus username/password sub-negotiation when configured).
    async fn handshake(&self, stream: &mut TcpStream) -> Result<()> {
        // Client greeting: offer username/password when credentials exist.
        let methods: &[u8] = if self.username.is_some() {
            &[AUTH_USERPASS, AUTH_NONE]
        } else {
            &[AUTH_NONE]
        };
        let mut greeting = Vec::with_capacity(2 + methods.len());
        greeting.push(SOCKS5_VERSION);
        greeting.push(methods.len() as u8);
        greeting.extend_from_slice(methods);
        stream.write_all(&greeting).await?;

        let mut selection = [0u8; 2];
        stream.read_exact(&mut selection).await?;
        if selection[0] != SOCKS5_VERSION {
            return Err(AnyTlsError::Protocol(format!(
                "outbound proxy sent invalid SOCKS5 version: {}",
                selection[0]
            )));
        }
        match selection[1] {
            AUTH_NONE => Ok(()),
            AUTH_USERPASS => self.userpass_auth(stream).await,
            AUTH_NO_ACCEPTABLE => Err(AnyTlsError::Protocol(
                "outbound proxy rejected all authentication methods".into(),
            )),
            other => Err(AnyTlsError::Protocol(format!(
                "outbound proxy selected unsupported auth method: {other:#04x}"
            ))),
        }
    }

    /// RFC 1929 username/password sub-negotiation.
    async fn userpass_auth(&self, stream: &mut TcpStream) -> Result<()> {
        let username = self.username.as_deref().unwrap_or_default();
        let password = self.password.as_deref().unwrap_or_default();
        if username.len() > 255 || password.len() > 255 {
            return Err(AnyTlsError::Config(
                "outbound proxy credentials must be at most 255 bytes".into(),
            ));
        }
        let mut request = Vec::with_capacity(4 + username.len() + password.len());
        request.push(USERPASS_VERSION);
        request.push(username.len() as u8);
        request.extend_from_slice(username.as_bytes());
        request.push(password.len() as u8);
        request.extend_from_slice(password.as_bytes());
        stream.write_all(&request).await?;

        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await?;
        if reply[0] != USERPASS_VERSION {
            return Err(AnyTlsError::Protocol(format!(
                "outbound proxy sent invalid username/password version: {}",
                reply[0]
            )));
        }
        if reply[1] != 0x00 {
            return Err(AnyTlsError::Protocol(
                "outbound proxy rejected username/password credentials".into(),
            ));
        }
        Ok(())
    }

    /// Open a TCP connection to `target_host:target_port` through the proxy.
    /// Hostnames are sent to the proxy unresolved (remote DNS).
    pub async fn tcp_connect(&self, target_host: &str, target_port: u16) -> Result<TcpStream> {
        let mut stream = TcpStream::connect((self.host.as_str(), self.port)).await?;
        self.handshake(&mut stream).await?;

        let mut request = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00];
        request.extend_from_slice(&encode_socks_addr(target_host, target_port)?);
        stream.write_all(&request).await?;

        // Reply: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT.
        // The address (starting at ATYP) is parsed/skipped by skip_socks_addr.
        let mut header = [0u8; 3];
        stream.read_exact(&mut header).await?;
        if header[0] != SOCKS5_VERSION {
            return Err(AnyTlsError::Protocol(format!(
                "outbound proxy sent invalid SOCKS5 reply version: {}",
                header[0]
            )));
        }
        if header[1] != 0x00 {
            return Err(AnyTlsError::Protocol(format!(
                "outbound proxy CONNECT to {target_host}:{target_port} failed: {}",
                socks5_reply_error(header[1])
            )));
        }
        skip_socks_addr(&mut stream).await?;
        Ok(stream)
    }

    /// Create a UDP association through the proxy (RFC 1928 UDP ASSOCIATE).
    pub async fn udp_associate(&self) -> Result<Socks5UdpAssociate> {
        let mut stream = TcpStream::connect((self.host.as_str(), self.port)).await?;
        self.handshake(&mut stream).await?;

        // Request a relay bound to 0.0.0.0:0; the proxy replies with its
        // relay endpoint, which is where datagrams must be sent.
        let request = [
            SOCKS5_VERSION,
            CMD_UDP_ASSOCIATE,
            0x00,
            ATYP_IPV4,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        stream.write_all(&request).await?;

        // Reply: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT.
        // read_socks_addr consumes the address starting at ATYP.
        let mut header = [0u8; 3];
        stream.read_exact(&mut header).await?;
        if header[0] != SOCKS5_VERSION {
            return Err(AnyTlsError::Protocol(format!(
                "outbound proxy sent invalid SOCKS5 reply version: {}",
                header[0]
            )));
        }
        if header[1] != 0x00 {
            return Err(AnyTlsError::Protocol(format!(
                "outbound proxy UDP ASSOCIATE failed: {}",
                socks5_reply_error(header[1])
            )));
        }
        let relay = read_socks_addr(&mut stream).await?;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(relay).await?;
        // Keep the controlling TCP connection open for the lifetime of the
        // association: dropping it would tear down the relay on many proxies.
        Ok(Socks5UdpAssociate {
            socket,
            relay,
            _control: stream,
        })
    }
}

/// A live SOCKS5 UDP association: datagrams are exchanged with the proxy
/// relay endpoint using the RFC 1928 UDP request header framing.
pub struct Socks5UdpAssociate {
    socket: UdpSocket,
    relay: SocketAddr,
    /// The TCP connection that established the association.
    _control: TcpStream,
}

impl Socks5UdpAssociate {
    pub fn relay_addr(&self) -> SocketAddr {
        self.relay
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    /// Send a payload to `target` through the relay (adds SOCKS5 UDP header).
    pub async fn send_to(&self, payload: &[u8], target: SocketAddr) -> Result<usize> {
        let mut packet = Vec::with_capacity(5 + 18 + payload.len());
        packet.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV (2 bytes) + FRAG
        encode_sockaddr_into(&mut packet, target);
        packet.extend_from_slice(payload);
        let sent = self.socket.send(&packet).await?;
        Ok(sent.saturating_sub(packet.len() - payload.len()))
    }

    /// Receive one relayed datagram, stripping the SOCKS5 UDP header.
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut raw = vec![0u8; buf.len().max(512)];
        let (n, _from) = self.socket.recv_from(&mut raw).await?;
        let (source, payload) = decode_udp_header(&raw[..n])?;
        let copy_len = payload.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&payload[..copy_len]);
        Ok((copy_len, source))
    }
}

/// Outbound UDP leg: a plain socket, or one relayed through a SOCKS5 proxy.
pub enum UdpOutbound {
    Direct(UdpSocket),
    Proxied(Socks5UdpAssociate),
}

impl UdpOutbound {
    pub fn local_addr(&self) -> Result<SocketAddr> {
        match self {
            Self::Direct(socket) => Ok(socket.local_addr()?),
            Self::Proxied(associate) => associate.local_addr(),
        }
    }

    pub async fn send_to(&self, payload: &[u8], target: SocketAddr) -> Result<usize> {
        match self {
            Self::Direct(socket) => Ok(socket.send_to(payload, target).await?),
            Self::Proxied(associate) => associate.send_to(payload, target).await,
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        match self {
            Self::Direct(socket) => Ok(socket.recv_from(buf).await?),
            Self::Proxied(associate) => associate.recv_from(buf).await,
        }
    }
}

/// Encode a host (IP literal or domain) + port as a SOCKS5 address.
fn encode_socks_addr(host: &str, port: u16) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            if host.is_empty() || host.len() > 255 {
                return Err(AnyTlsError::Protocol(format!(
                    "invalid target host length for SOCKS5: {}",
                    host.len()
                )));
            }
            buf.push(ATYP_DOMAIN);
            buf.push(host.len() as u8);
            buf.extend_from_slice(host.as_bytes());
        }
    }
    buf.extend_from_slice(&port.to_be_bytes());
    Ok(buf)
}

/// Encode a resolved socket address as a SOCKS5 address (for UDP headers).
fn encode_sockaddr_into(buf: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&ip.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
}

/// Read a SOCKS5 address from a stream (used for the UDP relay binding).
async fn read_socks_addr(stream: &mut TcpStream) -> Result<SocketAddr> {
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;
    match atyp[0] {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(buf)),
                u16::from_be_bytes(port_buf),
            ))
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            Ok(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(buf)),
                u16::from_be_bytes(port_buf),
            ))
        }
        ATYP_DOMAIN => {
            // Some proxies reply with a domain binding; resolve it so the
            // UDP relay endpoint is usable.
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let domain = String::from_utf8(domain).map_err(|e| {
                AnyTlsError::Protocol(format!("invalid domain from proxy: {e}"))
            })?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            let addrs = tokio::net::lookup_host((domain.as_str(), port)).await?;
            addrs.into_iter().next().ok_or_else(|| {
                AnyTlsError::Protocol(format!("cannot resolve proxy bind address: {domain}"))
            })
        }
        other => Err(AnyTlsError::Protocol(format!(
            "unknown address type from proxy: {other:#04x}"
        ))),
    }
}

/// Skip a variable-length SOCKS5 address (BND.ADDR + BND.PORT) in a reply.
async fn skip_socks_addr(stream: &mut TcpStream) -> Result<()> {
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;
    let skip = match atyp[0] {
        ATYP_IPV4 => 4 + 2,
        ATYP_IPV6 => 16 + 2,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize + 2
        }
        other => {
            return Err(AnyTlsError::Protocol(format!(
                "unknown address type in proxy reply: {other:#04x}"
            )));
        }
    };
    let mut discard = vec![0u8; skip];
    stream.read_exact(&mut discard).await?;
    Ok(())
}

/// Parse the RFC 1928 UDP request header, returning (source, payload).
fn decode_udp_header(packet: &[u8]) -> Result<(SocketAddr, &[u8])> {
    if packet.len() < 4 {
        return Err(AnyTlsError::Protocol(
            "SOCKS5 UDP packet too short".into(),
        ));
    }
    // packet[0..2] = RSV, packet[2] = FRAG (fragmentation is not supported).
    if packet[2] != 0 {
        return Err(AnyTlsError::Protocol(
            "fragmented SOCKS5 UDP packets are not supported".into(),
        ));
    }
    // Layout: RSV (2) | FRAG (1) | ATYP (1) | ADDR (addr_len) | PORT (2) | payload
    let (ip, addr_len) = match packet[3] {
        ATYP_IPV4 => {
            if packet.len() < 10 {
                return Err(AnyTlsError::Protocol(
                    "SOCKS5 UDP IPv4 packet too short".into(),
                ));
            }
            (IpAddr::V4(Ipv4Addr::from([packet[4], packet[5], packet[6], packet[7]])), 4usize)
        }
        ATYP_IPV6 => {
            if packet.len() < 22 {
                return Err(AnyTlsError::Protocol(
                    "SOCKS5 UDP IPv6 packet too short".into(),
                ));
            }
            (
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[4..20]).expect("length checked"))),
                16usize,
            )
        }
        other => {
            return Err(AnyTlsError::Protocol(format!(
                "unknown address type in SOCKS5 UDP packet: {other:#04x}"
            )));
        }
    };
    let port = u16::from_be_bytes([packet[4 + addr_len], packet[5 + addr_len]]);
    Ok((SocketAddr::new(ip, port), &packet[6 + addr_len..]))
}

/// Human-readable text for a SOCKS5 reply code (RFC 1928 §6).
fn socks5_reply_error(rep: u8) -> &'static str {
    match rep {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown error",
    }
}

fn split_host_port(authority: &str) -> Option<(String, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: [::1]:1080
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_url() {
        let proxy = OutboundProxy::parse("socks5://10.0.0.1:1080").unwrap();
        assert_eq!(proxy.host, "10.0.0.1");
        assert_eq!(proxy.port, 1080);
        assert_eq!(proxy.username, None);
        assert_eq!(proxy.password, None);
    }

    #[test]
    fn parse_url_with_credentials() {
        let proxy = OutboundProxy::parse("socks5://user:secret@proxy.example.com:8080").unwrap();
        assert_eq!(proxy.host, "proxy.example.com");
        assert_eq!(proxy.port, 8080);
        assert_eq!(proxy.username.as_deref(), Some("user"));
        assert_eq!(proxy.password.as_deref(), Some("secret"));
    }

    #[test]
    fn parse_url_with_username_only() {
        let proxy = OutboundProxy::parse("socks5://user@proxy.example.com:8080").unwrap();
        assert_eq!(proxy.username.as_deref(), Some("user"));
        assert_eq!(proxy.password, None);
    }

    #[test]
    fn parse_url_ipv6_host() {
        let proxy = OutboundProxy::parse("socks5://[::1]:1080").unwrap();
        assert_eq!(proxy.host, "::1");
        assert_eq!(proxy.port, 1080);
    }

    #[test]
    fn parse_rejects_other_schemes() {
        assert!(OutboundProxy::parse("http://127.0.0.1:1080").is_err());
        assert!(OutboundProxy::parse("127.0.0.1:1080").is_err());
    }

    #[test]
    fn parse_rejects_missing_port() {
        assert!(OutboundProxy::parse("socks5://proxy.example.com").is_err());
    }

    #[test]
    fn parse_rejects_empty_host() {
        assert!(OutboundProxy::parse("socks5://:1080").is_err());
    }

    #[test]
    fn encode_addr_prefers_ip_literals() {
        let v4 = encode_socks_addr("1.2.3.4", 80).unwrap();
        assert_eq!(v4[0], ATYP_IPV4);
        assert_eq!(&v4[1..5], &[1, 2, 3, 4]);

        let domain = encode_socks_addr("example.com", 443).unwrap();
        assert_eq!(domain[0], ATYP_DOMAIN);
        assert_eq!(domain[1], 11);
        assert_eq!(&domain[2..13], b"example.com");
    }

    #[test]
    fn udp_header_roundtrip() {
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let mut packet = vec![0x00, 0x00, 0x00];
        encode_sockaddr_into(&mut packet, target);
        packet.extend_from_slice(b"hello");

        let (source, payload) = decode_udp_header(&packet).unwrap();
        assert_eq!(source, target);
        assert_eq!(payload, b"hello");
    }

    #[tokio::test]
    async fn tcp_connect_through_mock_proxy() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Echo target server.
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = target.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    if let Ok(n) = conn.read(&mut buf).await {
                        let _ = conn.write_all(&buf[..n]).await;
                    }
                });
            }
        });

        // Mock SOCKS5 proxy: no-auth CONNECT, then relay to target_addr.
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut conn, _) = proxy.accept().await.unwrap();
            // Greeting: VER, NMETHODS, METHODS
            let mut greeting = [0u8; 2];
            conn.read_exact(&mut greeting).await.unwrap();
            let mut methods = vec![0u8; greeting[1] as usize];
            conn.read_exact(&mut methods).await.unwrap();
            conn.write_all(&[0x05, 0x00]).await.unwrap();
            // Request: VER, CMD, RSV, ATYP...
            let mut req_head = [0u8; 4];
            conn.read_exact(&mut req_head).await.unwrap();
            assert_eq!(req_head[1], CMD_CONNECT);
            // Skip the target address (domain of length 11 + port assumed).
            let atyp = req_head[3];
            let skip = match atyp {
                ATYP_DOMAIN => {
                    let mut len = [0u8; 1];
                    conn.read_exact(&mut len).await.unwrap();
                    let mut d = vec![0u8; len[0] as usize + 2];
                    conn.read_exact(&mut d).await.unwrap();
                    0
                }
                ATYP_IPV4 => {
                    let mut d = vec![0u8; 6];
                    conn.read_exact(&mut d).await.unwrap();
                    0
                }
                _ => 0,
            };
            let _ = skip;
            // Connect upstream and reply success.
            let mut upstream = TcpStream::connect(target_addr).await.unwrap();
            conn.write_all(&[0x05, 0x00, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut conn, &mut upstream).await;
        });

        let proxy = OutboundProxy::parse(&format!("socks5://{proxy_addr}")).unwrap();
        // Guard against handshake deadlocks: fail fast instead of hanging.
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut stream = proxy.tcp_connect("example.com", 80).await.unwrap();
            stream.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
        })
        .await;
        assert!(result.is_ok(), "tcp_connect through mock proxy timed out");
    }

    #[tokio::test]
    async fn udp_associate_through_mock_proxy() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Echo target server (UDP).
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let (n, from) = target.recv_from(&mut buf).await.unwrap();
                target.send_to(&buf[..n], from).await.unwrap();
            }
        });

        // Mock SOCKS5 proxy with UDP relay.
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut conn, _) = proxy.accept().await.unwrap();
            let mut greeting = [0u8; 2];
            conn.read_exact(&mut greeting).await.unwrap();
            let mut methods = vec![0u8; greeting[1] as usize];
            conn.read_exact(&mut methods).await.unwrap();
            conn.write_all(&[0x05, 0x00]).await.unwrap();

            let mut req = [0u8; 10];
            conn.read_exact(&mut req).await.unwrap();
            assert_eq!(req[1], CMD_UDP_ASSOCIATE);

            // Relay socket: forwards client datagrams to the echo target.
            let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay_addr = relay.local_addr().unwrap();
            let mut reply = vec![0x05, 0x00, 0x00, ATYP_IPV4];
            let IpAddr::V4(relay_ip) = relay_addr.ip() else { unreachable!() };
            reply.extend_from_slice(&relay_ip.octets());
            reply.extend_from_slice(&relay_addr.port().to_be_bytes());
            conn.write_all(&reply).await.unwrap();

            let mut buf = vec![0u8; 2048];
            loop {
                let (n, from) = relay.recv_from(&mut buf).await.unwrap();
                // Strip SOCKS5 UDP header (RSV2+FRAG1+ATYP1+ADDR4+PORT2), remember target.
                let header_len = 2 + 1 + 1 + 4 + 2;
                let target_sa = {
                    let ip = IpAddr::V4(Ipv4Addr::from([buf[4], buf[5], buf[6], buf[7]]));
                    let port = u16::from_be_bytes([buf[8], buf[9]]);
                    SocketAddr::new(ip, port)
                };
                relay
                    .send_to(&buf[header_len..n], target_sa)
                    .await
                    .unwrap();
                let (m, src) = relay.recv_from(&mut buf[header_len..]).await.unwrap();
                // Re-frame reply with the original target as source.
                let mut out = vec![0x00, 0x00, 0x00, ATYP_IPV4];
                let IpAddr::V4(src_ip) = src.ip() else { unreachable!() };
                out.extend_from_slice(&src_ip.octets());
                out.extend_from_slice(&src.port().to_be_bytes());
                out.extend_from_slice(&buf[header_len..header_len + m]);
                relay.send_to(&out, from).await.unwrap();
            }
        });

        let proxy = OutboundProxy::parse(&format!("socks5://{proxy_addr}")).unwrap();
        let associate = proxy.udp_associate().await.unwrap();
        associate
            .send_to(b"hello-udp", target_addr)
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let (n, src) = associate.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello-udp");
        assert_eq!(src, target_addr);
    }
}
