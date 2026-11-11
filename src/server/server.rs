//! AnyTLS Server implementation

use crate::padding::PaddingFactory;
use crate::server::forward::{ForwardTarget, read_auth_prefix, relay_forward_stream};
use crate::server::handler::{StreamHandler, TcpProxyHandler};
use crate::server::outbound_proxy::OutboundProxy;
use crate::session::Session;
use crate::util::{
    AnyTlsError, Result, StringMap, configure_tcp_stream, hash_password, PASSWORD_DIGEST_SIZE,
};
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{Instrument, Span, field, info_span};

/// Server manages AnyTLS server connections
pub struct Server {
    password_hash: [u8; 32],
    tls_config: Arc<RwLock<Arc<TlsAcceptor>>>,
    padding: Arc<PaddingFactory>,
    on_new_stream: Option<Arc<dyn Fn(Arc<crate::session::Stream>) + Send + Sync + 'static>>,
    server_settings: Option<StringMap>,
    forward_target: Option<ForwardTarget>,
    outbound_proxy: Option<Arc<OutboundProxy>>,
}

impl Server {
    /// Create a new server
    pub fn new(
        password: &str,
        tls_config: Arc<TlsAcceptor>,
        padding: Arc<PaddingFactory>,
        server_settings: Option<StringMap>,
    ) -> Self {
        let password_hash = hash_password(password);

        Self {
            password_hash,
            tls_config: Arc::new(RwLock::new(tls_config)),
            padding,
            on_new_stream: None,
            server_settings,
            forward_target: None,
            outbound_proxy: None,
        }
    }

    /// Create a new server with reloadable TLS config
    pub fn new_with_reloadable_tls(
        password: &str,
        tls_config: Arc<RwLock<Arc<TlsAcceptor>>>,
        padding: Arc<PaddingFactory>,
        server_settings: Option<StringMap>,
    ) -> Self {
        let password_hash = hash_password(password);

        Self {
            password_hash,
            tls_config,
            padding,
            on_new_stream: None,
            server_settings,
            forward_target: None,
            outbound_proxy: None,
        }
    }

    /// Set callback for new streams
    pub fn with_stream_handler<F>(mut self, callback: F) -> Self
    where
        F: Fn(Arc<crate::session::Stream>) + Send + Sync + 'static,
    {
        self.on_new_stream = Some(Arc::new(callback));
        self
    }

    /// Relay unauthenticated connections to the given target instead of dropping them
    pub fn with_forward_target(mut self, target: ForwardTarget) -> Self {
        self.forward_target = Some(target);
        self
    }

    /// Route outbound proxy traffic (TCP and UDP-over-TCP targets) through an
    /// upstream SOCKS5 proxy
    pub fn with_outbound_proxy(mut self, proxy: OutboundProxy) -> Self {
        self.outbound_proxy = Some(Arc::new(proxy));
        self
    }

    /// Start the server and listen for connections
    pub async fn listen(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;

        tracing::info!("[Server] Listening on {}", addr);

        let mut accept_backoff_us: u64 = 0;
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    accept_backoff_us = 0;
                    let tls_config = self.tls_config.read().unwrap().clone();
                    let password_hash = self.password_hash;
                    let padding = Arc::clone(&self.padding);
                    let on_new_stream = self.on_new_stream.clone();
                    let server_settings = self.server_settings.clone();
                    let forward_target = self.forward_target.clone();
                    let outbound_proxy = self.outbound_proxy.clone();
                    let span = info_span!(
                        "anytls.connection",
                        peer_addr = %addr,
                        session_id = field::Empty
                    );

                    tokio::spawn(
                        async move {
                            if let Err(e) = handle_connection(
                                stream,
                                tls_config,
                                password_hash,
                                padding,
                                on_new_stream,
                                server_settings,
                                forward_target,
                                outbound_proxy,
                            )
                            .await
                            {
                                tracing::error!("[Server] Connection error: {}", e);
                            }
                        }
                        .instrument(span),
                    );
                }
                Err(e) => {
                    crate::util::handle_accept_error("Server", &e, &mut accept_backoff_us).await;
                }
            }
        }
    }
}

/// Handle a single TCP connection
async fn handle_connection(
    tcp_stream: tokio::net::TcpStream,
    tls_config: Arc<TlsAcceptor>,
    password_hash: [u8; 32],
    padding: Arc<PaddingFactory>,
    on_new_stream: Option<Arc<dyn Fn(Arc<crate::session::Stream>) + Send + Sync + 'static>>,
    server_settings: Option<StringMap>,
    forward_target: Option<ForwardTarget>,
    outbound_proxy: Option<Arc<OutboundProxy>>,
) -> Result<()> {
    let peer_addr = tcp_stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    configure_tcp_stream(&tcp_stream, &peer_addr);
    let handshake_span = info_span!(
        "anytls.handshake",
        peer_addr = %peer_addr,
        session_id = field::Empty,
        tls_version = field::Empty,
        cipher_suite = field::Empty
    );
    let _handshake_guard = handshake_span.enter();
    tracing::info!("[Server] New connection from {}", peer_addr);
    // Perform TLS handshake
    tracing::debug!("[Server] Starting TLS handshake");
    let mut tls_stream = tls_config.accept(tcp_stream).await.map_err(|e| {
        tracing::error!("[Server] TLS handshake failed: {}", e);
        AnyTlsError::Tls(format!("TLS handshake failed: {}", e))
    })?;
    tracing::debug!("[Server] TLS handshake successful");
    let (_, server_connection) = tls_stream.get_ref();
    if let Some(protocol) = server_connection.protocol_version() {
        handshake_span.record("tls_version", field::display(format!("{:?}", protocol)));
    }
    if let Some(suite) = server_connection.negotiated_cipher_suite() {
        handshake_span.record(
            "cipher_suite",
            field::display(format!("{:?}", suite.suite())),
        );
    }

    // Authenticate client: read the fixed auth header manually so that an
    // unauthenticated connection can be forwarded verbatim (bytes already read
    // are replayed to the forward target).
    tracing::debug!("[Server] Authenticating client");
    let (prefix, prefix_len) = read_auth_prefix(&mut tls_stream).await?;
    let authenticated = prefix_len == PASSWORD_DIGEST_SIZE + 2
        && prefix[..PASSWORD_DIGEST_SIZE] == password_hash;
    if !authenticated {
        if let Some(target) = forward_target.as_ref() {
            tracing::debug!(
                "[Server] Authentication failed for {}; forwarding to {}:{}",
                peer_addr,
                target.host,
                target.port
            );
            if let Err(e) = relay_forward_stream(&peer_addr, target, tls_stream, prefix).await {
                tracing::debug!("[Server] Forward relay failed for {}: {}", peer_addr, e);
            }
            return Ok(());
        }
        tracing::debug!("[Server] Authentication failed for {}; no forward target", peer_addr);
        return Err(AnyTlsError::AuthenticationFailed);
    }
    // Drain the auth padding so the session reader starts at the first frame.
    let mut padding_len_bytes = [0u8; 2];
    tokio::io::AsyncReadExt::read_exact(&mut tls_stream, &mut padding_len_bytes).await?;
    let padding_len = u16::from_be_bytes(padding_len_bytes) as usize;
    if padding_len > 0 {
        let mut padding_buf = vec![0u8; padding_len];
        tokio::io::AsyncReadExt::read_exact(&mut tls_stream, &mut padding_buf).await?;
    }
    let (reader, writer) = tokio::io::split(tls_stream);
    tracing::debug!("[Server] Client authenticated");

    // Create callback channel for new streams
    let (stream_callback_tx, mut stream_callback_rx) =
        tokio::sync::mpsc::unbounded_channel::<Arc<crate::session::Stream>>();

    // Create server session
    let mut session = Session::new_server(reader, writer, padding);
    session.set_server_settings(server_settings.clone());

    // Set callback channel in session
    session.set_stream_callback(stream_callback_tx);

    let session = Arc::new(session);
    let session_id = session.id();
    Span::current().record("session_id", session_id);
    handshake_span.record("session_id", field::display(session_id));

    tracing::info!(
        session_id = session_id,
        peer_addr = %peer_addr,
        "[Server] Session {} created",
        session_id
    );

    // Handle new streams in a task
    if let Some(callback) = on_new_stream {
        tracing::debug!("[Server] Using custom stream callback");
        tokio::spawn(async move {
            while let Some(stream) = stream_callback_rx.recv().await {
                tracing::debug!(
                    "[Server] Received stream {} in custom callback",
                    stream.id()
                );
                // Spawn a new task for each stream to handle it asynchronously
                let stream_clone = Arc::clone(&stream);
                let callback_clone = Arc::clone(&callback);
                let stream_id = stream_clone.id();
                let stream_span =
                    info_span!("anytls.stream.callback", session_id = session_id, stream_id);
                tokio::spawn(
                    async move {
                        callback_clone(stream_clone);
                    }
                    .instrument(stream_span),
                );
            }
        });
    } else {
        // Use default TCP proxy handler if no callback is provided
        tracing::debug!("[Server] Using default TCP proxy handler");
        let session_for_handler = Arc::clone(&session);
        tokio::spawn(async move {
            while let Some(stream) = stream_callback_rx.recv().await {
                tracing::debug!(
                    "[Server] Received stream {} for default handler",
                    stream.id()
                );
                let stream_clone = Arc::clone(&stream);
                let session_clone = Arc::clone(&session_for_handler);
                // Create a new handler instance for each stream (TcpProxyHandler is small and stateless)
                let handler = match outbound_proxy.as_ref() {
                    Some(proxy) => TcpProxyHandler::with_outbound_proxy(Arc::clone(proxy)),
                    None => TcpProxyHandler::new(),
                };
                let stream_id = stream_clone.id();
                let stream_span = info_span!(
                    "anytls.stream.proxy",
                    session_id = session_clone.id(),
                    stream_id
                );
                tokio::spawn(
                    async move {
                        if let Err(e) = handler.handle_stream(stream_clone, session_clone).await {
                            tracing::error!("[Proxy] Handler error: {}", e);
                        }
                    }
                    .instrument(stream_span),
                );
            }
        });
    }

    // Start receive loop
    tracing::debug!("[Server] Starting receive loop");
    let session_clone = Arc::clone(&session);
    let recv_span = info_span!(
        "anytls.session.recv_loop",
        session_id = session_clone.id(),
        peer_addr = %peer_addr
    );
    tokio::spawn(
        async move {
            tracing::debug!("[Server] recv_loop task spawned");
            match session_clone.recv_loop().await {
                Ok(()) => {
                    tracing::debug!("[Server] recv_loop task completed normally");
                }
                Err(AnyTlsError::Io(e)) => {
                    // Check if this is a close_notify error (normal connection close)
                    let error_msg = e.to_string();
                    if error_msg.contains("close_notify")
                        || error_msg.contains("unexpected EOF")
                        || e.kind() == std::io::ErrorKind::UnexpectedEof
                    {
                        tracing::debug!(
                            "[Server] recv_loop task ended: Connection closed by client (no close_notify) - this is normal"
                        );
                    } else {
                        tracing::error!("[Server] recv_loop task error: {}", e);
                    }
                }
                Err(AnyTlsError::SessionClosed) => {
                    tracing::debug!("[Server] recv_loop task ended: Session closed");
                }
                Err(e) => {
                    tracing::error!("[Server] recv_loop task error: {}", e);
                }
            }
        }
        .instrument(recv_span),
    );

    // Start stream data processing
    tracing::debug!("[Server] Starting stream data processing");
    let session_clone = Arc::clone(&session);
    let process_span = info_span!(
        "anytls.session.process_stream_data",
        session_id = session_clone.id(),
        peer_addr = %peer_addr
    );
    tokio::spawn(
        async move {
            tracing::debug!("[Server] process_stream_data task spawned");
            if let Err(e) = session_clone.process_stream_data().await {
                tracing::error!("[Server] process_stream_data task error: {}", e);
            } else {
                tracing::debug!("[Server] process_stream_data task completed normally");
            }
        }
        .instrument(process_span),
    );

    tracing::debug!("[Server] Connection handler setup complete");

    // Wait for connection to close
    // The connection will be managed by the spawned tasks
    // In a production implementation, we'd wait for the session to close

    Ok(())
}
