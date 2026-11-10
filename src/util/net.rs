//! Network-related utilities (TCP tuning)

use std::io::ErrorKind;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::debug;

/// Minimum backoff applied after a retryable `accept()` failure.
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(100);

/// Maximum backoff applied after repeated retryable `accept()` failures.
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// Returns `true` for transient `accept()` errors that will keep failing
/// immediately if we retry without pausing (e.g. `EMFILE`/`ENFILE` when the
/// process is out of file descriptors, or `ENOBUFS`/`ENOMEM`).
///
/// Without a delay the accept loop spins in a tight hot loop, burning a CPU
/// core and flooding the logs, so callers must back off before retrying.
///
/// Note: on stable Rust `EMFILE`/`ENFILE`/`ENOBUFS`/`ENOMEM` all map to
/// `ErrorKind::Uncategorized`, so we match the raw errno values instead of the
/// unstable `ErrorKind::InsufficientResources` family.
fn is_retryable_accept_error(err: &std::io::Error) -> bool {
    if matches!(
        err.kind(),
        ErrorKind::OutOfMemory
            | ErrorKind::WouldBlock
            | ErrorKind::Interrupted
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
    ) {
        return true;
    }
    #[cfg(unix)]
    {
        // EMFILE (23) / ENFILE (24) are identical on Linux and macOS;
        // ENOBUFS differs between the two.
        let enobufs: i32 = if cfg!(target_os = "macos") { 55 } else { 105 };
        let code = err.raw_os_error();
        code == Some(23) || code == Some(24) || code == Some(12) || code == Some(enobufs)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Log a failed `accept()` and, for retryable errors, sleep with exponential
/// backoff (100 ms doubling up to 1 s) before the caller retries.
///
/// `backoff_us` carries the current backoff in microseconds across iterations
/// of the accept loop; reset it to 0 after a successful `accept()`.
pub async fn handle_accept_error(context: &str, err: &std::io::Error, backoff_us: &mut u64) {
    if is_retryable_accept_error(err) {
        let delay = if *backoff_us == 0 {
            ACCEPT_BACKOFF_MIN
        } else {
            ACCEPT_BACKOFF_MAX.min(Duration::from_micros(*backoff_us) * 2)
        };
        *backoff_us = delay.as_micros() as u64;
        tracing::error!(
            "[{}] Accept error: {} (retrying in {:?})",
            context,
            err,
            delay
        );
        tokio::time::sleep(delay).await;
    } else {
        *backoff_us = 0;
        tracing::error!("[{}] Accept error: {}", context, err);
    }
}

/// Enable low-latency options on a TCP stream (best-effort).
pub fn configure_tcp_stream(stream: &TcpStream, context: &str) {
    if let Err(err) = stream.set_nodelay(true) {
        debug!(
            "[Net] Failed to enable TCP_NODELAY for {}: {}",
            context, err
        );
    }

    #[cfg(any(unix, windows))]
    {
        use socket2::{SockRef, TcpKeepalive};

        let keepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(120))
            .with_interval(Duration::from_secs(30));

        if let Err(err) = SockRef::from(stream).set_tcp_keepalive(&keepalive) {
            debug!(
                "[Net] Failed to configure TCP keepalive for {}: {}",
                context, err
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emfile_enfile_are_retryable() {
        // EMFILE (23) and ENFILE (24) share the same numbers on Linux/macOS.
        assert!(is_retryable_accept_error(&std::io::Error::from_raw_os_error(23)));
        assert!(is_retryable_accept_error(&std::io::Error::from_raw_os_error(24)));
        // ENOMEM (12).
        assert!(is_retryable_accept_error(&std::io::Error::from_raw_os_error(12)));
    }

    #[test]
    fn unrelated_errors_are_not_retryable() {
        // EINVAL
        assert!(!is_retryable_accept_error(&std::io::Error::from_raw_os_error(22)));
        // ECONNABORTED maps via ErrorKind and is retryable; plain protocol errors are not.
        assert!(!is_retryable_accept_error(&std::io::Error::from_raw_os_error(40)));
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_grows_and_caps() {
        let emfile = std::io::Error::from_raw_os_error(23);
        let mut backoff: u64 = 0;
        let mut delays = Vec::new();
        for _ in 0..5 {
            let before = tokio::time::Instant::now();
            crate::util::handle_accept_error("Test", &emfile, &mut backoff).await;
            delays.push(before.elapsed());
        }
        assert_eq!(delays[0], ACCEPT_BACKOFF_MIN); // 100ms
        assert_eq!(delays[1], Duration::from_millis(200));
        assert_eq!(delays[2], Duration::from_millis(400));
        assert_eq!(delays[3], Duration::from_millis(800));
        assert_eq!(delays[4], ACCEPT_BACKOFF_MAX); // capped at 1s
    }

    #[tokio::test(start_paused = true)]
    async fn non_retryable_resets_backoff() {
        let emfile = std::io::Error::from_raw_os_error(23);
        let einval = std::io::Error::from_raw_os_error(22);
        let mut backoff: u64 = 0;
        crate::util::handle_accept_error("Test", &emfile, &mut backoff).await;
        assert!(backoff > 0);
        crate::util::handle_accept_error("Test", &einval, &mut backoff).await;
        assert_eq!(backoff, 0);
    }
}
