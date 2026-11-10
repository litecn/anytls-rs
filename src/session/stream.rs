//! Stream implementation for AnyTLS protocol
//!
//! Stream provides a duplex communication channel that implements AsyncRead and AsyncWrite

use crate::session::StreamReader;
use crate::util::{AnyTlsError, Result};
use bytes::Bytes;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;
use tokio_util::sync::{PollSendError, PollSender};

/// Stream represents a single data stream within a Session
/// It implements AsyncRead and AsyncWrite to be used as a connection
pub struct Stream {
    id: u32,

    // ===== 读取部分：使用独立的 StreamReader =====
    // Arc<Mutex<>> 是为了在 poll_read 中获取 &mut
    reader: Arc<tokio::sync::Mutex<StreamReader>>,

    // ===== 写入部分：直接使用 channel，无需锁 =====
    // 有界 sender：队列满时 send_data/poll_write 挂起，形成对上游（网站/本地客户端）
    // 的天然 TCP 背压，防止慢消费者场景下内存无界增长（jxo-me/anytls-rs#3 OOM）。
    writer_tx: PollSender<(u32, Bytes)>,

    // ===== SYNACK 通知 (用于超时检测) =====
    synack_tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<Result<()>>>>>,

    // ===== 状态管理 =====
    is_closed: Arc<AtomicBool>,
    close_error: Arc<tokio::sync::Mutex<Option<AnyTlsError>>>,
}

impl Stream {
    /// Create a new stream
    ///
    /// # Arguments
    /// * `id` - Stream ID
    /// * `reader` - StreamReader 用于读取数据
    /// * `writer_tx` - 发送数据到 Session 的有界 channel sender
    ///
    /// # Returns
    /// (Stream, Receiver) - The receiver can be used to wait for SYNACK
    pub fn new(
        id: u32,
        reader: StreamReader,
        writer_tx: PollSender<(u32, Bytes)>,
    ) -> (Self, oneshot::Receiver<Result<()>>) {
        let (synack_tx, synack_rx) = oneshot::channel();

        let stream = Self {
            id,
            reader: Arc::new(tokio::sync::Mutex::new(reader)),
            writer_tx,
            synack_tx: Arc::new(tokio::sync::Mutex::new(Some(synack_tx))),
            is_closed: Arc::new(AtomicBool::new(false)),
            close_error: Arc::new(tokio::sync::Mutex::new(None)),
        };

        (stream, synack_rx)
    }

    /// Notify that SYNACK has been received
    ///
    /// # Arguments
    /// * `result` - Ok(()) for success, Err for error
    pub async fn notify_synack(&self, result: Result<()>) {
        let mut tx_guard = self.synack_tx.lock().await;
        match tx_guard.take() {
            Some(tx) => {
                let result_clone = match &result {
                    Ok(()) => Ok(()),
                    Err(e) => Err(AnyTlsError::Protocol(e.to_string())),
                };
                let _ = tx.send(result_clone);
                tracing::debug!(
                    "[Stream] SYNACK notified for stream {}: {:?}",
                    self.id,
                    result.is_ok()
                );
            }
            _ => {
                tracing::warn!("[Stream] SYNACK already notified for stream {}", self.id);
            }
        }
    }

    /// Get stream ID
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Close the stream with error (can be called with `Arc<Stream>`)
    pub async fn close_with_error(&self, err: AnyTlsError) {
        if self
            .is_closed
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            tracing::warn!(
                stream_id = self.id,
                cause = %err,
                "[Stream] Closing stream with error"
            );
            *self.close_error.lock().await = Some(err);
        }
    }

    /// Check if stream is closed
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Relaxed)
    }

    /// Get a reference to the reader (for direct access in handlers)
    pub fn reader(&self) -> &Arc<tokio::sync::Mutex<StreamReader>> {
        &self.reader
    }

    /// Send data through the writer channel (无锁方式)
    ///
    /// 这个方法可以被多个任务并发调用，无需任何锁。
    /// 队列满时异步等待消费端腾出容量（背压），而不是无限入队。
    pub async fn send_data(
        &self,
        data: Bytes,
    ) -> std::result::Result<(), PollSendError<(u32, Bytes)>> {
        let mut tx = self.writer_tx.clone();
        // Wait until the bounded queue has capacity (backpressure), then enqueue.
        std::future::poll_fn(|cx| tx.poll_reserve(cx)).await?;
        tx.send_item((self.id, data))
    }
}

// Stream is not meant to be cloned - use Arc<Stream> instead
// This implementation is only for compatibility with HashMap storage

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let stream_id = self.id;
        let remaining = buf.remaining();

        // 使用 tokio::task::block_in_place 同步读取
        // 这避免了复杂的 Future polling 和借用问题
        let reader = Arc::clone(&self.reader);

        // 创建读取 future
        let mut read_fut = Box::pin(async move {
            let mut reader_guard = reader.lock().await;
            let mut temp_buf = vec![0u8; remaining];
            let n = reader_guard.read(&mut temp_buf).await?;
            Ok::<(usize, Vec<u8>), std::io::Error>((n, temp_buf))
        });

        // Poll the future
        match read_fut.as_mut().poll(cx) {
            Poll::Ready(Ok((n, temp_buf))) => {
                if n > 0 {
                    buf.put_slice(&temp_buf[..n]);
                    tracing::trace!(
                        "[Stream] poll_read: Read {} bytes (stream_id={})",
                        n,
                        stream_id
                    );
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                tracing::error!(
                    "[Stream] poll_read: Error reading (stream_id={}): {}",
                    stream_id,
                    e
                );
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let stream_id = self.id;
        let buf_len = buf.len();
        tracing::trace!(
            "[Stream] poll_write: stream_id={}, buf_len={}",
            stream_id,
            buf_len
        );

        if self.is_closed.load(Ordering::Relaxed) {
            tracing::warn!("[Stream] poll_write: Stream {} is closed", stream_id);
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }

        // Reserve a slot in the bounded session queue; if full, return Pending so
        // the caller stops producing (backpressure) instead of growing memory.
        let this = self.get_mut();
        match std::task::ready!(this.writer_tx.poll_reserve(cx)) {
            Ok(()) => {
                let data = Bytes::copy_from_slice(buf);
                tracing::trace!(
                    "[Stream] poll_write: Sending {} bytes to channel for stream {}",
                    buf_len,
                    stream_id
                );
                if let Err(e) = this.writer_tx.send_item((stream_id, data)) {
                    tracing::error!(
                        "[Stream] poll_write: send_item failed for stream {}: {:?}",
                        stream_id,
                        e
                    );
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "session channel closed",
                    )));
                }
                tracing::debug!(
                    "[Stream] poll_write: Successfully sent {} bytes to channel for stream {}",
                    buf_len,
                    stream_id
                );
                Poll::Ready(Ok(buf_len))
            }
            Err(e) => {
                tracing::error!(
                    "[Stream] poll_write: Failed to send {} bytes to channel for stream {}: {:?}",
                    buf_len,
                    stream_id,
                    e
                );
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "session channel closed",
                )))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Mark as closed
        self.is_closed.store(true, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::StreamReader;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    fn bounded_tx(cap: usize) -> (PollSender<(u32, Bytes)>, mpsc::Receiver<(u32, Bytes)>) {
        let (tx, rx) = mpsc::channel(cap);
        (PollSender::new(tx), rx)
    }

    #[tokio::test]
    async fn test_stream_write() {
        let (tx, mut rx) = bounded_tx(8);
        let (_reader_tx, reader_rx) = mpsc::unbounded_channel();

        let reader = StreamReader::new(1, reader_rx);
        let (mut stream, _synack_rx) = Stream::new(1, reader, tx);

        // 写入数据
        stream.write_all(b"hello").await.unwrap();

        // 验证数据发送到 channel
        let (stream_id, data) = rx.recv().await.unwrap();
        assert_eq!(stream_id, 1);
        assert_eq!(data.as_ref(), b"hello");
    }

    #[tokio::test(start_paused = true)]
    async fn test_stream_send_data_backpressure() {
        // Queue capacity 1: the second send must wait for the consumer instead of
        // growing memory unbounded (jxo-me/anytls-rs#3 OOM regression).
        let (tx, _rx) = bounded_tx(1);
        let (_reader_tx, reader_rx) = mpsc::unbounded_channel();
        let reader = StreamReader::new(1, reader_rx);
        let (stream, _synack_rx) = Stream::new(1, reader, tx);

        stream.send_data(Bytes::from("a")).await.unwrap();

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            stream.send_data(Bytes::from("b")),
        )
        .await;
        assert!(
            result.is_err(),
            "send_data must apply backpressure when the queue is full"
        );
    }

    #[tokio::test]
    async fn test_stream_send_data_unblocks_on_receiver_drop() {
        // Regression for the bounded-queue switch: when the queue is full and a
        // producer is parked in poll_reserve, closing the session (which drops
        // the receiver) must wake the producer with an error instead of hanging
        // forever and leaking the forwarding task.
        let (tx, rx) = bounded_tx(1);
        let (_reader_tx, reader_rx) = mpsc::unbounded_channel();
        let reader = StreamReader::new(1, reader_rx);
        let (stream, _synack_rx) = Stream::new(1, reader, tx);

        // Fill the queue so the next send parks in poll_reserve.
        stream.send_data(Bytes::from("a")).await.unwrap();

        let handle =
            tokio::spawn(async move { stream.send_data(Bytes::from("b")).await });

        // Let the task park in poll_reserve, then simulate session close by
        // dropping the receiver.
        tokio::task::yield_now().await;
        drop(rx);

        let res = tokio::time::timeout(std::time::Duration::from_secs(1), handle)
            .await
            .expect("send_data must not hang after the receiver is dropped");
        assert!(
            res.unwrap().is_err(),
            "send_data must fail once the channel is closed"
        );
    }

    #[tokio::test]
    async fn test_stream_read() {
        let (tx, _rx) = bounded_tx(8);
        let (reader_tx, reader_rx) = mpsc::unbounded_channel();

        let reader = StreamReader::new(1, reader_rx);
        let (mut stream, _synack_rx) = Stream::new(1, reader, tx);

        // 发送数据到 reader
        reader_tx.send(Bytes::from("world")).unwrap();

        // 读取数据
        let mut buf = vec![0u8; 10];
        let n = stream.read(&mut buf).await.unwrap();

        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"world");
    }

    #[tokio::test]
    async fn test_stream_read_write() {
        let (tx, mut rx) = bounded_tx(8);
        let (reader_tx, reader_rx) = mpsc::unbounded_channel();

        let reader = StreamReader::new(1, reader_rx);
        let (mut stream, _synack_rx) = Stream::new(1, reader, tx);

        // 同时读写
        reader_tx.send(Bytes::from("input")).unwrap();
        stream.write_all(b"output").await.unwrap();

        // 验证读取
        let mut buf = vec![0u8; 10];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"input");

        // 验证写入
        let (stream_id, data) = rx.recv().await.unwrap();
        assert_eq!(stream_id, 1);
        assert_eq!(data.as_ref(), b"output");
    }
}
