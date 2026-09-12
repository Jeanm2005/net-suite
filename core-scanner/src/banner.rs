use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Reads an initial banner string from an open TCP stream
pub async fn grab_banner(stream: &mut TcpStream) -> Option<String> {
    let mut buffer = [0u8; 256];

    // Send a standard HTTP probe to trigger a server header response if passive
    let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;

    match timeout(Duration::from_millis(400), stream.read(&mut buffer)).await {
        Ok(Ok(bytes_read)) if bytes_read > 0 => {
            String::from_utf8_lossy(&buffer[..bytes_read])
                .lines()
                .next()
                .map(|line| line.trim().to_string())
        }
        _ => None,
    }
}
