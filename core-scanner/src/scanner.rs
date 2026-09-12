use crate::banner::grab_banner;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug)]
pub struct ScanResult {
    pub port: u16,
    pub banner: Option<String>,
}

pub async fn scan_port(ip: IpAddr, port: u16, timeout_dur: Duration) -> Option<ScanResult> {
    let socket_addr = SocketAddr::new(ip, port);

    if let Ok(Ok(mut stream)) = timeout(timeout_dur, TcpStream::connect(&socket_addr)).await {
        let banner = grab_banner(&mut stream).await;
        return Some(ScanResult { port, banner });
    }

    None
}
