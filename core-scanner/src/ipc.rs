use crate::scanner::scan_port;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

#[derive(Debug, Deserialize)]
struct ScanRequest {
    target: IpAddr,
    start_port: u16,
    end_port: u16,
    #[serde(default = "default_concurrency")]
    concurrency: usize,
}

fn default_concurrency() -> usize {
    200
}

#[derive(Debug, Serialize)]
struct OpenPort {
    port: u16,
    banner: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScanResponse {
    target: IpAddr,
    open_ports: Vec<OpenPort>,
    error: Option<String>,
}

pub async fn run_daemon(socket_path: &str) {
    // Stale socket file from a previous run will make bind() fail otherwise
    let _ = std::fs::remove_file(socket_path);

    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Error: failed to bind Unix socket at {}: {}", socket_path, e);
            return;
        }
    };

    println!("[*] core-scanner daemon listening on {}", socket_path);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_client(stream));
            }
            Err(e) => eprintln!("Error accepting connection: {}", e),
        }
    }
}

// One JSON request per connection: read until the peer half-closes its
// write side, respond, then the connection closes.
async fn handle_client(mut stream: UnixStream) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];

    loop {
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => {
                eprintln!("Error reading from socket: {}", e);
                return;
            }
        }
    }

    let request: ScanRequest = match serde_json::from_slice(&buf) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[daemon] rejected malformed request: {}", e);
            let err_resp = serde_json::json!({ "error": format!("invalid request: {}", e) });
            let _ = stream.write_all(err_resp.to_string().as_bytes()).await;
            return;
        }
    };

    println!(
        "[daemon] scanning {} ports {}-{}",
        request.target, request.start_port, request.end_port
    );
    let response = run_scan(request).await;
    println!(
        "[daemon] {} -> {} open port(s)",
        response.target,
        response.open_ports.len()
    );

    let body = serde_json::to_vec(&response).unwrap_or_default();
    let _ = stream.write_all(&body).await;
}

async fn run_scan(req: ScanRequest) -> ScanResponse {
    let timeout_dur = Duration::from_millis(500);
    let semaphore = Arc::new(Semaphore::new(req.concurrency));
    let mut tasks = vec![];

    for port in req.start_port..=req.end_port {
        let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
        let target = req.target;
        tasks.push(tokio::spawn(async move {
            let res = scan_port(target, port, timeout_dur).await;
            drop(permit);
            res
        }));
    }

    let mut open_ports = vec![];
    for task in tasks {
        if let Ok(Some(result)) = task.await {
            open_ports.push(OpenPort {
                port: result.port,
                banner: result.banner,
            });
        }
    }

    ScanResponse {
        target: req.target,
        open_ports,
        error: None,
    }
}
