mod banner;
mod fingerprint;
mod flow_tracker;
mod ipc;
mod packet_capture;
mod scanner;

use clap::Parser;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Parser, Debug)]
#[command(author, version, about = "Network Analysis & Diagnostics Utility")]
struct Args {
    #[arg(short, long)]
    target: Option<IpAddr>,

    #[arg(short = 's', long, default_value_t = 1)]
    start_port: u16,

    #[arg(short = 'e', long, default_value_t = 1024)]
    end_port: u16,

    #[arg(short, long, default_value_t = 200)]
    concurrency: usize,

    #[arg(short, long)]
    monitor: Option<String>,

    /// Run as an IPC daemon on a Unix socket, accepting JSON scan requests
    #[arg(short, long)]
    daemon: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Some(socket_path) = args.daemon {
        ipc::run_daemon(&socket_path).await;
        return;
    }

    if let Some(interface) = args.monitor {
        let tracker = flow_tracker::FlowTracker::new();
        let reporter_tracker = Arc::clone(&tracker);

        // Every 10s, drain accumulated per-host counters into feature vectors
        // and print them as JSON lines.
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(10));
            for features in reporter_tracker.drain_window() {
                match serde_json::to_string(&features) {
                    Ok(json) => println!("[flow] {}", json),
                    Err(e) => eprintln!("[flow] serialize error: {}", e),
                }
            }
        });

        tokio::task::spawn_blocking(move || {
            packet_capture::monitor_interface(&interface, tracker);
        })
        .await
        .unwrap();
        return;
    }

    if let Some(target) = args.target {
        let timeout_dur = Duration::from_millis(500);
        let semaphore = Arc::new(Semaphore::new(args.concurrency));

        println!("Target: {}", target);
        println!("Port Range: {} - {}", args.start_port, args.end_port);
        println!("--------------------------------------------------");

        let mut tasks = vec![];
        for port in args.start_port..=args.end_port {
            let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
            let task = tokio::spawn(async move {
                let res = scanner::scan_port(target, port, timeout_dur).await;
                drop(permit);
                res
            });
            tasks.push(task);
        }

        for task in tasks {
            if let Ok(Some(result)) = task.await {
                match result.banner {
                    Some(banner) => println!("[+] Port {:<5} | OPEN | Banner: {}", result.port, banner),
                    None => println!("[+] Port {:<5} | OPEN | Banner: None / Silent", result.port),
                }
            }
        }

        println!("--------------------------------------------------");
        println!("Execution finished.");
    } else {
        println!("Error: Must provide either --target <IP>, --monitor <INTERFACE>, or --daemon <SOCKET_PATH>");
    }
}
