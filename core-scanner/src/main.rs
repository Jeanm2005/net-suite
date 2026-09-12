mod banner;
mod fingerprint;
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
    /// Target IP address to scan
    #[arg(short, long)]
    target: Option<IpAddr>,

    /// Starting port number
    #[arg(short = 's', long, default_value_t = 1)]
    start_port: u16,

    /// Ending port number
    #[arg(short = 'e', long, default_value_t = 1024)]
    end_port: u16,

    /// Maximum concurrent connection probes
    #[arg(short, long, default_value_t = 200)]
    concurrency: usize,

    /// Monitor live network headers on an interface (e.g., eth0)
    #[arg(short, long)]
    monitor: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Route 1: Live Interface Packet Monitor Mode
    if let Some(interface) = args.monitor {
        tokio::task::spawn_blocking(move || {
            packet_capture::monitor_interface(&interface);
        })
        .await
        .unwrap();
        return;
    }

    // Route 2: Port Scanner Mode
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
        println!("Error: Must provide either --target <IP> or --monitor <INTERFACE>");
    }
}
