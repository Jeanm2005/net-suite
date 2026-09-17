use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Default)]
struct RawCounters {
    packet_count: u64,
    byte_count: u64,
    dst_ports: HashSet<u16>,
    syn_count: u64,
    tcp_count: u64,
    udp_count: u64,
}

#[derive(Debug, Serialize, Clone)]
pub struct FlowFeatures {
    pub src_ip: String,
    pub window_secs: f64,
    pub packets_per_sec: f64,
    pub bytes_per_sec: f64,
    pub unique_dst_ports: usize,
    pub syn_ratio: f64,
    pub tcp_ratio: f64,
    pub udp_ratio: f64,
}

pub struct FlowTracker {
    counters: Mutex<HashMap<IpAddr, RawCounters>>,
    window_start: Mutex<Instant>,
}

impl FlowTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            counters: Mutex::new(HashMap::new()),
            window_start: Mutex::new(Instant::now()),
        })
    }

    pub fn record_tcp(&self, src: IpAddr, dst_port: u16, packet_len: usize, is_syn: bool) {
        let mut counters = self.counters.lock().unwrap();
        let entry = counters.entry(src).or_default();
        entry.packet_count += 1;
        entry.byte_count += packet_len as u64;
        entry.dst_ports.insert(dst_port);
        entry.tcp_count += 1;
        if is_syn {
            entry.syn_count += 1;
        }
    }

    pub fn record_udp(&self, src: IpAddr, dst_port: u16, packet_len: usize) {
        let mut counters = self.counters.lock().unwrap();
        let entry = counters.entry(src).or_default();
        entry.packet_count += 1;
        entry.byte_count += packet_len as u64;
        entry.dst_ports.insert(dst_port);
        entry.udp_count += 1;
    }

    pub fn drain_window(&self) -> Vec<FlowFeatures> {
        let mut counters = self.counters.lock().unwrap();
        let mut window_start = self.window_start.lock().unwrap();

        let elapsed = window_start.elapsed().as_secs_f64().max(0.001);
        let mut out = Vec::with_capacity(counters.len());

        for (ip, c) in counters.drain() {
            let total = (c.tcp_count + c.udp_count).max(1) as f64;
            out.push(FlowFeatures {
                src_ip: ip.to_string(),
                window_secs: elapsed,
                packets_per_sec: c.packet_count as f64 / elapsed,
                bytes_per_sec: c.byte_count as f64 / elapsed,
                unique_dst_ports: c.dst_ports.len(),
                syn_ratio: c.syn_count as f64 / total,
                tcp_ratio: c.tcp_count as f64 / total,
                udp_ratio: c.udp_count as f64 / total,
            });
        }

        *window_start = Instant::now();
        out
    }
}
