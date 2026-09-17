use crate::fingerprint::estimate_os_from_ttl;
use crate::flow_tracker::FlowTracker;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;
use std::sync::Arc;

/// Monitors live traffic on a given interface (requires elevated privileges),
/// feeding per-source flow statistics into `tracker` for later anomaly scoring.
pub fn monitor_interface(interface_name: &str, tracker: Arc<FlowTracker>) {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Specified network interface was not found");

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_, rx)) => ((), rx),
        Ok(_) => panic!("Unhandled datalink channel type"),
        Err(e) => panic!("Failed to open network interface channel: {}", e),
    };

    println!("[*] Live Packet Monitor attached to interface: {}", interface_name);

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet_len = packet.len();
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ip) = Ipv4Packet::new(ethernet.payload()) {
                            let src = IpAddr::V4(ip.get_source());

                            match ip.get_next_level_protocol() {
                                IpNextHeaderProtocols::Tcp => {
                                    if let Some(tcp) = TcpPacket::new(ip.payload()) {
                                        let ttl = ip.get_ttl();
                                        let os_guess = estimate_os_from_ttl(ttl);
                                        let is_syn = tcp.get_flags() & TcpFlags::SYN != 0;

                                        println!(
                                            "[Traffic] {}:{} -> {}:{} | TTL: {} ({})",
                                            ip.get_source(),
                                            tcp.get_source(),
                                            ip.get_destination(),
                                            tcp.get_destination(),
                                            ttl,
                                            os_guess
                                        );

                                        tracker.record_tcp(src, tcp.get_destination(), packet_len, is_syn);
                                    }
                                }
                                IpNextHeaderProtocols::Udp => {
                                    if let Some(udp) = UdpPacket::new(ip.payload()) {
                                        tracker.record_udp(src, udp.get_destination(), packet_len);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("Error reading interface frame: {}", e),
        }
    }
}
