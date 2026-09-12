use crate::fingerprint::estimate_os_from_ttl;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

/// Monitors live traffic headers on a given interface (Requires elevated privileges)
pub fn monitor_interface(interface_name: &str) {
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
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ip) = Ipv4Packet::new(ethernet.payload()) {
                            if ip.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                                if let Some(tcp) = TcpPacket::new(ip.payload()) {
                                    // Extract TTL and estimate OS family
                                    let ttl = ip.get_ttl();
                                    let os_guess = estimate_os_from_ttl(ttl);

                                    println!(
                                        "[Traffic] {}:{} -> {}:{} | TTL: {} ({})",
                                        ip.get_source(),
                                        tcp.get_source(),
                                        ip.get_destination(),
                                        tcp.get_destination(),
                                        ttl,
                                        os_guess
                                    );
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("Error reading interface frame: {}", e),
        }
    }
}
