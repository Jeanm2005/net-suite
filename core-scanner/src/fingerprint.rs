/// Basic heuristic mapping of default IP Time-To-Live (TTL) values to operating system families
pub fn estimate_os_from_ttl(ttl: u8) -> &'static str {
    match ttl {
        0..=64 => "Linux / Unix / Android / macOS",
        65..=128 => "Windows",
        129..=255 => "Network Infrastructure (Cisco/Solaris)",
    }
}
