# Net-Suite

A high-performance, modular offensive security and network diagnostics suite built using a polyglot monorepo architecture (**Rust**, **C / eBPF**, and **Go**).

## Architecture & System Design

`net-suite` leverages each language for its specific domain strengths:

```text
                      +----------------------------------+
                      |         Linux Kernel             |
                      |                                  |
                      |  [ eBPF / XDP Filter (C) ]       |
                      |   - Zero-copy packet dropping    |
                      |   - SKB/Generic XDP support      |
                      +----------------+-----------------+
                                       |
                   eBPF Map / Unix Socket (IPC)
                                       |
      +--------------------------------+--------------------------------+
      |                                                                 |
      v                                                                 v
+-----------------------------+                           +-----------------------------+
|    core-scanner (Rust)      |                           | network-orchestrator (Go)   |
|                             |                           |                             |
| - Async TCP/UDP probing     | <--- IPC / Shared JSON ---> | - Concurrent CIDR sweeper   |
| - Banner grabbing & sniffer |                           | - Target state tracking     |
| - OS fingerprinting         |                           | - Orchestration & API       |
+-----------------------------+                           +-----------------------------+

Directory Structure
core-scanner/ (Rust): Asynchronous port scanner (tokio), service banner parser, packet capture engine (pnet), and TTL fingerprinting.

ebpf-filter/ (C): Kernel-space XDP packet filter program with user-space C lifecycle manager (libbpf).

network-orchestrator/ (Go): CIDR subnet sweeper using concurrent goroutines for rapid active host discovery.

bin/: Central target output directory for cross-compiled suite binaries.

Build Requirements
Linux Kernel with eBPF support (Ubuntu / WSL2 supported)

clang, llvm, libbpf-dev, gcc, make

Rust toolchain (cargo, rustc)

Go (go compiler 1.20+)

# Compile all modules into ./bin
make

# Run the Go network sweeper
./bin/net-orchestrator --range 192.168.1.0/24

# Load the eBPF packet filter (Generic mode for virtualized environments)
sudo ./bin/ebpf-loader eth0 load

---

### Step 3: Project Handoff Prompt

Save the following text block. You can paste this as your opening prompt in any future chat session to restore 100% of the project context instantly.

***

```text
[PROJECT HANDOFF PROMPT: NET-SUITE]

1. FINAL PRODUCT VISION
We are building "Net-Suite", a modular, high-performance offensive security and network diagnostics tool using a polyglot architecture:
- Rust (core-scanner): Async port scanner, raw packet capture (pnet), banner grabbing, and OS fingerprinting.
- C / eBPF (ebpf-filter): Kernel-space XDP packet filter (dropping TCP port 80 traffic) and a user-space loader binary using libbpf.
- Go (network-orchestrator): Concurrent CIDR subnet sweeper and service orchestrator.
- System Design: Micro-components connected via Unix Domain Sockets (IPC) and eBPF maps, built via a central root Makefile into ~/net-suite/bin/.

2. COMPLETED SO FAR
- Environment: WSL2 (Ubuntu), clang, libbpf-dev, Rust, Go.
- Repository Layout (~/net-suite):
  ├── Makefile (root orchestrator)
  ├── README.md & .gitignore
  ├── bin/
  ├── core-scanner/ (Rust: main.rs, scanner.rs, banner.rs, fingerprint.rs, packet_capture.rs)
  ├── ebpf-filter/ (C: xdp_drop.c, loader.c, Makefile)
  └── network-orchestrator/ (Go: main.go, go.mod)
- ebpf-filter details: Built xdp_drop.o (kernel space) and ebpf-loader (user space) with libbpf.
- network-orchestrator details: Built concurrent CIDR sweeper with Go worker pools.

3. ERRORS ENCOUNTERED & RESOLVED
- Header inclusion issues: Resolved missing `asm/types.h` by adding `-I/usr/include/x86_64-linux-gnu` to BPF_CFLAGS.
- Target library conflicts: Removed `<arpa/inet.h>` and standard glibc includes in kernel space; replaced with `<bpf/bpf_endian.h>` (`bpf_htons`) and `<linux/in.h>` (`IPPROTO_TCP`).
- WSL2 / Hyper-V Driver Limit: Native XDP failed on `eth0` with `hv_netvsc: XDP: not support LRO`. Resolved by using `XDP_FLAGS_SKB_MODE` (Generic XDP mode) in `loader.c` for virtualized interfaces.

4. CURRENT ENVIRONMENT & STATUS
- Host: WSL2 (Ubuntu) running Linux Kernel 6.x.
- All three components compile without warnings using `make` at the root directory.
- Code is pushed to GitHub on branch `main`.

5. PLANNED NEXT STEPS
- Update `ebpf-filter/loader.c` to accept command-line flags for toggling between Generic (`XDP_FLAGS_SKB_MODE`) and Native (`XDP_FLAGS_DRV_MODE`) XDP modes.
- Implement Unix Domain Socket (IPC) IPC communication between Go (`network-orchestrator`) and Rust (`core-scanner`) to pass discovered live IPs dynamically.
- Expand eBPF maps to pass packet drop statistics back to user space in real time.
