# net-suite

A network security toolkit built across Rust, Go, C/eBPF, and Python — host discovery, port scanning, kernel-level packet filtering, and a bounded ML layer for flagging anomalous traffic. Built in WSL2 (Ubuntu on Windows 11) as a systems/networking-focused project, with a narrow ML layer.

## Architecture

```
network-orchestrator (Go)          core-scanner (Rust)
  CIDR sweep, ICMP-first     --->    Unix-socket daemon:
  host discovery, then                port scan + banner
  hands live hosts to the             grab + OS fingerprint
  scanner daemon over IPC             + live traffic capture
                                              |
                                              v
                                    flow_tracker: per-host
                                    packets/sec, bytes/sec,
                                    unique ports, SYN ratio,
                                    protocol mix, every 10s
                                              |
                                              v
                                    ml-scorer (Python):
                                    IsolationForest baseline
                                    per host, flags outliers
                                    (flag-only, no auto-action)

ebpf-filter (C/XDP)
  Kernel-level TCP-port drop, configurable via a BPF hash map
  (not hardcoded) — loaded/unloaded independently of the above
```

Each component is independently runnable. Nothing here auto-wires the ML layer's flags into the kernel filter yet — that's a deliberate, not-yet-built step (see Status below).

## Components

### `core-scanner` (Rust)

- **CLI scan mode**: `--target <IP> --start-port N --end-port N` — concurrent async port scan with banner grabbing and TTL-based OS fingerprinting.
- **Daemon mode**: `--daemon <socket-path>` — runs as a persistent Unix-socket JSON service. Accepts `{"target": "...", "start_port": N, "end_port": N}`, returns open ports + banners. Built so `network-orchestrator` can drive it automatically.
- **Monitor mode**: `--monitor <interface>` — live packet capture (requires root). Prints per-packet traffic lines and, every 10 seconds, a `[flow] {...}` JSON line per source host with aggregated traffic features (see `ml-scorer` below).

### `network-orchestrator` (Go)

- CIDR sweep with **ICMP-first, TCP-fallback** host discovery (a TCP `ECONNREFUSED` still counts as "host is up" even if the specific port is closed).
- Bounded concurrency via a semaphore — avoids spawning one goroutine per host unconditionally on large ranges. Refuses ranges larger than a `/20` outright.
- `--scan-live` flag: after sweeping, automatically calls `core-scanner`'s daemon over the Unix socket for every live host found, producing a single sweep-then-scan pipeline instead of two manual steps.

### `ebpf-filter` (C / eBPF / XDP)

- `xdp_drop.c`: an XDP program that drops incoming TCP packets whose destination port is in a BPF hash map (`drop_ports`) — configurable at load time, not compiled in.
- `loader.c`: attaches/detaches the XDP program on a given interface. `ebpf-loader <iface> load [port...]` populates the map with the given ports (defaults to port 80 if none given); `ebpf-loader <iface> unload` detaches cleanly. Runs in the foreground until Ctrl+C.

### `ml-scorer` (Python)

- Reads `[flow] {...}` JSON lines from `core-scanner --monitor`'s stdout.
- Maintains a rolling per-host history and trains an `IsolationForest` once 30 windows (~5 minutes) of history exist per host, retraining every 60 windows thereafter.
- Flags outlier windows to stdout with a severity score and a best-effort guess at which feature deviated most; normal windows log to stderr for visibility during development.
- **Flag-only.** Nothing here blocks or drops traffic automatically — see Status.

## Build

```bash
make rust   # builds core-scanner, copies binary to bin/
make c      # builds xdp_drop.o + ebpf-loader, copies both to bin/
make go     # builds network-orchestrator, copies binary to bin/
make all    # all three
make clean  # removes build artifacts and bin/
```

`ml-scorer` isn't part of the Makefile — it's a plain Python script:

```bash
cd ml-scorer
pip install -r requirements.txt --break-system-packages
```

## Usage

Sweep a subnet and auto-scan every live host found:

```bash
# Terminal 1 — start the scan daemon
cd core-scanner && ./target/release/port_scanner --daemon /tmp/net-suite-scanner.sock

# Terminal 2 — sweep + auto-scan
sudo ./bin/net-orchestrator --range 192.168.1.0/24 --scan-live --scan-end-port 1024
```

Monitor live traffic and feed it to the anomaly scorer:

```bash
cd core-scanner
sudo ./target/release/port_scanner --monitor eth0 | python3 ../ml-scorer/anomaly_scorer.py
```

Load the kernel-level filter against specific ports:

```bash
cd bin
sudo ./ebpf-loader eth0 load 8080 8443   # drops those two ports
sudo ./ebpf-loader eth0 unload           # detaches, Ctrl+C also works
```

## CI/CD

`.github/workflows/ci.yml` builds all three compiled components (Rust, Go, C/eBPF) on every push. On a build failure, a second job downloads that component's build log, asks Claude to propose a fix, applies it, **rebuilds locally to confirm the fix actually works**, and opens a pull request tagged `✅ VERIFIED` or `⚠️ UNVERIFIED` depending on whether the rebuild passed — it never merges automatically. This loop has been tested end-to-end against a real, deliberately introduced build failure.

## Status —

Everything below has been built **and independently validated** against real traffic/hosts:

- Core scanner CLI, daemon mode, and IPC bridge to `network-orchestrator` — confirmed against ground truth (daemon results matched standalone CLI results on the same target).
- Flow tracker — confirmed emitting correct per-host JSON, correctly separating concurrent traffic sources (including background OS traffic it wasn't deliberately fed).
- XDP filter — confirmed with a real before/after test: a service on a filtered port was unreachable while the filter was attached and immediately reachable again after detaching.
- Self-healing CI — confirmed against a real, intentionally introduced build failure; the autofix loop detected it, generated a fix, avoided a symbol collision on its own, verified the rebuild, and the fix was merged.

Known environment quirk: on WSL2/Hyper-V, native XDP attach fails against `hv_netvsc` unless LRO is disabled first (`sudo ethtool -K eth0 lro off`). This is not a code issue,just a driver limitation.

Not yet done:
- The ML scorer hasn't been run long enough on real traffic to know its actual false-positive rate. `contamination=0.05` in the code is an untuned guess.
- No automatic enforcement: a flagged anomaly does not currently trigger the eBPF filter, even though the filter's BPF-map design now supports being updated with a port at runtime for exactly this purpose. Wiring that connection is the next major step, deliberately gated behind proving the detector isn't crying wolf first.
- No automated tests yet for either the Rust/Go logic or the ML scoring logic.
