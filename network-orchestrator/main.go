package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type scanRequest struct {
	Target      string `json:"target"`
	StartPort   int    `json:"start_port"`
	EndPort     int    `json:"end_port"`
	Concurrency int    `json:"concurrency"`
}

type openPort struct {
	Port   int     `json:"port"`
	Banner *string `json:"banner"`
}

type scanResponse struct {
	Target    string     `json:"target"`
	OpenPorts []openPort `json:"open_ports"`
	Error     *string    `json:"error"`
}

func scanViaDaemon(socketPath, target string, startPort, endPort int) (*scanResponse, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to scanner daemon: %w", err)
	}
	defer conn.Close()

	req := scanRequest{Target: target, StartPort: startPort, EndPort: endPort, Concurrency: 200}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(body); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	if uc, ok := conn.(*net.UnixConn); ok {
		uc.CloseWrite()
	}

	respBytes, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var resp scanResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, fmt.Errorf("bad response %q: %w", string(respBytes), err)
	}
	return &resp, nil
}

func main() {
	rangeFlag := flag.String("range", "", "CIDR range to sweep, e.g. 192.168.1.0/24")
	concurrency := flag.Int("concurrency", 256, "max concurrent probes")
	timeoutMs := flag.Int("timeout", 300, "per-host probe timeout in milliseconds")
	scanLive := flag.Bool("scan-live", false, "after sweeping, port-scan every live host via the core-scanner daemon")
	scannerSocket := flag.String("scanner-socket", "/tmp/net-suite-scanner.sock", "path to the core-scanner daemon's Unix socket")
	scanStartPort := flag.Int("scan-start-port", 1, "start port for follow-up scans (with --scan-live)")
	scanEndPort := flag.Int("scan-end-port", 1024, "end port for follow-up scans (with --scan-live)")
	flag.Parse()

	if *rangeFlag == "" {
		fmt.Fprintln(os.Stderr, "Error: --range is required, e.g. --range 192.168.1.0/24")
		os.Exit(1)
	}

	prefix, err := netip.ParsePrefix(*rangeFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid CIDR %q: %v\n", *rangeFlag, err)
		os.Exit(1)
	}

	bits := prefix.Addr().BitLen() - prefix.Bits()
	if bits > 20 {
		fmt.Fprintf(os.Stderr, "Error: range covers %d hosts — narrow it to a /20 or smaller\n", 1<<bits)
		os.Exit(1)
	}

	icmpAvailable := canOpenICMP()
	if !icmpAvailable {
		fmt.Fprintln(os.Stderr, "[!] No permission for raw ICMP sockets (try running with sudo) — falling back to TCP-only liveness, which will undercount hosts with nothing listening on 80/443/22/445")
	}

	hosts := expandHosts(prefix, bits)
	fmt.Printf("Sweeping %d hosts in %s (concurrency=%d)\n", len(hosts), prefix, *concurrency)
	fmt.Println("--------------------------------------------------")

	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var alive []string
	var seqCounter int32
	timeout := time.Duration(*timeoutMs) * time.Millisecond

	for _, ip := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			seq := int(atomic.AddInt32(&seqCounter, 1))
			live := false
			if icmpAvailable {
				live = pingICMP(ip, timeout, seq)
			}
			if !live {
				live = isAliveTCP(ip, timeout)
			}
			if live {
				mu.Lock()
				alive = append(alive, ip)
				mu.Unlock()
				fmt.Printf("[+] %-15s | ALIVE\n", ip)
			}
		}(ip)
	}
	wg.Wait()

	fmt.Println("--------------------------------------------------")
	fmt.Printf("Sweep finished: %d/%d hosts responded\n", len(alive), len(hosts))

	if !*scanLive || len(alive) == 0 {
		return
	}

	fmt.Println("--------------------------------------------------")
	fmt.Printf("Scanning %d live host(s) via core-scanner daemon at %s (ports %d-%d)\n",
		len(alive), *scannerSocket, *scanStartPort, *scanEndPort)
	fmt.Println("--------------------------------------------------")

	for _, ip := range alive {
		resp, err := scanViaDaemon(*scannerSocket, ip, *scanStartPort, *scanEndPort)
		if err != nil {
			fmt.Printf("[!] %-15s | scan failed: %v\n", ip, err)
			continue
		}
		if resp.Error != nil {
			fmt.Printf("[!] %-15s | daemon error: %s\n", ip, *resp.Error)
			continue
		}
		if len(resp.OpenPorts) == 0 {
			fmt.Printf("[ ] %-15s | no open ports in range\n", ip)
			continue
		}
		for _, p := range resp.OpenPorts {
			banner := "None / Silent"
			if p.Banner != nil {
				banner = *p.Banner
			}
			fmt.Printf("[+] %-15s | Port %-5d | OPEN | Banner: %s\n", ip, p.Port, banner)
		}
	}
}

func expandHosts(prefix netip.Prefix, bits int) []string {
	addr := prefix.Masked().Addr()
	total := 1 << bits
	hosts := make([]string, 0, total)

	for i := 0; i < total; i++ {
		if total > 2 && (i == 0 || i == total-1) {
			addr = addr.Next()
			continue
		}
		hosts = append(hosts, addr.String())
		addr = addr.Next()
	}
	return hosts
}

func canOpenICMP() bool {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func pingICMP(ip string, timeout time.Duration, seq int) bool {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  seq,
			Data: []byte("net-suite"),
		},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return false
	}

	dst := &net.IPAddr{IP: net.ParseIP(ip)}
	if _, err := conn.WriteTo(b, dst); err != nil {
		return false
	}

	deadline := time.Now().Add(timeout)
	reply := make([]byte, 1500)
	for {
		if time.Until(deadline) <= 0 {
			return false
		}
		conn.SetReadDeadline(deadline)

		n, peer, err := conn.ReadFrom(reply)
		if err != nil {
			return false
		}
		if peer.String() != ip {
			continue
		}
		rm, err := icmp.ParseMessage(1, reply[:n])
		if err != nil {
			continue
		}
		if rm.Type == ipv4.ICMPTypeEchoReply {
			return true
		}
	}
}

func isAliveTCP(ip string, timeout time.Duration) bool {
	for _, port := range []string{"80", "443", "22", "445"} {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), timeout)
		if err == nil {
			conn.Close()
			return true
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			return true
		}
	}
	return false
}