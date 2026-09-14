package main

import (
	"errors"
	"flag"
	"fmt"
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

func main() {
	rangeFlag := flag.String("range", "", "CIDR range to sweep, e.g. 192.168.1.0/24")
	concurrency := flag.Int("concurrency", 256, "max concurrent probes")
	timeoutMs := flag.Int("timeout", 300, "per-host probe timeout in milliseconds")
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

// canOpenICMP checks once, up front, whether this process can open a raw
// ICMP socket at all, so the whole sweep can pick a strategy instead of
// failing silently host by host.
func canOpenICMP() bool {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// pingICMP sends one ICMP echo request and waits for a matching reply.
// It opens its own socket per call instead of sharing one across goroutines:
// a raw ICMP socket receives a copy of every inbound ICMP packet on the
// host regardless of which peer it was destined for, so concurrent reads
// on a shared socket can steal each other's replies. Filtering by peer
// address below is what makes per-call sockets safe to run concurrently.
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
			continue // some other host's reply landed on this socket; keep waiting
		}
		rm, err := icmp.ParseMessage(1, reply[:n]) // 1 = ICMPv4 protocol number
		if err != nil {
			continue
		}
		if rm.Type == ipv4.ICMPTypeEchoReply {
			return true
		}
	}
}

// isAliveTCP treats a host as live if a TCP handshake completes, or if the
// connection is actively refused — a refusal still proves the IP answered.
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
