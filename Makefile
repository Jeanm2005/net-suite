.PHONY: all rust c go clean

all: rust c go

rust:
	cd core-scanner && cargo build --release
	mkdir -p bin && cp core-scanner/target/release/port_scanner bin/core-scanner

c:
	cd ebpf-filter && make
	mkdir -p bin && cp ebpf-filter/xdp_drop.o bin/

go:
	cd network-orchestrator && go build -o ../bin/net-orchestrator main.go

clean:
	cd core-scanner && cargo clean
	cd ebpf-filter && make clean
	rm -rf bin/
