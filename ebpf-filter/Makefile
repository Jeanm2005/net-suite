CLANG ?= clang
CC ?= gcc
CFLAGS ?= -O2 -g -Wall

# Add host-arch includes so bpf target can locate asm/types.h
BPF_CFLAGS = -target bpf -I/usr/include -I/usr/include/x86_64-linux-gnu
LIBS = -lbpf -lelf

BPF_OBJ = xdp_drop.o
LOADER_BIN = ebpf-loader

all: $(BPF_OBJ) $(LOADER_BIN)

$(BPF_OBJ): xdp_drop.c
	$(CLANG) $(CFLAGS) $(BPF_CFLAGS) -c $< -o $@

$(LOADER_BIN): loader.c
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

clean:
	rm -f $(BPF_OBJ) $(LOADER_BIN)

.PHONY: all clean
