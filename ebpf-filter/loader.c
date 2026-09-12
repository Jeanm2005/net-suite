#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile int keep_running = 1;

void sig_handler(int sig) {
	keep_running = 0;
}

int main(int argc, char **argv) {
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <interface> <action: load|unload>\n", argv[0]);
		return 1;
	}

	const char *ifname = argv[1];
	const char *action = argv[2];

	unsigned int ifindex = if_nametoindex(ifname);
	if (ifindex == 0) {
		fprintf(stderr, "Error: Invalid interface name %s\n", ifname);
		return 1;
	}

	if (strcmp(action, "unload") == 0) {\
		printf("[*] Detaching XDP program from %s...\n", ifname);
		if (bpf_xdp_detach(ifindex, 0, NULL) < 0) {
			fprintf(stderr, "Failed to detach XDP program: %s\n", strerror(errno));
			return 1;
		}
		printf("[+] Successfully detached XDP program.\n");
		return 0;
	}

	if (strcmp(action, "load") != 0) {
		fprintf(stderr, "Error: Unknown action '%s'. Use 'load' or 'unload'.\n", action);
		return 1;
	}

	struct bpf_object *obj = bpf_object__open_file("xdp_drop.o", NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "Error: Failed to open BPF object file xdp_drop.o\n");
		return 1;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "Error: Failed to load BPF object into kernel\n");
		return 1;
	}

	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_drop_tcp_port");
	if (!prog) {
		fprintf(stderr, "Error: Failed to find BPF program 'xdp_drop_tcp_port'\n");
		return 1;
	}

	int prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "Error: Failed to get BPF program file descriptor\n");
		return 1;
	}

	printf("[*] Attaching XDP filter to interface %s (index %d)...\n", ifname, ifindex);
	if (bpf_xdp_attach(ifindex, prog_fd, 0, NULL) < 0) {
		fprintf(stderr, "Error: Failed to attach XDP program: %s\n", strerror(errno));
		return 1;
	}

	printf("[+] XDP Filter active on %s! Press Crtl+C to stop and detach.\n", ifname);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (keep_running) {
		sleep(1);
	}

	printf("\n[*] Cleaning up and detaching XDP program...\n");
    	bpf_xdp_detach(ifindex, 0, NULL);
   	bpf_object__close(obj);
    	printf("[+] Detached and exited cleanly.\n");

    	return 0;
}
