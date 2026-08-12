#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_MSG_SIZE 256
char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct network_event {
	__u32 pid;
	char comm[TASK_COMM_LEN];
	__u16 family;
	__u16 port;
	__u32 ip4;
	__u8 ip6[16];
	__u8 protocol;
	__u32 len;
	char data[MAX_MSG_SIZE];
};

const struct network_event *unused_network_event __attribute__((unused));

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
	struct sockaddr *uservaddr = (struct sockaddr *)ctx->args[1];
	struct network_event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		bpf_printk("Problema de alocare a memoriei ring bufferului in network!\n");
		return 0;
	}

	__u64 id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->protocol = 1;
	e->len = 0;
	e->data[0] = '\0';

	__u16 sa_family = 0;
	bpf_probe_read_user(&sa_family, sizeof(sa_family), &uservaddr->sa_family);
	e->family = sa_family;

	if (sa_family == 2) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)uservaddr;
		__u16 port = 0;
		bpf_probe_read_user(&port, sizeof(port), &addr_in->sin_port);
		e->port = __builtin_bswap16(port);

		__u32 ip4 = 0;
		bpf_probe_read_user(&ip4, sizeof(ip4), &addr_in->sin_addr.s_addr);
		e->ip4 = ip4;
	} else if (sa_family == 10) {
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)uservaddr;
		__u16 port = 0;
		bpf_probe_read_user(&port, sizeof(port), &addr_in6->sin6_port);
		e->port = __builtin_bswap16(port);

		bpf_probe_read_user(&e->ip6, sizeof(e->ip6), &addr_in6->sin6_addr);
	} else {
		e->port = 0;
		e->ip4 = 0;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_sendto")
int handle_sendto(struct trace_event_raw_sys_enter *ctx) {
	void *buf = (void *)ctx->args[1];
	size_t len = (size_t)ctx->args[2];
	struct sockaddr *uservaddr = (struct sockaddr *)ctx->args[4];

	struct network_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		bpf_printk("Problema de alocare a memoriei ring bufferului in network sendto!\n");
		return 0;
	}

	__u64 id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// Copiem continutul pachetului trimis (payload)
	__u32 copy_len = len > MAX_MSG_SIZE ? MAX_MSG_SIZE : (__u32)len;
	e->len = copy_len;
	e->data[0] = '\0';

	if (buf && copy_len > 0) {
		bpf_probe_read_user(&e->data, copy_len, buf);
	}

	if (uservaddr) {
		__u16 sa_family = 0;
		bpf_probe_read_user(&sa_family, sizeof(sa_family), &uservaddr->sa_family);
		e->family = sa_family;

		if (sa_family == 2) {
			struct sockaddr_in *addr_in = (struct sockaddr_in *)uservaddr;
			__u16 port = 0;
			bpf_probe_read_user(&port, sizeof(port), &addr_in->sin_port);
			e->port = __builtin_bswap16(port);

			if (e->port == 53) {
				e->protocol = 3; // DNS
			} else {
				e->protocol = 2; // UDP/TCP sendto
			}

			__u32 ip4 = 0;
			bpf_probe_read_user(&ip4, sizeof(ip4), &addr_in->sin_addr.s_addr);
			e->ip4 = ip4;
		} else if (sa_family == 10) {
			struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)uservaddr;
			__u16 port = 0;
			bpf_probe_read_user(&port, sizeof(port), &addr_in6->sin6_port);
			e->port = __builtin_bswap16(port);

			if (e->port == 53) {
				e->protocol = 3;
			} else {
				e->protocol = 2;
			}
			bpf_probe_read_user(&e->ip6, sizeof(e->ip6), &addr_in6->sin6_addr);
		} else {
			e->protocol = 2;
			e->port = 0;
			e->ip4 = 0;
		}
	} else {
		e->family = 0;
		e->port = 0;
		e->ip4 = 0;
		e->protocol = 2;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_socket")
int handle_socket(struct trace_event_raw_sys_enter *ctx) {
	int family = (int)ctx->args[0];
	int protocol = (int)ctx->args[2];

	if (protocol == 1) { // ICMP
		struct network_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
		if (!e) {
			bpf_printk("Problema de alocare a memoriei ring bufferului in network socket!\n");
			return 0;
		}

		__u64 id = bpf_get_current_pid_tgid();
		e->pid = id >> 32;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		e->family = family;
		e->protocol = 4; // RAW ICMP
		e->len = 0;
		e->data[0] = '\0';

		bpf_ringbuf_submit(e, 0);
	}
	return 0;
}
