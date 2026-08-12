#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define MAX_NAME_LEN 64

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

enum event_type {
	EVENT_MEMFD_CREATE = 1,
	EVENT_FINIT_MODULE = 2,
	EVENT_PTRACE       = 3,
	EVENT_BPF          = 4,
};

struct rootkit_event {
	__u32 type;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	char comm[TASK_COMM_LEN];
	__s64 arg1;
	__s64 arg2;
	char str_arg[MAX_NAME_LEN];
};

const struct rootkit_event *unused_rootkit_event __attribute__((unused));

static __always_inline struct rootkit_event* reserve_common_event(__u32 event_type) {
	struct rootkit_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		bpf_printk("A bubuit alocarea ringbuf in rootkit!\n");
		return NULL;
	}
	__u64 id = bpf_get_current_pid_tgid();
	
	e->type = event_type;
	e->pid = id >> 32;
	e->uid = bpf_get_current_uid_gid();
	
	struct task_struct *task = (struct task_struct*)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	
	e->arg1 = 0;
	e->arg2 = 0;
	e->str_arg[0] = '\0';
	
	return e;
}

// Folosit pentru fileless malware
SEC("tp/syscalls/sys_enter_memfd_create")
int handle_memfd_create(struct trace_event_raw_sys_enter *ctx) {
	struct rootkit_event *e = reserve_common_event(EVENT_MEMFD_CREATE);
	if (!e) return 0;
	
	const char *name_ptr = (const char *)ctx->args[0];
	e->arg2 = (long)ctx->args[1];
	bpf_core_read_user_str(&e->str_arg, sizeof(e->str_arg), name_ptr);
	
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Folosit pentru detectarea de noi module in kernel din fisiere .ko
SEC("tp/syscalls/sys_enter_finit_module")
int handle_finit_module(struct trace_event_raw_sys_enter *ctx) {
	struct rootkit_event *e = reserve_common_event(EVENT_FINIT_MODULE);
	if (!e) return 0;
	
	e->arg1 = (long)ctx->args[0];
	e->arg2 = (long)ctx->args[2];
	
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Folosit pentru a inspecta sau injecta cod in alte procese din sistem
SEC("tp/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx) {
	struct rootkit_event *e = reserve_common_event(EVENT_PTRACE);
	if (!e) return 0;
	
	e->arg1 = (long)ctx->args[0];
	e->arg2 = (long)ctx->args[1];
	
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Folosit pentru a detecta incarcarea altor programe BPF in kernel
SEC("tp/syscalls/sys_enter_bpf")
int handle_bpf(struct trace_event_raw_sys_enter *ctx) {
	struct rootkit_event *e = reserve_common_event(EVENT_BPF);
	if (!e) return 0;
	
	e->arg1 = (long)ctx->args[0];
	
	bpf_ringbuf_submit(e, 0);
	return 0;
}
