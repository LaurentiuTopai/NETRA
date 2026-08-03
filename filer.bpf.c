#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
char LICENSE[] SEC("license") = "GPL";


struct filer_event{

	__u32 pid;
	char comm[16];
	char filename[256];
	__u32 flags;

};
struct{
	__uint(type,BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256*1024);


}rb SEC(".maps");

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx){
	struct filer_event *e;

	e = bpf_ringbuf_reserve(&rb,sizeof(*e),0);
	if(!e){
		bpf_printk("Problema de alocare a memoriei ring bufferului in filer!\n");
		return 1;
	}
	__u64 id = bpf_get_current_pid_tgid();
	e->pid = id >>32;
	bpf_get_current_comm(&e->comm,sizeof(e->comm));
	const char *filename_ptr = (const char*)ctx->args[1];
	bpf_core_read_user_str(&e->filename,sizeof(e->filename),filename_ptr);

	e->flags = (int)ctx->args[2];

	bpf_ringbuf_submit(e,0);
	return 0;
}



