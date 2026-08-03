#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";


struct{
	__uint(type,BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256*1024);

}rb SEC(".maps");
struct event{
	__u32 pid;
	__u32 ppid;
	char comm[TASK_COMM_LEN];

};

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx){
	struct event *e;

	e = bpf_ringbuf_reserve(&rb,sizeof(*e),0);
	if(!e){
		bpf_printk("A bubuit la alocare de memorie pentru e!\n");
		return 0;
	}
	__u64 id = bpf_get_current_pid_tgid();

	e->pid = id >>	32;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	
	e->ppid = BPF_CORE_READ(task,real_parent,tgid);
	
	bpf_get_current_comm(&e->comm,sizeof(e->comm));
	
	bpf_ringbuf_submit(e,0);
}

