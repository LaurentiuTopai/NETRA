#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct{
	__uint(type,BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256*1024);

}rb SEC(".maps");



//Structura pachet:
// pid 
// comm
// family
// port
// ip4

struct network_event{
	__u32 pid;
	char comm[TASK_COMM_LEN];
	__u16 family;
	__u16 port;
	__u32 ip4;
	__u8 ip6[16];
	__u8 protocol;
};








//Aici vine path-ul pentru network
SEC("kprobe/__sys_connect")


//Aici parametrul de context
int BPF_KPROBE(handle_connect,int fd,struct sockaddr *uservaddr,int addrlen){
	struct network_event *e;

	e = bpf_ringbuf_reserve(&rb,sizeof(*e),0);
	if(!e){
		bpf_printk("Problema de alocare a memoriei ring bufferului in network!\n");
		return 1;
	}

	__u64 id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	bpf_get_current_comm(&e->comm,sizeof(e->comm));
		
	e->protocol = 1;

	__u16 sa_family = 0;
	bpf_core_read(&sa_family,sizeof(sa_family),&uservaddr->sa_family);
	e->family = sa_family;

	if(sa_family == 2){
		struct sockaddr_in *addr_in = (struct sockaddr_in *)uservaddr;
		
		__u16 port = 0;
		bpf_core_read(&port,sizeof(port),&addr_in->sin_port);
		e->port = __builtin_bswap16(port);

		__u32 ip4 = 0;
		bpf_core_read(&ip4,sizeof(ip4),&addr_in->sin_addr.s_addr);
		e->ip4 = ip4;
	}else if(sa_family == 10){
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)uservaddr;
		__u16 port = 0;
		bpf_core_read(&port,sizeof(port),&addr_in6->sin6_port);
		e->port = __builtin_bswap16(port);

		bpf_core_read(&e->ip6,sizeof(e->ip6),&addr_in6->sin6_addr);
	}else{
		e->port = 0;
		e->ip4 = 0;

	}
	bpf_ringbuf_submit(e,0);
	return 0;
}
SEC("kprobe/__sys_sendto")
int BPF_KPROBE(handle_sendto,int fd,void *buf,size_t len,unsigned int flags,struct sockaddr *uservaddr,int addrlen){
	struct network_event *e;
	e = bpf_ringbuf_reserve(&rb,sizeof(*e),0);
	if(!e){
		bpf_printk("Problema de alocare a memoriei ring bufferului in network func2!\n");
		return 1;
	}
	__u64 id = bpf_get_current_pid_tgid();
	e->pid = id >>32;
	bpf_get_current_comm(&e->comm,sizeof(e->comm));


	__u16 sa_family = 0;
	bpf_core_read(&sa_family,sizeof(sa_family),&uservaddr->sa_family);
	e->family = sa_family;

	if(sa_family == 2){
		struct sockaddr_in *addr_in = (struct sockaddr_in *)uservaddr;

		__u16 port = 0;
		bpf_core_read(&port,sizeof(port),&addr_in->sin_port);
		e->port = __builtin_bswap16(port);
	if(e->port == 53){
		e->protocol = 3;
	}else{
		e->protocol = 2;
	}
		__u32 ip4 = 0;
		bpf_core_read(&ip4,sizeof(ip4),&addr_in->sin_addr.s_addr);
		e->ip4 = ip4;
	}else if(sa_family == 10){

		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)uservaddr;
		__u16 port = 0;
		bpf_core_read(&port,sizeof(port),&addr_in6->sin6_port);
		e->port = __builtin_bswap16(port);
	if(e->port == 53){
		e->protocol = 3;
	}else{
		e->protocol = 2;
	}
		bpf_core_read(&e->ip6,sizeof(e->ip6),&addr_in6->sin6_addr);
	}else{
		e->protocol = 2;
		e->port = 0;
		e->ip4 = 0;
	}
	bpf_ringbuf_submit(e,0);
	return 0;
}

SEC("kprobe/__sys_socket")
int BPF_KPROBE(handle_socket,int family,int type,int protocol){
	//type 3 = SOCK_RAW
	//protocol 1 = IPPROTO_ICMP
	//
	//
	//
	//
  if(protocol==1){
	struct network_event *e;
	e = bpf_ringbuf_reserve(&rb,sizeof(*e),0);
	if(!e){
		bpf_printk("Problema de alocare a memoriei ring bufferului in network func3!\n");
		return 1;
	}

	__u64 id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	bpf_get_current_comm(&e->comm,sizeof(e->comm));
	e->family = family;
	e->protocol = 4;
	bpf_ringbuf_submit(e,0);
	}
  return 0;
}

