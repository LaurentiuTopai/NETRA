#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "network.bpf.skel.h"
#include <arpa/inet.h>
#include <sys/socket.h>

struct network_event{
	__u32 pid;
	char comm[16];
	__u16 family;
	__u16 port;
	__u32 ip4;
	__u8 ip6[16];
	__u8 protocol;
};

static int handle_event(void *ctx,void *data,size_t data_sz){

	const struct network_event *e = data;
if(e->protocol == 1){
	if(e->family == 2){
		char ip_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET,&e->ip4,ip_str,sizeof(ip_str));
		printf("[NETWOKR] Conexiune TCP detectata: PID%d | Comanda:%s | Destinatie IP:%s | Post:%d!\n",
				e->pid,e->comm,ip_str,e->port);
	 }else if(e->family == 10){
		char ip_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6,&e->ip6,ip_str,sizeof(ip_str));
		printf("[NETWORK] Conexiune TCP detectata: PID:%d | Comanda:%s | Destinatie IP:%s | Port%d!\n",
				e->pid,e->comm,ip_str,e->port);
	 }else{
		printf("[NETWORK] Conexiune TCP detectata: PID:%d | Comanda:%s | Conexiune Locala!\n",
				e->pid,e->comm);
	 }
	}
if(e->protocol == 2){
	if(e->family == 2){
		char ip_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET,&e->ip4,ip_str,sizeof(ip_str));
		printf("[NETWORK] Conexiune UDP detectata: PID:%d | Comanda:%s | Destinatie IP:%s | Port:%d!\n",
				e->pid,e->comm,ip_str,e->port);

	}else if(e->family == 10){
		char ip_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6,&e->ip6,ip_str,sizeof(ip_str));
		printf("[NETWORK] Conexiune UDP detectata: PID:%d | Comanda:%s | Destinatie IP:%s | Port:%d!\n",
				e->pid,e->comm,ip_str,e->port);
	}else{
		printf("[NETWORK] Conexiune UDP detectata: PID:%d | Comanda:%s | Conexiune Locala!\n",
		e->pid,e->comm);
	}
  }
if(e->protocol == 3){
	if(e->family == 2){
		char ip_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET,&e->ip4,ip_str,sizeof(ip_str));
		printf("[NETWORK] Conexiune DNS detectata: PID:%d | Comanda:%s | Server DNS: %s!\n",
				e->pid,e->comm,ip_str);
	}else if(e->family == 10){
		char ip_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6,&e->ip6,ip_str,sizeof(ip_str));
		printf("[NETWORK] Conexiune DNS detectata: PID:%d | Comanda:%s | Server DNS: %s!\n",
				e->pid,e->comm,ip_str);
	}
}
if(e->protocol == 4){
	printf("[NETWORK] Conexiune ICMP detectata: PID:%d | Comanda:%s | Family:%d!\n",
			e->pid,e->comm,e->family);
}
	return 0;
}

int main(int argc,char** argv){
	struct network_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;

	setvbuf(stdout,NULL,_IONBF,0);

	skel = network_bpf__open_and_load();
	if(!skel){
		fprintf(stderr,"[NETWORK]Erroare la deschiderea si incarcarea programului eBPF!\n");
		return 1;
	}
	err = network_bpf__attach(skel);
	if(err){
		fprintf(stderr,"[NETWORK]Erroare la atasarea programului eBPF!\n");
		return 1;
	}
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),handle_event,NULL,NULL);
	if(!rb){
		err = -1;
		fprintf(stderr,"[NETWORK]Erroare la crearea ring bufferului!\n");
		goto cleanup;
	}
	printf("[Network] a pornit cu succes!\n");
	while(1){
		err = ring_buffer__poll(rb,100);
		if(err<0 && err != -EINTR){
			fprintf(stderr,"[NETWORK]Erroare la pollul-irea ringului de buffer:%d",err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	network_bpf__destroy(skel);
	if(err<0){
		err = -errno;
	}else{
		err = 0;
	}

	return 0;
}





