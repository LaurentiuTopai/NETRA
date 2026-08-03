#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "edr.bpf.skel.h"

struct event{
	__u32 pid;
	__u32 ppid;
	char comm[16];
};

static int handle_event(void *ctx,void *data,size_t data_sz){
	const struct event *e = data;
	printf("[EDR] proces nou detectat :PID:%d  PPID:%d  Commanda:%s\n",e->pid,e->ppid,e->comm);
	return 0;
}

int main(int argc,char **argv){
	struct edr_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;
	setvbuf(stdout,NULL,_IONBF,0);

	skel = edr_bpf__open_and_load();
	if(!skel){
		fprintf(stderr,"[EDR]Erroare la deschiderea si incarcarea programului eBPF!\n");
		return 1;
	}
	err = edr_bpf__attach(skel);
	if(err){
		fprintf(stderr,"[EDR]Erroare la atasarea programului eBPF!\n");
		return 1;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),handle_event,NULL,NULL);
	if(!rb){
		err = -1;
		fprintf(stderr,"[EDR]Erroare la crearea ring bufferului!\n");
		goto cleanup;
	}
	printf("[EDR] a pornit cu succes!\n");
	while(1){
		err = ring_buffer__poll(rb,100);
		if(err<0 && err != -EINTR){
			fprintf(stderr,"Erroare la pollu-irea ringului de buffer:%d",err);
			break;
		}

	}

cleanup:
	ring_buffer__free(rb);
	edr_bpf__destroy(skel);
	if(err<0){
		err = -errno;
	}else{
		err = 0;
	}




	return 0;
}












