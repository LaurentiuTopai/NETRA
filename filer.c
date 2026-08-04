#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "filer.bpf.skel.h"
#include <errno.h>
#include <fcntl.h>

struct filer_event{
	__u32 pid;
	char comm[16];
	char filename[256];
	__u32 flags;
};

static int handle_event(void *ctx,void *data,size_t data_sz){

	char flag_str[256];
	const struct filer_event *e = data;
	int is_write = (e->flags & O_ACCMODE) == O_WRONLY ||
		       (e->flags & O_ACCMODE) == O_RDWR;
	decode_flags(e->flags,flag_str,sizeof(flag_str));
	printf("[FILE] PID: %-6d | Comm: %-16s | Fisier: %s | Flags:%s!\n",
			e->pid, e->comm,e->filename,flag_str);
	return 0;
}
void decode_flags(int flags, char *buf,size_t len){
	buf[0]='\0';

	int access_mode = flags & O_ACCMODE;
	if(access_mode == O_RDONLY){
		strncat(buf,"O_RDONLY",len - strlen(buf) - 1);
	}else if(access_mode == O_WRONLY){
		strncat(buf,"O_WRONLY",len - strlen(buf) - 1);
	}else if(access_mode == O_RDWR){
		strncat(buf,"O_RDWR",len - strlen(buf) - 1);
	}


	if(flags & O_CREAT) strncat(buf,"| O_CREAT", len - strlen(buf) - 1);
	if(flags & O_TRUNC) strncat(buf,"| O_TRUNC", len - strlen(buf) - 1);
	if(flags & O_APPEND) strncat(buf,"| O_APPEND",len - strlen(buf) - 1);
	if(flags & O_CLOEXEC) strncat(buf,"| O_CLOEXEC",len - strlen(buf) - 1);
}


int main(int argc,char **argv){
	struct filer_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;

	setvbuf(stdout,NULL,_IONBF,0);
	skel = filer_bpf__open_and_load();
	if(!skel){
		fprintf(stderr,"[FILE]Erroare la deschiderea si incarcarea programului eBPF!\n");
		return 1;
	}
	err = filer_bpf__attach(skel);
	if(err){
		fprintf(stderr,"[FILE]Erroare la atasarea programului eBPF!\n");
		return 1;
	}
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),handle_event,NULL,NULL);
	if(!rb){
		err = -1;
		fprintf(stderr,"[FILE]Erroare la crearea ring bufferului!\n");
		goto cleanup;
	}
	printf("[FILE] a pornit cu succes!\n");
	while(1){
		err = ring_buffer__poll(rb,100);
		if(err<0 && err!= -EINTR){
			fprintf(stderr,"[FILE]Erroare la pollul-irea ringului de buffer:%d",err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	filer_bpf__destroy(skel);
	if(err<0){
		err = -errno;
	}else{
		err = 0;
	}


	return 0;
}




