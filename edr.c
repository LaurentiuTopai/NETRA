#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <time.h>
#include "edr.bpf.skel.h"
#include "uthash.h"
#include "filer.bpf.skel.h"
#include "response.h"
#include <fcntl.h>
#include <string.h>
#define MAX_WRITES_ALLOWED 20
#define TIME_WINDOW_SEC 1
struct event{
	__u32 pid;
	__u32 ppid;
	char comm[16];
	int suspicious_writes_count;
	int locked_extensions_count;
	time_t first_seen;
};
struct process_entry{
	__u32 pid;
	__u32 ppid;
	char comm[16];
	int modified_files_count;
	int suspicious_writes_count;
	int locked_extensions_count;
	UT_hash_handle hh;
	char last_extension[32];
	char last_file[256];
	time_t window_start;
	time_t window_actual;
};
struct filer_event{
	__u32 pid;
	char comm[16];
	char filename[256];
	__u32 flags;
};

static const char *WHITE_LISTED_PROC[]={
	"/proc/",
	"/sys/",
	"/tmp/",
	"/var/log/",
	"/home/laurentiu/.cache/",
	"/home/laurentiu/.local/share/tracker/3",
	NULL
};
static const char *WHITE_LISTED_COMM[]={
	"ThreadPoolForeg",
	"CompositorTileW",
	"Chrome_IOThread",
	"chrome",
	NULL
};

struct process_entry *users = NULL;
int is_comm_whitelisted(const char *comm);
int is_path_whitelisted(const char *filename);
static int handle_event(void *ctx,void *data,size_t data_sz){
	const struct event *e = data;
	printf("[EDR] proces nou detectat :PID:%d  PPID:%d  Commanda:%s\n",e->pid,e->ppid,e->comm);
	add_or_update_process(e->pid,e->ppid,e->comm);
	//print_process
	return 0;
}
static int handle_file_event(void *ctx,void *data,size_t data_sz){
	const struct filer_event *e = data;
	int is_write= (e->flags & O_ACCMODE) == O_WRONLY ||
		      (e->flags & O_ACCMODE) == O_RDWR;
	if(is_write){
		register_file_write(e->pid,e->comm,e->filename);
	}
	return 0;
}
void register_file_write(__u32 pid,const char *comm,const char *filename){
	struct process_entry *s;
	HASH_FIND_INT(users,&pid,s);
	if(s==NULL){
		s = calloc(1,sizeof(*s));
		s->pid = pid;
		snprintf(s->comm,sizeof(s->comm),"%s",comm);
		s->window_start = time(NULL);
		HASH_ADD_INT(users,pid,s);
	}
	time_t now = time(NULL);

	if(now - s->window_start > TIME_WINDOW_SEC){
		s->window_start = now;
		s->suspicious_writes_count = 0;
	}
	s->suspicious_writes_count++;
	s->modified_files_count++;
	snprintf(s->last_file,sizeof(s->last_file),"%s",filename);
	s->window_actual = now;
	if(s->suspicious_writes_count > MAX_WRITES_ALLOWED && !is_path_whitelisted(s->last_file)){
		printf("[ALERTA] Pid:%d (%s) a scris %d fisiere in %d secunde! Posibil RANSOMWARE!\n",
				pid,comm,s->suspicious_writes_count,TIME_WINDOW_SEC);
		quarantine_process(pid,s->comm);
	}
}
void print_process(){
	struct process_entry *s,*tmp;
	printf("\n------Stare actuala HASHMAP---------");
	HASH_ITER(hh,users,s,tmp){
		printf("In HASHMAP: PID:%d | PPID:%d, | Total_Accesari:%d | Nume:%s\n",
				s->pid,s->ppid,s->modified_files_count,s->comm);
	}
}
void add_or_update_process(__u32 pid,__u32 ppid,const char *comm){
	struct process_entry *s;
	HASH_FIND_INT(users,&pid,s);
	if(s==NULL){
		s = (struct process_entry *)calloc(1,sizeof(struct process_entry));
		s->pid = pid;
		s->window_start = time(NULL);
		s->window_actual = time(NULL);
		snprintf(s->comm,sizeof(s->comm),"%s",comm);
		s->modified_files_count = 1;

		HASH_ADD_INT(users,pid,s);
	}else{
		s->modified_files_count++;
		s->window_actual = time(NULL);
	}

}





int main(int argc,char **argv){
	struct edr_bpf *skel;
	struct filer_bpf *filer_skel;
	struct ring_buffer *rb = NULL;
	int err;
	setvbuf(stdout,NULL,_IONBF,0);
	// EDR
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

	//FILER
	filer_skel = filer_bpf__open_and_load();
	if(!filer_skel){
		fprintf(stderr,"[EDR]Erroare la deschiderea si incarcarea programului eBPF din filer!\n");
		return 1;
	}
	err = filer_bpf__attach(filer_skel);
	if(err){
		fprintf(stderr,"[EDR]Erroare la atasare programului eBPF din filer!\n");
		return 1;
	}
	
	//Ring buffer
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),handle_event,NULL,NULL);
	if(!rb){
		err = -1;
		fprintf(stderr,"[EDR]Erroare la crearea ring bufferului!\n");
		goto cleanup;
	}
	err = ring_buffer__add(rb,bpf_map__fd(filer_skel->maps.rb),handle_file_event,NULL);
	if(err){
		fprintf(stderr,"[EDR] erroare de atasare file_skel!\n");
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
	filer_bpf__destroy(filer_skel);
	if(err<0){
		err = -errno;
	}else{
		err = 0;
	}


	return 0;
}






int is_path_whitelisted(const char *filename){
	for(int i = 0;WHITE_LISTED_PROC[i]!=NULL;i++){
		if(strncmp(filename,WHITE_LISTED_PROC[i],strlen(WHITE_LISTED_PROC[i]))==0){
			return 1;
		}
	}
	return 0;
}
int is_comm_whitelisted(const char *comm){
	for(int i=0;WHITE_LISTED_COMM[i];i++){
		if(strncmp(comm,WHITE_LISTED_COMM[i],strlen(WHITE_LISTED_COMM[i]))==0){
			return 1;
		}
	}
	return 0;
}




