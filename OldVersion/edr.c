#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <arpa/inet.h>
#include "uthash.h"

#include "edr.bpf.skel.h"
#include "filer.bpf.skel.h"
#include "network.bpf.skel.h"

#include "response.h"
#include "whitelisting.h"

#include <fcntl.h>
#include <string.h>


#define MAX_WRITES_ALLOWED 20
#define TIME_WINDOW_SEC 1
#define SPYWARE_EXFIL_WINDOW_SEC 10

struct event{
	__u32 pid;
	__u32 ppid;
	char comm[16];
	int suspicious_writes_count;
	int locked_extensions_count;
	time_t first_seen;
};
struct exit_event{
	__u32 pid;
};
struct process_entry{
	__u32 pid;
	__u32 ppid;
	char comm[16];

	//file activity
	int modified_files_count;
	int suspicious_writes_count;
	int locked_extensions_count;
	UT_hash_handle hh;
	char last_extension[32];
	char last_file[256];
	time_t window_start;
	time_t window_actual;
	
	//sensitive files
	time_t last_sensitive_read_time;
	char last_sensitive_read_file[256];

	//network
	time_t last_network_time;
	__u16 last_family;
	__u16 last_port;
	__u32 last_ip4;
	__u8 last_ip6[16];
};
struct filer_event{
	__u32 pid;
	char comm[16];
	char filename[256];
	__u32 flags;
};

struct network_event{
	__u32 pid;
	char comm[16];
	__u16 family;
	__u16 port;
	__u32 ip4;
	__u8 ip6[16];
	__u8 protocol;
};

struct process_entry *users = NULL;

static int handle_event(void *ctx,void *data,size_t data_sz){
	const struct event *e = data;
	printf("[EDR]{START} proces nou detectat :PID:%u  PPID:%u  Commanda:%s\n",e->pid,e->ppid,e->comm);
	add_or_update_process(e->pid,e->ppid,e->comm);
	//print_process
	return 0;
}
static int exit_handle_event(void *ctx,void *data,size_t data_sz){
	const struct exit_event *e = data;
	struct process_entry *s;
	HASH_FIND_INT(users,&e->pid,s);
	if(s != NULL){
		printf("[EDR]{EXIT} proces scos: PID %u\n",e->pid);
		HASH_DEL(users,s);
		free(s);
	}
	return 0;
}
static int handle_file_event(void *ctx,void *data,size_t data_sz){
	const struct filer_event *e = data;
	int is_write= (e->flags & O_ACCMODE) == O_WRONLY ||
		      (e->flags & O_ACCMODE) == O_RDWR;
	int is_read = (e->flags & O_ACCMODE) == O_RDONLY ||
		      (e->flags & O_ACCMODE) == O_RDWR;
	if(is_write){
		register_file_write(e->pid,e->comm,e->filename);
	}
	if(is_read){
		register_sensitive_read(e->pid,e->comm,e->filename);
	}
	return 0;
}
static int handle_network_event(void *ctx,void *data,size_t data_sz){
	const struct network_event *e = data;
	struct process_entry *s;
	HASH_FIND_INT(users,&e->pid,s);
	if(s==NULL){
		s = calloc(1,sizeof(*s));
		s->pid = e->pid;
		snprintf(s->comm,sizeof(s->comm),"%s",e->comm);
		HASH_ADD_INT(users,pid,s);
	}
	time_t now = time(NULL);
	s->last_network_time = time;
	s->last_family = e->family;
	s->last_port = e->port;
	s->last_ip4 = e->ip4;
	memcpy(s->last_ip6,e->ip6,sizeof(s->last_ip6));

	if(s->last_sensitive_read_time > 0 && (now - s->last_sensitive_read_time) <=SPYWARE_EXFIL_WINDOW_SEC){
		char ip_str[INET6_ADDRSTRLEN] = {0};
		if(e->family == 2){
			inet_ntop(AF_INET,&e->ip4,ip_str,sizeof(ip_str));
		}else if (e->family == 10){
			inet_ntop(AF_INET6,&e->ip6,ip_str,sizeof(ip_str));
		}

		printf("[SPYWARE_WATCH] pid:%u (%s) a citit fisier sensibil %s acum %ld secunde\n",
				s->pid,s->comm,s->last_sensitive_read_file,(now - s->last_sensitive_read_time));
		quarantine_process(s->pid,s->comm);	
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
	if(s->suspicious_writes_count > MAX_WRITES_ALLOWED && !is_path_whitelisted(s->last_file) && !is_comm_whitelisted(s->comm)){
		printf("[ALERTA] Pid:%u (%s) a scris %d fisiere in %u secunde! Posibil RANSOMWARE!\n",
				pid,comm,s->suspicious_writes_count,TIME_WINDOW_SEC);
		quarantine_process(pid,s->comm);
	}
}
void register_sensitive_read(__u32 pid ,const char *comm,const char *filename){
	if(!is_sensitive_path(filename)){
		return;
	}
	if(is_comm_whitelisted(comm)){
		return;
	}
	struct process_entry *s;
	HASH_FIND_INT(users,&pid,s);
	if(s==NULL){
		s = calloc(1,sizeof(*s));
		s->pid = pid;
		snprintf(s->comm,sizeof(s->comm),"%s",comm);
		HASH_ADD_INT(users,pid,s);
	}
	s->last_sensitive_read_time = time(NULL);
	snprintf(s->last_sensitive_read_file,sizeof(s->last_sensitive_read_file),"%s",filename);
	printf("[SPYWARE_WATCH] pid:%u (%s) a citit fisier sensibil:%s !\n",pid,comm,filename);
}

void print_process(){
	struct process_entry *s,*tmp;
	printf("\n------Stare actuala HASHMAP---------");
	HASH_ITER(hh,users,s,tmp){
		printf("In HASHMAP: PID:%u | PPID:%u, | Total_Accesari:%u | Nume:%s\n",
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
	struct network_bpf *network_skel;
	struct ring_buffer *rb = NULL;
	struct ring_buffer *exit_rb = NULL;
	int err;
	setvbuf(stdout,NULL,_IOLBF,0);
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
	//NETWORK
	
	network_skel = network_bpf__open_and_load();
	if(!network_skel){
		fprintf(stderr,"[EDR]Erroare la deschiderea si incarcarea [rpgramului eBPF din network!\n");
		return 1;
	}
	err = network_bpf__attach(network_skel);
	if(err){
		fprintf(stderr,"[EDR] Erroare la atasare programului eBPF din network!\n");
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
	err = ring_buffer__add(rb,bpf_map__fd(network_skel->maps.rb),handle_network_event,NULL);
	if(err){
		fprintf(stderr,"[EDR] erroare la atasare network_skel!\n");
		goto cleanup;
	}
	err = ring_buffer__add(rb,bpf_map__fd(skel->maps.exit_rb),exit_handle_event,NULL);
	if(err){
		fprintf(stderr,"[EDR] erroare la atasare Exit_RingBuffer !\n");
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
	network_bpf__destroy(network_skel);
	if(err<0){
		err = -errno;
	}else{
		err = 0;
	}


	return 0;
}







