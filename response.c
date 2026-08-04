#include "response.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>

void quarantine_process(__u32 pid,const char* comm){
	if(kill(pid,SIGSTOP) == 0){
		printf("[RASPUNS] PID:%d (%s) a fost suspendat (SIGSTOP)!\n",pid,comm);
	}else{
		perror("[RASPUNS] Erroare la suspendare!\n");
	}
}
void kill_malicious_process(__u32 pid){
	if(kill(pid,SIGKILL) == 0){
		printf("[RASPUNS] PID:%d (%s) a fost oprit (SIGKILL)!\n");
	}else{
		perror("[RASPUNS] Erroare la kill!\n");
	}
}
/**
void dump_process_forensics(__u32 pid){
	
}
*/
