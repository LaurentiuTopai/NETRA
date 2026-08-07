#ifndef RESPONSE_H
#define RESPONSE_H


#include <sys/types.h>
#include <linux/types.h>

void quarantine_process(__u32 pid,const char *comm);
void kill_malicious_process(__u32 pid);
void dump_process_forensics(__u32 pid);

#endif
