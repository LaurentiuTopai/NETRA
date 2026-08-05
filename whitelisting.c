#include <string.h>
#include "whitelisting.h"

static const char *WHITE_LISTED_PATH[]={
	"/proc/",
	"/sys/",
	"/dev/",
	"/var/log/",
	"/home/laurentiu/.cache/",
	"/home/laurentiu/.local/share/tracker3/",
	"/bin",
	NULL
};

static const char *WHITE_LISTED_COMM[]={
	"ThreadPoolForeg",
	"CompositorTileW",
	"Chrome_IOThread",
	"chrome",
	"zsh",
	"tracker-miner-f",
	"tracker-extract",
	NULL
};

static const char *SENSITIVE_PATH[]={
	"/home/laurentiu/.ssh/",
	"/home/laurentiu/.mozilla/",
	"/home/laurentiu/.config/google-chrome/",
	"/home/laurentiu/Documents/",
	"/home/laurentiu/Desktop",
	"/etc/passwd",
	"/etc/shadow",
	NULL
};

int is_ip_local_or_whitelisted(__u32 ip4){
	__u8 first_byte = ip4 & 0xFF;
	if(first_byte == 127) return 1;
	if(first_byte == 10) return 1;
	if(first_byte == 192) return 1;
	return 0;
}

int is_path_whitelisted(const char *filename){
	for(int i=0;WHITE_LISTED_PATH[i]!=NULL;i++){
		if(strncmp(filename,WHITE_LISTED_PATH[i],strlen(WHITE_LISTED_PATH[i]))==0){
			return 1;
		}
	}

	return 0;
}
int is_comm_whitelisted(const char *comm){
	for(int i=0;WHITE_LISTED_COMM[i]!=NULL;i++){
		if(strncmp(comm,WHITE_LISTED_COMM[i],strlen(WHITE_LISTED_COMM[i]))==0){
			return 1;
		}
	}
	return 0;
}
int is_sensitive_path(const char *filename){
	for(int i=0;SENSITIVE_PATH[i]!=NULL;i++){
		if(strncmp(filename,SENSITIVE_PATH[i],strlen(SENSITIVE_PATH[i]))==0){
			return 1;
		}
	}
	return 0;
}


