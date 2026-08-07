#ifndef WHITELIST_H
#define WHITELIST_H

#include <linux/types.h>

int is_path_whitelisted(const char *filename);
int is_comm_whitelisted(const char *comm);
int is_ip4_whitelisted(__u32 ip4);
int is_ip6_whitelisted(__u8 ip6[16]);

#endif
