#ifndef SOCKFD_CACHE_H
#define SOCKFD_CACHE_H

#include "internal_proto.h"
#include "work.h"

enum channel_status {
	IO,
	NonIO
};
struct sockfd *sockfd_cache_get(const struct node_id *nid);
void sockfd_cache_put(const struct node_id *nid, struct sockfd *sfd);
void sockfd_cache_del_node(const struct node_id *nid);
void sockfd_cache_del(const struct node_id *nid, struct sockfd *sfd);
void sockfd_cache_add(const struct node_id *nid);
void sockfd_cache_add_group(const struct rb_root *nroot);

int sockfd_init(void);
int start_node_connectivity_monitor(void);

/* sockfd_cache */
struct sockfd {
	int fd;
	int idx;
};

#endif	/* SOCKFD_CACHE_H */
