/*
 * Copyright (C) 2015 China Mobile Inc.
 *
 * Liu Yuan <liuyuan@cmss.chinamobile.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SHEEPDOG_H_
#define SHEEPDOG_H_

#ifndef NO_SHEEPDOG_LOGGER
# define NO_SHEEPDOG_LOGGER
#endif

#include "sheepdog_proto.h"
#include "list.h"
#include "util.h"

#include <arpa/inet.h>

struct sd_cluster {
	int sockfd;
	uint8_t addr[INET_ADDRSTRLEN];
	unsigned int port;
	uint32_t seq_num;
	pthread_t request_thread;
	pthread_t reply_thread;
	int request_fd, reply_fd;
	struct list_head request_list;
	struct list_head inflight_list;
	struct list_head blocking_list;
	uatomic_bool stop_request_handler;
	uatomic_bool stop_reply_handler;
	struct sd_rw_lock request_lock;
	struct sd_rw_lock inflight_lock;
	struct sd_rw_lock blocking_lock;
	struct sd_mutex submit_mutex;
};

struct sd_request {
	struct list_node list;
	struct sd_vdi *vdi;
	void *data;
	size_t length;
	off_t offset;
	bool write;
};

struct sd_vdi {
	struct sd_cluster *cluster;
	struct sd_inode *inode;
	uint32_t vid;
	struct sd_rw_lock lock;
};

int sd_init(void);
void sd_free(void);
struct sd_cluster *sd_connect(char *host);
int sd_disconnect(struct sd_cluster *sd);
int sd_run_sdreq(struct sd_cluster *c, struct sd_req *hdr, void *data);

#endif
