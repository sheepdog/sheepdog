/*
 * Copyright (C) 2009 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __VOST_H__
#define __VOST_H__

#include <inttypes.h>

#include "sheepdog_proto.h"
#include "list.h"
#include "event.h"
#include "logger.h"
#include "work.h"
#include "net.h"

struct client_info {
	struct connection conn;

	struct request *rx_req;

	struct request *tx_req;

	struct list_head reqs;
	struct list_head done_reqs;
};

struct request;

typedef void (*req_end_t)(struct request *);

struct request {
	struct sd_req rq;
	struct sd_rsp rp;

	void *data;

	struct client_info *ci;
	struct list_head r_siblings;
	struct list_head r_wlist;

	req_end_t done;
	struct work work;
};

extern uint32_t node_list_version;

extern int nr_nodes;
extern int dogport;
extern struct sheepdog_node_list_entry *node_list_entries;

int create_listen_port(int port);

int init_store(char *dir);

void queue_request(struct request *req);

int get_node_list(void *buf, unsigned int size, unsigned int *epoch, int *idx,
		  int set_timer);
#endif
