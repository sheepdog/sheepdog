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
#ifndef __COLLIE_H__
#define __COLLIE_H__

#include <inttypes.h>
#include <corosync/cpg.h>

#include "sheepdog_proto.h"
#include "event.h"
#include "logger.h"
#include "work.h"
#include "net.h"
#include "meta.h"

#define SD_MSG_JOIN             0x01
#define SD_MSG_VDI_OP           0x02
#define SD_MSG_MASTER_CHANGED   0x03

struct client_info {
	struct connection conn;

	struct request *rx_req;

	struct request *tx_req;

	struct list_head reqs;
	struct list_head done_reqs;
};

struct request;

typedef void (*req_end_t) (struct request *);

struct request {
	struct sd_req rq;
	struct sd_rsp rp;

	void *data;

	struct client_info *ci;
	struct list_head r_siblings;
	struct list_head r_wlist;
	struct list_head pending_list;

	req_end_t done;
	struct work work;
};

struct cluster_info {
	cpg_handle_t handle;
	/* set after finishing the JOIN procedure */
	int join_finished;
	uint32_t this_nodeid;
	uint32_t this_pid;
	struct sheepdog_node_list_entry this_node;

	uint32_t epoch;
	uint32_t status;

	/*
	 * we add a node to cpg_node_list in confchg then move it to
	 * sd_node_list when the node joins sheepdog.
	 */
	struct list_head cpg_node_list;
	struct list_head sd_node_list;

	struct list_head vm_list;
	struct list_head pending_list;

	DECLARE_BITMAP(vdi_inuse, SD_NR_VDIS);

	int nr_sobjs;

	struct list_head cpg_event_siblings;
	struct cpg_event *cur_cevent;
	unsigned long cpg_event_work_flags;
};

struct cluster_info *sys;

int create_listen_port(int port, void *data);

int init_store(char *dir);

int add_vdi(char *data, int data_len, uint64_t size,
	    uint64_t *new_oid, uint64_t base_oid, uint32_t copies,
	    int is_snapshot);

int del_vdi(char *data, int data_len, uint32_t snapid);

int lookup_vdi(char *data, int data_len, uint64_t *oid, uint32_t snapid);

int read_vdis(char *data, int len, unsigned int *rsp_len);

int get_ordered_sd_node_list(struct sheepdog_node_list_entry *entries);

int create_cluster(int port);

void so_queue_request(struct work *work, int idx);

void store_queue_request(struct work *work, int idx);

int read_epoch(uint32_t *epoch, uint64_t *ctime,
	       struct sheepdog_node_list_entry *entries, int *nr_entries);
void epoch_queue_request(struct work *work, int idx);

void cluster_queue_request(struct work *work, int idx);

int update_epoch_store(uint32_t epoch);

int set_global_nr_copies(uint32_t copies);
int get_global_nr_copies(uint32_t *copies);
int set_nodeid(uint64_t nodeid);
int get_nodeid(uint64_t *nodeid);

#define DATA_OBJ_NR_WORKER_THREAD 4
extern struct work_queue *dobj_queue;

int epoch_log_write(uint32_t epoch, char *buf, int len);
int epoch_log_read(uint32_t epoch, char *buf, int len);
int get_latest_epoch(void);
int remove_epoch(int epoch);
int set_cluster_ctime(uint64_t ctime);
uint64_t get_cluster_ctime(void);

int start_recovery(uint32_t epoch, unsigned long *failed_vdis, int nr_failed_vdis);
int start_deletion(uint64_t oid);

static inline int is_myself(struct sheepdog_node_list_entry *e)
{
	return e->id == sys->this_node.id;
}

#endif
