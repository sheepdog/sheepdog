/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __SHEEP_PRIV_H__
#define __SHEEP_PRIV_H__

#include <inttypes.h>

#include "sheepdog_proto.h"
#include "event.h"
#include "logger.h"
#include "work.h"
#include "net.h"
#include "sheep.h"
#include "cluster.h"

#define SD_OP_REMOVE_OBJ     0x91

#define SD_OP_GET_OBJ_LIST   0xA1
#define SD_OP_GET_EPOCH      0XA2

#define SD_STATUS_OK                0x00
#define SD_STATUS_WAIT_FOR_FORMAT   0x01
#define SD_STATUS_WAIT_FOR_JOIN     0x02
#define SD_STATUS_SHUTDOWN          0x03
#define SD_STATUS_JOIN_FAILED       0x04
#define SD_STATUS_HALT              0x05

#define SD_RES_NETWORK_ERROR    0x81 /* Network error between sheeps */

enum cpg_event_type {
	CPG_EVENT_JOIN,
	CPG_EVENT_LEAVE,
	CPG_EVENT_NOTIFY,
	CPG_EVENT_REQUEST,
};

#define is_membership_change_event(x) \
	((x) == CPG_EVENT_JOIN || (x) == CPG_EVENT_LEAVE)

struct cpg_event {
	enum cpg_event_type ctype;
	struct list_head cpg_event_list;
	unsigned int skip;
};

struct client_info {
	struct connection conn;

	struct request *rx_req;

	struct request *tx_req;

	struct list_head reqs;
	struct list_head done_reqs;

	int refcnt;
};

struct request;

typedef void (*req_end_t) (struct request *);

struct request {
	struct cpg_event cev;
	struct sd_req rq;
	struct sd_rsp rp;

	void *data;

	struct client_info *ci;
	struct list_head r_siblings;
	struct list_head r_wlist;
	struct list_head pending_list;

	uint64_t local_oid;

	struct sheepdog_vnode_list_entry entry[SD_MAX_VNODES];
	int nr_vnodes;
	int nr_zones;
	int check_consistency;

	req_end_t done;
	struct work work;
};

#define MAX_DATA_OBJECT_BMAPS 64

struct data_object_bmap {
	uint32_t vdi_id;
	DECLARE_BITMAP(dobjs, MAX_DATA_OBJS);

	struct list_head list;
};

struct cluster_info {
	struct cluster_driver *cdrv;

	/* set after finishing the JOIN procedure */
	int join_finished;
	struct sheepdog_node_list_entry this_node;

	uint32_t epoch;
	uint32_t status;
	uint16_t flags;

	/*
	 * we add a node to cpg_node_list in confchg then move it to
	 * sd_node_list when the node joins sheepdog.
	 */
	struct list_head cpg_node_list;
	struct list_head sd_node_list;

	/* leave list is only used to account for bad nodes when we start
	 * up the cluster nodes after we shutdown the cluster through collie.
	 */
	struct list_head leave_list;

	/* this array contains a list of ordered virtual nodes */
	struct sheepdog_vnode_list_entry vnodes[SD_MAX_VNODES];
	int nr_vnodes;

	struct list_head pending_list;

	DECLARE_BITMAP(vdi_inuse, SD_NR_VDIS);

	struct list_head outstanding_req_list;
	struct list_head req_wait_for_obj_list;
	struct list_head consistent_obj_list;

	uint32_t nr_sobjs;

	struct list_head cpg_event_siblings;
	struct cpg_event *cur_cevent;
	unsigned long cpg_event_work_flags;
	int nr_outstanding_io;
	int nr_outstanding_reqs;

	uint32_t recovered_epoch;

	int use_directio;

	struct work_queue *cpg_wqueue;
	struct work_queue *gateway_wqueue;
	struct work_queue *io_wqueue;
	struct work_queue *deletion_wqueue;
	struct work_queue *recovery_wqueue;
};

extern struct cluster_info *sys;

int create_listen_port(int port, void *data);

int is_io_request(unsigned op);
int init_store(const char *dir);
int init_base_path(const char *dir);

int add_vdi(uint32_t epoch, char *data, int data_len, uint64_t size,
	    uint32_t *new_vid, uint32_t base_vid, uint32_t copies,
	    int is_snapshot, unsigned int *nr_copies);

int del_vdi(uint32_t epoch, char *data, int data_len, uint32_t *vid,
	    uint32_t snapid, unsigned int *nr_copies);

int lookup_vdi(uint32_t epoch, char *name, char *tag, uint32_t *vid,
	       uint32_t snapid, unsigned int *nr_copies, uint64_t *ctime);

int read_vdis(char *data, int len, unsigned int *rsp_len);

int get_vdi_attr(uint32_t epoch, struct sheepdog_vdi_attr *vattr, int data_len,
		 uint32_t vid, uint32_t *attrid, int copies, uint64_t ctime,
		 int write, int excl, int delete);

int get_ordered_sd_node_list(struct sheepdog_node_list_entry *entries);
void setup_ordered_sd_vnode_list(struct request *req);
void get_ordered_sd_vnode_list(struct sheepdog_vnode_list_entry *entries,
			       int *nr_vnodes, int *nr_zones);
int is_access_to_busy_objects(uint64_t oid);
int is_access_local(struct sheepdog_vnode_list_entry *e, int nr_nodes,
		    uint64_t oid, int copies);

void resume_pending_requests(void);

int create_cluster(int port, int64_t zone);
int leave_cluster(void);

void start_cpg_event_work(void);
void store_queue_request(struct work *work, int idx);
int write_object_local(uint64_t oid, char *data, unsigned int datalen,
		       uint64_t offset, uint16_t flags, int copies,
		       uint32_t epoch, int create);
int read_object_local(uint64_t oid, char *data, unsigned int datalen,
		      uint64_t offset, int copies, uint32_t epoch);

int read_epoch(uint32_t *epoch, uint64_t *ctime,
	       struct sheepdog_node_list_entry *entries, int *nr_entries);
void cluster_queue_request(struct work *work, int idx);

int update_epoch_store(uint32_t epoch);

int set_global_nr_copies(uint32_t copies);
int get_global_nr_copies(uint32_t *copies);
int set_cluster_flags(uint16_t flags);
int get_cluster_flags(uint16_t *flags);

int sys_flag_nohalt(void);

#define NR_GW_WORKER_THREAD 4
#define NR_IO_WORKER_THREAD 4

int epoch_log_write(uint32_t epoch, char *buf, int len);
int epoch_log_read(uint32_t epoch, char *buf, int len);
int epoch_log_read_nr(uint32_t epoch, char *buf, int len);
int epoch_log_read_remote(uint32_t epoch, char *buf, int len);
int get_latest_epoch(void);
int remove_epoch(int epoch);
int set_cluster_ctime(uint64_t ctime);
uint64_t get_cluster_ctime(void);

int start_recovery(uint32_t epoch);
void resume_recovery_work(void);
int is_recoverying_oid(uint64_t oid);

int write_object(struct sheepdog_vnode_list_entry *e,
		 int vnodes, int zones, uint32_t node_version,
		 uint64_t oid, char *data, unsigned int datalen,
		 uint64_t offset, uint16_t flags, int nr, int create);
int read_object(struct sheepdog_vnode_list_entry *e,
		int vnodes, int zones, uint32_t node_version,
		uint64_t oid, char *data, unsigned int datalen,
		uint64_t offset, int nr);
int remove_object(struct sheepdog_vnode_list_entry *e,
		  int vnodes, int zones, uint32_t node_version,
		  uint64_t oid, int nr);

int get_sheep_fd(uint8_t *addr, uint16_t port, int node_idx,
		 uint32_t epoch, int worker_idx);

/* Journal */
int jrnl_perform(int fd, void *buf, size_t count, off_t offset,
		 const char *path, const char *jrnl_dir);
int jrnl_recover(const char *jrnl_dir);

static inline int is_myself(uint8_t *addr, uint16_t port)
{
	return (memcmp(addr, sys->this_node.addr,
		       sizeof(sys->this_node.addr)) == 0) &&
		port == sys->this_node.port;
}

#endif
