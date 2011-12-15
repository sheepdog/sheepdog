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

#define SD_STATUS_OK                0x00000001
#define SD_STATUS_WAIT_FOR_FORMAT   0x00000002
#define SD_STATUS_WAIT_FOR_JOIN     0x00000004
#define SD_STATUS_SHUTDOWN          0x00000008
#define SD_STATUS_JOIN_FAILED       0x00000010
#define SD_STATUS_HALT              0x00000020

#define SD_RES_NETWORK_ERROR    0x81 /* Network error between sheep */

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

	struct sd_op_template *op;

	void *data;
	unsigned int data_length;

	struct client_info *ci;
	struct list_head r_siblings;
	struct list_head r_wlist;
	struct list_head pending_list;

	uint64_t local_oid;

	struct sheepdog_vnode_list_entry *entry;
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

#define MAX_OUTSTANDING_DATA_SIZE (256 * 1024 * 1024)

struct cluster_info {
	struct cluster_driver *cdrv;
	const char *cdrv_option;

	/* set after finishing the JOIN procedure */
	int join_finished;
	struct sheepdog_node_list_entry this_node;

	uint32_t epoch;
	uint32_t status;
	uint16_t flags;

	/* leave list is only used to account for bad nodes when we start
	 * up the cluster nodes after we shutdown the cluster through collie.
	 */
	struct list_head leave_list;

	struct sheepdog_node_list_entry nodes[SD_MAX_NODES];
	int nr_nodes;

	/* this array contains a list of ordered virtual nodes */
	struct sheepdog_vnode_list_entry vnodes[SD_MAX_VNODES];
	int nr_vnodes;

	struct list_head pending_list;

	DECLARE_BITMAP(vdi_inuse, SD_NR_VDIS);

	struct list_head outstanding_req_list;
	struct list_head req_wait_for_obj_list;
	struct list_head consistent_obj_list;
	struct list_head blocking_conn_list;

	uint32_t nr_sobjs;

	struct list_head cpg_event_siblings;
	struct cpg_event *cur_cevent;
	int nr_outstanding_io;
	int nr_outstanding_reqs;
	unsigned int outstanding_data_size;

	uint32_t recovered_epoch;

	int use_directio;

	struct work_queue *cpg_wqueue;
	struct work_queue *gateway_wqueue;
	struct work_queue *io_wqueue;
	struct work_queue *deletion_wqueue;
	struct work_queue *recovery_wqueue;
};

struct siocb {
	int fd;
	uint16_t flags;
	uint32_t epoch;
	void *buf;
	uint32_t length;
	uint64_t offset;
};

struct store_driver {
	const char *driver_name;
	int (*init)(char *path);
	int (*open)(uint64_t oid, struct siocb *, int create);
	int (*write)(uint64_t oid, struct siocb *);
	int (*read)(uint64_t oid, struct siocb *);
	int (*close)(uint64_t oid, struct siocb *);
	/* Operations in recovery */
	int (*get_objlist)(struct siocb *);
	int (*link)(uint64_t oid, struct siocb *, int tgt_epoch);
};

extern void register_store_driver(struct store_driver *);

extern struct cluster_info *sys;

int create_listen_port(int port, void *data);

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

int get_zones_nr_from(struct sheepdog_node_list_entry *nodes, int nr_nodes);
void setup_ordered_sd_vnode_list(struct request *req);
int get_ordered_sd_vnode_list(struct sheepdog_vnode_list_entry **entries,
			      int *nr_vnodes, int *nr_zones);
void free_ordered_sd_vnode_list(struct sheepdog_vnode_list_entry *entries);
int is_access_to_busy_objects(uint64_t oid);
int is_access_local(struct sheepdog_vnode_list_entry *e, int nr_nodes,
		    uint64_t oid, int copies);

void resume_pending_requests(void);

int create_cluster(int port, int64_t zone);
int leave_cluster(void);

void start_cpg_event_work(void);
void do_io_request(struct work *work);
int write_object_local(uint64_t oid, char *data, unsigned int datalen,
		       uint64_t offset, uint16_t flags, int copies,
		       uint32_t epoch, int create);
int read_object_local(uint64_t oid, char *data, unsigned int datalen,
		      uint64_t offset, int copies, uint32_t epoch);

int read_epoch(uint32_t *epoch, uint64_t *ctime,
	       struct sheepdog_node_list_entry *entries, int *nr_entries);
void do_cluster_request(struct work *work);

int update_epoch_store(uint32_t epoch);
int update_epoch_log(int epoch);

int set_cluster_copies(uint8_t copies);
int get_cluster_copies(uint8_t *copies);
int set_cluster_flags(uint16_t flags);
int get_cluster_flags(uint16_t *flags);

int store_create_and_write_obj(const struct sd_req *, struct sd_rsp *, void *);
int store_write_obj(const struct sd_req *, struct sd_rsp *, void *);
int store_read_obj(const struct sd_req *, struct sd_rsp *, void *);
int store_remove_obj(const struct sd_req *, struct sd_rsp *, void *);

#define NR_GW_WORKER_THREAD 4
#define NR_IO_WORKER_THREAD 4

int epoch_log_read(uint32_t epoch, char *buf, int len);
int epoch_log_read_nr(uint32_t epoch, char *buf, int len);
int epoch_log_read_remote(uint32_t epoch, char *buf, int len);
int get_latest_epoch(void);
int remove_epoch(int epoch);
int set_cluster_ctime(uint64_t ctime);
uint64_t get_cluster_ctime(void);
int stat_sheep(uint64_t *store_size, uint64_t *store_free, uint32_t epoch);
int get_obj_list(const struct sd_list_req *hdr, struct sd_list_rsp *rsp, void *data);

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

void del_sheep_fd(int fd);
int get_sheep_fd(uint8_t *addr, uint16_t port, int node_idx, uint32_t epoch);

/* Operations */

struct sd_op_template *get_sd_op(uint8_t opcode);
int is_cluster_op(struct sd_op_template *op);
int is_local_op(struct sd_op_template *op);
int is_io_op(struct sd_op_template *op);
int is_force_op(struct sd_op_template *op);
int has_process_work(struct sd_op_template *op);
int has_process_main(struct sd_op_template *op);
int do_process_work(struct sd_op_template *op, const struct sd_req *req,
		    struct sd_rsp *rsp, void *data);
int do_process_main(struct sd_op_template *op, const struct sd_req *req,
		    struct sd_rsp *rsp, void *data);

/* Journal */
struct jrnl_descriptor *jrnl_begin(void *buf, size_t count, off_t offset,
				   const char *path, const char *jrnl_dir);
int jrnl_end(struct jrnl_descriptor * jd);
int jrnl_recover(const char *jrnl_dir);

static inline int is_myself(uint8_t *addr, uint16_t port)
{
	return (memcmp(addr, sys->this_node.addr,
		       sizeof(sys->this_node.addr)) == 0) &&
		port == sys->this_node.port;
}

/* Cluster status/flag helper */

static inline int sys_flag_nohalt(void)
{
	return sys->flags & SD_FLAG_NOHALT;
}

static inline int sys_stat_ok(void)
{
	return sys->status & SD_STATUS_OK;
}

static inline int sys_stat_wait_format(void)
{
	return sys->status & SD_STATUS_WAIT_FOR_FORMAT;
}

static inline int sys_stat_wait_join(void)
{
	return sys->status & SD_STATUS_WAIT_FOR_JOIN;
}

static inline int sys_stat_join_failed(void)
{
	return sys->status & SD_STATUS_JOIN_FAILED;
}

static inline int sys_stat_shutdown(void)
{
	return sys->status & SD_STATUS_SHUTDOWN;
}

static inline int sys_stat_halt(void)
{
	return sys->status & SD_STATUS_HALT;
}

static inline void sys_stat_set(uint32_t s)
{
	sys->status = s;
}

static inline uint32_t sys_stat_get(void)
{
	return sys->status;
}

static inline int sys_can_recover(void)
{
	return sys_stat_ok() || sys_stat_halt();
}

static inline int sys_can_halt(void)
{
	return sys_stat_ok() && !sys_flag_nohalt();
}

#endif
