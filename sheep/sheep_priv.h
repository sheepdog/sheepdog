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
#include <stdbool.h>
#include <urcu/uatomic.h>

#include "sheepdog_proto.h"
#include "event.h"
#include "logger.h"
#include "work.h"
#include "net.h"
#include "sheep.h"
#include "cluster.h"
#include "rbtree.h"
#include "strbuf.h"

struct client_info {
	struct connection conn;

	struct request *rx_req;

	struct request *tx_req;

	struct list_head done_reqs;

	int refcnt;
};

struct vnode_info {
	struct sd_vnode vnodes[SD_MAX_VNODES];
	int nr_vnodes;

	struct sd_node nodes[SD_MAX_NODES];
	int nr_nodes;

	int nr_zones;
	int refcnt;
};

struct request {
	struct sd_req rq;
	struct sd_rsp rp;

	struct sd_op_template *op;

	void *data;
	unsigned int data_length;

	struct client_info *ci;
	struct list_head request_list;
	struct list_head pending_list;

	int refcnt;
	int local;
	int done;
	int wait_efd;

	uint64_t local_oid;

	struct vnode_info *vnodes;

	struct work work;
};

struct cluster_info {
	struct cluster_driver *cdrv;
	const char *cdrv_option;

	int enable_write_cache;

	/* set after finishing the JOIN procedure */
	int join_finished;
	struct sd_node this_node;

	uint32_t epoch;
	uint32_t status;
	uint16_t flags;

	/*
	 * List of nodes that were past of the last epoch before a shutdown,
	 * but failed to join.
	 */
	struct list_head failed_nodes;

	/*
	 * List of nodes that weren't part of the last epoch, but joined
	 * before restarting the cluster.
	 */
	struct list_head delayed_nodes;

	struct list_head pending_list;

	DECLARE_BITMAP(vdi_inuse, SD_NR_VDIS);

	int nr_copies;
	int req_efd;

	pthread_mutex_t wait_req_lock;
	struct list_head wait_req_queue;
	struct list_head wait_rw_queue;
	struct list_head wait_obj_queue;
	int nr_outstanding_reqs;

	uint32_t recovered_epoch;

	int use_directio;

	struct work_queue *gateway_wqueue;
	struct work_queue *io_wqueue;
	struct work_queue *deletion_wqueue;
	struct work_queue *recovery_wqueue;
	struct work_queue *block_wqueue;
};

struct siocb {
	uint16_t flags;
	uint32_t epoch;
	void *buf;
	uint32_t length;
	uint64_t offset;
};

struct store_driver {
	struct list_head list;
	const char *name;
	int (*init)(char *path);
	int (*exist)(uint64_t oid);
	int (*write)(uint64_t oid, struct siocb *, int create);
	int (*read)(uint64_t oid, struct siocb *);
	int (*format)(struct siocb *);
	int (*remove_object)(uint64_t oid);
	/* Operations in recovery */
	int (*link)(uint64_t oid, struct siocb *, uint32_t tgt_epoch);
	int (*atomic_put)(uint64_t oid, struct siocb *);
	int (*begin_recover)(struct siocb *);
	int (*end_recover)(uint32_t epoch, struct vnode_info *old_vnode_info);
	int (*purge_obj)(void);
	/* Operations for snapshot */
	int (*snapshot)(struct siocb *);
	int (*cleanup)(struct siocb *);
	int (*restore)(struct siocb *);
	int (*get_snap_file)(struct siocb *);
};

extern struct list_head store_drivers;
#define add_store_driver(driver)                                 \
static void __attribute__((constructor)) add_ ## driver(void) {  \
	list_add(&driver.list, &store_drivers);                  \
}

static inline struct store_driver *find_store_driver(const char *name)
{
	struct store_driver *driver;

	list_for_each_entry(driver, &store_drivers, list) {
		if (strcmp(driver->name, name) == 0)
			return driver;
	}
	return NULL;
}

extern struct cluster_info *sys;
extern struct store_driver *sd_store;
extern char *obj_path;
extern char *mnt_path;
extern char *jrnl_path;
extern char *epoch_path;
extern mode_t def_fmode;
extern mode_t def_dmode;

/* One should call this function to get sys->epoch outside main thread */
static inline uint32_t sys_epoch(void)
{
	return uatomic_read(&sys->epoch);
}

int create_listen_port(int port, void *data);

int init_store(const char *dir, int enable_write_cache);
int init_base_path(const char *dir);

int add_vdi(char *data, int data_len, uint64_t size, uint32_t *new_vid,
	    uint32_t base_vid, int is_snapshot, unsigned int *nr_copies);

int del_vdi(struct request *req, char *data, int data_len, uint32_t *vid,
	    uint32_t snapid, unsigned int *nr_copies);

int lookup_vdi(char *name, char *tag, uint32_t *vid, uint32_t snapid,
	       unsigned int *nr_copies, uint64_t *ctime);

int read_vdis(char *data, int len, unsigned int *rsp_len);

int get_vdi_attr(struct sheepdog_vdi_attr *vattr, int data_len, uint32_t vid,
		uint32_t *attrid, uint64_t ctime, int write,
		int excl, int delete);

int local_get_node_list(const struct sd_req *req, struct sd_rsp *rsp,
		void *data);

bool have_enough_zones(void);
struct vnode_info *grab_vnode_info(struct vnode_info *vnode_info);
struct vnode_info *get_vnode_info(void);
void put_vnode_info(struct vnode_info *vnodes);
struct vnode_info *get_vnode_info_epoch(uint32_t epoch);

struct sd_vnode *oid_to_vnode(struct vnode_info *vnode_info, uint64_t oid,
		int copy_idx);
void oid_to_vnodes(struct vnode_info *vnode_info, uint64_t oid, int nr_copies,
		struct sd_vnode **vnodes);
int get_nr_copies(struct vnode_info *vnode_info);

void resume_pending_requests(void);
void resume_wait_epoch_requests(void);
void resume_wait_obj_requests(uint64_t oid);
void resume_wait_recovery_requests(void);
void flush_wait_obj_requests(void);

int create_cluster(int port, int64_t zone, int nr_vnodes,
		   bool explicit_addr);
int leave_cluster(void);

void queue_cluster_request(struct request *req);

int update_epoch_log(uint32_t epoch, struct sd_node *nodes, size_t nr_nodes);
int log_current_epoch(void);

int set_cluster_copies(uint8_t copies);
int get_cluster_copies(uint8_t *copies);
int set_cluster_flags(uint16_t flags);
int get_cluster_flags(uint16_t *flags);
int set_cluster_store(const char *name);
int get_cluster_store(char *buf);

int store_file_write(void *buffer, size_t len);
void *store_file_read(void);
int get_max_nr_copies_from(struct sd_node *entries, int nr);

int epoch_log_read(uint32_t epoch, struct sd_node *nodes, int len);
int epoch_log_read_remote(uint32_t epoch, struct sd_node *nodes, int len);
uint32_t get_latest_epoch(void);
int set_cluster_ctime(uint64_t ctime);
uint64_t get_cluster_ctime(void);
int get_obj_list(const struct sd_list_req *, struct sd_list_rsp *, void *);

int start_recovery(struct vnode_info *cur_vnodes,
	struct vnode_info *old_vnodes);
void resume_recovery_work(void);
bool oid_in_recovery(uint64_t oid);
int is_recovery_init(void);
int node_in_recovery(void);

int write_object(uint64_t oid, char *data, unsigned int datalen,
		 uint64_t offset, uint16_t flags, int create);
int read_object(uint64_t oid, char *data, unsigned int datalen,
		uint64_t offset);
int remove_object(uint64_t oid);

int exec_local_req(struct sd_req *rq, void *data);
void local_req_init(void);

int prealloc(int fd, uint32_t size);

int objlist_cache_insert(uint64_t oid);
void objlist_cache_remove(uint64_t oid);

void put_request(struct request *req);

/* Operations */

struct sd_op_template *get_sd_op(uint8_t opcode);
const char *op_name(struct sd_op_template *op);
int is_cluster_op(struct sd_op_template *op);
int is_local_op(struct sd_op_template *op);
int is_peer_op(struct sd_op_template *op);
int is_gateway_op(struct sd_op_template *op);
int is_force_op(struct sd_op_template *op);
int has_process_work(struct sd_op_template *op);
int has_process_main(struct sd_op_template *op);
void do_process_work(struct work *work);
int do_process_main(struct sd_op_template *op, const struct sd_req *req,
		    struct sd_rsp *rsp, void *data);
int sheep_do_op_work(struct sd_op_template *op, struct request *req);
int gateway_to_peer_opcode(int opcode);

/* Journal */
struct jrnl_descriptor *jrnl_begin(const void *buf, size_t count, off_t offset,
				   const char *path, const char *jrnl_dir);
int jrnl_end(struct jrnl_descriptor * jd);
int jrnl_recover(const char *jrnl_dir);

static inline int is_myself(uint8_t *addr, uint16_t port)
{
	return (memcmp(addr, sys->this_node.nid.addr,
		       sizeof(sys->this_node.nid.addr)) == 0) &&
		port == sys->this_node.nid.port;
}

static inline int vnode_is_local(struct sd_vnode *v)
{
	return is_myself(v->nid.addr, v->nid.port);
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

/* gateway operations */
int gateway_read_obj(struct request *req);
int gateway_write_obj(struct request *req);
int gateway_create_and_write_obj(struct request *req);
int gateway_remove_obj(struct request *req);

/* backend store */
int peer_read_obj(struct request *req);
int peer_write_obj(struct request *req);
int peer_create_and_write_obj(struct request *req);
int peer_remove_obj(struct request *req);

/* object_cache */

int bypass_object_cache(struct request *req);
int object_is_cached(uint64_t oid);

int object_cache_handle_request(struct request *req);
int object_cache_write(uint64_t oid, char *data, unsigned int datalen,
		       uint64_t offset, uint16_t flags, int create);
int object_cache_read(uint64_t oid, char *data, unsigned int datalen,
		      uint64_t offset);
int object_cache_flush_vdi(struct request *req);
int object_cache_flush_and_del(struct request *req);
void object_cache_delete(uint32_t vid);
int object_cache_init(const char *p);
void object_cache_remove(uint64_t oid);

/* sockfd_cache */
struct sockfd {
	int fd;
	int idx;
};

void sockfd_cache_del(struct node_id *);
void sockfd_cache_add(struct node_id *);
void sockfd_cache_add_group(struct sd_node *nodes, int nr);

struct sockfd *sheep_get_sockfd(struct node_id *);
void sheep_put_sockfd(struct node_id *, struct sockfd *);
void sheep_del_sockfd(struct node_id *, struct sockfd *);

#endif
