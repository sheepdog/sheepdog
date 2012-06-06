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
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <urcu/uatomic.h>

#include "sheepdog_proto.h"
#include "sheep_priv.h"
#include "list.h"
#include "util.h"
#include "logger.h"
#include "work.h"
#include "cluster.h"

struct node {
	struct sd_node ent;
	struct list_head list;
};

struct join_message {
	uint8_t proto_ver;
	uint8_t nr_copies;
	uint16_t nr_nodes;
	uint16_t nr_leave_nodes;
	uint16_t cluster_flags;
	uint32_t cluster_status;
	uint32_t epoch;
	uint64_t ctime;
	uint32_t result;
	uint8_t inc_epoch; /* set non-zero when we increment epoch of all nodes */
	uint8_t store[STORE_LEN];
	union {
		struct sd_node nodes[0];
		struct sd_node leave_nodes[0];
	};
};

struct vdi_op_message {
	struct sd_req req;
	struct sd_rsp rsp;
	uint8_t data[0];
};

struct vdi_bitmap_work {
	struct work work;
	DECLARE_BITMAP(vdi_inuse, SD_NR_VDIS);
	size_t nr_members;
	struct sd_node members[];
};

static struct vnode_info *current_vnode_info;

static size_t get_join_message_size(struct join_message *jm)
{
	/* jm->nr_nodes is always larger than jm->nr_leave_nodes, so
	 * it is safe to use jm->nr_nodes. */
	return sizeof(*jm) + jm->nr_nodes * sizeof(jm->nodes[0]);
}

static int get_zones_nr_from(struct sd_node *nodes, int nr_nodes)
{
	int nr_zones = 0, i, j;
	uint32_t zones[SD_MAX_REDUNDANCY];

	for (i = 0; i < nr_nodes; i++) {
		/*
		 * Only count zones that actually store data, pure gateways
		 * don't contribute to the redundancy level.
		 */
		if (!nodes[i].nr_vnodes)
			continue;

		for (j = 0; j < nr_zones; j++) {
			if (nodes[i].zone == zones[j])
				break;
		}

		if (j == nr_zones) {
			zones[nr_zones] = nodes[i].zone;
			if (++nr_zones == ARRAY_SIZE(zones))
				break;
		}
	}

	return nr_zones;
}

bool have_enough_zones(void)
{
	if (sys_flag_nohalt())
		return true;

	if (!current_vnode_info)
		return false;

	dprintf("flags %d, nr_zones %d, copies %d\n",
		sys->flags, current_vnode_info->nr_zones, sys->nr_copies);

	if (current_vnode_info->nr_zones >= sys->nr_copies)
		return true;
	return false;
}

static int get_node_idx(struct vnode_info *vnode_info, struct sd_node *ent)
{
	ent = bsearch(ent, vnode_info->nodes, vnode_info->nr_nodes,
		      sizeof(*ent), node_cmp);
	if (!ent)
		return -1;

	return ent - vnode_info->nodes;
}

/*
 * If we have less zones available than the desired redundancy we have to do
 * with nr_zones copies, sorry.
 *
 * Note that you generally want to use get_nr_copies below, as it uses the
 * current vnode state snapshot instead of global data.
 */
int get_max_nr_copies_from(struct sd_node *nodes, int nr_nodes)
{
	return min((int)sys->nr_copies, get_zones_nr_from(nodes, nr_nodes));
}

/*
 * Grab an additional reference to the passed in vnode info.
 *
 * The caller must already hold a reference to vnode_info, this function must
 * only be used to grab an additional reference from code that wants the
 * vnode information to outlive the request structure.
 */
struct vnode_info *grab_vnode_info(struct vnode_info *vnode_info)
{
	assert(uatomic_read(&vnode_info->refcnt) > 0);

	uatomic_inc(&vnode_info->refcnt);
	return vnode_info;
}

/*
 * Get a reference to the currently active vnode information structure,
 * this must only be called from the main thread.
 */
struct vnode_info *get_vnode_info(void)
{
	assert(current_vnode_info);

	return grab_vnode_info(current_vnode_info);
}

/*
 * Release a reference to the current vnode information.
 *
 * Must be called from the main thread.
 */
void put_vnode_info(struct vnode_info *vnode_info)
{
	if (vnode_info) {
		assert(uatomic_read(&vnode_info->refcnt) > 0);

		if (uatomic_sub_return(&vnode_info->refcnt, 1) == 0)
			free(vnode_info);
	}
}

struct sd_vnode *oid_to_vnode(struct vnode_info *vnode_info, uint64_t oid,
		int copy_idx)
{
	int idx = obj_to_sheep(vnode_info->vnodes, vnode_info->nr_vnodes,
			oid, copy_idx);

	return &vnode_info->vnodes[idx];
}

void oid_to_vnodes(struct vnode_info *vnode_info, uint64_t oid, int nr_copies,
		struct sd_vnode **vnodes)
{
	int idx_buf[SD_MAX_COPIES], i, n;

	obj_to_sheeps(vnode_info->vnodes, vnode_info->nr_vnodes,
			oid, nr_copies, idx_buf);

	for (i = 0; i < nr_copies; i++) {
		n = idx_buf[i];
		vnodes[i] = &vnode_info->vnodes[n];
	}
}

static struct vnode_info *alloc_vnode_info(struct sd_node *nodes,
					   size_t nr_nodes)
{
	struct vnode_info *vnode_info;

	vnode_info = xzalloc(sizeof(*vnode_info));

	vnode_info->nr_nodes = nr_nodes;
	memcpy(vnode_info->nodes, nodes, sizeof(*nodes) * nr_nodes);
	qsort(vnode_info->nodes, nr_nodes, sizeof(*nodes), node_cmp);

	vnode_info->nr_vnodes = nodes_to_vnodes(nodes, nr_nodes,
						vnode_info->vnodes);
	vnode_info->nr_zones = get_zones_nr_from(nodes, nr_nodes);
	uatomic_set(&vnode_info->refcnt, 1);
	return vnode_info;
}

struct vnode_info *get_vnode_info_epoch(uint32_t epoch)
{
	struct sd_node nodes[SD_MAX_NODES];
	int nr_nodes;

	nr_nodes = epoch_log_read_nr(epoch, (void *)nodes, sizeof(nodes));
	if (nr_nodes < 0) {
		nr_nodes = epoch_log_read_remote(epoch, (void *)nodes,
						 sizeof(nodes));
		if (nr_nodes == 0)
			return NULL;
		nr_nodes /= sizeof(nodes[0]);
	}

	return alloc_vnode_info(nodes, nr_nodes);
}

int local_get_node_list(const struct sd_req *req, struct sd_rsp *rsp,
			       void *data)
{
	struct sd_node_rsp *node_rsp = (struct sd_node_rsp *)rsp;
	int nr_nodes;

	if (current_vnode_info) {
		nr_nodes = current_vnode_info->nr_nodes;
		memcpy(data, current_vnode_info->nodes,
			sizeof(struct sd_node) * nr_nodes);
		node_rsp->data_length = nr_nodes * sizeof(struct sd_node);
		node_rsp->nr_nodes = nr_nodes;
		node_rsp->local_idx = get_node_idx(current_vnode_info,
						   &sys->this_node);
	} else {
		node_rsp->data_length = 0;
		node_rsp->nr_nodes = 0;
		node_rsp->local_idx = 0;
	}

	node_rsp->master_idx = -1;
	return SD_RES_SUCCESS;
}

/*
 * If we have less zones available than the desired redundancy we have to do
 * with nr_zones copies, sorry.
 */
int get_nr_copies(struct vnode_info *vnode_info)
{
	return min(vnode_info->nr_zones, sys->nr_copies);
}

static struct vdi_op_message *prepare_cluster_msg(struct request *req,
		size_t *sizep)
{
	struct vdi_op_message *msg;
	size_t size;

	if (has_process_main(req->op))
		size = sizeof(*msg) + req->rq.data_length;
	else
		size = sizeof(*msg);

	assert(size <= SD_MAX_EVENT_BUF_SIZE);

	msg = zalloc(size);
	if (!msg) {
		eprintf("failed to allocate memory\n");
		return NULL;
	}

	memcpy(&msg->req, &req->rq, sizeof(struct sd_req));
	memcpy(&msg->rsp, &req->rp, sizeof(struct sd_rsp));

	if (has_process_main(req->op))
		memcpy(msg->data, req->data, req->rq.data_length);

	*sizep = size;
	return msg;
}

static void do_cluster_request(struct work *work)
{
	struct request *req = container_of(work, struct request, work);
	int ret;

	ret = do_process_work(req);
	req->rp.result = ret;
}

static void cluster_op_done(struct work *work)
{
	struct request *req = container_of(work, struct request, work);
	struct vdi_op_message *msg;
	size_t size;

	msg = prepare_cluster_msg(req, &size);
	if (!msg)
		panic();

	sys->cdrv->unblock(msg, size);

	free(msg);
}

/*
 * Perform a blocked cluster operation.
 *
 * Must run in the main thread as it access unlocked state like
 * sys->pending_list.
 */
void sd_block_handler(void)
{
	struct request *req = list_first_entry(&sys->pending_list,
						struct request, pending_list);

	req->work.fn = do_cluster_request;
	req->work.done = cluster_op_done;

	queue_work(sys->block_wqueue, &req->work);
}

/*
 * Execute a cluster operation by letting the cluster driver send it to all
 * nodes in the cluster.
 *
 * Must run in the main thread as it access unlocked state like
 * sys->pending_list.
 */
void queue_cluster_request(struct request *req)
{
	eprintf("%p %x\n", req, req->rq.opcode);

	if (has_process_work(req->op)) {
		list_add_tail(&req->pending_list, &sys->pending_list);
		sys->cdrv->block();
	} else {
		struct vdi_op_message *msg;
		size_t size;

		msg = prepare_cluster_msg(req, &size);
		if (!msg)
			return;

		list_add_tail(&req->pending_list, &sys->pending_list);

		msg->rsp.result = SD_RES_SUCCESS;
		sys->cdrv->notify(msg, size);

		free(msg);
	}
}

static inline int get_nodes_nr_from(struct list_head *l)
{
	struct node *node;
	int nr = 0;
	list_for_each_entry(node, l, list) {
		nr++;
	}
	return nr;
}

static int get_nodes_nr_epoch(uint32_t epoch)
{
	struct sd_node nodes[SD_MAX_NODES];
	int nr;

	nr = epoch_log_read(epoch, (char *)nodes, sizeof(nodes));
	nr /= sizeof(nodes[0]);
	return nr;
}

static struct sd_node *find_entry_list(struct sd_node *entry,
					struct list_head *head)
{
	struct node *n;
	list_for_each_entry(n, head, list)
		if (node_eq(&n->ent, entry))
			return entry;

	return NULL;

}

static struct sd_node *find_entry_epoch(struct sd_node *entry,
					uint32_t epoch)
{
	struct sd_node nodes[SD_MAX_NODES];
	int nr, i;

	nr = epoch_log_read_nr(epoch, (char *)nodes, sizeof(nodes));

	for (i = 0; i < nr; i++)
		if (node_eq(&nodes[i], entry))
			return entry;

	return NULL;
}

static int cluster_sanity_check(struct sd_node *entries,
			     int nr_entries, uint64_t ctime, uint32_t epoch)
{
	int ret = SD_RES_SUCCESS, nr_local_entries;
	struct sd_node local_entries[SD_MAX_NODES];
	uint32_t lepoch;

	if (sys_stat_wait_format() || sys_stat_shutdown())
		goto out;
	/*
	 * When the joining node is newly created and we are not waiting for
	 * join we need not check anything.
	 */
	if (nr_entries == 0 && !sys_stat_wait_join())
		goto out;

	if (ctime != get_cluster_ctime()) {
		ret = SD_RES_INVALID_CTIME;
		goto out;
	}

	lepoch = get_latest_epoch();
	if (epoch > lepoch) {
		ret = SD_RES_OLD_NODE_VER;
		goto out;
	}

	if (sys_can_recover())
		goto out;

	if (epoch < lepoch) {
		ret = SD_RES_NEW_NODE_VER;
		goto out;
	}

	nr_local_entries = epoch_log_read_nr(epoch, (char *)local_entries,
			sizeof(local_entries));

	if (nr_entries != nr_local_entries ||
	    memcmp(entries, local_entries, sizeof(entries[0]) * nr_entries) != 0) {
		ret = SD_RES_INVALID_EPOCH;
		goto out;
	}

out:
	return ret;
}

static int get_cluster_status(struct sd_node *from,
			      struct sd_node *entries,
			      int nr_entries, uint64_t ctime, uint32_t epoch,
			      uint32_t *status, uint8_t *inc_epoch)
{
	int ret = SD_RES_SUCCESS;
	int nr, nr_local_entries, nr_leave_entries;
	struct sd_node local_entries[SD_MAX_NODES];
	char str[256];
	uint32_t sys_stat = sys_stat_get();

	*status = sys_stat;
	if (inc_epoch)
		*inc_epoch = 0;

	ret = cluster_sanity_check(entries, nr_entries, ctime, epoch);
	if (ret)
		goto out;

	switch (sys_stat) {
	case SD_STATUS_HALT:
	case SD_STATUS_OK:
		if (inc_epoch)
			*inc_epoch = 1;
		break;
	case SD_STATUS_WAIT_FOR_FORMAT:
		if (nr_entries != 0)
			ret = SD_RES_NOT_FORMATTED;
		break;
	case SD_STATUS_WAIT_FOR_JOIN:
		if (!current_vnode_info)
			nr = 1;
		else
			nr = current_vnode_info->nr_nodes + 1;

		nr_local_entries = epoch_log_read_nr(epoch, (char *)local_entries,
						  sizeof(local_entries));

		if (nr != nr_local_entries) {
			nr_leave_entries = get_nodes_nr_from(&sys->leave_list);
			if (nr_local_entries == nr + nr_leave_entries) {
				/* Even though some nodes have left, we can make do without them.
				 * Order cluster to do recovery right now.
				 */
				if (inc_epoch)
					*inc_epoch = 1;
				*status = SD_STATUS_OK;
			}
			break;
		}

		*status = SD_STATUS_OK;
		break;
	case SD_STATUS_SHUTDOWN:
		ret = SD_RES_SHUTDOWN;
		break;
	default:
		break;
	}
out:
	if (ret)
		eprintf("%x, %s\n", ret,
			addr_to_str(str, sizeof(str), from->addr, from->port));

	return ret;
}

static int get_vdi_bitmap_from(struct sd_node *node)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	static DECLARE_BITMAP(tmp_vdi_inuse, SD_NR_VDIS);
	int fd, i, ret = SD_RES_SUCCESS;
	unsigned int rlen, wlen;
	char host[128];

	if (is_myself(node->addr, node->port))
		goto out;

	addr_to_str(host, sizeof(host), node->addr, 0);

	fd = connect_to(host, node->port);
	if (fd < 0) {
		vprintf(SDOG_ERR, "unable to get the VDI bitmap from %s: %m\n", host);
		ret = -SD_RES_EIO;
		goto out;
	}

	vprintf(SDOG_ERR, "%s:%d\n", host, node->port);

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = SD_OP_READ_VDIS;
	hdr.epoch = sys->epoch;
	hdr.data_length = sizeof(tmp_vdi_inuse);
	rlen = hdr.data_length;
	wlen = 0;

	ret = exec_req(fd, &hdr, (char *)tmp_vdi_inuse,
			&wlen, &rlen);

	close(fd);

	if (ret || rsp->result != SD_RES_SUCCESS) {
		vprintf(SDOG_ERR, "unable to get the VDI bitmap (%d, %d)\n", ret,
				rsp->result);
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(sys->vdi_inuse); i++)
		sys->vdi_inuse[i] |= tmp_vdi_inuse[i];
out:
	return ret;
}

static void do_get_vdi_bitmap(struct work *work)
{
	struct vdi_bitmap_work *w =
		container_of(work, struct vdi_bitmap_work, work);
	int i;

	for (i = 0; i < w->nr_members; i++) {
		/* We should not fetch vdi_bitmap from myself */
		if (node_eq(&w->members[i], &sys->this_node))
			continue;

		get_vdi_bitmap_from(&w->members[i]);

		/*
		 * If a new comer try to join the running cluster, it only
		 * need read one copy of bitmap from one of other members.
		 */
		if (sys_stat_wait_format())
			break;
	}
}

static void get_vdi_bitmap_done(struct work *work)
{
	struct vdi_bitmap_work *w =
		container_of(work, struct vdi_bitmap_work, work);

	free(w);
}

int log_current_epoch(void)
{
	if (!current_vnode_info)
		return update_epoch_log(sys->epoch, NULL, 0);
	return update_epoch_log(sys->epoch, current_vnode_info->nodes,
				current_vnode_info->nr_nodes);
}

static void log_last_epoch(struct join_message *msg, struct sd_node *joined,
		struct sd_node *nodes, size_t nr_nodes)
{
	if ((msg->cluster_status == SD_STATUS_OK ||
	     msg->cluster_status == SD_STATUS_HALT) && msg->inc_epoch) {
		struct sd_node old_nodes[SD_MAX_NODES];
		size_t count = 0, i;

		/* exclude the newly added one */
		for (i = 0; i < nr_nodes; i++) {
			if (!node_eq(nodes + i, joined))
				old_nodes[count++] = nodes[i];
		}
		put_vnode_info(current_vnode_info);
		current_vnode_info = alloc_vnode_info(old_nodes, count);
		log_current_epoch();
	}
}

static void finish_join(struct join_message *msg, struct sd_node *joined,
		struct sd_node *nodes, size_t nr_nodes)
{
	int i;

	sys->join_finished = 1;
	sys->nr_copies = msg->nr_copies;
	sys->epoch = msg->epoch;

	/*
	 * Make sure we have an epoch log record for the epoch before
	 * this node joins, as recovery expects this record to exist.
	 */
	log_last_epoch(msg, joined, nodes, nr_nodes);

	if (msg->cluster_status != SD_STATUS_OK) {
		int nr_leave_nodes;
		uint32_t le;

		nr_leave_nodes = msg->nr_leave_nodes;
		le = get_latest_epoch();
		for (i = 0; i < nr_leave_nodes; i++) {
			struct node *n;

			if (find_entry_list(&msg->leave_nodes[i], &sys->leave_list) ||
			    !find_entry_epoch(&msg->leave_nodes[i], le)) {
				continue;
			}

			n = zalloc(sizeof(*n));
			if (!n)
				panic("failed to allocate memory\n");
			n->ent = msg->leave_nodes[i];
			list_add_tail(&n->list, &sys->leave_list);
		}
	}

	if (!sd_store && strlen((char *)msg->store)) {
		sd_store = find_store_driver((char *)msg->store);
		if (sd_store) {
			sd_store->init(obj_path);
			if (set_cluster_store(sd_store->name) != SD_RES_SUCCESS)
				panic("failed to store into config file\n");
		} else
				panic("backend store %s not supported\n", msg->store);
	}

	/* We need to purge the stale objects for sheep joining back
	 * after crash
	 */
	if (msg->inc_epoch)
		if (sd_store->purge_obj &&
		    sd_store->purge_obj() != SD_RES_SUCCESS)
			eprintf("WARN: may have stale objects\n");
}

static void update_cluster_info(struct join_message *msg,
		struct sd_node *joined, struct sd_node *nodes, size_t nr_nodes)
{
	struct node *n, *t;
	struct vnode_info *old_vnode_info;

	eprintf("status = %d, epoch = %d, %x, %d\n", msg->cluster_status,
		msg->epoch, msg->result, sys->join_finished);

	if (sys_stat_join_failed())
		return;

	if (!sys->join_finished)
		finish_join(msg, joined, nodes, nr_nodes);

	old_vnode_info = current_vnode_info;
	current_vnode_info = alloc_vnode_info(nodes, nr_nodes);

	if (msg->cluster_status == SD_STATUS_OK ||
	    msg->cluster_status == SD_STATUS_HALT) {
		if (msg->inc_epoch) {
			uatomic_inc(&sys->epoch);
			log_current_epoch();
		}
		/* Fresh node */
		if (!sys_stat_ok() && !sys_stat_halt()) {
			set_cluster_copies(sys->nr_copies);
			set_cluster_flags(sys->flags);
			set_cluster_ctime(msg->ctime);
		}
	}

	if (!sys_stat_ok() &&
	    (msg->cluster_status == SD_STATUS_OK ||
	     msg->cluster_status == SD_STATUS_HALT)) {
		int array_len = nr_nodes * sizeof(struct sd_node);
		struct vdi_bitmap_work *w;

		w = xmalloc(sizeof(*w) + array_len);
		w->nr_members = nr_nodes;
		memcpy(w->members, nodes, array_len);

		w->work.fn = do_get_vdi_bitmap;
		w->work.done = get_vdi_bitmap_done;
		queue_work(sys->block_wqueue, &w->work);
	}

	sys_stat_set(msg->cluster_status);

	if (sys_can_recover() && msg->inc_epoch) {
		list_for_each_entry_safe(n, t, &sys->leave_list, list)
			list_del(&n->list);
		start_recovery(current_vnode_info, old_vnode_info);
	}

	put_vnode_info(old_vnode_info);

	if (sys_stat_halt()) {
		if (current_vnode_info->nr_zones >= sys->nr_copies)
			sys_stat_set(SD_STATUS_OK);
	}
}

/*
 * Pass on a notification message from the cluster driver.
 *
 * Must run in the main thread as it accesses unlocked state like
 * sys->pending_list.
 */
void sd_notify_handler(struct sd_node *sender, void *data, size_t data_len)
{
	struct vdi_op_message *msg = data;
	struct sd_op_template *op = get_sd_op(msg->req.opcode);
	int ret = msg->rsp.result;
	struct request *req = NULL;

	dprintf("size: %zd, from: %s\n", data_len, node_to_str(sender));

	if (is_myself(sender->addr, sender->port)) {
		req = list_first_entry(&sys->pending_list, struct request,
				       pending_list);
		list_del(&req->pending_list);
	}

	if (ret == SD_RES_SUCCESS && has_process_main(op))
		ret = do_process_main(op, &msg->req, &msg->rsp, msg->data);

	if (req) {
		msg->rsp.result = ret;
		if (has_process_main(req->op))
			memcpy(req->data, msg->data, msg->rsp.data_length);
		memcpy(&req->rp, &msg->rsp, sizeof(req->rp));
		req_done(req);
	}
}

enum cluster_join_result sd_check_join_cb(struct sd_node *joining, void *opaque)
{
	struct join_message *jm = opaque;

	if (jm->proto_ver != SD_SHEEP_PROTO_VER) {
		eprintf("%s: invalid protocol version: %d\n", __func__,
			jm->proto_ver);
		jm->result = SD_RES_VER_MISMATCH;
		return CJ_RES_FAIL;
	}

	if (node_eq(joining, &sys->this_node)) {
		struct sd_node entries[SD_MAX_NODES];
		int nr_entries;
		uint64_t ctime;
		uint32_t epoch;
		int ret;

		/*
		 * If I'm the first sheep joins in colosync, I
		 * becomes the master without sending JOIN.
		 */

		vprintf(SDOG_DEBUG, "%s\n", node_to_str(&sys->this_node));

		nr_entries = ARRAY_SIZE(entries);
		ret = read_epoch(&epoch, &ctime, entries, &nr_entries);
		if (ret == SD_RES_SUCCESS) {
			sys->epoch = epoch;
			jm->ctime = ctime;
			get_cluster_status(joining, entries, nr_entries, ctime,
					   epoch, &jm->cluster_status, NULL);
		} else
			jm->cluster_status = SD_STATUS_WAIT_FOR_FORMAT;

		return CJ_RES_SUCCESS;
	}

	jm->result = get_cluster_status(joining, jm->nodes, jm->nr_nodes,
					jm->ctime, jm->epoch,
					&jm->cluster_status, &jm->inc_epoch);
	dprintf("%d, %d\n", jm->result, jm->cluster_status);

	jm->nr_copies = sys->nr_copies;
	jm->cluster_flags = sys->flags;
	jm->ctime = get_cluster_ctime();
	jm->nr_leave_nodes = 0;

	if (sd_store)
		strcpy((char *)jm->store, sd_store->name);

	if (jm->result == SD_RES_SUCCESS && jm->cluster_status != SD_STATUS_OK) {
		struct node *node;

		list_for_each_entry(node, &sys->leave_list, list) {
			jm->leave_nodes[jm->nr_leave_nodes] = node->ent;
			jm->nr_leave_nodes++;
		}
	} else if (jm->result != SD_RES_SUCCESS &&
		   jm->epoch > sys->epoch &&
		   jm->cluster_status == SD_STATUS_WAIT_FOR_JOIN) {
		eprintf("transfer mastership (%d, %d)\n", jm->epoch, sys->epoch);
		return CJ_RES_MASTER_TRANSFER;
	}
	jm->epoch = sys->epoch;

	switch (jm->result) {
	case SD_RES_SUCCESS:
		return CJ_RES_SUCCESS;
	case SD_RES_OLD_NODE_VER:
	case SD_RES_NEW_NODE_VER:
		return CJ_RES_JOIN_LATER;
	default:
		return CJ_RES_FAIL;
	}
}

static int send_join_request(struct sd_node *ent)
{
	struct join_message *msg;
	int nr_entries, ret;

	msg = zalloc(sizeof(*msg) + SD_MAX_NODES * sizeof(msg->nodes[0]));
	if (!msg)
		panic("failed to allocate memory\n");
	msg->proto_ver = SD_SHEEP_PROTO_VER;

	get_cluster_copies(&msg->nr_copies);
	get_cluster_flags(&msg->cluster_flags);

	nr_entries = SD_MAX_NODES;
	ret = read_epoch(&msg->epoch, &msg->ctime, msg->nodes, &nr_entries);
	if (ret == SD_RES_SUCCESS)
		msg->nr_nodes = nr_entries;

	ret = sys->cdrv->join(ent, msg, get_join_message_size(msg));

	vprintf(SDOG_INFO, "%s\n", node_to_str(&sys->this_node));

	free(msg);

	return ret;
}

void sd_join_handler(struct sd_node *joined, struct sd_node *members,
		size_t nr_members, enum cluster_join_result result,
		void *opaque)
{
	int i;
	int nr, nr_local, nr_leave;
	struct node *n;
	struct join_message *jm = opaque;
	uint32_t le = get_latest_epoch();

	if (node_eq(joined, &sys->this_node)) {
		if (result == CJ_RES_FAIL) {
			eprintf("Fail to join. The joining node has an invalid epoch.\n");
			sys->cdrv->leave();
			exit(1);
		} else if (result == CJ_RES_JOIN_LATER) {
			eprintf("Fail to join. The joining node should be added after the cluster start working.\n");
			sys->cdrv->leave();
			exit(1);
		}
	}

	switch (result) {
	case CJ_RES_SUCCESS:
		dprintf("join %s\n", node_to_str(joined));
		for (i = 0; i < nr_members; i++)
			dprintf("[%x] %s\n", i, node_to_str(members + i));

		if (sys_stat_shutdown())
			break;

		update_cluster_info(jm, joined, members, nr_members);

		if (node_eq(joined, &sys->this_node))
			/* this output is used for testing */
			vprintf(SDOG_DEBUG, "join Sheepdog cluster\n");
		break;
	case CJ_RES_FAIL:
	case CJ_RES_JOIN_LATER:
		if (!sys_stat_wait_join())
			break;

		if (find_entry_list(joined, &sys->leave_list)
		    || !find_entry_epoch(joined, le)) {
			break;
		}

		n = zalloc(sizeof(*n));
		if (!n)
			panic("failed to allocate memory\n");

		n->ent = *joined;

		list_add_tail(&n->list, &sys->leave_list);

		nr_local = get_nodes_nr_epoch(sys->epoch);
		nr = nr_members;
		nr_leave = get_nodes_nr_from(&sys->leave_list);

		dprintf("%d == %d + %d\n", nr_local, nr, nr_leave);
		if (nr_local == nr + nr_leave) {
			sys_stat_set(SD_STATUS_OK);
			log_current_epoch();
		}
		break;
	case CJ_RES_MASTER_TRANSFER:
		nr = jm->nr_leave_nodes;
		for (i = 0; i < nr; i++) {
			if (find_entry_list(&jm->leave_nodes[i], &sys->leave_list)
			    || !find_entry_epoch(&jm->leave_nodes[i], le)) {
				continue;
			}

			n = zalloc(sizeof(*n));
			if (!n)
				panic("failed to allocate memory\n");

			n->ent = jm->leave_nodes[i];

			list_add_tail(&n->list, &sys->leave_list);
		}

		/* Sheep needs this to identify itself as master.
		 * Now mastership transfer is done.
		 */
		if (!sys->join_finished) {
			sys->join_finished = 1;
			sys->epoch = get_latest_epoch();

			put_vnode_info(current_vnode_info);
			current_vnode_info = alloc_vnode_info(&sys->this_node, 1);
		}

		nr_local = get_nodes_nr_epoch(sys->epoch);
		nr = nr_members;
		nr_leave = get_nodes_nr_from(&sys->leave_list);

		dprintf("%d == %d + %d\n", nr_local, nr, nr_leave);
		if (nr_local == nr + nr_leave) {
			sys_stat_set(SD_STATUS_OK);
			log_current_epoch();
		}

		if (node_eq(joined, &sys->this_node))
			/* this output is used for testing */
			vprintf(SDOG_DEBUG, "join Sheepdog cluster\n");
		break;
	}
}

void sd_leave_handler(struct sd_node *left, struct sd_node *members,
		size_t nr_members)
{
	struct vnode_info *old_vnode_info;
	int i;

	dprintf("leave %s\n", node_to_str(left));
	for (i = 0; i < nr_members; i++)
		dprintf("[%x] %s\n", i, node_to_str(members + i));

	if (sys_stat_shutdown())
		return;

	old_vnode_info = current_vnode_info;
	current_vnode_info = alloc_vnode_info(members, nr_members);

	if (sys_can_recover()) {
		uatomic_inc(&sys->epoch);
		log_current_epoch();
		start_recovery(current_vnode_info, old_vnode_info);
	}
	put_vnode_info(old_vnode_info);

	if (sys_can_halt()) {
		if (current_vnode_info->nr_zones < sys->nr_copies)
			sys_stat_set(SD_STATUS_HALT);
	}
}

int create_cluster(int port, int64_t zone, int nr_vnodes)
{
	int ret;

	if (!sys->cdrv) {
		sys->cdrv = find_cdrv("corosync");
		if (sys->cdrv)
			dprintf("use corosync cluster driver as default\n");
		else {
			/* corosync cluster driver is not compiled */
			sys->cdrv = find_cdrv("local");
			dprintf("use local cluster driver as default\n");
		}
	}

	ret = sys->cdrv->init(sys->cdrv_option);
	if (ret < 0)
		return -1;

	if (sys->cdrv->get_local_addr)
		ret = sys->cdrv->get_local_addr(sys->this_node.addr);
	else
		ret = get_local_addr(sys->this_node.addr);
	if (ret < 0)
		return -1;

	sys->this_node.port = port;
	sys->this_node.nr_vnodes = nr_vnodes;
	if (zone == -1) {
		/* use last 4 bytes as zone id */
		uint8_t *b = sys->this_node.addr + 12;
		sys->this_node.zone = b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24;
	} else
		sys->this_node.zone = zone;
	dprintf("zone id = %u\n", sys->this_node.zone);

	if (get_latest_epoch() == 0)
		sys_stat_set(SD_STATUS_WAIT_FOR_FORMAT);
	else
		sys_stat_set(SD_STATUS_WAIT_FOR_JOIN);
	INIT_LIST_HEAD(&sys->pending_list);
	INIT_LIST_HEAD(&sys->leave_list);

	INIT_LIST_HEAD(&sys->consistent_obj_list);
	INIT_LIST_HEAD(&sys->blocking_conn_list);

	INIT_LIST_HEAD(&sys->wait_rw_queue);
	INIT_LIST_HEAD(&sys->wait_obj_queue);

	ret = send_join_request(&sys->this_node);
	if (ret != 0)
		return -1;

	return 0;
}

/* after this function is called, this node only works as a gateway */
int leave_cluster(void)
{
	return sys->cdrv->leave();
}
