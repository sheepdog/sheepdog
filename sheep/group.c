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

struct vdi_bitmap_work {
	struct work work;
	DECLARE_BITMAP(vdi_inuse, SD_NR_VDIS);
	size_t nr_members;
	struct sd_node members[];
};

static struct vnode_info *current_vnode_info;

static size_t get_join_message_size(struct join_message *jm)
{
	/*
	 * jm->nr_nodes is guaranteed to be larger than jm->nr_failed_nodes,
	 * so it is safe to unconditionally use jm->nr_nodes here.
	 */
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
		      sizeof(*ent), node_id_cmp);
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
	qsort(vnode_info->nodes, nr_nodes, sizeof(*nodes), node_id_cmp);

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

	nr_nodes = epoch_log_read(epoch, nodes, sizeof(nodes));
	if (nr_nodes < 0) {
		nr_nodes = epoch_log_read_remote(epoch, nodes, sizeof(nodes));
		if (nr_nodes == 0)
			return NULL;
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

/*
 * Indicator if a cluster operation is currently running.
 */
static bool cluster_op_running = false;

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

static void cluster_op_done(struct work *work)
{
	struct request *req = container_of(work, struct request, work);
	struct vdi_op_message *msg;
	size_t size;

	cluster_op_running = false;

	dprintf("%s (%p)\n", op_name(req->op), req);

	msg = prepare_cluster_msg(req, &size);
	if (!msg)
		panic();

	sys->cdrv->unblock(msg, size);

	free(msg);
}

/*
 * Perform a blocked cluster operation if we were the node requesting it
 * and do not have any other operation pending.
 *
 * If this method returns false the caller must call the method again for
 * the same event once it gets notified again.
 *
 * Must run in the main thread as it accesses unlocked state like
 * sys->pending_list.
 */
bool sd_block_handler(struct sd_node *sender)
{
	struct request *req;

	if (!node_eq(sender, &sys->this_node))
		return false;
	if (cluster_op_running)
		return false;

	cluster_op_running = true;

	req = list_first_entry(&sys->pending_list,
				struct request, pending_list);
	req->work.fn = do_process_work;
	req->work.done = cluster_op_done;

	queue_work(sys->block_wqueue, &req->work);
	return true;
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
	eprintf("%s (%p)\n", op_name(req->op), req);

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

	return epoch_log_read(epoch, nodes, sizeof(nodes));
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

	if (!epoch)
		return NULL;

	nr = epoch_log_read(epoch, nodes, sizeof(nodes));

	for (i = 0; i < nr; i++)
		if (node_eq(&nodes[i], entry))
			return entry;

	return NULL;
}

/*
 * Add a node to the list of nodes that weren't part of the cluster before
 * it shut down, and thus do not count toward the nodes required to allow
 * an automated restart.  These nodes will become part of the cluster by
 * the time it does get restarted.
 */
static bool add_delayed_node(uint32_t epoch, struct sd_node *node)
{
	struct node *n;

	if (find_entry_list(node, &sys->delayed_nodes))
		return false;
	assert(!find_entry_epoch(node, epoch));

	n = xmalloc(sizeof(*n));
	n->ent = *node;
	list_add_tail(&n->list, &sys->delayed_nodes);
	return true;
}

/*
 * For a node that failed to join check if was part of the original
 * epoch, and if so add it to the list of node expected to be present
 * but failing to join.
 */
static bool add_failed_node(uint32_t epoch, struct sd_node *node)
{
	struct node *n;

	if (find_entry_list(node, &sys->failed_nodes))
		return false;
	if (!find_entry_epoch(node, epoch))
		return false;

	n = xmalloc(sizeof(*n));
	n->ent = *node;
	list_add_tail(&n->list, &sys->failed_nodes);
	return true;
}

/*
 * Add the failed and delayed nodes in a join message to the local
 * lists of such nodes.
 */
static void update_exceptional_node_list(uint32_t epoch, struct join_message *jm)
{
	int i;

	for (i = 0; i < jm->nr_failed_nodes; i++)
		add_failed_node(epoch, &jm->nodes[i]);
	for ( ; i < jm->nr_failed_nodes + jm->nr_delayed_nodes; i++)
		add_delayed_node(epoch, &jm->nodes[i]);
}

/*
 * Format the lists of failed or delayed nodes into the join message.
 */
static void format_exceptional_node_list(struct join_message *jm)
{
	struct node *n;

	list_for_each_entry(n, &sys->failed_nodes, list)
		jm->nodes[jm->nr_failed_nodes++] = n->ent;
	list_for_each_entry(n, &sys->delayed_nodes, list)
		jm->nodes[jm->nr_failed_nodes + jm->nr_delayed_nodes++] = n->ent;
}

static void clear_exceptional_node_lists(void)
{
	struct node *n, *t;

	list_for_each_entry_safe(n, t, &sys->failed_nodes, list)
		list_del(&n->list);
	list_for_each_entry_safe(n, t, &sys->delayed_nodes, list)
		list_del(&n->list);
}

static int cluster_sanity_check(uint32_t epoch, uint64_t ctime)
{
	uint64_t local_ctime = get_cluster_ctime();
	uint32_t local_epoch = get_latest_epoch();

	if (ctime != local_ctime) {
		eprintf("joining node ctime doesn't match: %"
			PRIu64 " vs %" PRIu64 "\n",
			ctime, local_ctime);
		return CJ_RES_FAIL;
	}

	if (epoch > local_epoch) {
		eprintf("joining node epoch too large: %"
			PRIu32 " vs %" PRIu32 "\n",
			epoch, local_epoch);
		return CJ_RES_FAIL;
	}

	return CJ_RES_SUCCESS;
}

static int cluster_wait_for_join_check(struct sd_node *joined,
		struct sd_node *entries, int nr_entries, uint32_t epoch,
		uint64_t ctime, uint32_t *status, uint8_t *inc_epoch)
{
	struct sd_node local_entries[SD_MAX_NODES];
	int nr, nr_local_entries, nr_failed_entries, nr_delayed_nodes;
	uint32_t local_epoch = get_latest_epoch();
	int ret;

	if (nr_entries == 0)
		return CJ_RES_JOIN_LATER;

	ret = cluster_sanity_check(epoch, ctime);
	if (ret != CJ_RES_SUCCESS)  {
		if (epoch > sys->epoch) {
			eprintf("transfer mastership (%d, %d)\n",
				epoch, sys->epoch);
			return CJ_RES_MASTER_TRANSFER;
		}
		return ret;
	}

	nr_local_entries = epoch_log_read(epoch, local_entries,
					  sizeof(local_entries));
	if (nr_local_entries == -1)
		return CJ_RES_FAIL;

	if (epoch < local_epoch) {
		eprintf("joining node epoch too small: %"
			PRIu32 " vs %" PRIu32 "\n",
			epoch, local_epoch);

		if (bsearch(joined, local_entries, nr_local_entries,
			    sizeof(struct sd_node), node_id_cmp))
			return CJ_RES_FAIL;
		return CJ_RES_JOIN_LATER;
	}

	if (nr_entries != nr_local_entries) {
		eprintf("epoch log entries do not match: %d vs %d\n",
			nr_entries, nr_local_entries);
		return CJ_RES_FAIL;
	}


	if (memcmp(entries, local_entries,
		   sizeof(entries[0]) * nr_entries) != 0) {
		eprintf("epoch log entries does not match\n");
		return CJ_RES_FAIL;
	}

	if (!current_vnode_info)
		nr = 1;
	else
		nr = current_vnode_info->nr_nodes + 1;

	nr_delayed_nodes = get_nodes_nr_from(&sys->delayed_nodes);

	/*
	 * If we have all members from the last epoch log in the in-memory
	 * node list, and no new nodes joining we can set the cluster live
	 * now without incrementing the epoch.
	 */
	if (nr == nr_local_entries && !nr_delayed_nodes) {
		*status = SD_STATUS_OK;
		return CJ_RES_SUCCESS;
	}

	/*
	 * If we reach the old node count, but some node failed we have to
	 * update the epoch before setting the cluster live.
	 */
	nr_failed_entries = get_nodes_nr_from(&sys->failed_nodes);
	if (nr_local_entries == nr + nr_failed_entries - nr_delayed_nodes) {
		if (inc_epoch)
			*inc_epoch = 1;
		*status = SD_STATUS_OK;
		return CJ_RES_SUCCESS;
	}

	/*
	 * The join was successful, but we don't have enough nodes yet to set
	 * the cluster live.
	 */
	return CJ_RES_SUCCESS;
}

static int cluster_running_check(int nr_entries, uint32_t epoch, uint64_t ctime,
				 uint8_t *inc_epoch)
{
	int ret;

	/*
	 * When the joining node is newly created and we are not waiting for
	 * join we do not need to check anything.
	 */
	if (nr_entries != 0) {
		ret = cluster_sanity_check(epoch, ctime);
		if (ret != CJ_RES_SUCCESS)
			return ret;
	}

	if (inc_epoch)
		*inc_epoch = 1;
	return CJ_RES_SUCCESS;
}

static int get_cluster_status(struct sd_node *joined, struct sd_node *entries,
		int nr_entries, uint64_t ctime, uint32_t epoch,
		uint32_t *status, uint8_t *inc_epoch)
{
	*status = sys->status;
	if (inc_epoch)
		*inc_epoch = 0;

	switch (sys->status) {
	case SD_STATUS_WAIT_FOR_FORMAT:
		if (nr_entries == 0)
			return CJ_RES_SUCCESS;
		return CJ_RES_FAIL;
	case SD_STATUS_SHUTDOWN:
		return CJ_RES_FAIL;
	case SD_STATUS_OK:
	case SD_STATUS_HALT:
		return cluster_running_check(nr_entries, epoch, ctime,
					     inc_epoch);
	case SD_STATUS_WAIT_FOR_JOIN:
		return cluster_wait_for_join_check(joined, entries, nr_entries,
						   epoch, ctime, status,
						   inc_epoch);
	default:
		eprintf("invalid system status: 0x%x\n", sys->status);
		abort();
	}
}

static int get_vdi_bitmap_from(struct sd_node *node)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	static DECLARE_BITMAP(tmp_vdi_inuse, SD_NR_VDIS);
	int fd, i, ret = SD_RES_SUCCESS;
	unsigned int rlen, wlen;
	char host[128];

	if (is_myself(node->nid.addr, node->nid.port))
		goto out;

	addr_to_str(host, sizeof(host), node->nid.addr, 0);

	fd = connect_to(host, node->nid.port);
	if (fd < 0) {
		vprintf(SDOG_ERR, "unable to get the VDI bitmap from %s: %m\n", host);
		ret = -SD_RES_EIO;
		goto out;
	}

	vprintf(SDOG_ERR, "%s:%d\n", host, node->nid.port);

	sd_init_req(&hdr, SD_OP_READ_VDIS);
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

static struct vnode_info *alloc_old_vnode_info(struct sd_node *joined,
		struct sd_node *nodes, size_t nr_nodes)
{
	struct sd_node old_nodes[SD_MAX_NODES];
	size_t count = 0, i;

	/* exclude the newly added one */
	for (i = 0; i < nr_nodes; i++) {
		if (!node_eq(nodes + i, joined))
			old_nodes[count++] = nodes[i];
	}
	return alloc_vnode_info(old_nodes, count);
}

static void finish_join(struct join_message *msg, struct sd_node *joined,
		struct sd_node *nodes, size_t nr_nodes)
{
	sys->join_finished = 1;
	sys->nr_copies = msg->nr_copies;
	sys->epoch = msg->epoch;

	if (msg->cluster_status != SD_STATUS_OK)
		update_exceptional_node_list(get_latest_epoch(), msg);

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
			panic("can't remove stale objects\n");

	sockfd_cache_add_group(nodes, nr_nodes);
}

static void update_cluster_info(struct join_message *msg,
				struct sd_node *joined, struct sd_node *nodes,
				size_t nr_nodes)
{
	struct vnode_info *old_vnode_info;

	eprintf("status = %d, epoch = %d, finished: %d\n", msg->cluster_status,
		msg->epoch, sys->join_finished);

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
		clear_exceptional_node_lists();

		if (!old_vnode_info) {
			old_vnode_info = alloc_old_vnode_info(joined, nodes,
							      nr_nodes);
		}

		start_recovery(current_vnode_info, old_vnode_info);
	}

	put_vnode_info(old_vnode_info);

	if (sys_stat_halt()) {
		if (current_vnode_info->nr_zones >= sys->nr_copies)
			sys_stat_set(SD_STATUS_OK);
	}

	sockfd_cache_add(&joined->nid);
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

	dprintf("op %s, size: %zd, from: %s\n",
		op_name(op), data_len, node_to_str(sender));

	if (is_myself(sender->nid.addr, sender->nid.port)) {
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

		put_request(req);
	}
}

enum cluster_join_result sd_check_join_cb(struct sd_node *joining, void *opaque)
{
	struct join_message *jm = opaque;
	char str[256];
	int ret;

	if (jm->proto_ver != SD_SHEEP_PROTO_VER) {
		eprintf("%s: invalid protocol version: %d\n", __func__,
			jm->proto_ver);
		return CJ_RES_FAIL;
	}

	if (node_eq(joining, &sys->this_node)) {
		struct sd_node entries[SD_MAX_NODES];
		int nr_entries;
		uint32_t epoch;

		/*
		 * If I'm the first sheep joins in colosync, I
		 * becomes the master without sending JOIN.
		 */

		vprintf(SDOG_DEBUG, "%s\n", node_to_str(&sys->this_node));

		epoch = get_latest_epoch();
		if (!epoch) {
			jm->cluster_status = SD_STATUS_WAIT_FOR_FORMAT;
			return CJ_RES_SUCCESS;
		}

		nr_entries = epoch_log_read(epoch, entries, sizeof(entries));
		if (nr_entries == -1)
			return CJ_RES_FAIL;

		sys->epoch = epoch;
		jm->ctime = get_cluster_ctime();
		get_cluster_status(joining, entries, nr_entries, jm->ctime,
				   epoch, &jm->cluster_status, NULL);
		return CJ_RES_SUCCESS;
	}

	ret = get_cluster_status(joining, jm->nodes, jm->nr_nodes,
					jm->ctime, jm->epoch,
					&jm->cluster_status, &jm->inc_epoch);
	eprintf("%s: ret = 0x%x, cluster_status = 0x%x\n",
		addr_to_str(str, sizeof(str), joining->nid.addr, joining->nid.port),
		ret, jm->cluster_status);

	jm->nr_copies = sys->nr_copies;
	jm->cluster_flags = sys->flags;
	jm->epoch = sys->epoch;
	jm->ctime = get_cluster_ctime();
	jm->nr_failed_nodes = 0;

	if (sd_store)
		strcpy((char *)jm->store, sd_store->name);

	if (jm->cluster_status != SD_STATUS_OK &&
	    (ret == CJ_RES_SUCCESS || CJ_RES_JOIN_LATER))
		format_exceptional_node_list(jm);
	return ret;
}

static int send_join_request(struct sd_node *ent)
{
	struct join_message *msg;
	int ret;

	msg = zalloc(sizeof(*msg) + SD_MAX_NODES * sizeof(msg->nodes[0]));
	if (!msg)
		panic("failed to allocate memory\n");
	msg->proto_ver = SD_SHEEP_PROTO_VER;

	get_cluster_copies(&msg->nr_copies);
	get_cluster_flags(&msg->cluster_flags);

	msg->epoch = get_latest_epoch();
	msg->ctime = get_cluster_ctime();

	if (msg->epoch) {
		msg->nr_nodes = epoch_log_read(msg->epoch, msg->nodes,
					       sizeof(struct sd_node) *
					       SD_MAX_NODES);
		if (msg->nr_nodes == -1)
			return SD_RES_EIO;
	}

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
	int nr, nr_local, nr_failed, nr_delayed_nodes;
	struct join_message *jm = opaque;
	uint32_t le = get_latest_epoch();

	if (node_eq(joined, &sys->this_node)) {
		if (result == CJ_RES_FAIL) {
			eprintf("Failed to join, exiting.\n");
			sys->cdrv->leave();
			exit(1);
		}
	}

	switch (result) {
	case CJ_RES_JOIN_LATER:
		add_delayed_node(le, joined);
		/*FALLTHRU*/
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
		if (!sys_stat_wait_join())
			break;

		if (!add_failed_node(le, joined))
			break;

		nr_local = get_nodes_nr_epoch(sys->epoch);
		nr = nr_members;
		nr_failed = get_nodes_nr_from(&sys->failed_nodes);
		nr_delayed_nodes = get_nodes_nr_from(&sys->delayed_nodes);

		dprintf("%d == %d + %d\n", nr_local, nr, nr_failed);
		if (nr_local == nr + nr_failed - nr_delayed_nodes) {
			sys_stat_set(SD_STATUS_OK);
			log_current_epoch();
		}
		break;
	case CJ_RES_MASTER_TRANSFER:
		update_exceptional_node_list(le, jm);

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
		nr_failed = get_nodes_nr_from(&sys->failed_nodes);
		nr_delayed_nodes = get_nodes_nr_from(&sys->delayed_nodes);

		dprintf("%d == %d + %d\n", nr_local, nr, nr_failed);
		if (nr_local == nr + nr_failed - nr_delayed_nodes) {
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

	sockfd_cache_del(&left->nid);
}

int create_cluster(int port, int64_t zone, int nr_vnodes,
		   bool explicit_addr)
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

	if (!explicit_addr) {
		if (sys->cdrv->get_local_addr)
			ret = sys->cdrv->get_local_addr(sys->this_node.nid.addr);
		else
			ret = get_local_addr(sys->this_node.nid.addr);
		if (ret < 0)
			return -1;
	}

	sys->this_node.nid.port = port;
	sys->this_node.nr_vnodes = nr_vnodes;
	if (zone == -1) {
		/* use last 4 bytes as zone id */
		uint8_t *b = sys->this_node.nid.addr + 12;
		sys->this_node.zone = b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24;
	} else
		sys->this_node.zone = zone;
	dprintf("zone id = %u\n", sys->this_node.zone);

	if (get_latest_epoch() == 0)
		sys_stat_set(SD_STATUS_WAIT_FOR_FORMAT);
	else
		sys_stat_set(SD_STATUS_WAIT_FOR_JOIN);
	INIT_LIST_HEAD(&sys->pending_list);
	INIT_LIST_HEAD(&sys->failed_nodes);
	INIT_LIST_HEAD(&sys->delayed_nodes);

	INIT_LIST_HEAD(&sys->wait_req_queue);
	INIT_LIST_HEAD(&sys->wait_rw_queue);
	INIT_LIST_HEAD(&sys->wait_obj_queue);

	ret = send_join_request(&sys->this_node);
	if (ret != 0)
		return -1;

	return 0;
}

/* We will call this function for two reason:
 * 1) make this node working as a gateway, or
 * 2) the program is going to shutdown itself.
 */
int leave_cluster(void)
{
	static int left;

	if (left)
		return 0;

	left = 1;
	return sys->cdrv->leave();
}
