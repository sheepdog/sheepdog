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

#include "sheep_priv.h"

struct node {
	struct sd_node ent;
	struct list_head list;
};

struct get_vdis_work {
	struct work work;
	DECLARE_BITMAP(vdi_inuse, SD_NR_VDIS);
	struct sd_node joined;
	size_t nr_members;
	struct sd_node members[];
};

static pthread_mutex_t wait_vdis_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wait_vdis_cond = PTHREAD_COND_INITIALIZER;
static bool is_vdi_list_ready = true;

static main_thread(struct vnode_info *) current_vnode_info;
static main_thread(struct list_head *) pending_block_list;
static main_thread(struct list_head *) pending_notify_list;

static int get_zones_nr_from(const struct sd_node *nodes, int nr_nodes)
{
	int nr_zones = 0, i, j;
	uint32_t zones[SD_MAX_COPIES];

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
	int max_copies;
	struct vnode_info *cur_vinfo = main_thread_get(current_vnode_info);

	if (sys->cinfo.flags & SD_FLAG_NOHALT)
		return true;

	if (!cur_vinfo)
		return false;

	max_copies = get_max_copy_number();

	sd_dprintf("flags %d, nr_zones %d, min copies %d",
		   sys->cinfo.flags, cur_vinfo->nr_zones, max_copies);

	if (!cur_vinfo->nr_zones)
		return false;

	if (sys->cinfo.flags & SD_FLAG_QUORUM) {
		if (cur_vinfo->nr_zones > (max_copies/2))
			return true;
	} else {
		if (cur_vinfo->nr_zones >= max_copies)
			return true;
	}
	return false;
}

static int get_node_idx(struct vnode_info *vnode_info, struct sd_node *ent)
{
	ent = xbsearch(ent, vnode_info->nodes, vnode_info->nr_nodes, node_cmp);
	if (!ent)
		return -1;

	return ent - vnode_info->nodes;
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
	refcount_inc(&vnode_info->refcnt);
	return vnode_info;
}

/*
 * Get a reference to the currently active vnode information structure,
 * this must only be called from the main thread.
 * This can return NULL if cluster is not started yet.
 */
struct vnode_info *get_vnode_info(void)
{
	struct vnode_info *cur_vinfo = main_thread_get(current_vnode_info);

	if (cur_vinfo == NULL)
		return NULL;

	return grab_vnode_info(cur_vinfo);
}

/* Release a reference to the current vnode information. */
void put_vnode_info(struct vnode_info *vnode_info)
{
	if (vnode_info) {
		if (refcount_dec(&vnode_info->refcnt) == 0)
			free(vnode_info);
	}
}

struct vnode_info *alloc_vnode_info(const struct sd_node *nodes,
				    size_t nr_nodes)
{
	struct vnode_info *vnode_info;

	vnode_info = xzalloc(sizeof(*vnode_info));

	vnode_info->nr_nodes = nr_nodes;
	memcpy(vnode_info->nodes, nodes, sizeof(*nodes) * nr_nodes);
	xqsort(vnode_info->nodes, nr_nodes, node_cmp);

	recalculate_vnodes(vnode_info->nodes, nr_nodes);

	vnode_info->nr_vnodes = nodes_to_vnodes(vnode_info->nodes, nr_nodes,
						vnode_info->vnodes);
	vnode_info->nr_zones = get_zones_nr_from(nodes, nr_nodes);
	refcount_set(&vnode_info->refcnt, 1);
	return vnode_info;
}

struct vnode_info *get_vnode_info_epoch(uint32_t epoch,
					struct vnode_info *cur_vinfo)
{
	struct sd_node nodes[SD_MAX_NODES];
	int nr_nodes;

	nr_nodes = epoch_log_read(epoch, nodes, sizeof(nodes));
	if (nr_nodes < 0) {
		nr_nodes = epoch_log_read_remote(epoch, nodes, sizeof(nodes),
						 NULL, cur_vinfo);
		if (nr_nodes == 0)
			return NULL;
	}

	return alloc_vnode_info(nodes, nr_nodes);
}

int local_get_node_list(const struct sd_req *req, struct sd_rsp *rsp,
			       void *data)
{
	int nr_nodes;
	struct vnode_info *cur_vinfo = main_thread_get(current_vnode_info);

	if (cur_vinfo) {
		nr_nodes = cur_vinfo->nr_nodes;
		memcpy(data, cur_vinfo->nodes,
			sizeof(struct sd_node) * nr_nodes);
		rsp->data_length = nr_nodes * sizeof(struct sd_node);
		rsp->node.nr_nodes = nr_nodes;
		rsp->node.local_idx = get_node_idx(cur_vinfo, &sys->this_node);
	} else {
		rsp->node.nr_nodes = 0;
		rsp->node.local_idx = 0;
	}

	rsp->node.master_idx = -1;
	return SD_RES_SUCCESS;
}

/* Indicator if a cluster operation is currently running. */
static bool cluster_op_running;

static struct vdi_op_message *prepare_cluster_msg(struct request *req,
		size_t *sizep)
{
	struct vdi_op_message *msg;
	size_t size;

	if (has_process_main(req->op) && req->rq.flags & SD_FLAG_CMD_WRITE)
		/* notify data that was received from the sender */
		size = sizeof(*msg) + req->rq.data_length;
	else
		/* notify data that was set in process_work */
		size = sizeof(*msg) + req->rp.data_length;

	assert(size <= SD_MAX_EVENT_BUF_SIZE);

	msg = xzalloc(size);
	memcpy(&msg->req, &req->rq, sizeof(struct sd_req));
	memcpy(&msg->rsp, &req->rp, sizeof(struct sd_rsp));

	if (has_process_main(req->op) && size > sizeof(*msg))
		memcpy(msg->data, req->data, size - sizeof(*msg));

	*sizep = size;
	return msg;
}

static void cluster_op_done(struct work *work)
{
	struct request *req = container_of(work, struct request, work);
	struct vdi_op_message *msg;
	size_t size;
	int ret;

	if (req->status == REQUEST_DROPPED)
		goto drop;

	sd_dprintf("%s (%p)", op_name(req->op), req);

	msg = prepare_cluster_msg(req, &size);

	ret = sys->cdrv->unblock(msg, size);
	if (ret != SD_RES_SUCCESS) {
		/*
		 * Failed to unblock, shoot myself to let other sheep
		 * unblock the event.
		 * FIXME: handle it gracefully.
		 */
		sd_printf(SDOG_EMERG, "Failed to unblock, %s, exiting.",
			  sd_strerror(ret));
		exit(1);
	}

	free(msg);
	req->status = REQUEST_DONE;
	return;
drop:
	list_del(&req->pending_list);
	req->rp.result = SD_RES_CLUSTER_ERROR;
	put_request(req);
	cluster_op_running = false;
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
bool sd_block_handler(const struct sd_node *sender)
{
	struct request *req;

	if (!node_is_local(sender))
		return false;
	if (cluster_op_running)
		return false;

	cluster_op_running = true;

	req = list_first_entry(main_thread_get(pending_block_list),
				struct request, pending_list);
	req->work.fn = do_process_work;
	req->work.done = cluster_op_done;

	queue_work(sys->block_wqueue, &req->work);
	req->status = REQUEST_QUEUED;
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
	int ret;
	sd_dprintf("%s (%p)", op_name(req->op), req);

	if (has_process_work(req->op)) {
		ret = sys->cdrv->block();
		if (ret != SD_RES_SUCCESS) {
			sd_eprintf("failed to broadcast block to cluster, %s",
				   sd_strerror(ret));
			goto error;
		}
		list_add_tail(&req->pending_list,
			      main_thread_get(pending_block_list));
	} else {
		struct vdi_op_message *msg;
		size_t size;

		msg = prepare_cluster_msg(req, &size);
		msg->rsp.result = SD_RES_SUCCESS;

		ret = sys->cdrv->notify(msg, size);
		if (ret != SD_RES_SUCCESS) {
			sd_eprintf("failed to broadcast notify to cluster, %s",
				   sd_strerror(ret));
			goto error;
		}

		list_add_tail(&req->pending_list,
			      main_thread_get(pending_notify_list));

		free(msg);
	}
	req->status = REQUEST_INIT;
	return;
error:
	req->rp.result = ret;
	put_request(req);
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

int epoch_log_read_remote(uint32_t epoch, struct sd_node *nodes, int len,
			  time_t *timestamp, struct vnode_info *vinfo)
{
	int i, nr, ret;
	char buf[SD_MAX_NODES * sizeof(struct sd_node) + sizeof(time_t)];

	nr = vinfo->nr_nodes;
	for (i = 0; i < nr; i++) {
		struct sd_req hdr;
		struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
		const struct sd_node *node = vinfo->nodes + i;
		int nodes_len;

		if (node_is_local(node))
			continue;

		sd_init_req(&hdr, SD_OP_GET_EPOCH);
		hdr.data_length = len;
		hdr.obj.tgt_epoch = epoch;
		hdr.epoch = sys_epoch();
		ret = sheep_exec_req(&node->nid, &hdr, buf);
		if (ret != SD_RES_SUCCESS)
			continue;

		nodes_len = rsp->data_length - sizeof(timestamp);
		memcpy((void *)nodes, buf, nodes_len);
		if (timestamp)
			memcpy(timestamp, buf + nodes_len, sizeof(timestamp));

		return nodes_len / sizeof(struct sd_node);
	}

	/*
	 * If no node has targeted epoch log, return 0 here to at least
	 * allow reading older epoch logs.
	 */
	return 0;
}

static bool cluster_ctime_check(const struct join_message *jm)
{
	if (jm->cinfo.epoch == 0 || sys->cinfo.epoch == 0)
		return true;

	if (jm->cinfo.ctime != sys->cinfo.ctime) {
		sd_eprintf("joining node ctime doesn't match: %"
			   PRIu64 " vs %" PRIu64, jm->cinfo.ctime,
			   sys->cinfo.ctime);
		return false;
	}

	return true;
}

/*
 * Check whether enough node members are gathered.
 *
 * Sheepdog can start automatically if and only if all the members in the latest
 * epoch are gathered.
 */
static bool enough_nodes_gathered(struct join_message *jm,
				  const struct sd_node *joining,
				  const struct sd_node *nodes,
				  size_t nr_nodes)
{
	for (int i = 0; i < jm->cinfo.nr_nodes; i++) {
		const struct sd_node *key = jm->cinfo.nodes + i, *n;

		n = xlfind(key, nodes, nr_nodes, node_cmp);
		if (n == NULL && !node_eq(key, joining)) {
			sd_dprintf("%s doesn't join yet", node_to_str(key));
			return false;
		}
	}

	sd_dprintf("all the nodes are gathered, %d, %zd", jm->cinfo.nr_nodes,
		   nr_nodes);
	return true;
}

static int cluster_wait_check(const struct sd_node *joining,
			      const struct sd_node *nodes, size_t nr_nodes,
			      struct join_message *jm)
{
	if (!cluster_ctime_check(jm)) {
		sd_dprintf("joining node is invalid");
		return sys->status;
	}

	if (jm->cinfo.epoch > sys->cinfo.epoch) {
		sd_dprintf("joining node has a larger epoch, %" PRIu32 ", %"
			   PRIu32, jm->cinfo.epoch, sys->cinfo.epoch);
		sys->cinfo = jm->cinfo;
	} else if (jm->cinfo.epoch < sys->cinfo.epoch) {
		sd_dprintf("joining node has a smaller epoch, %" PRIu32 ", %"
			   PRIu32, jm->cinfo.epoch, sys->cinfo.epoch);
		jm->cinfo = sys->cinfo;
	}

	/*
	 * If we have all members from the last epoch log in the in-memory
	 * node list, we can set the cluster live now.
	 */
	if (sys->cinfo.epoch > 0 &&
	    enough_nodes_gathered(jm, joining, nodes, nr_nodes))
		return SD_STATUS_OK;

	return sys->status;
}

static int get_vdis_from(struct sd_node *node)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	struct vdi_state *vs = NULL;
	int i, ret = SD_RES_SUCCESS;
	unsigned int rlen;
	int count;

	if (node_is_local(node))
		goto out;

	rlen = SD_DATA_OBJ_SIZE; /* FIXME */
	vs = xzalloc(rlen);
	sd_init_req(&hdr, SD_OP_GET_VDI_COPIES);
	hdr.data_length = rlen;
	hdr.epoch = sys_epoch();
	ret = sheep_exec_req(&node->nid, &hdr, (char *)vs);
	if (ret != SD_RES_SUCCESS)
		goto out;

	count = rsp->data_length / sizeof(*vs);
	for (i = 0; i < count; i++) {
		set_bit(vs[i].vid, sys->vdi_inuse);
		add_vdi_state(vs[i].vid, vs[i].nr_copies, vs[i].snapshot);
	}
out:
	free(vs);
	return ret;
}

static void do_get_vdis(struct work *work)
{
	struct get_vdis_work *w =
		container_of(work, struct get_vdis_work, work);
	int i, ret;

	if (!node_is_local(&w->joined)) {
		sd_dprintf("try to get vdi bitmap from %s",
			   node_to_str(&w->joined));
		ret = get_vdis_from(&w->joined);
		if (ret != SD_RES_SUCCESS)
			sd_printf(SDOG_ALERT, "failed to get vdi bitmap from "
				  "%s", node_to_str(&w->joined));
		return;
	}

	for (i = 0; i < w->nr_members; i++) {
		/* We should not fetch vdi_bitmap and copy list from myself */
		if (node_is_local(&w->members[i]))
			continue;

		sd_dprintf("try to get vdi bitmap from %s",
			   node_to_str(&w->members[i]));
		ret = get_vdis_from(&w->members[i]);
		if (ret != SD_RES_SUCCESS) {
			/* try to read from another node */
			sd_printf(SDOG_ALERT, "failed to get vdi bitmap from "
				  "%s", node_to_str(&w->members[i]));
			continue;
		}

		/*
		 * TODO: If the target node has a valid vdi bitmap (the node has
		 * already called do_get_vdis against all the nodes), we can
		 * exit this loop here.
		 */
	}
}

static void get_vdis_done(struct work *work)
{
	struct get_vdis_work *w =
		container_of(work, struct get_vdis_work, work);

	pthread_mutex_lock(&wait_vdis_lock);
	is_vdi_list_ready = true;
	pthread_cond_broadcast(&wait_vdis_cond);
	pthread_mutex_unlock(&wait_vdis_lock);

	free(w);
}

int inc_and_log_epoch(void)
{
	struct vnode_info *cur_vinfo = main_thread_get(current_vnode_info);

	if (cur_vinfo) {
		/* update cluster info to the latest state */
		sys->cinfo.nr_nodes = cur_vinfo->nr_nodes;
		memcpy(sys->cinfo.nodes, cur_vinfo->nodes,
		       sizeof(cur_vinfo->nodes[0]) * cur_vinfo->nr_nodes);
	} else
		sys->cinfo.nr_nodes = 0;

	uatomic_inc(&sys->cinfo.epoch);

	return update_epoch_log(sys->cinfo.epoch, sys->cinfo.nodes,
				sys->cinfo.nr_nodes);
}

static struct vnode_info *alloc_old_vnode_info(const struct sd_node *joined,
					       const struct sd_node *nodes,
					       size_t nr_nodes)
{
	struct sd_node old_nodes[SD_MAX_NODES];

	/* exclude the newly added one */
	memcpy(old_nodes, nodes, sizeof(*nodes) * nr_nodes);
	xlremove(joined, old_nodes, &nr_nodes, node_cmp);

	return alloc_vnode_info(old_nodes, nr_nodes);
}

static void setup_backend_store(const struct join_message *jm)
{
	int ret;

	if (jm->cinfo.store[0] == '\0')
		return;

	if (!sd_store) {
		sd_store = find_store_driver((char *)jm->cinfo.store);
		if (!sd_store)
			panic("backend store %s not supported",
			      jm->cinfo.store);

		ret = sd_store->init();
		if (ret != SD_RES_SUCCESS)
			panic("failed to initialize store");
	}

	/*
	 * We need to purge the stale objects for sheep joining back
	 * after crash
	 */
	if (xlfind(&sys->this_node, jm->cinfo.nodes, jm->cinfo.nr_nodes,
		   node_cmp) == NULL) {
		ret = sd_store->purge_obj();
		if (ret != SD_RES_SUCCESS)
			panic("can't remove stale objects");
	}
}

static void finish_join(const struct join_message *msg,
			const struct sd_node *joined,
			const struct sd_node *nodes, size_t nr_nodes)
{
	sockfd_cache_add_group(nodes, nr_nodes);
}

static void get_vdis(const struct sd_node *nodes, size_t nr_nodes,
		     const struct sd_node *joined)
{
	int array_len = nr_nodes * sizeof(struct sd_node);
	struct get_vdis_work *w;

	w = xmalloc(sizeof(*w) + array_len);
	w->joined = *joined;
	w->nr_members = nr_nodes;
	memcpy(w->members, nodes, array_len);

	is_vdi_list_ready = false;

	w->work.fn = do_get_vdis;
	w->work.done = get_vdis_done;
	queue_work(sys->block_wqueue, &w->work);
}

void wait_get_vdis_done(void)
{
	sd_dprintf("waiting for vdi list");

	pthread_mutex_lock(&wait_vdis_lock);
	while (!is_vdi_list_ready)
		pthread_cond_wait(&wait_vdis_cond, &wait_vdis_lock);
	pthread_mutex_unlock(&wait_vdis_lock);

	sd_dprintf("vdi list ready");
}

void recalculate_vnodes(struct sd_node *nodes, int nr_nodes)
{
	int i, nr_non_gateway_nodes = 0;
	uint64_t avg_size = 0;
	float factor;

	for (i = 0; i < nr_nodes; i++) {
		if (nodes[i].space) {
			avg_size += nodes[i].space;
			nr_non_gateway_nodes++;
		}
	}

	if (!nr_non_gateway_nodes)
		return;

	avg_size /= nr_non_gateway_nodes;

	for (i = 0; i < nr_nodes; i++) {
		factor = (float)nodes[i].space / (float)avg_size;
		nodes[i].nr_vnodes = rintf(SD_DEFAULT_VNODES * factor);
		sd_dprintf("node %d has %d vnodes, free space %" PRIu64,
			   nodes[i].nid.port, nodes[i].nr_vnodes,
			   nodes[i].space);
	}
}

static void update_cluster_info(const struct join_message *msg,
				const struct sd_node *joined,
				const struct sd_node *nodes,
				size_t nr_nodes)
{
	struct vnode_info *old_vnode_info;

	sd_dprintf("status = %d, epoch = %d", msg->cluster_status,
		   msg->cinfo.epoch);

	if (!sys->gateway_only)
		setup_backend_store(msg);

	if (node_is_local(joined))
		finish_join(msg, joined, nodes, nr_nodes);

	old_vnode_info = main_thread_get(current_vnode_info);
	main_thread_set(current_vnode_info,
			  alloc_vnode_info(nodes, nr_nodes));

	get_vdis(nodes, nr_nodes, joined);

	switch (msg->cluster_status) {
	case SD_STATUS_OK:
	case SD_STATUS_HALT:
		if (sys->status == SD_STATUS_WAIT) {
			if (!is_cluster_formatted())
				/* initialize config file */
				set_cluster_config(&sys->cinfo);
		}

		sys->status = msg->cluster_status;

		if (nr_nodes != msg->cinfo.nr_nodes) {
			int ret = inc_and_log_epoch();
			if (ret != 0)
				panic("cannot log current epoch %d",
				      sys->cinfo.epoch);

			if (!old_vnode_info) {
				old_vnode_info = alloc_old_vnode_info(joined,
						nodes, nr_nodes);
			}

			start_recovery(main_thread_get(current_vnode_info),
				       old_vnode_info, true);
		} else
			start_recovery(main_thread_get(current_vnode_info),
				       main_thread_get(current_vnode_info),
				       false);

		if (have_enough_zones())
			sys->status = SD_STATUS_OK;
		break;
	default:
		sys->status = msg->cluster_status;
		break;
	}

	put_vnode_info(old_vnode_info);

	sockfd_cache_add(&joined->nid);
}

/*
 * Pass on a notification message from the cluster driver.
 *
 * Must run in the main thread as it accesses unlocked state like
 * sys->pending_list.
 */
void sd_notify_handler(const struct sd_node *sender, void *data,
		       size_t data_len)
{
	struct vdi_op_message *msg = data;
	const struct sd_op_template *op = get_sd_op(msg->req.opcode);
	int ret = msg->rsp.result;
	struct request *req = NULL;

	sd_dprintf("op %s, size: %zu, from: %s", op_name(op), data_len,
		   node_to_str(sender));

	if (node_is_local(sender)) {
		if (has_process_work(op))
			req = list_first_entry(
				main_thread_get(pending_block_list),
				struct request, pending_list);
		else
			req = list_first_entry(
				main_thread_get(pending_notify_list),
				struct request, pending_list);
		list_del(&req->pending_list);
	}

	if (ret == SD_RES_SUCCESS && has_process_main(op))
		ret = do_process_main(op, &msg->req, &msg->rsp, msg->data);

	if (req) {
		msg->rsp.result = ret;
		if (has_process_main(req->op) &&
		    !(req->rq.flags & SD_FLAG_CMD_WRITE))
			memcpy(req->data, msg->data, msg->rsp.data_length);
		memcpy(&req->rp, &msg->rsp, sizeof(req->rp));

		put_request(req);
	}

	if (has_process_work(op))
		cluster_op_running = false;
}

/*
 * Accept the joining node and pass the cluster info to it.
 *
 * Note that 'nodes' doesn't contain 'joining'.
 *
 * Return true if the joining node is accepted.  At least one nodes in the
 * cluster must call this function and succeed in accept of the joining node.
 */
bool sd_join_handler(const struct sd_node *joining,
		     const struct sd_node *nodes, size_t nr_nodes,
		     void *opaque)
{
	struct join_message *jm = opaque;
	char str[MAX_NODE_STR_LEN];

	/*
	 * If nr_nodes is 0, the joining node is the first member of the cluster
	 * and joins sheepdog successfully without any check.  If nr_nodes is
	 * not 0, the joining node has to wait for another node to accept it.
	 */
	if (nr_nodes > 0 && node_is_local(joining)) {
		sd_dprintf("wait for another node to accept this node");
		return false;
	}

	sd_dprintf("check %s, %d", node_to_str(joining), sys->status);

	jm->proto_ver = SD_SHEEP_PROTO_VER;

	if (sys->status == SD_STATUS_WAIT)
		jm->cluster_status = cluster_wait_check(joining, nodes,
							nr_nodes, jm);
	else
		jm->cluster_status = sys->status;

	sd_dprintf("%s: cluster_status = 0x%x",
		   addr_to_str(str, sizeof(str), joining->nid.addr,
			       joining->nid.port), jm->cluster_status);

	jm->cinfo = sys->cinfo;

	return true;
}

static int send_join_request(struct sd_node *ent)
{
	struct join_message *msg;
	int ret;

	msg = xzalloc(sizeof(*msg));
	msg->cinfo = sys->cinfo;

	ret = sys->cdrv->join(ent, msg, sizeof(*msg));

	sd_printf(SDOG_INFO, "%s", node_to_str(&sys->this_node));

	free(msg);

	return ret;
}

static void requeue_cluster_request(void)
{
	struct request *req, *p;
	struct vdi_op_message *msg;
	size_t size;

	list_for_each_entry_safe(req, p, main_thread_get(pending_notify_list),
				 pending_list) {
		/*
		 * ->notify() was called and succeeded but after that
		 * this node session-timeouted and sd_notify_handler
		 * wasn't called from notify event handler in cluster
		 * driver. We manually call sd_notify_handler to finish
		 * the request.
		 */
		sd_dprintf("finish pending notify request, op: %s",
			   op_name(req->op));
		msg = prepare_cluster_msg(req, &size);
		sd_notify_handler(&sys->this_node, msg, size);
		free(msg);
	}

	list_for_each_entry_safe(req, p, main_thread_get(pending_block_list),
				 pending_list) {
		switch (req->status) {
		case REQUEST_INIT:
			/* this request has never been executed, re-queue it */
			sd_dprintf("requeue a block request, op: %s",
				   op_name(req->op));
			list_del(&req->pending_list);
			queue_cluster_request(req);
			break;
		case REQUEST_QUEUED:
			/*
			 * This request is being handled by the 'block' thread
			 * and ->unblock() isn't called yet. We can't call
			 * ->unblock thereafter because other sheep has
			 * unblocked themselves due to cluster driver session
			 * timeout. Mark it as dropped to stop cluster_op_done()
			 * from calling ->unblock.
			 */
			sd_dprintf("drop pending block request, op: %s",
				   op_name(req->op));
			req->status = REQUEST_DROPPED;
			break;
		case REQUEST_DONE:
			/*
			 * ->unblock() was called and succeeded but after that
			 * this node session-timeouted and sd_notify_handler
			 * wasn't called from unblock event handler in cluster
			 * driver. We manually call sd_notify_handler to finish
			 * the request.
			 */
			sd_dprintf("finish pending block request, op: %s",
				   op_name(req->op));
			msg = prepare_cluster_msg(req, &size);
			sd_notify_handler(&sys->this_node, msg, size);
			free(msg);
			break;
		default:
			break;
		}
	}
}

int sd_reconnect_handler(void)
{
	sys->status = SD_STATUS_WAIT;
	if (sys->cdrv->init(sys->cdrv_option) != 0)
		return -1;
	if (send_join_request(&sys->this_node) != 0)
		return -1;
	requeue_cluster_request();
	return 0;
}

static bool cluster_join_check(const struct join_message *jm)
{
	if (jm->proto_ver != SD_SHEEP_PROTO_VER) {
		sd_eprintf("invalid protocol version: %d, %d",
			   jm->proto_ver, SD_SHEEP_PROTO_VER);
		return false;
	}

	if (!cluster_ctime_check(jm))
		return false;

	if (jm->cinfo.epoch == sys->cinfo.epoch &&
	    memcmp(jm->cinfo.nodes, sys->cinfo.nodes,
		   sizeof(jm->cinfo.nodes[0]) * jm->cinfo.nr_nodes) != 0) {
		sd_printf(SDOG_ALERT, "epoch log entries does not match");
		return false;
	}

	return true;
}

void sd_accept_handler(const struct sd_node *joined,
		       const struct sd_node *members, size_t nr_members,
		       const void *opaque)
{
	int i;
	const struct join_message *jm = opaque;

	if (!cluster_join_check(jm)) {
		sd_eprintf("failed to join Sheepdog");
		exit(1);
	}

	sys->cinfo = jm->cinfo;

	sd_dprintf("join %s", node_to_str(joined));
	for (i = 0; i < nr_members; i++)
		sd_dprintf("[%x] %s", i, node_to_str(members + i));

	if (sys->status == SD_STATUS_SHUTDOWN)
		return;

	update_cluster_info(jm, joined, members, nr_members);

	if (node_is_local(joined))
		/* this output is used for testing */
		sd_printf(SDOG_DEBUG, "join Sheepdog cluster");
}

void sd_leave_handler(const struct sd_node *left, const struct sd_node *members,
		      size_t nr_members)
{
	struct vnode_info *old_vnode_info;
	int i, ret;

	sd_dprintf("leave %s", node_to_str(left));
	for (i = 0; i < nr_members; i++)
		sd_dprintf("[%x] %s", i, node_to_str(members + i));

	if (sys->status == SD_STATUS_SHUTDOWN)
		return;

	if (node_is_local(left))
		/* Mark leave node as gateway only node */
		sys->this_node.nr_vnodes = 0;

	old_vnode_info = main_thread_get(current_vnode_info);
	main_thread_set(current_vnode_info,
			  alloc_vnode_info(members, nr_members));
	switch (sys->status) {
	case SD_STATUS_HALT:
	case SD_STATUS_OK:
		ret = inc_and_log_epoch();
		if (ret != 0)
			panic("cannot log current epoch %d", sys->cinfo.epoch);
		start_recovery(main_thread_get(current_vnode_info),
			       old_vnode_info, true);
		if (!have_enough_zones())
			sys->status = SD_STATUS_HALT;
		break;
	default:
		break;
	}

	put_vnode_info(old_vnode_info);

	sockfd_cache_del(&left->nid);
}

static void update_node_size(struct sd_node *node)
{
	struct vnode_info *cur_vinfo = main_thread_get(current_vnode_info);
	int idx = get_node_idx(cur_vinfo, node);
	assert(idx != -1);
	cur_vinfo->nodes[idx].space = node->space;
}

static void kick_node_recover(void)
{
	struct vnode_info *old = main_thread_get(current_vnode_info);
	int ret;

	main_thread_set(current_vnode_info,
			alloc_vnode_info(old->nodes, old->nr_nodes));
	ret = inc_and_log_epoch();
	if (ret != 0)
		panic("cannot log current epoch %d", sys->cinfo.epoch);
	start_recovery(main_thread_get(current_vnode_info), old, true);
	put_vnode_info(old);
}

void sd_update_node_handler(struct sd_node *node)
{
	update_node_size(node);
	kick_node_recover();
}

int create_cluster(int port, int64_t zone, int nr_vnodes,
		   bool explicit_addr)
{
	int ret;

	if (!sys->cdrv) {
		sys->cdrv = find_cdrv(DEFAULT_CLUSTER_DRIVER);
		sd_dprintf("use %s cluster driver as default",
			   DEFAULT_CLUSTER_DRIVER);
	}

	ret = sys->cdrv->init(sys->cdrv_option);
	if (ret < 0)
		return -1;

	if (!explicit_addr) {
		ret = sys->cdrv->get_local_addr(sys->this_node.nid.addr);

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
	sd_dprintf("zone id = %u", sys->this_node.zone);

	sys->this_node.space = sys->disk_space;

	sys->cinfo.epoch = get_latest_epoch();
	if (sys->cinfo.epoch) {
		sys->cinfo.nr_nodes = epoch_log_read(sys->cinfo.epoch,
						     sys->cinfo.nodes,
						     sizeof(sys->cinfo.nodes));
		if (sys->cinfo.nr_nodes == -1)
			return -1;
	}
	sys->status = SD_STATUS_WAIT;

	main_thread_set(pending_block_list,
			  xzalloc(sizeof(struct list_head)));
	INIT_LIST_HEAD(main_thread_get(pending_block_list));
	main_thread_set(pending_notify_list,
			  xzalloc(sizeof(struct list_head)));
	INIT_LIST_HEAD(main_thread_get(pending_notify_list));

	INIT_LIST_HEAD(&sys->local_req_queue);
	INIT_LIST_HEAD(&sys->req_wait_queue);

	ret = send_join_request(&sys->this_node);
	if (ret != 0)
		return -1;

	return 0;
}

/*
 * We will call this function for two reason:
 * 1) make this node working as a gateway, or
 * 2) the program is going to shutdown itself.
 */
int leave_cluster(void)
{
	static bool left;

	if (left)
		return 0;

	left = true;
	return sys->cdrv->leave();
}
