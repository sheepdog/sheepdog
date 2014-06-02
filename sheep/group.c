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
	struct list_node list;
};

struct get_vdis_work {
	struct work work;
	DECLARE_BITMAP(vdi_inuse, SD_NR_VDIS);
	struct sd_node joined;
	struct rb_root nroot;
};

static struct sd_mutex wait_vdis_lock = SD_MUTEX_INITIALIZER;
static struct sd_cond wait_vdis_cond = SD_COND_INITIALIZER;
static refcnt_t nr_get_vdis_works;

static main_thread(struct vnode_info *) current_vnode_info;
static main_thread(struct list_head *) pending_block_list;
static main_thread(struct list_head *) pending_notify_list;

static int get_zones_nr_from(struct rb_root *nroot)
{
	int nr_zones = 0, j;
	uint32_t zones[SD_MAX_COPIES];
	struct sd_node *n;

	rb_for_each_entry(n, nroot, rb) {
		/*
		 * Only count zones that actually store data, pure gateways
		 * don't contribute to the redundancy level.
		 */
		if (!n->nr_vnodes)
			continue;

		for (j = 0; j < nr_zones; j++) {
			if (n->zone == zones[j])
				break;
		}

		if (j == nr_zones) {
			zones[nr_zones] = n->zone;
			if (++nr_zones == ARRAY_SIZE(zones))
				break;
		}
	}

	return nr_zones;
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
main_fn struct vnode_info *get_vnode_info(void)
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
		if (refcount_dec(&vnode_info->refcnt) == 0) {
			rb_destroy(&vnode_info->vroot, struct sd_vnode, rb);
			rb_destroy(&vnode_info->nroot, struct sd_node, rb);
			free(vnode_info);
		}
	}
}

static void recalculate_vnodes(struct rb_root *nroot)
{
	int nr_non_gateway_nodes = 0;
	uint64_t avg_size = 0;
	struct sd_node *n;
	float factor;

	rb_for_each_entry(n, nroot, rb) {
		if (n->space) {
			avg_size += n->space;
			nr_non_gateway_nodes++;
		}
	}

	if (!nr_non_gateway_nodes)
		return;

	avg_size /= nr_non_gateway_nodes;

	rb_for_each_entry(n, nroot, rb) {
		factor = (float)n->space / (float)avg_size;
		n->nr_vnodes = rintf(SD_DEFAULT_VNODES * factor);
		sd_debug("node %s has %d vnodes, free space %" PRIu64,
			 node_to_str(n), n->nr_vnodes, n->space);
	}
}

struct vnode_info *alloc_vnode_info(const struct rb_root *nroot)
{
	struct vnode_info *vnode_info;
	struct sd_node *n;

	vnode_info = xzalloc(sizeof(*vnode_info));

	INIT_RB_ROOT(&vnode_info->vroot);
	INIT_RB_ROOT(&vnode_info->nroot);
	rb_for_each_entry(n, nroot, rb) {
		struct sd_node *new = xmalloc(sizeof(*new));
		*new = *n;
		if (unlikely(rb_insert(&vnode_info->nroot, new, rb, node_cmp)))
			panic("node hash collision");
		vnode_info->nr_nodes++;
	}

	recalculate_vnodes(&vnode_info->nroot);

	if (is_cluster_diskmode(&sys->cinfo))
		disks_to_vnodes(&vnode_info->nroot, &vnode_info->vroot);
	else
		nodes_to_vnodes(&vnode_info->nroot, &vnode_info->vroot);
	vnode_info->nr_zones = get_zones_nr_from(&vnode_info->nroot);
	refcount_set(&vnode_info->refcnt, 1);
	return vnode_info;
}

struct vnode_info *get_vnode_info_epoch(uint32_t epoch,
					struct vnode_info *cur_vinfo)
{
	struct sd_node nodes[SD_MAX_NODES];
	struct rb_root nroot = RB_ROOT;
	int nr_nodes;

	nr_nodes = epoch_log_read(epoch, nodes, sizeof(nodes));
	if (nr_nodes < 0) {
		nr_nodes = epoch_log_read_remote(epoch, nodes, sizeof(nodes),
						 NULL, cur_vinfo);
		if (nr_nodes == 0)
			return NULL;
	}
	for (int i = 0; i < nr_nodes; i++)
		rb_insert(&nroot, &nodes[i], rb, node_cmp);

	return alloc_vnode_info(&nroot);
}

int get_nodes_epoch(uint32_t epoch, struct vnode_info *cur_vinfo,
		    struct sd_node *nodes, int len)
{
	int nr_nodes;

	nr_nodes = epoch_log_read(epoch, nodes, len);
	if (nr_nodes < 0)
		nr_nodes = epoch_log_read_remote(epoch, nodes, len,
						 NULL, cur_vinfo);
	return nr_nodes;
}

int local_get_node_list(const struct sd_req *req, struct sd_rsp *rsp,
			void *data)
{
	int nr_nodes;
	struct vnode_info *cur_vinfo = get_vnode_info();

	if (cur_vinfo) {
		nr_nodes = cur_vinfo->nr_nodes;
		nodes_to_buffer(&cur_vinfo->nroot, data);
		rsp->data_length = nr_nodes * sizeof(struct sd_node);
		rsp->node.nr_nodes = nr_nodes;

		put_vnode_info(cur_vinfo);
	} else {
		rsp->node.nr_nodes = 0;
	}

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

	sd_debug("%s (%p)", op_name(req->op), req);

	msg = prepare_cluster_msg(req, &size);

	ret = sys->cdrv->unblock(msg, size);
	if (ret != SD_RES_SUCCESS) {
		/*
		 * Failed to unblock, shoot myself to let other sheep
		 * unblock the event.
		 * FIXME: handle it gracefully.
		 */
		sd_emerg("Failed to unblock, %s, exiting.", sd_strerror(ret));
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
main_fn bool sd_block_handler(const struct sd_node *sender)
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
main_fn void queue_cluster_request(struct request *req)
{
	int ret;
	sd_debug("%s (%p)", op_name(req->op), req);

	if (has_process_work(req->op)) {
		ret = sys->cdrv->block();
		if (ret != SD_RES_SUCCESS) {
			sd_err("failed to broadcast block to cluster, %s",
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
			sd_err("failed to broadcast notify to cluster, %s",
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

int epoch_log_read_remote(uint32_t epoch, struct sd_node *nodes, int len,
			  time_t *timestamp, struct vnode_info *vinfo)
{
	char buf[SD_MAX_NODES * sizeof(struct sd_node) + sizeof(time_t)];
	const struct sd_node *node;
	int ret;

	rb_for_each_entry(node, &vinfo->nroot, rb) {
		struct sd_req hdr;
		struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
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

		nodes_len = rsp->data_length - sizeof(*timestamp);
		memcpy((void *)nodes, buf, nodes_len);
		if (timestamp)
			memcpy(timestamp, buf + nodes_len, sizeof(*timestamp));

		return nodes_len / sizeof(struct sd_node);
	}

	/*
	 * If no node has targeted epoch log, return 0 here to at least
	 * allow reading older epoch logs.
	 */
	return 0;
}

static bool cluster_ctime_check(const struct cluster_info *cinfo)
{
	if (cinfo->epoch == 0 || sys->cinfo.epoch == 0)
		return true;

	if (cinfo->ctime != sys->cinfo.ctime) {
		sd_err("joining node ctime doesn't match: %" PRIu64 " vs %"
		       PRIu64, cinfo->ctime, sys->cinfo.ctime);
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
static bool enough_nodes_gathered(struct cluster_info *cinfo,
				  const struct sd_node *joining,
				  const struct rb_root *nroot,
				  size_t nr_nodes)
{
	for (int i = 0; i < cinfo->nr_nodes; i++) {
		const struct sd_node *key = cinfo->nodes + i, *n;

		n = rb_search(nroot, key, rb, node_cmp);
		if (n == NULL && !node_eq(key, joining)) {
			sd_debug("%s doesn't join yet", node_to_str(key));
			return false;
		}
	}

	sd_debug("all the nodes are gathered, %d, %zd", cinfo->nr_nodes,
		 nr_nodes);
	return true;
}

/*
 * We have to use memcpy beause some cluster drivers like corosync can't support
 * to send the whole cluster_info structure.
 */
static void cluster_info_copy(struct cluster_info *dst,
			      const struct cluster_info *src)
{
	int len = offsetof(struct cluster_info, nodes) +
		src->nr_nodes * sizeof(struct sd_node);
	memcpy(dst, src, len);
}

static enum sd_status cluster_wait_check(const struct sd_node *joining,
					 const struct rb_root *nroot,
					 size_t nr_nodes,
					 struct cluster_info *cinfo)
{
	if (!cluster_ctime_check(cinfo)) {
		sd_debug("joining node is invalid");
		return sys->cinfo.status;
	}

	if (cinfo->epoch > sys->cinfo.epoch) {
		sd_debug("joining node has a larger epoch, %" PRIu32 ", %"
			 PRIu32, cinfo->epoch, sys->cinfo.epoch);
		cluster_info_copy(&sys->cinfo, cinfo);
	}

	/*
	 * If we have all members from the last epoch log in the in-memory
	 * node list, we can set the cluster live now.
	 */
	if (sys->cinfo.epoch > 0 &&
	    enough_nodes_gathered(&sys->cinfo, joining, nroot, nr_nodes))
		return SD_STATUS_OK;

	return sys->cinfo.status;
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
		atomic_set_bit(vs[i].vid, sys->vdi_inuse);
		add_vdi_state(vs[i].vid, vs[i].nr_copies, vs[i].snapshot,
			      vs[i].copy_policy);
	}
out:
	free(vs);
	return ret;
}

static void do_get_vdis(struct work *work)
{
	struct get_vdis_work *w =
		container_of(work, struct get_vdis_work, work);
	struct sd_node *n;
	int ret;

	if (!node_is_local(&w->joined)) {
		sd_debug("try to get vdi bitmap from %s",
			 node_to_str(&w->joined));
		ret = get_vdis_from(&w->joined);
		if (ret != SD_RES_SUCCESS)
			sd_alert("failed to get vdi bitmap from %s",
				 node_to_str(&w->joined));
		return;
	}

	rb_for_each_entry(n, &w->nroot, rb) {
		/* We should not fetch vdi_bitmap and copy list from myself */
		if (node_is_local(n))
			continue;

		sd_debug("try to get vdi bitmap from %s", node_to_str(n));
		ret = get_vdis_from(n);
		if (ret != SD_RES_SUCCESS) {
			/* try to read from another node */
			sd_alert("failed to get vdi bitmap from %s",
				 node_to_str(n));
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

	sd_mutex_lock(&wait_vdis_lock);
	refcount_dec(&nr_get_vdis_works);
	sd_cond_broadcast(&wait_vdis_cond);
	sd_mutex_unlock(&wait_vdis_lock);

	rb_destroy(&w->nroot, struct sd_node, rb);
	free(w);
}

int inc_and_log_epoch(void)
{
	struct vnode_info *cur_vinfo = get_vnode_info();

	if (cur_vinfo) {
		/* update cluster info to the latest state */
		sys->cinfo.nr_nodes = cur_vinfo->nr_nodes;
		nodes_to_buffer(&cur_vinfo->nroot, sys->cinfo.nodes);

		put_vnode_info(cur_vinfo);
	} else
		sys->cinfo.nr_nodes = 0;

	uatomic_inc(&sys->cinfo.epoch);

	return update_epoch_log(sys->cinfo.epoch, sys->cinfo.nodes,
				sys->cinfo.nr_nodes);
}

static struct vnode_info *alloc_old_vnode_info(void)
{
	struct rb_root old_root = RB_ROOT;
	struct vnode_info *old;

	/*
	 * If the previous cluster has failed node, (For example, 3 good nodes
	 * and 1 failed node), the 'nroot' will present 4 good nodes after
	 * shutdown and restart this 4 nodes cluster, this is incorrect.
	 * We should use old nodes information which is stored in epoch to
	 * rebuild old_vnode_info.
	 */
	for (int i = 0; i < sys->cinfo.nr_nodes; i++) {
		struct sd_node *new = xmalloc(sizeof(*new));
		*new = sys->cinfo.nodes[i];
		if (rb_insert(&old_root, new, rb, node_cmp))
			panic("node hash collision");
	}

	old = alloc_vnode_info(&old_root);
	rb_destroy(&old_root, struct sd_node, rb);
	return old;
}

static void setup_backend_store(const struct cluster_info *cinfo)
{
	int ret;

	if (cinfo->store[0] == '\0')
		return;

	if (!sd_store) {
		sd_store = find_store_driver((char *)cinfo->store);
		if (!sd_store)
			panic("backend store %s not supported", cinfo->store);

		ret = sd_store->init();
		if (ret != SD_RES_SUCCESS)
			panic("failed to initialize store");
	}

	/*
	 * We need to purge the stale objects for sheep joining back
	 * after crash
	 */
	if (xlfind(&sys->this_node, cinfo->nodes, cinfo->nr_nodes,
		   node_cmp) == NULL) {
		ret = sd_store->purge_obj();
		if (ret != SD_RES_SUCCESS)
			panic("can't remove stale objects");
	}
}

static void get_vdis(const struct rb_root *nroot, const struct sd_node *joined)
{
	struct get_vdis_work *w;

	w = xmalloc(sizeof(*w));
	w->joined = *joined;
	INIT_RB_ROOT(&w->nroot);
	rb_copy(nroot, struct sd_node, rb, &w->nroot, node_cmp);
	refcount_inc(&nr_get_vdis_works);

	w->work.fn = do_get_vdis;
	w->work.done = get_vdis_done;
	queue_work(sys->block_wqueue, &w->work);
}

void wait_get_vdis_done(void)
{
	sd_debug("waiting for vdi list");

	sd_mutex_lock(&wait_vdis_lock);
	while (refcount_read(&nr_get_vdis_works) > 0)
		sd_cond_wait(&wait_vdis_cond, &wait_vdis_lock);
	sd_mutex_unlock(&wait_vdis_lock);

	sd_debug("vdi list ready");
}

static bool membership_changed(const struct cluster_info *cinfo,
			  const struct rb_root *nroot,
			  size_t nr_nodes)
{
	const struct sd_node *key, *n;
	int i, ret;

	if (nr_nodes != cinfo->nr_nodes)
		return true;

	if (!is_cluster_diskmode(cinfo))
		return false;

	for (i = 0; i < cinfo->nr_nodes; i++) {
		key = cinfo->nodes + i;
		n = rb_search(nroot, key, rb, node_cmp);
		if (!n)
			continue;
		ret = memcmp(n->disks, key->disks,
			     sizeof(struct disk_info) * DISK_MAX);
		if (ret)
			return true;
	}
	return false;
}

static void update_cluster_info(const struct cluster_info *cinfo,
				const struct sd_node *joined,
				const struct rb_root *nroot,
				size_t nr_nodes)
{
	struct vnode_info *old_vnode_info;

	sd_debug("status = %d, epoch = %d", cinfo->status, cinfo->epoch);

	if (!sys->gateway_only)
		setup_backend_store(cinfo);

	if (node_is_local(joined))
		sockfd_cache_add_group(nroot);
	sockfd_cache_add(&joined->nid);

	/*
	 * We need use main_thread_get() to obtain current_vnode_info. The
	 * reference count of old_vnode_info is decremented at the last of this
	 * function in order to release old_vnode_info. The counter part
	 * of this dereference is alloc_vnode_info().
	 */
	old_vnode_info = main_thread_get(current_vnode_info);
	main_thread_set(current_vnode_info, alloc_vnode_info(nroot));

	get_vdis(nroot, joined);

	if (cinfo->status == SD_STATUS_OK) {
		if (!is_cluster_formatted())
			/* initialize config file */
			set_cluster_config(&sys->cinfo);

		if (membership_changed(cinfo, nroot, nr_nodes)) {
			int ret;
			if (old_vnode_info)
				put_vnode_info(old_vnode_info);

			old_vnode_info = alloc_old_vnode_info();
			ret = inc_and_log_epoch();
			if (ret != 0)
				panic("cannot log current epoch %d",
				      sys->cinfo.epoch);

			start_recovery(main_thread_get(current_vnode_info),
				       old_vnode_info, true);
		} else if (!was_cluster_shutdowned()) {
			start_recovery(main_thread_get(current_vnode_info),
				       main_thread_get(current_vnode_info),
				       false);
		}
		set_cluster_shutdown(false);
	}

	put_vnode_info(old_vnode_info);
}

/*
 * Pass on a notification message from the cluster driver.
 *
 * Must run in the main thread as it accesses unlocked state like
 * sys->pending_list.
 */
main_fn void sd_notify_handler(const struct sd_node *sender, void *data,
			       size_t data_len)
{
	struct vdi_op_message *msg = data;
	const struct sd_op_template *op = get_sd_op(msg->req.opcode);
	int ret = msg->rsp.result;
	struct request *req = NULL;

	sd_debug("op %s, size: %zu, from: %s", op_name(op), data_len,
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
main_fn bool sd_join_handler(const struct sd_node *joining,
			     const struct rb_root *nroot, size_t nr_nodes,
			     void *opaque)
{
	struct cluster_info *cinfo = opaque;
	enum sd_status status;

	/*
	 * If nr_nodes is 0, the joining node is the first member of the cluster
	 * and joins sheepdog successfully without any check.  If nr_nodes is
	 * not 0, the joining node has to wait for another node to accept it.
	 */
	if (nr_nodes > 0 && node_is_local(joining)) {
		sd_debug("wait for another node to accept this node");
		return false;
	}

	sd_debug("check %s, %d", node_to_str(joining), sys->cinfo.status);

	if (sys->cinfo.status == SD_STATUS_WAIT)
		status = cluster_wait_check(joining, nroot, nr_nodes, cinfo);
	else
		status = sys->cinfo.status;

	cluster_info_copy(cinfo, &sys->cinfo);
	cinfo->status = status;
	cinfo->proto_ver = SD_SHEEP_PROTO_VER;

	sd_debug("%s: cluster_status = 0x%x",
		 addr_to_str(joining->nid.addr, joining->nid.port),
		 cinfo->status);

	return true;
}

static int send_join_request(void)
{
	struct sd_node *n = &sys->this_node;

	sd_info("%s", node_to_str(n));
	return sys->cdrv->join(n, &sys->cinfo, sizeof(sys->cinfo));
}

static void requeue_cluster_request(void)
{
	struct request *req;
	struct vdi_op_message *msg;
	size_t size;

	list_for_each_entry(req, main_thread_get(pending_notify_list),
			    pending_list) {
		/*
		 * ->notify() was called and succeeded but after that
		 * this node session-timeouted and sd_notify_handler
		 * wasn't called from notify event handler in cluster
		 * driver. We manually call sd_notify_handler to finish
		 * the request.
		 */
		sd_debug("finish pending notify request, op: %s",
			 op_name(req->op));
		msg = prepare_cluster_msg(req, &size);
		sd_notify_handler(&sys->this_node, msg, size);
		free(msg);
	}

	list_for_each_entry(req, main_thread_get(pending_block_list),
			    pending_list) {
		switch (req->status) {
		case REQUEST_INIT:
			/* this request has never been executed, re-queue it */
			sd_debug("requeue a block request, op: %s",
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
			sd_debug("drop pending block request, op: %s",
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
			sd_debug("finish pending block request, op: %s",
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

main_fn int sd_reconnect_handler(void)
{
	sys->cinfo.status = SD_STATUS_WAIT;
	if (sys->cdrv->init(sys->cdrv_option) != 0)
		return -1;
	if (send_join_request() != 0)
		return -1;
	requeue_cluster_request();
	return 0;
}

static bool cluster_join_check(const struct cluster_info *cinfo)
{
	if (cinfo->proto_ver != SD_SHEEP_PROTO_VER) {
		sd_err("invalid protocol version: %d, %d", cinfo->proto_ver,
		       SD_SHEEP_PROTO_VER);
		return false;
	}

	if (!cluster_ctime_check(cinfo))
		return false;

	/*
	 * Sheepdog's recovery code assumes every node have the same epoch
	 * history. But we don't check epoch history of joining node because:
	 * 1. inconsist epoch history only happens in the network partition case
	 *    for the corosync driver, but corosync driver will panic for such
	 *    case to prevent epoch inconsistency.
	 * 2. checking epoch history with joining node is too expensive and is
	 *    unneeded for zookeeper driver.
	 *
	 * That said, we don't check epoch history at all.
	 */

	return true;
}

main_fn void sd_accept_handler(const struct sd_node *joined,
			       const struct rb_root *nroot, size_t nr_nodes,
			       const void *opaque)
{
	const struct cluster_info *cinfo = opaque;
	struct sd_node *n;

	if (node_is_local(joined) && !cluster_join_check(cinfo)) {
		sd_err("failed to join Sheepdog");
		exit(1);
	}

	cluster_info_copy(&sys->cinfo, cinfo);

	sd_debug("join %s", node_to_str(joined));
	rb_for_each_entry(n, nroot, rb) {
		sd_debug("%s", node_to_str(n));
	}

	if (sys->cinfo.status == SD_STATUS_SHUTDOWN)
		return;

	update_cluster_info(cinfo, joined, nroot, nr_nodes);

	if (node_is_local(joined))
		/* this output is used for testing */
		sd_debug("join Sheepdog cluster");
}

main_fn void sd_leave_handler(const struct sd_node *left,
			      const struct rb_root *nroot, size_t nr_nodes)
{
	struct vnode_info *old_vnode_info;
	struct sd_node *n;
	int ret;

	sd_debug("leave %s", node_to_str(left));
	rb_for_each_entry(n, nroot, rb) {
		sd_debug("%s", node_to_str(n));
	}

	if (sys->cinfo.status == SD_STATUS_SHUTDOWN)
		return;

	if (node_is_local(left))
		/* Mark leave node as gateway only node */
		sys->this_node.nr_vnodes = 0;

	/*
	 * Using main_thread_get() instead of get_vnode_info() is allowed
	 * because of the same reason of update_cluster_info()
	 */
	old_vnode_info = main_thread_get(current_vnode_info);
	main_thread_set(current_vnode_info, alloc_vnode_info(nroot));
	if (sys->cinfo.status == SD_STATUS_OK) {
		ret = inc_and_log_epoch();
		if (ret != 0)
			panic("cannot log current epoch %d", sys->cinfo.epoch);
		start_recovery(main_thread_get(current_vnode_info),
			       old_vnode_info, true);
	}

	put_vnode_info(old_vnode_info);

	sockfd_cache_del_node(&left->nid);
}

static void update_node_size(struct sd_node *node)
{
	struct vnode_info *cur_vinfo = get_vnode_info();
	struct sd_node *n = rb_search(&cur_vinfo->nroot, node, rb, node_cmp);

	if (unlikely(!n))
		panic("can't find %s", node_to_str(node));
	n->space = node->space;
	if (is_cluster_diskmode(&sys->cinfo)) {
		memset(n->disks, 0, sizeof(struct disk_info) * DISK_MAX);
		for (int i = 0; i < DISK_MAX; i++)
			if (node->disks[i].disk_id)
				n->disks[i] = node->disks[i];
	}
	put_vnode_info(cur_vinfo);
}

static void kick_node_recover(void)
{
	/*
	 * Using main_thread_get() instead of get_vnode_info() is allowed
	 * because of the same reason of update_cluster_info()
	 */
	struct vnode_info *old = main_thread_get(current_vnode_info);
	int ret;

	main_thread_set(current_vnode_info, alloc_vnode_info(&old->nroot));
	ret = inc_and_log_epoch();
	if (ret != 0)
		panic("cannot log current epoch %d", sys->cinfo.epoch);
	start_recovery(main_thread_get(current_vnode_info), old, true);
	put_vnode_info(old);
}

main_fn void sd_update_node_handler(struct sd_node *node)
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
		sd_debug("use %s cluster driver as default",
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
	sd_debug("zone id = %u", sys->this_node.zone);

	sys->this_node.space = sys->disk_space;

	update_node_disks();

	sys->cinfo.epoch = get_latest_epoch();
	if (sys->cinfo.epoch) {
		sys->cinfo.nr_nodes = epoch_log_read(sys->cinfo.epoch,
						     sys->cinfo.nodes,
						     sizeof(sys->cinfo.nodes));
		if (sys->cinfo.nr_nodes == -1)
			return -1;
	}
	sys->cinfo.status = SD_STATUS_WAIT;

	main_thread_set(pending_block_list,
			  xzalloc(sizeof(struct list_head)));
	INIT_LIST_HEAD(main_thread_get(pending_block_list));
	main_thread_set(pending_notify_list,
			  xzalloc(sizeof(struct list_head)));
	INIT_LIST_HEAD(main_thread_get(pending_notify_list));

	INIT_LIST_HEAD(&sys->local_req_queue);
	INIT_LIST_HEAD(&sys->req_wait_queue);

	ret = send_join_request();
	if (ret != 0)
		return -1;

	INIT_LIST_HEAD(&sys->prevented_cow_request_queue);
	INIT_LIST_HEAD(&sys->pending_prevent_cow_request_queue);

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
