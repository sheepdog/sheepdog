/*
 * Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "sheep_priv.h"
#include "trace/trace.h"

enum sd_op_type {
	SD_OP_TYPE_CLUSTER = 1, /* cluster operations */
	SD_OP_TYPE_LOCAL,       /* local operations */
	SD_OP_TYPE_PEER,          /* io operations */
	SD_OP_TYPE_GATEWAY,	/* gateway operations */
};

struct sd_op_template {
	const char *name;
	enum sd_op_type type;

	/* process request even when cluster is not working */
	bool force;

	/*
	 * Indicates administrative operation to trace.
	 * If true is set, rx_main and tx_main log operations at info level.
	 */
	bool is_admin_op;

	/*
	 * process_work() will be called in a worker thread, and process_main()
	 * will be called in the main thread.
	 *
	 * If type is SD_OP_TYPE_CLUSTER, it is guaranteed that only one node
	 * processes a cluster operation at the same time.  We can use this for
	 * for example to implement distributed locking.  process_work()
	 * will be called on the local node, and process_main() will be called
	 * on every node.
	 *
	 * If type is SD_OP_TYPE_LOCAL, both process_work() and process_main()
	 * will be called on the local node.
	 *
	 * If type is SD_OP_TYPE_PEER, only process_work() will be called, and it
	 * will be called on the local node.
	 */
	int (*process_work)(struct request *req);
	int (*process_main)(const struct sd_req *req, struct sd_rsp *rsp,
			    void *data, const struct sd_node *sender);
};

/*
 * The last gathered epoch is the epoch at which all the nodes complete the
 * recovery and purge the stale objects.
 */
uint32_t last_gathered_epoch = 1;

static int stat_sheep(uint64_t *store_size, uint64_t *store_free,
		      uint32_t epoch)
{
	uint64_t used;

	if (sys->gateway_only) {
		*store_size = 0;
		*store_free = 0;
	} else {
		*store_size = md_get_size(&used);
		*store_free = *store_size - used;
	}
	return SD_RES_SUCCESS;
}

static int cluster_new_vdi(struct request *req)
{
	const struct sd_req *hdr = &req->rq;
	struct sd_rsp *rsp = &req->rp;
	uint32_t vid;
	int ret;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	struct vdi_iocb iocb = {
		.name = req->data,
		.data_len = hdr->data_length,
		.size = hdr->vdi.vdi_size,
		.base_vid = hdr->vdi.base_vdi_id,
		.create_snapshot = !!hdr->vdi.snapid,
		.copy_policy = hdr->vdi.copy_policy,
		.store_policy = hdr->vdi.store_policy,
		.nr_copies = hdr->vdi.copies,
		.block_size_shift = hdr->vdi.block_size_shift,
		.time = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000,
	};

	/* Client doesn't specify redundancy scheme (copy = 0) */
	if (!hdr->vdi.copies) {
		iocb.nr_copies = sys->cinfo.nr_copies;
		iocb.copy_policy = sys->cinfo.copy_policy;
	}

	if (iocb.copy_policy)
		iocb.nr_copies = ec_policy_to_dp(iocb.copy_policy, NULL, NULL);

	if (!hdr->vdi.block_size_shift)
		iocb.block_size_shift = sys->cinfo.block_size_shift;

	if (hdr->data_length != SD_MAX_VDI_LEN)
		return SD_RES_INVALID_PARMS;

	if (iocb.create_snapshot)
		ret = vdi_snapshot(&iocb, &vid);
	else
		ret = vdi_create(&iocb, &vid);

	rsp->vdi.vdi_id = vid;
	rsp->vdi.copies = iocb.nr_copies;
	rsp->vdi.block_size_shift = iocb.block_size_shift;

	return ret;
}

static int post_cluster_new_vdi(const struct sd_req *req, struct sd_rsp *rsp,
				void *data, const struct sd_node *sender)
{
	unsigned long nr = rsp->vdi.vdi_id;
	int ret = rsp->result;

	sd_info("req->vdi.base_vdi_id: %x, rsp->vdi.vdi_id: %x", req->vdi.base_vdi_id, rsp->vdi.vdi_id);

	sd_debug("done %d %lx", ret, nr);
	if (ret == SD_RES_SUCCESS)
		atomic_set_bit(nr, sys->vdi_inuse);

	return ret;
}

static int vdi_init_tag(const char **tag, const char *buf, uint32_t len)
{
	if (len == SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN)
		*tag = buf + SD_MAX_VDI_LEN;
	else if (len == SD_MAX_VDI_LEN)
		*tag = NULL;
	else
		return -1;

	return 0;
}

static int cluster_del_vdi(struct request *req)
{
	const struct sd_req *hdr = &req->rq;
	uint32_t data_len = hdr->data_length;
	struct vdi_iocb iocb = {
		.name = req->data,
		.data_len = data_len,
		.snapid = hdr->vdi.snapid,
	};

	if (vdi_init_tag(&iocb.tag, req->data, data_len) < 0)
		return SD_RES_INVALID_PARMS;

	return vdi_delete(&iocb, req);
}

struct cache_deletion_work {
	uint32_t vid;
	struct work work;
};

static void cache_delete_work(struct work *work)
{
	struct cache_deletion_work *dw =
		container_of(work, struct cache_deletion_work, work);

	object_cache_delete(dw->vid);
}

static void cache_delete_done(struct work *work)
{
	struct cache_deletion_work *dw =
		container_of(work, struct cache_deletion_work, work);

	free(dw);
}

static int post_cluster_del_vdi(const struct sd_req *req, struct sd_rsp *rsp,
				void *data, const struct sd_node *sender)
{
	unsigned long vid = rsp->vdi.vdi_id;
	struct cache_deletion_work *dw;
	int ret = rsp->result;

	if (ret == SD_RES_SUCCESS) {
		atomic_set_bit(vid, sys->vdi_deleted);
		vdi_mark_deleted(vid);

		if (sys->cinfo.flags & SD_CLUSTER_FLAG_RECYCLE_VID)
			run_vid_gc(vid);
	}

	if (!sys->enable_object_cache)
		return ret;

	dw = xzalloc(sizeof(*dw));
	dw->vid = vid;
	dw->work.fn = cache_delete_work;
	dw->work.done = cache_delete_done;

	queue_work(sys->deletion_wqueue, &dw->work);

	return ret;
}

/*
 * Look up vid and copy number from vdi name
 *
 * This must be a cluster operation.  If QEMU reads the vdi object
 * while sheep snapshots the vdi, sheep can return SD_RES_NO_VDI.  To
 * avoid this problem, SD_OP_GET_INFO must be ordered with
 * SD_OP_NEW_VDI.
 */
static int cluster_get_vdi_info(struct request *req)
{
	const struct sd_req *hdr = &req->rq;
	struct sd_rsp *rsp = &req->rp;
	uint32_t data_len = hdr->data_length;
	int ret;
	struct vdi_info info = {};
	struct vdi_iocb iocb = {
		.name = req->data,
		.data_len = data_len,
		.snapid = hdr->vdi.snapid,
	};

	if (vdi_init_tag(&iocb.tag, req->data, data_len) < 0)
		return SD_RES_INVALID_PARMS;

	ret = vdi_lookup(&iocb, &info);
	if (ret != SD_RES_SUCCESS)
		return ret;

	rsp->vdi.vdi_id = info.vid;
	rsp->vdi.copies = get_vdi_copy_number(info.vid);
	rsp->vdi.block_size_shift = get_vdi_block_size_shift(info.vid);

	return ret;
}

static int remove_epoch(uint32_t epoch)
{
	int ret;
	char path[PATH_MAX];

	sd_debug("remove epoch %"PRIu32, epoch);
	snprintf(path, sizeof(path), "%s%08u", epoch_path, epoch);
	ret = unlink(path);
	if (ret && errno != ENOENT) {
		sd_err("failed to remove %s: %m", path);
		return SD_RES_EIO;
	}

	return SD_RES_SUCCESS;
}

static int get_vnodes(struct vnode_info *vinfo, int *nr_vnodes)
{
	int ret;
	struct sd_node *node;

	rb_for_each_entry(node, &vinfo->nroot, rb) {
		struct sd_req hdr;
		if (node_is_local(node))
			continue;
		if (node->nr_vnodes == 0)
			continue;

		sd_init_req(&hdr, SD_OP_GET_VNODES);
		hdr.data_length = sizeof(*nr_vnodes);
		hdr.epoch = sys_epoch();
		ret = sheep_exec_req(&node->nid, &hdr, nr_vnodes);
		if (ret != SD_RES_SUCCESS)
			return ret;
		node->nr_vnodes = *nr_vnodes;
	}
	return SD_RES_SUCCESS;
}

static int cluster_make_fs(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data, const struct sd_node *sender)
{
	int i, ret = SD_RES_SUCCESS;
	uint32_t latest_epoch;
	struct store_driver *driver;
	char *store_name = data;
	int32_t nr_vnodes;
	struct vnode_info *vinfo = get_vnode_info();

	driver = find_store_driver(data);
	if (!driver) {
		ret = SD_RES_NO_STORE;
		goto out;
	}

	pstrcpy((char *)sys->cinfo.store, sizeof(sys->cinfo.store),
		store_name);
	sd_store = driver;
	latest_epoch = get_latest_epoch();

	ret = sd_store->format();
	if (ret != SD_RES_SUCCESS)
		goto out;

	ret = sd_store->init();
	if (ret != SD_RES_SUCCESS)
		goto out;

	if (sys->gateway_only) {
		ret = get_vnodes(vinfo, &nr_vnodes);
		if (ret != SD_RES_SUCCESS)
			goto out;
	}

	sys->cinfo.nr_copies = req->cluster.copies;
	sys->cinfo.copy_policy = req->cluster.copy_policy;
	sys->cinfo.block_size_shift = req->cluster.block_size_shift;
	sys->cinfo.flags = req->cluster.flags;
	if (!sys->cinfo.nr_copies)
		sys->cinfo.nr_copies = SD_DEFAULT_COPIES;
	if (!sys->cinfo.block_size_shift)
		sys->cinfo.block_size_shift = SD_DEFAULT_BLOCK_SIZE_SHIFT;
	sys->cinfo.ctime = req->cluster.ctime;
	set_cluster_config(&sys->cinfo);

	for (i = 1; i <= latest_epoch; i++)
		remove_epoch(i);

	memset(sys->vdi_inuse, 0, sizeof(sys->vdi_inuse));
	memset(sys->vdi_deleted, 0, sizeof(sys->vdi_deleted));
	clean_vdi_state();
	objlist_cache_format();

	sys->cinfo.epoch = 0;

	ret = inc_and_log_epoch();
	if (ret) {
		ret = SD_RES_EIO;
		goto out;
	}

	sys->cinfo.status = SD_STATUS_OK;

out:
	put_vnode_info(vinfo);
	return ret;
}

static int cluster_shutdown(const struct sd_req *req, struct sd_rsp *rsp,
			    void *data, const struct sd_node *sender)
{
	sys->cinfo.status = SD_STATUS_SHUTDOWN;
	if (!node_in_recovery()) {
		unregister_listening_fds();

		if (set_cluster_shutdown(true) != SD_RES_SUCCESS)
			/*
			 * It's okay we failed to set 'shutdown', just start
			 * recovery after restart blindly.
			 */
			sd_err("failed to set cluster as shutdown");
	}

	return SD_RES_SUCCESS;
}

static int cluster_enable_recover(const struct sd_req *req, struct sd_rsp *rsp,
				  void *data, const struct sd_node *sender)
{
	sys->cinfo.disable_recovery = false;
	resume_suspended_recovery();
	return SD_RES_SUCCESS;
}

static int cluster_disable_recover(const struct sd_req *req, struct sd_rsp *rsp,
				   void *data, const struct sd_node *sender)
{
	sys->cinfo.disable_recovery = true;
	return SD_RES_SUCCESS;
}

static int cluster_get_vdi_attr(struct request *req)
{
	const struct sd_req *hdr = &req->rq;
	struct sd_rsp *rsp = &req->rp;
	uint32_t vid, attrid = 0;
	struct sheepdog_vdi_attr *vattr;
	struct vdi_iocb iocb = {};
	struct vdi_info info = {};
	int ret;

	vattr = req->data;
	iocb.name = vattr->name;
	iocb.tag = vattr->tag;
	iocb.snapid = hdr->vdi.snapid;
	ret = vdi_lookup(&iocb, &info);
	if (ret != SD_RES_SUCCESS)
		return ret;
	/*
	 * the current VDI id can change if we take a snapshot,
	 * so we use the hash value of the VDI name as the VDI id
	 */
	vid = sd_hash_vdi(vattr->name);
	ret = get_vdi_attr(req->data, hdr->data_length,
			   vid, &attrid, info.create_time,
			   !!(hdr->flags & SD_FLAG_CMD_CREAT),
			   !!(hdr->flags & SD_FLAG_CMD_EXCL),
			   !!(hdr->flags & SD_FLAG_CMD_DEL));

	rsp->vdi.vdi_id = vid;
	rsp->vdi.attr_id = attrid;
	rsp->vdi.copies = get_vdi_copy_number(vid);

	return ret;
}

static int local_release_vdi(struct request *req)
{
	uint32_t vid = req->rq.vdi.base_vdi_id;
	int ret;

	if (!sys->enable_object_cache)
		return SD_RES_SUCCESS;

	if (!vid) {
		sd_info("Some VDI failed to release the object cache. "
			"Probably you are running old QEMU.");
		return SD_RES_SUCCESS;
	}

	ret = object_cache_flush_vdi(vid);
	if (ret == SD_RES_SUCCESS)
		object_cache_delete(vid);

	return ret;
}

static int local_get_store_list(struct request *req)
{
	struct strbuf buf = STRBUF_INIT;
	struct store_driver *driver;

	list_for_each_entry(driver, &store_drivers, list) {
		strbuf_addf(&buf, "%s ", driver->name);
	}
	req->rp.data_length = strbuf_copyout(&buf, req->data, req->data_length);

	strbuf_release(&buf);
	return SD_RES_SUCCESS;
}

static int local_read_vdis(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data, const struct sd_node *sender)
{
	return read_vdis(data, req->data_length, &rsp->data_length);
}

static int local_read_del_vdis(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data, const struct sd_node *sender)
{
	return read_del_vdis(data, req->data_length, &rsp->data_length);
}

static int local_get_vdi_copies(const struct sd_req *req, struct sd_rsp *rsp,
				void *data, const struct sd_node *sender)
{
	return fill_vdi_state_list(req, rsp, data);
}

static int local_stat_sheep(struct request *req)
{
	struct sd_rsp *rsp = &req->rp;
	uint32_t epoch = req->rq.epoch;

	return stat_sheep(&rsp->node.store_size, &rsp->node.store_free, epoch);
}

static int local_stat_recovery(const struct sd_req *req, struct sd_rsp *rsp,
			       void *data, const struct sd_node *sender)
{
	get_recovery_state(data);
	rsp->data_length = sizeof(struct recovery_state);

	return SD_RES_SUCCESS;
}

static int local_stat_cluster(struct request *req)
{
	struct sd_rsp *rsp = &req->rp;
	struct epoch_log *elog;
	char *next_elog;
	int i, max_elogs;
	uint32_t epoch;
	uint32_t nodes_nr = req->rq.cluster.nodes_nr;

	if (req->vinfo == NULL) {
		sd_debug("cluster is not started up");
		goto out;
	}

	max_elogs = req->rq.data_length / (sizeof(*elog)
			+ nodes_nr * sizeof(struct sd_node));
	next_elog = (char *)req->data;
	epoch = get_latest_epoch();
	for (i = 0; i < max_elogs; i++) {
		int nr_nodes = 0, ret;

		if (epoch <= 0)
			break;

		elog = (struct epoch_log *)next_elog;
		memset(elog, 0, sizeof(*elog));

		/* some filed only need to store in first elog */
		if (i == 0) {
			elog->ctime = sys->cinfo.ctime;
			elog->disable_recovery = sys->cinfo.disable_recovery;
			elog->nr_copies = sys->cinfo.nr_copies;
			elog->copy_policy = sys->cinfo.copy_policy;
			elog->flags = sys->cinfo.flags;
			pstrcpy(elog->drv_name, STORE_LEN,
				(char *)sys->cinfo.store);
		}

		elog->epoch = epoch;
		if (nodes_nr > 0) {
			ret = epoch_log_read_with_timestamp(
					epoch, elog->nodes,
					nodes_nr * sizeof(struct sd_node),
					&nr_nodes, (time_t *)&elog->time);
			if (ret == SD_RES_NO_TAG)
				ret = epoch_log_read_remote(
					epoch, elog->nodes,
					nodes_nr * sizeof(struct sd_node),
					&nr_nodes, (time_t *)&elog->time,
					req->vinfo);
			if (ret == SD_RES_BUFFER_SMALL)
				return ret;
			elog->nr_nodes = nr_nodes;
		} else
			elog->nr_nodes = 0;

		next_elog = (char *)elog->nodes
				+ nodes_nr * sizeof(struct sd_node);
		rsp->data_length += sizeof(*elog)
				+ nodes_nr * sizeof(struct sd_node);
		epoch--;
	}
out:
	switch (sys->cinfo.status) {
	case SD_STATUS_OK:
		return SD_RES_SUCCESS;
	case SD_STATUS_WAIT:
		if (sys->cinfo.ctime == 0)
			return SD_RES_WAIT_FOR_FORMAT;
		else
			return SD_RES_WAIT_FOR_JOIN;
	case SD_STATUS_SHUTDOWN:
		return SD_RES_SHUTDOWN;
	default:
		return SD_RES_SYSTEM_ERROR;
	}
}

static int local_get_obj_list(struct request *req)
{
	return get_obj_list(&req->rq, &req->rp, req->data);
}

static int local_get_epoch(struct request *req)
{
	uint32_t epoch = req->rq.obj.tgt_epoch;
	int nr_nodes = 0, nodes_len, ret;
	time_t timestamp;

	sd_debug("%d", epoch);

	ret =
		epoch_log_read_with_timestamp(epoch, req->data,
					req->rq.data_length - sizeof(timestamp),
					&nr_nodes, &timestamp);
	if (ret != SD_RES_SUCCESS)
		return ret;

	nodes_len = nr_nodes * sizeof(struct sd_node);
	memcpy((void *)((char *)req->data + nodes_len), &timestamp,
		sizeof(timestamp));
	req->rp.data_length = nodes_len + sizeof(time_t);
	return SD_RES_SUCCESS;
}

static int cluster_force_recover_work(struct request *req)
{
	struct vnode_info *old_vnode_info;
	uint32_t epoch = sys_epoch();

	/*
	 * We should manually recover the cluster when
	 * 1) the master is physically down (different epoch condition).
	 * 2) some nodes are physically down (same epoch condition).
	 * In both case, the nodes(s) stat is WAIT_FOR_JOIN.
	 */
	if (sys->cinfo.status != SD_STATUS_WAIT || req->vinfo == NULL)
		return SD_RES_FORCE_RECOVER;

	old_vnode_info = get_vnode_info_epoch(epoch, req->vinfo);
	if (!old_vnode_info) {
		sd_emerg("cannot get vnode info for epoch %d", epoch);
		put_vnode_info(old_vnode_info);
		return SD_RES_FORCE_RECOVER;
	}

	if (req->rq.data_length <
	    sizeof(struct sd_node) * old_vnode_info->nr_nodes) {
		sd_err("too small buffer size, %d", req->rq.data_length);
		return SD_RES_INVALID_PARMS;
	}

	req->rp.epoch = epoch;
	req->rp.data_length = sizeof(struct sd_node) * old_vnode_info->nr_nodes;
	nodes_to_buffer(&old_vnode_info->nroot, req->data);

	put_vnode_info(old_vnode_info);

	return SD_RES_SUCCESS;
}

static int cluster_force_recover_main(const struct sd_req *req,
				      struct sd_rsp *rsp,
				      void *data, const struct sd_node *sender)
{
	struct vnode_info *old_vnode_info, *vnode_info;
	int ret = SD_RES_SUCCESS;
	struct sd_node *nodes = data;
	size_t nr_nodes = rsp->data_length / sizeof(*nodes);
	struct rb_root nroot = RB_ROOT;

	if (rsp->epoch != sys->cinfo.epoch) {
		sd_err("epoch was incremented while cluster_force_recover");
		return SD_RES_FORCE_RECOVER;
	}

	ret = inc_and_log_epoch();
	if (ret) {
		sd_emerg("cannot update epoch log");
		goto err;
	}

	if (!is_cluster_formatted())
		/* initialize config file */
		set_cluster_config(&sys->cinfo);

	sys->cinfo.status = SD_STATUS_OK;

	for (int i = 0; i < nr_nodes; i++)
		rb_insert(&nroot, &nodes[i], rb, node_cmp);

	vnode_info = get_vnode_info();
	old_vnode_info = alloc_vnode_info(&nroot);
	start_recovery(vnode_info, old_vnode_info, true, false);
	put_vnode_info(vnode_info);
	put_vnode_info(old_vnode_info);
	return ret;
err:
	panic("failed in force recovery");
}

static int cluster_cleanup(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data, const struct sd_node *sender)
{
	int ret;

	if (node_in_recovery())
		return SD_RES_NODE_IN_RECOVERY;

	if (sys->gateway_only)
		return SD_RES_SUCCESS;

	if (sd_store->cleanup)
		ret = sd_store->cleanup();
	else
		ret = SD_RES_NO_SUPPORT;

	return ret;
}

static int cluster_notify_vdi_add(const struct sd_req *req, struct sd_rsp *rsp,
				  void *data, const struct sd_node *sender)
{
	if (req->vdi_state.old_vid)
		/* make the previous working vdi a snapshot */
		add_vdi_state(req->vdi_state.old_vid,
			      get_vdi_copy_number(req->vdi_state.old_vid),
			      true, req->vdi_state.copy_policy,
			      get_vdi_block_size_shift(req->vdi_state.old_vid),
			      0);

	if (req->vdi_state.set_bitmap)
		atomic_set_bit(req->vdi_state.new_vid, sys->vdi_inuse);

	add_vdi_state(req->vdi_state.new_vid, req->vdi_state.copies, false,
		      req->vdi_state.copy_policy,
		      req->vdi_state.block_size_shift, req->vdi_state.old_vid);

	return SD_RES_SUCCESS;
}

static int cluster_notify_vdi_del(const struct sd_req *req, struct sd_rsp *rsp,
				  void *data, const struct sd_node *sender)
{
	uint32_t vid = *(uint32_t *)data;

	return objlist_cache_cleanup(vid);
}

static int cluster_delete_cache(const struct sd_req *req, struct sd_rsp *rsp,
				void *data, const struct sd_node *sender)
{
	uint32_t vid = oid_to_vid(req->obj.oid);

	if (sys->enable_object_cache)
		object_cache_delete(vid);

	return SD_RES_SUCCESS;
}

static int cluster_recovery_completion(const struct sd_req *req,
				       struct sd_rsp *rsp,
				       void *data, const struct sd_node *sender)
{
	static struct sd_node recovereds[SD_MAX_NODES], *node;
	static size_t nr_recovereds;
	static int latest_epoch;
	struct vnode_info *vnode_info;
	int i;
	uint32_t epoch = req->obj.tgt_epoch;

	node = (struct sd_node *)data;

	if (latest_epoch > epoch)
		return SD_RES_SUCCESS;

	if (latest_epoch < epoch) {
		sd_debug("new epoch %d", epoch);
		latest_epoch = epoch;
		nr_recovereds = 0;
	}

	recovereds[nr_recovereds++] = *node;
	xqsort(recovereds, nr_recovereds, node_cmp);

	sd_debug("%s is recovered at epoch %d", node_to_str(node), epoch);
	for (i = 0; i < nr_recovereds; i++)
		sd_debug("[%x] %s", i, node_to_str(recovereds + i));

	if (sys->cinfo.epoch != latest_epoch)
		return SD_RES_SUCCESS;

	vnode_info = get_vnode_info();

	if (vnode_info->nr_nodes == nr_recovereds) {
		for (i = 0; i < nr_recovereds; ++i) {
			if (!rb_search(&vnode_info->nroot, &recovereds[i],
				       rb, node_cmp))
				break;
		}
		if (i == nr_recovereds) {
			sd_notice("all nodes are recovered, epoch %d", epoch);
			last_gathered_epoch = epoch;
			/* sd_store can be NULL if this node is a gateway */
			if (vnode_info->nr_zones >= ec_max_data_strip &&
			    sd_store && sd_store->cleanup)
				sd_store->cleanup();
		}
	}

	put_vnode_info(vnode_info);

	return SD_RES_SUCCESS;
}

static int cluster_alter_cluster_copy(const struct sd_req *req,
				      struct sd_rsp *rsp, void *data,
				      const struct sd_node *sender)
{
	if (req->cluster.copy_policy != 0)
		return SD_RES_INVALID_PARMS;

	sys->cinfo.nr_copies = req->cluster.copies;
	return set_cluster_config(&sys->cinfo);
}

static int cluster_alter_vdi_copy(const struct sd_req *req, struct sd_rsp *rsp,
				  void *data, const struct sd_node *sender)
{
	if (req->cluster.copy_policy != 0)
		return SD_RES_INVALID_PARMS;

	uint32_t vid = req->vdi_state.new_vid;
	int nr_copies = req->vdi_state.copies;
	uint32_t block_size_shift = req->vdi_state.block_size_shift;
	struct vnode_info *vinfo;

	add_vdi_state(vid, nr_copies, false, 0, block_size_shift, 0);

	vinfo = get_vnode_info();
	start_recovery(vinfo, vinfo, false, false);
	put_vnode_info(vinfo);

	return SD_RES_SUCCESS;
}

static bool node_size_varied(void)
{
	uint64_t new, used, old = sys->this_node.space;
	double diff;

	if (sys->gateway_only)
		return false;

	new = md_get_size(&used);
	/* If !old, it is forced-out-gateway. Not supported by current node */
	if (!old) {
		if (new)
			return true;
		else
			return false;
	}

	diff = new > old ? (double)(new - old) : (double)(old - new);
	sd_debug("new %"PRIu64 ", old %"PRIu64", ratio %f", new, old,
		 diff / (double)old);
	if (diff / (double)old < 0.01)
		return false;

	sys->this_node.space = new;
	set_node_space(new);

	return true;
}

static int cluster_reweight(const struct sd_req *req, struct sd_rsp *rsp,
			    void *data, const struct sd_node *sender)
{
	if (node_size_varied())
		return sys->cdrv->update_node(&sys->this_node);

	return SD_RES_SUCCESS;
}

static int local_md_info(struct request *request)
{
	struct sd_rsp *rsp = &request->rp;

	sd_assert(request->rq.data_length == sizeof(struct sd_md_info));
	rsp->data_length = md_get_info((struct sd_md_info *)request->data);

	return rsp->data_length ? SD_RES_SUCCESS : SD_RES_UNKNOWN;
}

static int local_md_plug(const struct sd_req *req, struct sd_rsp *rsp,
			 void *data, const struct sd_node *sender)
{
	char *disks = (char *)data;

	return md_plug_disks(disks);
}

static int local_md_unplug(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data, const struct sd_node *sender)
{
	char *disks = (char *)data;

	return md_unplug_disks(disks);
}

static int local_get_hash(struct request *request)
{
	struct sd_req *req = &request->rq;
	struct sd_rsp *rsp = &request->rp;

	if (!sd_store->get_hash)
		return SD_RES_NO_SUPPORT;

	return sd_store->get_hash(req->obj.oid, req->obj.tgt_epoch,
				  rsp->hash.digest);
}

static int local_get_cache_info(struct request *request)
{
	struct sd_rsp *rsp = &request->rp;

	sd_assert(request->rq.data_length == sizeof(struct object_cache_info));
	rsp->data_length = object_cache_get_info((struct object_cache_info *)
						 request->data);

	return SD_RES_SUCCESS;
}

static int local_cache_purge(struct request *req)
{
	const struct sd_req *hdr = &req->rq;
	uint32_t vid = oid_to_vid(req->rq.obj.oid);

	if (hdr->flags == SD_FLAG_CMD_WRITE) {
		object_cache_delete(vid);
		goto out;
	}
	object_cache_format();
out:
	return SD_RES_SUCCESS;
}

static int local_sd_stat(const struct sd_req *req, struct sd_rsp *rsp,
			 void *data, const struct sd_node *sender)
{
	memcpy(data, &sys->stat, sizeof(struct sd_stat));
	rsp->data_length = sizeof(struct sd_stat);
	return SD_RES_SUCCESS;
}

/* Return SD_RES_INVALID_PARMS to ask client not to send flush req again */
static int local_flush_vdi(struct request *req)
{
	int ret = SD_RES_INVALID_PARMS;

	if (sys->enable_object_cache) {
		uint32_t vid = oid_to_vid(req->rq.obj.oid);
		ret = object_cache_flush_vdi(vid);
	}

	return ret;
}

static int local_discard_obj(struct request *req)
{
	uint64_t oid = req->rq.obj.oid;
	uint32_t vid = oid_to_vid(oid), tmp_vid;
	int ret, idx = data_oid_to_idx(oid);
	struct sd_inode *inode = xmalloc(sizeof(struct sd_inode));

	sd_debug("%"PRIx64, oid);
	ret = sd_read_object(vid_to_vdi_oid(vid), (char *)inode,
			     sizeof(struct sd_inode), 0);
	if (ret != SD_RES_SUCCESS)
		goto out;

	tmp_vid = sd_inode_get_vid(inode, idx);
	/* if vid in idx is not exist, we don't need to remove it */
	if (tmp_vid) {
		sd_inode_set_vid(inode, idx, 0);
		ret = sd_inode_write_vid(inode, idx, vid, 0, 0, false, false);
		if (ret != SD_RES_SUCCESS)
			goto out;
		if (sd_remove_object(oid) != SD_RES_SUCCESS)
			sd_err("failed to remove %"PRIx64, oid);
	}
	/*
	 * Return success even if sd_remove_object fails because we have updated
	 * inode successfully.
	 */
out:
	free(inode);
	return ret;
}

static int local_flush_and_del(struct request *req)
{
	if (!sys->enable_object_cache)
		return SD_RES_SUCCESS;
	return object_cache_flush_and_del(req);
}

static int local_trace_enable(const struct sd_req *req, struct sd_rsp *rsp,
			      void *data, const struct sd_node *sender)
{
	return trace_enable(data);
}

static int local_trace_disable(const struct sd_req *req, struct sd_rsp *rsp,
			       void *data, const struct sd_node *sender)
{
	return trace_disable(data);
}

static int local_trace_status(const struct sd_req *req, struct sd_rsp *rsp,
			      void *data, const struct sd_node *sender)
{
	rsp->data_length = trace_status(data);

	return SD_RES_SUCCESS;
}

static int local_trace_read_buf(struct request *request)
{
	struct sd_req *req = &request->rq;
	struct sd_rsp *rsp = &request->rp;
	int ret;

	ret = trace_buffer_pop(request->data, req->data_length);
	if (ret == -1)
		return SD_RES_AGAIN;

	rsp->data_length = ret;
	sd_debug("%u", rsp->data_length);
	return SD_RES_SUCCESS;
}

static int local_kill_node(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data, const struct sd_node *sender)
{
	sys->cinfo.status = SD_STATUS_KILLED;
	unregister_listening_fds();

	return SD_RES_SUCCESS;
}

static int peer_remove_obj(struct request *req)
{
	uint64_t oid = req->rq.obj.oid;
	uint8_t ec_index = req->rq.obj.ec_index;

	objlist_cache_remove(oid);

	return sd_store->remove_object(oid, ec_index);
}

int peer_read_obj(struct request *req)
{
	struct sd_req *hdr = &req->rq;
	struct sd_rsp *rsp = &req->rp;
	int ret;
	uint32_t epoch = hdr->epoch;
	struct siocb iocb;

	if (sys->gateway_only)
		return SD_RES_NO_OBJ;

	memset(&iocb, 0, sizeof(iocb));
	iocb.epoch = epoch;
	iocb.buf = req->data;
	iocb.length = hdr->data_length;
	iocb.offset = hdr->obj.offset;
	iocb.ec_index = hdr->obj.ec_index;
	iocb.copy_policy = hdr->obj.copy_policy;
	iocb.wildcard = !!(hdr->flags & SD_FLAG_CMD_WILDCARD);
	ret = sd_store->read(hdr->obj.oid, &iocb);
	if (ret != SD_RES_SUCCESS)
		goto out;

	rsp->data_length = hdr->data_length;
out:
	return ret;
}

static int peer_write_obj(struct request *req)
{
	struct sd_req *hdr = &req->rq;
	struct siocb iocb = { };
	uint64_t oid = hdr->obj.oid;

	iocb.epoch = hdr->epoch;
	iocb.buf = req->data;
	iocb.length = hdr->data_length;
	iocb.offset = hdr->obj.offset;
	iocb.ec_index = hdr->obj.ec_index;
	iocb.copy_policy = hdr->obj.copy_policy;

	return sd_store->write(oid, &iocb);
}

static int peer_create_and_write_obj(struct request *req)
{
	struct sd_req *hdr = &req->rq;
	struct siocb iocb = { };

	iocb.epoch = hdr->epoch;
	iocb.buf = req->data;
	iocb.length = hdr->data_length;
	iocb.ec_index = hdr->obj.ec_index;
	iocb.copy_policy = hdr->obj.copy_policy;
	iocb.offset = hdr->obj.offset;

	return sd_store->create_and_write(hdr->obj.oid, &iocb);
}

static int local_get_loglevel(struct request *req)
{
	int32_t current_level;

	current_level = get_loglevel();
	memcpy(req->data, &current_level, sizeof(current_level));
	req->rp.data_length = sizeof(current_level);

	sd_info("returning log level: %u", current_level);

	return SD_RES_SUCCESS;
}

static int local_set_loglevel(struct request *req)
{
	int32_t new_level = 0;

	memcpy(&new_level, req->data, sizeof(int32_t));
	if (!(LOG_EMERG <= new_level && new_level <= LOG_DEBUG)) {
		sd_err("invalid log level: %d", new_level);
		return SD_RES_INVALID_PARMS;
	}

	set_loglevel(new_level);

	return SD_RES_SUCCESS;
}

static int local_oid_exist(struct request *req)
{
	uint64_t oid = req->rq.obj.oid;
	uint8_t ec_index = local_ec_index(req->vinfo, oid);

	if (sys->this_node.nr_vnodes == 0)
		return SD_RES_NO_OBJ;

	if (is_erasure_oid(oid) && ec_index == SD_MAX_COPIES)
		return SD_RES_NO_OBJ;

	if (sd_store->exist(oid, ec_index))
		return SD_RES_SUCCESS;
	return SD_RES_NO_OBJ;
}

static int local_oids_exist(const struct sd_req *req, struct sd_rsp *rsp,
			    void *data, const struct sd_node *sender)
{
	struct request *r = container_of(req, struct request, rq);
	uint64_t *oids = (uint64_t *) data;
	uint8_t ec_index;
	int i, j, n = req->data_length / sizeof(uint64_t);

	for (i = 0, j = 0; i < n; i++) {
		ec_index = local_ec_index(r->vinfo, oids[i]);
		if (is_erasure_oid(oids[i]) && ec_index == SD_MAX_COPIES)
			oids[j++] = oids[i];
		else if (!sd_store->exist(oids[i], ec_index))
			oids[j++] = oids[i];
	}

	if (j > 0) {
		rsp->data_length = sizeof(uint64_t) * j;
		return SD_RES_NO_OBJ;
	}

	return SD_RES_SUCCESS;
}

static int local_cluster_info(const struct sd_req *req, struct sd_rsp *rsp,
			      void *data, const struct sd_node *sender)
{
	memcpy(data, &sys->cinfo, sizeof(sys->cinfo));
	rsp->data_length = sizeof(sys->cinfo);
	return SD_RES_SUCCESS;
}

#ifdef HAVE_NFS

static int local_nfs_create(struct request *req)
{
	return nfs_create(req->data);
}

static int local_nfs_delete(struct request *req)
{
	return nfs_delete(req->data);
}

#else

static inline int local_nfs_create(struct request *req)
{
	return 0;
}

static inline int local_nfs_delete(struct request *req)
{
	return 0;
}

#endif

static bool is_zero_ledger(uint32_t *ledger)
{
	for (int i = 0; i < SD_LEDGER_OBJ_SIZE / sizeof(uint32_t); i++)
		if (ledger[i])
			return false;

	return true;
}

int peer_decref_object(struct request *req)
{
	struct sd_req *hdr = &req->rq;
	int ret;
	uint32_t epoch = hdr->epoch;
	uint64_t ledger_oid = hdr->ref.oid;
	uint64_t data_oid = ledger_oid_to_data_oid(ledger_oid);
	uint32_t generation = hdr->ref.generation;
	uint32_t count = hdr->ref.count;
	uint32_t *ledger = NULL;
	bool exist = false, locked;
	static struct sd_mutex lock = SD_MUTEX_INITIALIZER;

	sd_debug("%" PRIx64 ", %" PRIu32 ", %" PRIu32 ", %" PRIu32,
		 ledger_oid, epoch, generation, count);

	ledger = xvalloc(SD_LEDGER_OBJ_SIZE);
	memset(ledger, 0, SD_LEDGER_OBJ_SIZE);

	struct siocb iocb = {
		.epoch = epoch,
		.buf = ledger,
		.length = SD_LEDGER_OBJ_SIZE,
	};

	/* we don't allow concurrent updates to the ledger objects */
	sd_mutex_lock(&lock);
	locked = true;

	ret = sd_store->read(ledger_oid, &iocb);
	switch (ret) {
	case SD_RES_SUCCESS:
		exist = true;
		break;
	case SD_RES_NO_OBJ:
		/* initialize ledger */
		ledger[0] = 1;
		break;
	default:
		sd_err("failed to read ledger object %"PRIx64": %s",
		       ledger_oid, sd_strerror(ret));
		goto out;
	}

	ledger[generation]--;
	ledger[generation + 1] += count;

	if (is_zero_ledger(ledger)) {
		struct sd_node *nodes[SD_MAX_COPIES];
		int nr_copies;

		nr_copies = get_obj_copy_number(ledger_oid,
						req->vinfo->nr_zones);
		memset(nodes, 0, sizeof(nodes));

		/* reclaim object */
		if (exist) {
			ret = sd_store->remove_object(ledger_oid, -1);
			if (ret != SD_RES_SUCCESS) {
				sd_err("error %s", sd_strerror(ret));
				goto out;
			}
		}
		sd_mutex_unlock(&lock);
		locked = false;

		oid_to_nodes(ledger_oid, &req->vinfo->vroot, nr_copies,
			     (const struct sd_node **)nodes);

		if (!node_cmp(&sys->this_node, nodes[0])) {
			/* only first one node needs to remove the object */
			ret = sd_remove_object(data_oid);
			if (ret != SD_RES_SUCCESS) {
				sd_err("error %s", sd_strerror(ret));
				goto out;
			}
		}
	} else {
		/* update ledger */
		if (exist)
			ret = sd_store->write(ledger_oid, &iocb);
		else
			ret = sd_store->create_and_write(ledger_oid, &iocb);

		if (ret != SD_RES_SUCCESS)
			sd_err("failed to update ledger object %"PRIx64": %s",
			       ledger_oid, sd_strerror(ret));
	}
out:
	if (locked)
		sd_mutex_unlock(&lock);
	free(ledger);

	return ret;
}

static int local_prevent_inode_update(const struct sd_req *req,
				      struct sd_rsp *rsp,
				      void *data, const struct sd_node *sender)
{
	/* FIXME: change type of process_main() */
	struct request *rq = container_of(req, struct request, rq);

	sd_debug("preventing inode update request, ongoing inode update"
		 " requests: %d", sys->nr_ongoing_inode_update_request);

	sys->nr_prevent_inode_update++;

	if (sys->nr_ongoing_inode_update_request) {
		list_add_tail(&rq->pending_prevent_inode_update_reqs,
			      &sys->pending_prevent_inode_update_request_queue);
		get_request(rq);
	}

	return SD_RES_SUCCESS;
}

static int local_allow_inode_update(const struct sd_req *req,
				    struct sd_rsp *rsp,
				    void *data, const struct sd_node *sender)
{
	struct request *rq;

	sd_debug("allowing inode update request");
	sys->nr_prevent_inode_update--;

	if (sys->nr_prevent_inode_update)
		return SD_RES_SUCCESS;

	list_for_each_entry(rq, &sys->prevented_inode_update_request_queue,
			    prevented_inode_update_request_list) {
		list_del(&rq->prevented_inode_update_request_list);
		requeue_request(rq);
	}

	return SD_RES_SUCCESS;
}

static int local_repair_replica(struct request *req)
{
	int ret;
	struct node_id nid;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	struct siocb iocb = { 0 };
	uint64_t oid = req->rq.forw.oid;
	size_t rlen = get_store_objsize(oid);
	void *buf = xvalloc(rlen);

	sd_init_req(&hdr, SD_OP_READ_PEER);
	hdr.epoch = req->rq.epoch;
	hdr.data_length = rlen;
	hdr.obj.oid = oid;

	memcpy(nid.addr, req->rq.forw.addr, sizeof(nid.addr));
	nid.port = req->rq.forw.port;
	ret = sheep_exec_req(&nid, &hdr, buf);
	if (ret == SD_RES_SUCCESS) {
		sd_debug("read object %016"PRIx64" from %s successfully, "
				"try saving to local", oid,
				addr_to_str(nid.addr, nid.port));
		iocb.epoch = req->rq.epoch;
		iocb.length = rsp->data_length;
		iocb.offset = rsp->obj.offset;
		iocb.buf = buf;
		ret = sd_store->create_and_write(oid, &iocb);
		if (ret != SD_RES_SUCCESS)
			sd_err("failed to write object %016"PRIx64
					" to local", oid);
	} else {
		sd_err("failed to read object %016"PRIx64
				" from %s: %s", oid,
				addr_to_str(nid.addr, nid.port),
				sd_strerror(ret));
	}

	free(buf);
	return ret;
}

static int cluster_lock_vdi_work(struct request *req)
{
	if (sys->node_status == SD_NODE_STATUS_COLLECTING_CINFO) {
		/*
		 * this node is collecting vdi locking status, not ready for
		 * allowing lock by itself
		 */
		sd_err("This node is not ready for vdi locking, try later");
		return SD_RES_COLLECTING_CINFO;
	}

	return cluster_get_vdi_info(req);
}

static int cluster_lock_vdi_main(const struct sd_req *req, struct sd_rsp *rsp,
				 void *data, const struct sd_node *sender)
{
	uint32_t vid = rsp->vdi.vdi_id;

	if (sys->node_status == SD_NODE_STATUS_COLLECTING_CINFO) {
		sd_debug("logging vdi unlock information for later replay");
		log_vdi_op_lock(vid, &sender->nid, req->vdi.type);
		return SD_RES_SUCCESS;
	}

	if (!(sys->cinfo.flags & SD_CLUSTER_FLAG_USE_LOCK)) {
		sd_debug("vdi lock is disabled");
		return SD_RES_SUCCESS;
	}

	sd_info("node: %s is locking VDI (type: %s): %"PRIx32,
		node_to_str(sender),
		req->vdi.type == LOCK_TYPE_NORMAL ? "normal" : "shared", vid);

	if (!vdi_lock(vid, &sender->nid, req->vdi.type)) {
		sd_err("locking %"PRIx32 "failed", vid);
		return SD_RES_VDI_LOCKED;
	}

	return SD_RES_SUCCESS;
}

static int cluster_release_vdi_main(const struct sd_req *req,
				    struct sd_rsp *rsp, void *data,
				    const struct sd_node *sender)
{
	uint32_t vid = req->vdi.base_vdi_id;

	if (sys->node_status == SD_NODE_STATUS_COLLECTING_CINFO) {
		sd_debug("logging vdi lock information for later replay");
		log_vdi_op_unlock(vid, &sender->nid, req->vdi.type);
		return SD_RES_SUCCESS;
	}

	if (!(sys->cinfo.flags & SD_CLUSTER_FLAG_USE_LOCK)) {
		sd_debug("vdi lock is disabled");
		return SD_RES_SUCCESS;
	}

	sd_info("node: %s is unlocking VDI (type: %s): %"PRIx32, node_to_str(sender),
		req->vdi.type == LOCK_TYPE_NORMAL ? "normal" : "shared", vid);

	vdi_unlock(vid, &sender->nid, req->vdi.type);

	return SD_RES_SUCCESS;
}

static int local_vdi_state_checkpoint_ctl(const struct sd_req *req,
					struct sd_rsp *rsp, void *data,
					const struct sd_node *sender)
{
	bool get = !!req->vdi_state_checkpoint.get;
	int epoch = req->vdi_state_checkpoint.tgt_epoch;
	uint32_t vid = req->vdi_state_checkpoint.vid;
	int ret;

	sd_info("%s vdi state checkpoint at epoch %d",
		get ? "getting" : "freeing", epoch);

	if (get) {
		sd_debug("target VID: %"PRIx32, vid);

		ret = get_vdi_state_checkpoint(epoch, vid, data);
		if (ret == SD_RES_SUCCESS)
			rsp->data_length = sizeof(struct vdi_state);
		else {
			sd_info("failed to get vdi state checkpoint: %s",
			       sd_strerror(ret));

			return ret;
		}
	} else
		free_vdi_state_checkpoint(epoch);

	return SD_RES_SUCCESS;
}

static int local_get_cluster_default(const struct sd_req *req,
				     struct sd_rsp *rsp,
				     void *data, const struct sd_node *sender)
{
	rsp->cluster_default.nr_copies = sys->cinfo.nr_copies;
	rsp->cluster_default.copy_policy = sys->cinfo.copy_policy;
	rsp->cluster_default.block_size_shift = sys->cinfo.block_size_shift;

	return SD_RES_SUCCESS;
}

static int cluster_inode_coherence(const struct sd_req *req,
				   struct sd_rsp *rsp, void *data,
				   const struct sd_node *sender)
{
	sd_debug("inode coherence: %s %"PRIx32" from %s",
		 req->inode_coherence.validate ? "validate" : "invalidate",
		 req->inode_coherence.vid, node_to_str(sender));

	return inode_coherence_update(req->inode_coherence.vid,
			       !!req->inode_coherence.validate, &sender->nid);
}

static int local_get_recovery(struct request *req)
{
	struct recovery_throttling rthrottling;

	rthrottling = get_recovery();
	memcpy(req->data, &rthrottling, sizeof(rthrottling));
	req->rp.data_length = sizeof(rthrottling);

	return SD_RES_SUCCESS;
}

static int local_set_recovery(struct request *req)
{
	struct recovery_throttling *rthrottling;

	rthrottling = xmalloc(sizeof(struct recovery_throttling));

	memcpy(rthrottling, req->data, sizeof(struct recovery_throttling));
	set_recovery(rthrottling);

	free(rthrottling);
	return SD_RES_SUCCESS;
}

static int local_get_vnodes(struct request *req)
{
	int *nr_vnodes;

	nr_vnodes = req->data;
	req->rp.data_length = sizeof(*nr_vnodes);
	*nr_vnodes = sys->this_node.nr_vnodes;

	return SD_RES_SUCCESS;
}

static int local_set_vnodes(const struct sd_req *req,
				struct sd_rsp *rsp, void *data,
				const struct sd_node *sender)
{
	int ret;
	int *nr_vnodes = (int *)data;

	if (sys->gateway_only) {
		sd_err("failed to set vnodes, cause operating in gateway mode.");
		return SD_RES_GATEWAY_MODE;
	}
	if (is_cluster_autovnodes(&sys->cinfo)) {
		sd_err("failed to set vnodes, cause operating in auto vnodes strategy.");
		return SD_RES_INVALID_VNODES_STRATEGY;
	}

	if (1 > *nr_vnodes || *nr_vnodes > UINT16_MAX) {
		sd_err("invalid vnodes: %d", *nr_vnodes);
		return SD_RES_INVALID_PARMS;
	}

	sys->this_node.nr_vnodes = *nr_vnodes;

	ret = sys->cdrv->update_node(&sys->this_node);

	return ret;
}

static struct sd_op_template sd_ops[] = {

	/* cluster operations */
	[SD_OP_NEW_VDI] = {
		.name = "NEW_VDI",
		.type = SD_OP_TYPE_CLUSTER,
		.is_admin_op = true,
		.process_work = cluster_new_vdi,
		.process_main = post_cluster_new_vdi,
	},

	[SD_OP_DEL_VDI] = {
		.name = "DEL_VDI",
		.type = SD_OP_TYPE_CLUSTER,
		.is_admin_op = true,
		.process_work = cluster_del_vdi,
		.process_main = post_cluster_del_vdi,
	},

	[SD_OP_MAKE_FS] = {
		.name = "MAKE_FS",
		.type = SD_OP_TYPE_CLUSTER,
		.force = true,
		.is_admin_op = true,
		.process_main = cluster_make_fs,
	},

	[SD_OP_SHUTDOWN] = {
		.name = "SHUTDOWN",
		.type = SD_OP_TYPE_CLUSTER,
		.force = true,
		.is_admin_op = true,
		.process_main = cluster_shutdown,
	},

	[SD_OP_GET_VDI_ATTR] = {
		.name = "GET_VDI_ATTR",
		.type = SD_OP_TYPE_CLUSTER,
		.process_work = cluster_get_vdi_attr,
	},

	[SD_OP_FORCE_RECOVER] = {
		.name = "FORCE_RECOVER",
		.type = SD_OP_TYPE_CLUSTER,
		.force = true,
		.is_admin_op = true,
		.process_work = cluster_force_recover_work,
		.process_main = cluster_force_recover_main,
	},

	[SD_OP_CLEANUP] = {
		.name = "CLEANUP",
		.type = SD_OP_TYPE_CLUSTER,
		.force = true,
		.process_main = cluster_cleanup,
	},

	[SD_OP_NOTIFY_VDI_DEL] = {
		.name = "NOTIFY_VDI_DEL",
		.type = SD_OP_TYPE_CLUSTER,
		.force = true,
		.process_main = cluster_notify_vdi_del,
	},

	[SD_OP_NOTIFY_VDI_ADD] = {
		.name = "NOTIFY_VDI_ADD",
		.type = SD_OP_TYPE_CLUSTER,
		.force = true,
		.process_main = cluster_notify_vdi_add,
	},

	[SD_OP_DELETE_CACHE] = {
		.name = "DELETE_CACHE",
		.type = SD_OP_TYPE_CLUSTER,
		.process_main = cluster_delete_cache,
	},

	[SD_OP_COMPLETE_RECOVERY] = {
		.name = "COMPLETE_RECOVERY",
		.type = SD_OP_TYPE_CLUSTER,
		.force = true,
		.process_main = cluster_recovery_completion,
	},

	[SD_OP_GET_VDI_INFO] = {
		.name = "GET_VDI_INFO",
		.type = SD_OP_TYPE_CLUSTER,
		.process_work = cluster_get_vdi_info,
	},

	[SD_OP_LOCK_VDI] = {
		.name = "LOCK_VDI",
		.type = SD_OP_TYPE_CLUSTER,
		.process_work = cluster_lock_vdi_work,
		.process_main = cluster_lock_vdi_main,
	},

	[SD_OP_RELEASE_VDI] = {
		.name = "RELEASE_VDI",
		.type = SD_OP_TYPE_CLUSTER,
		.process_work = local_release_vdi,
		.process_main = cluster_release_vdi_main,
	},

	[SD_OP_REWEIGHT] = {
		.name = "REWEIGHT",
		.type = SD_OP_TYPE_CLUSTER,
		.is_admin_op = true,
		.process_main = cluster_reweight,
	},

	[SD_OP_ENABLE_RECOVER] = {
		.name = "ENABLE_RECOVER",
		.type = SD_OP_TYPE_CLUSTER,
		.is_admin_op = true,
		.process_main = cluster_enable_recover,
	},

	[SD_OP_DISABLE_RECOVER] = {
		.name = "DISABLE_RECOVER",
		.type = SD_OP_TYPE_CLUSTER,
		.is_admin_op = true,
		.process_main = cluster_disable_recover,
	},

	[SD_OP_ALTER_CLUSTER_COPY] = {
		.name = "ALTER_CLUSTER_COPY",
		.type = SD_OP_TYPE_CLUSTER,
		.is_admin_op = true,
		.process_main = cluster_alter_cluster_copy,
	},

	[SD_OP_ALTER_VDI_COPY] = {
		.name = "ALTER_VDI_COPY",
		.type = SD_OP_TYPE_CLUSTER,
		.is_admin_op = true,
		.process_main = cluster_alter_vdi_copy,
	},

	[SD_OP_INODE_COHERENCE] = {
		.name = "INODE_COHERENCE",
		.type = SD_OP_TYPE_CLUSTER,
		.process_main = cluster_inode_coherence,
	},

	/* local operations */

	[SD_OP_GET_STORE_LIST] = {
		.name = "GET_STORE_LIST",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_work = local_get_store_list,
	},

	[SD_OP_READ_VDIS] = {
		.name = "READ_VDIS",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_main = local_read_vdis,
	},

	[SD_OP_READ_DEL_VDIS] = {
		.name = "READ_DEL_VDIS",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_main = local_read_del_vdis,
	},

	[SD_OP_GET_VDI_COPIES] = {
		.name = "GET_VDI_COPIES",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_main = local_get_vdi_copies,
	},

	[SD_OP_GET_NODE_LIST] = {
		.name = "GET_NODE_LIST",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_main = local_get_node_list,
	},

	[SD_OP_STAT_SHEEP] = {
		.name = "STAT_SHEEP",
		.type = SD_OP_TYPE_LOCAL,
		.process_work = local_stat_sheep,
	},

	[SD_OP_STAT_RECOVERY] = {
		.name = "STAT_RECOVERY",
		.type = SD_OP_TYPE_LOCAL,
		.process_main = local_stat_recovery,
	},

	[SD_OP_STAT_CLUSTER] = {
		.name = "STAT_CLUSTER",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_work = local_stat_cluster,
	},

	[SD_OP_GET_OBJ_LIST] = {
		.name = "GET_OBJ_LIST",
		.type = SD_OP_TYPE_LOCAL,
		.process_work = local_get_obj_list,
	},

	[SD_OP_GET_EPOCH] = {
		.name = "GET_EPOCH",
		.type = SD_OP_TYPE_LOCAL,
		.process_work = local_get_epoch,
	},

	[SD_OP_FLUSH_VDI] = {
		.name = "FLUSH_VDI",
		.type = SD_OP_TYPE_LOCAL,
		.process_work = local_flush_vdi,
	},

	[SD_OP_DISCARD_OBJ] = {
		.name = "DISCARD_OBJ",
		.type = SD_OP_TYPE_LOCAL,
		.process_work = local_discard_obj,
	},

	[SD_OP_FLUSH_DEL_CACHE] = {
		.name = "DEL_CACHE",
		.type = SD_OP_TYPE_LOCAL,
		.process_work = local_flush_and_del,
	},

	[SD_OP_TRACE_ENABLE] = {
		.name = "TRACE_ENABLE",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_main = local_trace_enable,
	},

	[SD_OP_TRACE_DISABLE] = {
		.name = "TRACE_DISABLE",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_main = local_trace_disable,
	},

	[SD_OP_TRACE_STATUS] = {
		.name = "TRACE_STATUS",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_main = local_trace_status,
	},

	[SD_OP_TRACE_READ_BUF] = {
		.name = "TRACE_READ_BUF",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_work = local_trace_read_buf,
	},

	[SD_OP_KILL_NODE] = {
		.name = "KILL_NODE",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.is_admin_op = true,
		.process_main = local_kill_node,
	},

	[SD_OP_MD_INFO] = {
		.name = "MD_INFO",
		.type = SD_OP_TYPE_LOCAL,
		.process_work = local_md_info,
	},

	[SD_OP_MD_PLUG] = {
		.name = "MD_PLUG_DISKS",
		.type = SD_OP_TYPE_LOCAL,
		.is_admin_op = true,
		.process_main = local_md_plug,
	},

	[SD_OP_MD_UNPLUG] = {
		.name = "MD_UNPLUG_DISKS",
		.type = SD_OP_TYPE_LOCAL,
		.is_admin_op = true,
		.process_main = local_md_unplug,
	},

	[SD_OP_GET_HASH] = {
		.name = "GET_HASH",
		.type = SD_OP_TYPE_LOCAL,
		.process_work = local_get_hash,
	},

	[SD_OP_GET_CACHE_INFO] = {
		.name = "GET_CACHE_INFO",
		.type = SD_OP_TYPE_LOCAL,
		.process_work = local_get_cache_info,
	},

	[SD_OP_CACHE_PURGE] = {
		.name = "CACHE_PURGE",
		.type = SD_OP_TYPE_LOCAL,
		.process_work = local_cache_purge,
	},

	[SD_OP_STAT] = {
		.name = "STAT",
		.type = SD_OP_TYPE_LOCAL,
		.process_main = local_sd_stat,
	},

	[SD_OP_GET_LOGLEVEL] = {
		.name = "GET_LOGLEVEL",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_work = local_get_loglevel,
	},

	[SD_OP_SET_LOGLEVEL] = {
		.name = "SET_LOGLEVEL",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_work = local_set_loglevel,
	},

	[SD_OP_EXIST] =  {
		.name = "EXIST",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_work = local_oid_exist,
	},

	[SD_OP_OIDS_EXIST] =  {
		.name = "OIDS_EXIST",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_main = local_oids_exist,
	},

	[SD_OP_CLUSTER_INFO] = {
		.name = "CLUSTER INFO",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_main = local_cluster_info,
	},

#ifdef HAVE_NFS
	[SD_OP_NFS_CREATE] = {
		.name = "NFS_CREATE",
		.type = SD_OP_TYPE_LOCAL,
		.force = false,
		.process_work = local_nfs_create,
	},

	[SD_OP_NFS_DELETE] = {
		.name = "NFS_DELETE",
		.type = SD_OP_TYPE_LOCAL,
		.force = false,
		.process_work = local_nfs_delete,
	},
#endif

	[SD_OP_PREVENT_INODE_UPDATE] = {
		.name = "PREVENT_INODE_UPDATE",
		.type = SD_OP_TYPE_LOCAL,
		.process_main = local_prevent_inode_update,
	},

	[SD_OP_ALLOW_INODE_UPDATE] = {
		.name = "ALLOW_INODE_UPDATE",
		.type = SD_OP_TYPE_LOCAL,
		.process_main = local_allow_inode_update,
	},

	[SD_OP_REPAIR_REPLICA] = {
		.name = "REPAIR_REPLICA",
		.type = SD_OP_TYPE_LOCAL,
		.process_work = local_repair_replica,
	},

	[SD_OP_VDI_STATE_CHECKPOINT_CTL] = {
		.name = "VDI_STATE_CHECKPOINT_CTL",
		.type = SD_OP_TYPE_LOCAL,
		.process_main = local_vdi_state_checkpoint_ctl,
	},

	[SD_OP_GET_CLUSTER_DEFAULT] = {
		.name = "GET_CLUSTER_DEFAULT",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_main = local_get_cluster_default,
	},

	[SD_OP_GET_VNODES] = {
		.name = "GET_VNODES",
		.type = SD_OP_TYPE_LOCAL,
		.process_work = local_get_vnodes,
	},

	[SD_OP_SET_VNODES] = {
		.name = "SET_VNODES",
		.type = SD_OP_TYPE_LOCAL,
		.process_main = local_set_vnodes,
	},

	/* gateway I/O operations */
	[SD_OP_CREATE_AND_WRITE_OBJ] = {
		.name = "CREATE_AND_WRITE_OBJ",
		.type = SD_OP_TYPE_GATEWAY,
		.process_work = gateway_create_and_write_obj,
	},

	[SD_OP_READ_OBJ] = {
		.name = "READ_OBJ",
		.type = SD_OP_TYPE_GATEWAY,
		.process_work = gateway_read_obj,
	},

	[SD_OP_WRITE_OBJ] = {
		.name = "WRITE_OBJ",
		.type = SD_OP_TYPE_GATEWAY,
		.process_work = gateway_write_obj,
	},

	[SD_OP_REMOVE_OBJ] = {
		.name = "REMOVE_OBJ",
		.type = SD_OP_TYPE_GATEWAY,
		.process_work = gateway_remove_obj,
	},

	[SD_OP_DECREF_OBJ] = {
		.name = "DECREF_OBJ",
		.type = SD_OP_TYPE_GATEWAY,
		.process_work = gateway_decref_object,
	},

	/* peer I/O operations */
	[SD_OP_CREATE_AND_WRITE_PEER] = {
		.name = "CREATE_AND_WRITE_PEER",
		.type = SD_OP_TYPE_PEER,
		.process_work = peer_create_and_write_obj,
	},

	[SD_OP_READ_PEER] = {
		.name = "READ_PEER",
		.type = SD_OP_TYPE_PEER,
		.process_work = peer_read_obj,
	},

	[SD_OP_WRITE_PEER] = {
		.name = "WRITE_PEER",
		.type = SD_OP_TYPE_PEER,
		.process_work = peer_write_obj,
	},

	[SD_OP_REMOVE_PEER] = {
		.name = "REMOVE_PEER",
		.type = SD_OP_TYPE_PEER,
		.process_work = peer_remove_obj,
	},

	[SD_OP_DECREF_PEER] = {
		.name = "DECREF_PEER",
		.type = SD_OP_TYPE_PEER,
		.process_work = peer_decref_object,
	},

	[SD_OP_GET_RECOVERY] = {
		.name = "GET_RECOVERY",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_work = local_get_recovery,
	},

	[SD_OP_SET_RECOVERY] = {
		.name = "SET_RECOVERY",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_work = local_set_recovery,
	},
};

const struct sd_op_template *get_sd_op(uint8_t opcode)
{
	if (sd_ops[opcode].type == 0)
		return NULL;

	return sd_ops + opcode;
}

const char *op_name(const struct sd_op_template *op)
{
	if (op == NULL)
		return "(invalid opcode)";

	return op->name;
}

bool is_cluster_op(const struct sd_op_template *op)
{
	return op != NULL && op->type == SD_OP_TYPE_CLUSTER;
}

bool is_local_op(const struct sd_op_template *op)
{
	return op != NULL && op->type == SD_OP_TYPE_LOCAL;
}

bool is_peer_op(const struct sd_op_template *op)
{
	return op != NULL && op->type == SD_OP_TYPE_PEER;
}

bool is_gateway_op(const struct sd_op_template *op)
{
	return op != NULL && op->type == SD_OP_TYPE_GATEWAY;
}

bool is_force_op(const struct sd_op_template *op)
{
	return op != NULL && op->force;
}

bool is_logging_op(const struct sd_op_template *op)
{
	return op != NULL && op->is_admin_op;
}

bool has_process_work(const struct sd_op_template *op)
{
	return op != NULL && !!op->process_work;
}

bool has_process_main(const struct sd_op_template *op)
{
	return op != NULL && !!op->process_main;
}

void do_process_work(struct work *work)
{
	struct request *req = container_of(work, struct request, work);
	int ret = SD_RES_SUCCESS;

	sd_debug("%x, %" PRIx64", %"PRIu32, req->rq.opcode, req->rq.obj.oid,
		 req->rq.epoch);

	if (req->op->process_work)
		ret = req->op->process_work(req);

	if (ret != SD_RES_SUCCESS) {
		sd_debug("failed: %x, %" PRIx64" , %u, %s", req->rq.opcode,
			 req->rq.obj.oid, req->rq.epoch, sd_strerror(ret));
	}

	req->rp.result = ret;
}

int do_process_main(const struct sd_op_template *op, const struct sd_req *req,
		    struct sd_rsp *rsp, void *data,
		    const struct sd_node *sender)
{
	return op->process_main(req, rsp, data, sender);
}

static int map_table[] = {
	[SD_OP_CREATE_AND_WRITE_OBJ] = SD_OP_CREATE_AND_WRITE_PEER,
	[SD_OP_READ_OBJ] = SD_OP_READ_PEER,
	[SD_OP_WRITE_OBJ] = SD_OP_WRITE_PEER,
	[SD_OP_REMOVE_OBJ] = SD_OP_REMOVE_PEER,
	[SD_OP_DECREF_OBJ] = SD_OP_DECREF_PEER,
};

int gateway_to_peer_opcode(int opcode)
{
	sd_assert(opcode < ARRAY_SIZE(map_table));
	return map_table[opcode];
}
