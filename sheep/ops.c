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
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>

#include "sheep_priv.h"
#include "strbuf.h"
#include "trace/trace.h"
#include "util.h"

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
	int (*process_main)(const struct sd_req *req, struct sd_rsp *rsp, void *data);
};

static int stat_sheep(uint64_t *store_size, uint64_t *store_free, uint32_t epoch)
{
	int ret;
	DIR *dir;
	struct dirent *d;
	uint64_t used = 0;
	struct stat s;
	char path[1024];
	struct strbuf store_dir = STRBUF_INIT;

	strbuf_addf(&store_dir, "%s", obj_path);
	dir = opendir(store_dir.buf);
	if (!dir) {
		ret = SD_RES_EIO;
		goto out;
	}

	while ((d = readdir(dir))) {
		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		snprintf(path, sizeof(path), "%s/%s", store_dir.buf, d->d_name);

		ret = stat(path, &s);
		if (ret)
			continue;

		used += s.st_size;
	}

	closedir(dir);
	ret = SD_RES_SUCCESS;

	*store_size = sys->disk_space;
	if (sys->gateway_only)
		*store_free = 0;
	else
		*store_free = sys->disk_space - used;
out:
	strbuf_release(&store_dir);
	return ret;
}

static int cluster_new_vdi(struct request *req)
{
	const struct sd_req *hdr = &req->rq;
	struct sd_rsp *rsp = &req->rp;
	uint32_t vid = 0;
	struct vdi_iocb iocb;
	int ret;

	iocb.name = req->data;
	iocb.data_len = hdr->data_length;
	iocb.size = hdr->vdi.vdi_size;
	iocb.base_vid = hdr->vdi.base_vdi_id;
	iocb.create_snapshot = !!hdr->vdi.snapid;
	iocb.nr_copies = hdr->vdi.copies;

	if (!iocb.nr_copies)
		iocb.nr_copies = sys->nr_copies;

	ret = add_vdi(&iocb, &vid);

	rsp->vdi.vdi_id = vid;
	rsp->vdi.copies = iocb.nr_copies;

	return ret;
}

static int post_cluster_new_vdi(const struct sd_req *req, struct sd_rsp *rsp,
				void *data)
{
	unsigned long nr = rsp->vdi.vdi_id;
	int ret = rsp->result;

	vprintf(SDOG_INFO, "done %d %ld\n", ret, nr);
	if (ret == SD_RES_SUCCESS) {
		set_bit(nr, sys->vdi_inuse);
		add_vdi_copy_number(nr, rsp->vdi.copies);
	}

	return ret;
}

static int cluster_del_vdi(struct request *req)
{
	const struct sd_req *hdr = &req->rq;
	struct sd_rsp *rsp = &req->rp;
	uint32_t vid = 0, nr_copies = sys->nr_copies;
	int ret;

	ret = del_vdi(req, req->data, hdr->data_length,
		      &vid, hdr->vdi.snapid, &nr_copies);

	rsp->vdi.vdi_id = vid;
	rsp->vdi.copies = nr_copies;

	return ret;
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
				void *data)
{
	unsigned long vid = rsp->vdi.vdi_id;
	struct cache_deletion_work *dw;
	int ret = rsp->result;

	if (!is_object_cache_enabled())
		return ret;

	dw = xzalloc(sizeof(*dw));
	dw->vid = vid;
	dw->work.fn = cache_delete_work;
	dw->work.done = cache_delete_done;

	queue_work(sys->deletion_wqueue, &dw->work);

	return ret;
}

static int cluster_get_vdi_info(struct request *req)
{
	const struct sd_req *hdr = &req->rq;
	struct sd_rsp *rsp = &req->rp;
	uint32_t vid = 0, nr_copies = sys->nr_copies;
	void *tag;
	int ret;

	if (hdr->data_length == SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN)
		tag = (char *)req->data + SD_MAX_VDI_LEN;
	else if (hdr->data_length == SD_MAX_VDI_LEN)
		tag = NULL;
	else
		return SD_RES_INVALID_PARMS;

	ret = lookup_vdi(req->data, tag, &vid,
			 hdr->vdi.snapid, &nr_copies, NULL);
	if (ret != SD_RES_SUCCESS)
		return ret;

	rsp->vdi.vdi_id = vid;
	rsp->vdi.copies = nr_copies;

	return ret;
}

static int remove_epoch(uint32_t epoch)
{
	int ret;
	char path[PATH_MAX];

	dprintf("remove epoch %"PRIu32"\n", epoch);
	snprintf(path, sizeof(path), "%s%08u", epoch_path, epoch);
	ret = unlink(path);
	if (ret && ret != -ENOENT) {
		eprintf("failed to remove %s: %s\n", path, strerror(-ret));
		return SD_RES_EIO;
	}

	snprintf(path, sizeof(path), "%s%08u/", jrnl_path, epoch);
	ret = rmdir_r(path);
	if (ret && ret != -ENOENT) {
		eprintf("failed to remove %s: %s\n", path, strerror(-ret));
		return SD_RES_EIO;
	}
	return 0;
}

static int cluster_make_fs(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data)
{
	const struct sd_so_req *hdr = (const struct sd_so_req *)req;
	int i, ret;
	uint32_t latest_epoch;
	uint64_t created_time;
	struct store_driver *driver;
	char *store_name = data;

	driver = find_store_driver(data);
	if (!driver)
		return SD_RES_NO_STORE;

	sd_store = driver;
	latest_epoch = get_latest_epoch();

	ret = sd_store->format();
	if (ret != SD_RES_SUCCESS)
		return ret;
	if (set_cluster_store(store_name) < 0)
		return SD_RES_EIO;

	ret = sd_store->init(obj_path);
	if (ret != SD_RES_SUCCESS)
		return ret;

	sys->nr_copies = hdr->copies;
	sys->flags = hdr->flags;
	if (!sys->nr_copies)
		sys->nr_copies = SD_DEFAULT_COPIES;

	created_time = hdr->ctime;
	set_cluster_ctime(created_time);
	set_cluster_copies(sys->nr_copies);
	set_cluster_flags(sys->flags);

	for (i = 1; i <= latest_epoch; i++)
		remove_epoch(i);

	memset(sys->vdi_inuse, 0, sizeof(sys->vdi_inuse));

	sys->epoch = 1;
	sys->recovered_epoch = 1;

	ret = log_current_epoch();
	if (ret)
		return SD_RES_EIO;

	if (have_enough_zones())
		sys->status = SD_STATUS_OK;
	else
		sys->status = SD_STATUS_HALT;

	return SD_RES_SUCCESS;
}

static int cluster_shutdown(const struct sd_req *req, struct sd_rsp *rsp,
			    void *data)
{
	sys->status = SD_STATUS_SHUTDOWN;
	return SD_RES_SUCCESS;
}

static int cluster_enable_recover(const struct sd_req *req,
				    struct sd_rsp *rsp, void *data)
{
	sys->disable_recovery = false;
	resume_suspended_recovery();
	return SD_RES_SUCCESS;
}

static int cluster_disable_recover(const struct sd_req *req,
				   struct sd_rsp *rsp, void *data)
{
	sys->disable_recovery = true;
	return SD_RES_SUCCESS;
}

static int cluster_get_vdi_attr(struct request *req)
{
	const struct sd_req *hdr = &req->rq;
	struct sd_rsp *rsp = &req->rp;
	uint32_t vid = 0, attrid = 0, nr_copies = sys->nr_copies;
	uint64_t created_time = 0;
	int ret;
	struct sheepdog_vdi_attr *vattr;

	vattr = req->data;
	ret = lookup_vdi(vattr->name, vattr->tag, &vid,
			 hdr->vdi.snapid, &nr_copies, &created_time);
	if (ret != SD_RES_SUCCESS)
		return ret;

	/* the current VDI id can change if we take a snapshot,
	   so we use the hash value of the VDI name as the VDI id */
	vid = fnv_64a_buf(vattr->name, strlen(vattr->name), FNV1A_64_INIT);
	vid &= SD_NR_VDIS - 1;
	ret = get_vdi_attr(req->data, hdr->data_length,
			   vid, &attrid, created_time,
			   !!(hdr->flags & SD_FLAG_CMD_CREAT),
			   !!(hdr->flags & SD_FLAG_CMD_EXCL),
			   !!(hdr->flags & SD_FLAG_CMD_DEL));

	rsp->vdi.vdi_id = vid;
	rsp->vdi.attr_id = attrid;
	rsp->vdi.copies = nr_copies;

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
			   void *data)
{
	return read_vdis(data, req->data_length, &rsp->data_length);
}

static int local_get_vdi_copies(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data)
{
	rsp->data_length = fill_vdi_copy_list(data);

	return SD_RES_SUCCESS;
}

static int local_stat_sheep(struct request *req)
{
	struct sd_node_rsp *node_rsp = (struct sd_node_rsp *)&req->rp;
	uint32_t epoch = req->rq.epoch;

	return stat_sheep(&node_rsp->store_size, &node_rsp->store_free, epoch);
}

static int local_stat_recovery(const struct sd_req *req, struct sd_rsp *rsp,
					void *data)
{
	if (node_in_recovery())
		return SD_RES_NODE_IN_RECOVERY;

	return SD_RES_SUCCESS;
}

static int local_stat_cluster(struct request *req)
{
	struct sd_rsp *rsp = &req->rp;
	struct epoch_log *log;
	int i, max_logs;
	uint32_t epoch;

	max_logs = req->rq.data_length / sizeof(*log);
	epoch = get_latest_epoch();
	for (i = 0; i < max_logs; i++) {
		if (epoch <= 0)
			break;

		log = (struct epoch_log *)req->data + i;
		memset(log, 0, sizeof(*log));
		log->epoch = epoch;
		log->ctime = get_cluster_ctime();
		log->nr_nodes = epoch_log_read(epoch, log->nodes,
					       sizeof(log->nodes));
		if (log->nr_nodes == -1)
			log->nr_nodes = epoch_log_read_remote(epoch, log->nodes,
							      sizeof(log->nodes));

		log->nr_copies = sys->nr_copies;

		rsp->data_length += sizeof(*log);
		/* FIXME: this hack would require sizeof(time_t) < sizeof(log->nodes[0]) */
		log->time = *(uint64_t *)(&log->nodes[log->nr_nodes]);
		epoch--;
	}

	switch (sys->status) {
	case SD_STATUS_OK:
		return SD_RES_SUCCESS;
	case SD_STATUS_WAIT_FOR_FORMAT:
		return SD_RES_WAIT_FOR_FORMAT;
	case SD_STATUS_WAIT_FOR_JOIN:
		return SD_RES_WAIT_FOR_JOIN;
	case SD_STATUS_SHUTDOWN:
		return SD_RES_SHUTDOWN;
	case SD_STATUS_HALT:
		return SD_RES_HALT;
	default:
		return SD_RES_SYSTEM_ERROR;
	}
}

static int local_get_obj_list(struct request *req)
{
	return get_obj_list((const struct sd_list_req *)&req->rq,
			    (struct sd_list_rsp *)&req->rp, req->data);
}

static int local_get_epoch(struct request *req)
{
	uint32_t epoch = req->rq.obj.tgt_epoch;
	int nr_nodes;

	dprintf("%d\n", epoch);

	nr_nodes = epoch_log_read(epoch, req->data, req->rq.data_length);
	if (nr_nodes == -1)
		return SD_RES_NO_TAG;

	req->rp.data_length = nr_nodes * sizeof(struct sd_node) + sizeof(time_t);
	return SD_RES_SUCCESS;
}

static int cluster_force_recover(const struct sd_req *req, struct sd_rsp *rsp,
				void *data)
{
	struct vnode_info *old_vnode_info, *vnode_info;
	int ret = SD_RES_SUCCESS;
	uint8_t c;
	uint16_t f;

	/* We should manually recover the cluster when
	 * 1) the master is physically down (different epoch condition).
	 * 2) some nodes are physically down (same epoch condition).
	 * In both case, the nodes(s) stat is WAIT_FOR_JOIN.
	 */
	if (sys->status != SD_STATUS_WAIT_FOR_JOIN)
		return SD_RES_FORCE_RECOVER;

	ret = get_cluster_copies(&c);
	if (ret)
		return ret;
	ret = get_cluster_flags(&f);
	if (ret)
		return ret;

	sys->nr_copies = c;
	sys->flags = f;

	old_vnode_info = get_vnode_info_epoch(sys->epoch);
	if (!old_vnode_info) {
		eprintf("cannot get vnode info for epoch %d\n", sys->epoch);
		return SD_RES_EIO;
	}

	sys->epoch++; /* some nodes are left, so we get a new epoch */
	ret = log_current_epoch();
	if (ret) {
		ret = SD_RES_EIO;
		sys->epoch--;
		goto out;
	}

	if (have_enough_zones())
		sys->status = SD_STATUS_OK;
	else
		sys->status = SD_STATUS_HALT;

	vnode_info = get_vnode_info();
	start_recovery(vnode_info, old_vnode_info);
	put_vnode_info(vnode_info);
out:
	put_vnode_info(old_vnode_info);
	return ret;
}

static int cluster_snapshot(const struct sd_req *req, struct sd_rsp *rsp,
			    void *data)
{
	int ret;
	struct siocb iocb = { 0 };

	if (sd_store->snapshot)
		ret = sd_store->snapshot(&iocb);
	else
		ret = SD_RES_NO_SUPPORT;

	return ret;
}

static int cluster_cleanup(const struct sd_req *req, struct sd_rsp *rsp,
				void *data)
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

static int cluster_notify_vdi_del(const struct sd_req *req, struct sd_rsp *rsp,
				  void *data)
{
	uint32_t vid = *(uint32_t *)data;

	return objlist_cache_cleanup(vid);
}

static int cluster_recovery_completion(const struct sd_req *req,
				       struct sd_rsp *rsp,
				       void *data)
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
		dprintf("new epoch %d\n", epoch);
		latest_epoch = epoch;
		nr_recovereds = 0;
	}

	recovereds[nr_recovereds++] = *(struct sd_node *)node;
	qsort(recovereds, nr_recovereds, sizeof(*recovereds), node_id_cmp);

	dprintf("%s is recovered at epoch %d\n", node_to_str(node), epoch);
	for (i = 0; i < nr_recovereds; i++)
		dprintf("[%x] %s\n", i, node_to_str(recovereds + i));

	if (sys->epoch != latest_epoch)
		return SD_RES_SUCCESS;

	vnode_info = get_vnode_info();

	if (vnode_info->nr_nodes == nr_recovereds &&
	    memcmp(vnode_info->nodes, recovereds,
		   sizeof(*recovereds) * nr_recovereds) == 0) {
		dprintf("all nodes are recovered at epoch %d\n", epoch);
		if (sd_store->cleanup)
			sd_store->cleanup();
	}

	put_vnode_info(vnode_info);

	return SD_RES_SUCCESS;
}

static int local_set_cache_size(const struct sd_req *req, struct sd_rsp *rsp,
				  void *data)
{
	uint32_t cache_size = *(uint32_t *)data;

	uatomic_set(&sys->object_cache_size, cache_size);
	dprintf("Max cache size set to %dM\n", cache_size);

	object_cache_try_to_reclaim();

	return SD_RES_SUCCESS;
}

static int cluster_restore(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data)
{
	int ret;
	struct siocb iocb = { .epoch = req->obj.tgt_epoch };

	if (sd_store->restore)
		ret = sd_store->restore(&iocb);
	else
		ret = SD_RES_NO_SUPPORT;
	return ret;
}

static int local_get_snap_file(struct request *req)
{
	int ret;
	struct siocb iocb = { .buf = req->data };

	if (sd_store->get_snap_file) {
		ret = sd_store->get_snap_file(&iocb);
		req->rp.data_length = iocb.length;
	} else
		ret = SD_RES_NO_SUPPORT;

	return ret;
}

static int local_flush_vdi(struct request *req)
{
	int ret = SD_RES_SUCCESS;

	if (is_object_cache_enabled()) {
		ret = object_cache_flush_vdi(req);
		if (ret != SD_RES_SUCCESS)
			return ret;
	}

	if (is_disk_cache_enabled()) {
		struct sd_req hdr;

		sd_init_req(&hdr, SD_OP_FLUSH_NODES);
		return exec_local_req(&hdr, NULL);
	}

	return ret;
}

static int local_flush_and_del(struct request *req)
{
	if (!is_object_cache_enabled())
		return SD_RES_SUCCESS;
	return object_cache_flush_and_del(req);
}

static int local_trace_ops(const struct sd_req *req, struct sd_rsp *rsp, void *data)
{
	int enable = req->data_length, ret;

	if (enable)
		ret = trace_enable();
	else
		ret = trace_disable();

	return ret;
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
	dprintf("%u\n", rsp->data_length);
	return SD_RES_SUCCESS;
}

static int local_kill_node(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data)
{
	sys->status = SD_STATUS_KILLED;

	return SD_RES_SUCCESS;
}

static int read_copy_from_replica(struct request *req, uint32_t epoch,
				  uint64_t oid, char *buf)
{
	struct request read_req = { };
	struct sd_req *hdr = &read_req.rq;
	struct sd_rsp *rsp = &read_req.rp;
	int ret;

	/* Create a fake gateway read request */
	sd_init_req(hdr, SD_OP_READ_OBJ);
	hdr->data_length = SD_DATA_OBJ_SIZE;
	hdr->epoch = epoch;

	hdr->obj.oid = oid;
	hdr->obj.offset = 0;
	hdr->obj.copies = get_req_copy_number(req);

	read_req.data = buf;
	read_req.op = get_sd_op(hdr->opcode);
	read_req.vinfo = req->vinfo;

	ret = gateway_read_obj(&read_req);

	if (ret == SD_RES_SUCCESS)
		set_trimmed_sectors(buf, rsp->obj.offset, rsp->data_length,
				    SD_DATA_OBJ_SIZE);

	return ret;
}

int peer_remove_obj(struct request *req)
{
	uint64_t oid = req->rq.obj.oid;

	objlist_cache_remove(oid);
	object_cache_remove(oid);

	return sd_store->remove_object(oid);
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
	iocb.flags = hdr->flags;
	iocb.buf = req->data;
	iocb.length = hdr->data_length;
	iocb.offset = hdr->obj.offset;
	ret = sd_store->read(hdr->obj.oid, &iocb);
	if (ret != SD_RES_SUCCESS)
		goto out;

	rsp->data_length = hdr->data_length;
	rsp->obj.offset = 0;
	trim_zero_sectors(req->data, &rsp->obj.offset, &rsp->data_length);

	if (hdr->obj.copies)
		rsp->obj.copies = hdr->obj.copies;
	else
		rsp->obj.copies = get_obj_copy_number(hdr->obj.oid,
						      req->vinfo->nr_zones);
out:
	return ret;
}

static int do_create_and_write_obj(struct siocb *iocb, struct sd_req *hdr,
				   uint32_t epoch, void *data)
{
	iocb->buf = data;
	iocb->length = hdr->data_length;
	iocb->offset = hdr->obj.offset;

	return sd_store->create_and_write(hdr->obj.oid, iocb);
}

int peer_write_obj(struct request *req)
{
	struct sd_req *hdr = &req->rq;
	struct siocb iocb = { };
	uint64_t oid = hdr->obj.oid;

	iocb.epoch = hdr->epoch;
	iocb.flags = hdr->flags;
	iocb.buf = req->data;
	iocb.length = hdr->data_length;
	iocb.offset = hdr->obj.offset;

	return sd_store->write(oid, &iocb);
}

int peer_create_and_write_obj(struct request *req)
{
	struct sd_req *hdr = &req->rq;
	struct sd_req cow_hdr;
	uint32_t epoch = hdr->epoch;
	uint64_t oid = hdr->obj.oid;
	char *buf = NULL;
	struct siocb iocb;
	int ret = SD_RES_SUCCESS;

	memset(&iocb, 0, sizeof(iocb));
	iocb.epoch = epoch;
	iocb.flags = hdr->flags;
	iocb.length = get_objsize(oid);
	if (hdr->flags & SD_FLAG_CMD_COW) {
		dprintf("%" PRIx64 ", %" PRIx64 "\n", oid, hdr->obj.cow_oid);

		buf = valloc(SD_DATA_OBJ_SIZE);
		if (!buf) {
			eprintf("can not allocate memory\n");
			goto out;
		}
		if (hdr->data_length != SD_DATA_OBJ_SIZE) {
			ret = read_copy_from_replica(req, hdr->epoch,
						     hdr->obj.cow_oid, buf);
			if (ret != SD_RES_SUCCESS) {
				eprintf("failed to read cow object\n");
				goto out;
			}
		}

		memcpy(buf + hdr->obj.offset, req->data, hdr->data_length);
		memcpy(&cow_hdr, hdr, sizeof(cow_hdr));
		cow_hdr.data_length = SD_DATA_OBJ_SIZE;
		cow_hdr.obj.offset = 0;
		trim_zero_sectors(buf, &cow_hdr.obj.offset,
				  &cow_hdr.data_length);

		ret = do_create_and_write_obj(&iocb, &cow_hdr, epoch, buf);
	} else
		ret = do_create_and_write_obj(&iocb, hdr, epoch, req->data);

	if (SD_RES_SUCCESS == ret)
		objlist_cache_insert(oid);
out:
	if (buf)
		free(buf);
	return ret;
}

int peer_flush(struct request *req)
{
	if (sys->gateway_only)
		return SD_RES_SUCCESS;

	return sd_store->flush();
}

static struct sd_op_template sd_ops[] = {

	/* cluster operations */
	[SD_OP_NEW_VDI] = {
		.name = "NEW_VDI",
		.type = SD_OP_TYPE_CLUSTER,
		.process_work = cluster_new_vdi,
		.process_main = post_cluster_new_vdi,
	},

	[SD_OP_DEL_VDI] = {
		.name = "DEL_VDI",
		.type = SD_OP_TYPE_CLUSTER,
		.process_work = cluster_del_vdi,
		.process_main = post_cluster_del_vdi,
	},

	[SD_OP_GET_VDI_INFO] = {
		.name = "GET_VDI_INFO",
		.type = SD_OP_TYPE_CLUSTER,
		.process_work = cluster_get_vdi_info,
	},

	[SD_OP_LOCK_VDI] = {
		.name = "LOCK_VDI",
		.type = SD_OP_TYPE_CLUSTER,
		.process_work = cluster_get_vdi_info,
	},

	[SD_OP_MAKE_FS] = {
		.name = "MAKE_FS",
		.type = SD_OP_TYPE_CLUSTER,
		.force = true,
		.process_main = cluster_make_fs,
	},

	[SD_OP_SHUTDOWN] = {
		.name = "SHUTDOWN",
		.type = SD_OP_TYPE_CLUSTER,
		.process_main = cluster_shutdown,
	},

	[SD_OP_GET_VDI_ATTR] = {
		.name = "GET_VDI_ATTR",
		.type = SD_OP_TYPE_CLUSTER,
		.process_work = cluster_get_vdi_attr,
	},

	[SD_OP_RELEASE_VDI] = {
		.name = "RELEASE_VDI",
		.type = SD_OP_TYPE_CLUSTER,
	},

	[SD_OP_FORCE_RECOVER] = {
		.name = "FORCE_RECOVER",
		.type = SD_OP_TYPE_CLUSTER,
		.force = true,
		.process_main = cluster_force_recover,
	},

	[SD_OP_SNAPSHOT] = {
		.name = "SNAPSHOT",
		.type = SD_OP_TYPE_CLUSTER,
		.force = true,
		.process_main = cluster_snapshot,
	},

	[SD_OP_RESTORE] = {
		.name = "RESTORE",
		.type = SD_OP_TYPE_CLUSTER,
		.force = true,
		.process_main = cluster_restore,
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

	[SD_OP_COMPLETE_RECOVERY] = {
		.name = "COMPLETE_RECOVERY",
		.type = SD_OP_TYPE_CLUSTER,
		.force = true,
		.process_main = cluster_recovery_completion,
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

	[SD_OP_GET_SNAP_FILE] = {
		.name = "GET_SNAP_FILE",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_work = local_get_snap_file,
	},

	[SD_OP_FLUSH_VDI] = {
		.name = "FLUSH_VDI",
		.type = SD_OP_TYPE_LOCAL,
		.process_work = local_flush_vdi,
	},

	[SD_OP_FLUSH_DEL_CACHE] = {
		.name = "DEL_CACHE",
		.type = SD_OP_TYPE_LOCAL,
		.process_work = local_flush_and_del,
	},

	[SD_OP_TRACE] = {
		.name = "TRACE",
		.type = SD_OP_TYPE_LOCAL,
		.force = true,
		.process_main = local_trace_ops,
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
		.process_main = local_kill_node,
	},

	[SD_OP_SET_CACHE_SIZE] = {
		.name = "SET_CACHE_SIZE",
		.type = SD_OP_TYPE_LOCAL,
		.process_main = local_set_cache_size,
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

	[SD_OP_ENABLE_RECOVER] = {
		.name = "ENABLE_RECOVER",
		.type = SD_OP_TYPE_CLUSTER,
		.process_main = cluster_enable_recover,
	},

	[SD_OP_DISABLE_RECOVER] = {
		.name = "DISABLE_RECOVER",
		.type = SD_OP_TYPE_CLUSTER,
		.process_main = cluster_disable_recover,
	},

	[SD_OP_FLUSH_PEER] = {
		.name = "FLUSH_PEER",
		.type = SD_OP_TYPE_PEER,
		.process_work = peer_flush,
	},
	[SD_OP_FLUSH_NODES] = {
		.name = "FLUSH_NODES",
		.type = SD_OP_TYPE_GATEWAY,
		.process_work = gateway_flush_nodes,
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
	return op->name;
}

bool is_cluster_op(const struct sd_op_template *op)
{
	return op->type == SD_OP_TYPE_CLUSTER;
}

bool is_local_op(const struct sd_op_template *op)
{
	return op->type == SD_OP_TYPE_LOCAL;
}

bool is_peer_op(const struct sd_op_template *op)
{
	return op->type == SD_OP_TYPE_PEER;
}

bool is_gateway_op(const struct sd_op_template *op)
{
	return op->type == SD_OP_TYPE_GATEWAY;
}

bool is_force_op(const struct sd_op_template *op)
{
	return !!op->force;
}

bool has_process_work(const struct sd_op_template *op)
{
	return !!op->process_work;
}

bool has_process_main(const struct sd_op_template *op)
{
	return !!op->process_main;
}

void do_process_work(struct work *work)
{
	struct request *req = container_of(work, struct request, work);
	int ret = SD_RES_SUCCESS;

	dprintf("%x, %" PRIx64", %"PRIu32"\n",
		req->rq.opcode, req->rq.obj.oid, req->rq.epoch);

	if (req->op->process_work)
		ret = req->op->process_work(req);

	if (ret != SD_RES_SUCCESS) {
		dprintf("failed: %x, %" PRIx64" , %u, %"PRIx32"\n",
			req->rq.opcode, req->rq.obj.oid, req->rq.epoch, ret);
	}

	req->rp.result = ret;
}

int do_process_main(const struct sd_op_template *op, const struct sd_req *req,
		    struct sd_rsp *rsp, void *data)
{
	return op->process_main(req, rsp, data);
}

int sheep_do_op_work(const struct sd_op_template *op, struct request *req)
{
	return op->process_work(req);
}

static int map_table[] = {
	[SD_OP_CREATE_AND_WRITE_OBJ] = SD_OP_CREATE_AND_WRITE_PEER,
	[SD_OP_READ_OBJ] = SD_OP_READ_PEER,
	[SD_OP_WRITE_OBJ] = SD_OP_WRITE_PEER,
	[SD_OP_REMOVE_OBJ] = SD_OP_REMOVE_PEER,
	[SD_OP_FLUSH_NODES] = SD_OP_FLUSH_PEER,
};

int gateway_to_peer_opcode(int opcode)
{
	assert(opcode < ARRAY_SIZE(map_table));
	return map_table[opcode];
}
