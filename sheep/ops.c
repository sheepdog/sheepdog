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

enum sd_op_type {
	SD_OP_TYPE_CLUSTER = 1, /* cluster operations */
	SD_OP_TYPE_LOCAL,       /* local operations */
	SD_OP_TYPE_IO,          /* io operations */
};

struct sd_op_template {
	enum sd_op_type type;

	/* process request even when cluster is not working */
	int force;

	/*
	 * process_work() will be called in the worker thread, and
	 * process_main() will be called in the main thread.
	 *
	 * If type is SD_OP_TYPE_CLUSTER, it is guaranteed that only
	 * one node processes a cluster operation at the same time.
	 * We can use this for something like distributed locking.
	 * process_work() will be called on the local node, and
	 * process_main() will be called on every nodes.
	 *
	 * If type is SD_OP_TYPE_LOCAL, both process_work() and
	 * process_main() will be called on the local node.
	 *
	 * If type is SD_OP_TYPE_IO, neither process_work() nor
	 * process_main() is used because this type of operation is
	 * heavily intertwined with Sheepdog core codes.  We will be
	 * unlikely to add new operations of this type.
	 */
	int (*process_work)(const struct sd_req *req, struct sd_rsp *rsp, void *data);
	int (*process_main)(const struct sd_req *req, struct sd_rsp *rsp, void *data);
};

struct flush_work {
	struct object_cache *cache;
	struct work work;
};

static void get_store_dir(struct strbuf *buf, uint32_t epoch)
{
	if (!strcmp(sd_store->name, "simple"))
		strbuf_addf(buf, "%s%08u/", obj_path, epoch);
	else /* XXX assume other store doesn't need epoch/obj pattern */
		strbuf_addf(buf, "%s", obj_path);
}

static int stat_sheep(uint64_t *store_size, uint64_t *store_free, uint32_t epoch)
{
	struct statvfs vs;
	int ret;
	DIR *dir;
	struct dirent *d;
	uint64_t used = 0;
	struct stat s;
	char path[1024];
	struct strbuf store_dir = STRBUF_INIT;

	ret = statvfs(mnt_path, &vs);
	if (ret) {
		ret = SD_RES_EIO;
		goto out;
	}

	get_store_dir(&store_dir, epoch);
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

	*store_size = (uint64_t)vs.f_frsize * vs.f_bfree + used;
	*store_free = (uint64_t)vs.f_frsize * vs.f_bfree;
out:
	strbuf_release(&store_dir);
	return ret;
}

static int cluster_new_vdi(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data)
{
	const struct sd_vdi_req *hdr = (const struct sd_vdi_req *)req;
	struct sd_vdi_rsp *vdi_rsp = (struct sd_vdi_rsp *)rsp;
	uint32_t vid = 0, nr_copies = sys->nr_copies;
	int ret;

	ret = add_vdi(hdr->epoch, data, hdr->data_length, hdr->vdi_size, &vid,
		      hdr->base_vdi_id, hdr->copies,
		      hdr->snapid, &nr_copies);

	vdi_rsp->vdi_id = vid;
	vdi_rsp->copies = nr_copies;

	return ret;
}

static int post_cluster_new_vdi(const struct sd_req *req, struct sd_rsp *rsp,
				void *data)
{
	struct sd_vdi_rsp *vdi_rsp = (struct sd_vdi_rsp *)rsp;
	unsigned long nr = vdi_rsp->vdi_id;
	int ret = vdi_rsp->result;

	vprintf(SDOG_INFO, "done %d %ld\n", ret, nr);
	set_bit(nr, sys->vdi_inuse);

	return SD_RES_SUCCESS;
}

static int cluster_del_vdi(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data)
{
	const struct sd_vdi_req *hdr = (const struct sd_vdi_req *)req;
	struct sd_vdi_rsp *vdi_rsp = (struct sd_vdi_rsp *)rsp;
	uint32_t vid = 0, nr_copies = sys->nr_copies;
	int ret;

	ret = del_vdi(hdr->epoch, data, hdr->data_length, &vid,
		      hdr->snapid, &nr_copies);

	if (ret == SD_RES_SUCCESS)
		object_cache_delete(vid);
	vdi_rsp->vdi_id = vid;
	vdi_rsp->copies = nr_copies;

	return ret;
}

static int cluster_get_vdi_info(const struct sd_req *req, struct sd_rsp *rsp,
				void *data)
{
	const struct sd_vdi_req *hdr = (const struct sd_vdi_req *)req;
	struct sd_vdi_rsp *vdi_rsp = (struct sd_vdi_rsp *)rsp;
	uint32_t vid = 0, nr_copies = sys->nr_copies;
	void *tag;
	int ret;

	if (hdr->proto_ver != SD_PROTO_VER)
		return SD_RES_VER_MISMATCH;

	if (hdr->data_length == SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN)
		tag = (char *)data + SD_MAX_VDI_LEN;
	else if (hdr->data_length == SD_MAX_VDI_LEN)
		tag = NULL;
	else
		return SD_RES_INVALID_PARMS;

	ret = lookup_vdi(hdr->epoch, data, tag, &vid, hdr->snapid,
			 &nr_copies, NULL);
	if (ret != SD_RES_SUCCESS)
		return ret;

	vdi_rsp->vdi_id = vid;
	vdi_rsp->copies = nr_copies;

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
	struct siocb iocb = { 0 };

	sd_store = find_store_driver(data);
	if (!sd_store)
		return SD_RES_NO_STORE;

	latest_epoch = get_latest_epoch();
	iocb.epoch = latest_epoch;
	sd_store->format(&iocb);
	sd_store->init(obj_path);
	sys->nr_copies = hdr->copies;
	sys->flags = hdr->flags;
	if (!sys->nr_copies)
		sys->nr_copies = SD_DEFAULT_REDUNDANCY;

	created_time = hdr->ctime;
	set_cluster_ctime(created_time);

	for (i = 1; i <= latest_epoch; i++)
		remove_epoch(i);

	memset(sys->vdi_inuse, 0, sizeof(sys->vdi_inuse));

	sys->epoch = 1;
	sys->recovered_epoch = 1;

	ret = update_epoch_log(sys->epoch);
	if (ret)
		return SD_RES_EIO;

	update_epoch_store(sys->epoch);

	set_cluster_copies(sys->nr_copies);
	set_cluster_flags(sys->flags);

	if (sys_flag_nohalt())
		sys_stat_set(SD_STATUS_OK);
	else {
		int nr_zones = get_zones_nr_from(sys->nodes, sys->nr_nodes);

		if (nr_zones >= sys->nr_copies)
			sys_stat_set(SD_STATUS_OK);
		else
			sys_stat_set(SD_STATUS_HALT);
	}

	return SD_RES_SUCCESS;
}

static int cluster_shutdown(const struct sd_req *req, struct sd_rsp *rsp,
			    void *data)
{
	sys_stat_set(SD_STATUS_SHUTDOWN);

	return SD_RES_SUCCESS;
}

static int cluster_get_vdi_attr(const struct sd_req *req, struct sd_rsp *rsp,
				void *data)
{
	const struct sd_vdi_req *hdr = (const struct sd_vdi_req *)req;
	struct sd_vdi_rsp *vdi_rsp = (struct sd_vdi_rsp *)rsp;
	uint32_t vid = 0, attrid = 0, nr_copies = sys->nr_copies;
	uint64_t created_time = 0;
	int ret;
	struct sheepdog_vdi_attr *vattr;

	vattr = data;
	ret = lookup_vdi(hdr->epoch, vattr->name, vattr->tag,
			 &vid, hdr->snapid, &nr_copies, &created_time);
	if (ret != SD_RES_SUCCESS)
		return ret;

	/* the current VDI id can change if we take a snapshot,
	   so we use the hash value of the VDI name as the VDI id */
	vid = fnv_64a_buf(vattr->name, strlen(vattr->name), FNV1A_64_INIT);
	vid &= SD_NR_VDIS - 1;
	ret = get_vdi_attr(hdr->epoch, data, hdr->data_length, vid,
			   &attrid, nr_copies, created_time,
			   hdr->flags & SD_FLAG_CMD_CREAT,
			   hdr->flags & SD_FLAG_CMD_EXCL,
			   hdr->flags & SD_FLAG_CMD_DEL);

	vdi_rsp->vdi_id = vid;
	vdi_rsp->attr_id = attrid;
	vdi_rsp->copies = nr_copies;

	return ret;
}

static int local_get_store_list(const struct sd_req *req, struct sd_rsp *rsp,
				void *data)
{
	struct strbuf buf = STRBUF_INIT;
	struct store_driver *driver;

	list_for_each_entry(driver, &store_drivers, list) {
		strbuf_addf(&buf, "%s ", driver->name);
	}
	memcpy(data, buf.buf, buf.len);

	strbuf_release(&buf);
	return SD_RES_SUCCESS;
}

static int local_read_vdis(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data)
{
	return read_vdis(data, req->data_length, &rsp->data_length);
}

static int get_node_idx(struct sd_node *ent,
			struct sd_node *entries, int nr_nodes)
{
	ent = bsearch(ent, entries, nr_nodes, sizeof(*ent), node_cmp);
	if (!ent)
		return -1;

	return ent - entries;
}

static int local_get_node_list(const struct sd_req *req, struct sd_rsp *rsp,
			       void *data)
{
	struct sd_node_rsp *node_rsp = (struct sd_node_rsp *)rsp;
	int nr_nodes;

	nr_nodes = sys->nr_nodes;
	memcpy(data, sys->nodes, sizeof(*sys->nodes) * nr_nodes);
	node_rsp->data_length = nr_nodes * sizeof(struct sd_node);
	node_rsp->nr_nodes = nr_nodes;
	node_rsp->local_idx = get_node_idx(&sys->this_node, data, nr_nodes);
	node_rsp->master_idx = -1;

	return SD_RES_SUCCESS;
}

static int local_stat_sheep(const struct sd_req *req, struct sd_rsp *rsp,
			    void *data)
{
	struct sd_node_rsp *node_rsp = (struct sd_node_rsp *)rsp;
	uint32_t epoch = req->epoch;

	return stat_sheep(&node_rsp->store_size, &node_rsp->store_free, epoch);
}

static int local_stat_recovery(const struct sd_req *req, struct sd_rsp *rsp,
					void *data)
{
	if (node_in_recovery())
		return SD_RES_SUCCESS;
	else
		return SD_RES_UNKNOWN;

	return SD_RES_UNKNOWN;
}

static int local_stat_cluster(const struct sd_req *req, struct sd_rsp *rsp,
			      void *data)
{
	struct epoch_log *log;
	int i, max_logs;
	uint32_t sys_stat = sys_stat_get(), epoch;

	max_logs = rsp->data_length / sizeof(*log);
	epoch = get_latest_epoch();
	rsp->data_length = 0;
	for (i = 0; i < max_logs; i++) {
		if (epoch <= 0)
			break;

		log = (struct epoch_log *)data + i;
		log->epoch = epoch;
		log->ctime = get_cluster_ctime();
		log->nr_nodes = epoch_log_read(epoch, (char *)log->nodes,
					       sizeof(log->nodes));
		if (log->nr_nodes == -1)
			log->nr_nodes = epoch_log_read_remote(epoch,
							      (char *)log->nodes,
							      sizeof(log->nodes));
		log->nr_copies = get_max_nr_copies_from(log->nodes, log->nr_nodes);

		rsp->data_length += sizeof(*log);
		log->nr_nodes /= sizeof(log->nodes[0]);
		/* FIXME: this hack would require sizeof(time_t) < sizeof(log->nodes[0]) */
		log->time = *(uint64_t *)(&log->nodes[log->nr_nodes]);
		epoch--;
	}

	switch (sys_stat) {
	case SD_STATUS_OK:
		return SD_RES_SUCCESS;
	case SD_STATUS_WAIT_FOR_FORMAT:
		return SD_RES_WAIT_FOR_FORMAT;
	case SD_STATUS_WAIT_FOR_JOIN:
		return SD_RES_WAIT_FOR_JOIN;
	case SD_STATUS_SHUTDOWN:
		return SD_RES_SHUTDOWN;
	case SD_STATUS_JOIN_FAILED:
		return SD_RES_JOIN_FAILED;
	case SD_STATUS_HALT:
		return SD_RES_HALT;
	default:
		return SD_RES_SYSTEM_ERROR;
	}
}

static int local_kill_node(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data)
{
	exit(1);
}

static int local_get_obj_list(const struct sd_req *req, struct sd_rsp *rsp,
			      void *data)
{
	return get_obj_list((const struct sd_list_req *)req,
			    (struct sd_list_rsp *)rsp, data);
}

static int local_get_epoch(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data)
{
	const struct sd_obj_req *obj_req = (const struct sd_obj_req *)req;
	struct sd_obj_rsp *obj_rsp = (struct sd_obj_rsp *)rsp;
	uint32_t epoch = obj_req->tgt_epoch;
	int len, ret;
	dprintf("%d\n", epoch);
	len = epoch_log_read(epoch, (char *)data, obj_req->data_length);
	if (len == -1) {
		ret = SD_RES_NO_TAG;
		obj_rsp->data_length = 0;
	} else {
		ret = SD_RES_SUCCESS;
		obj_rsp->data_length = len;
	}
	return ret;
}

static int cluster_manual_recover(const struct sd_req *req, struct sd_rsp *rsp,
				void *data)
{
	int s, nr_zones = 0, ret = SD_RES_SUCCESS;
	uint8_t c;
	uint16_t f;

	/* We should manually recover the cluster when
	 * 1) the master is physically down (different epoch condition).
	 * 2) some nodes are physically down (same epoch condition).
	 * In both case, the nodes(s) stat is WAIT_FOR_JOIN.
	 */
	if (!sys_stat_wait_join()) {
		ret = SD_RES_MANUAL_RECOVER;
		goto out;
	}

	ret = get_cluster_copies(&c);
	if (ret)
		goto out;
	ret = get_cluster_flags(&f);
	if (ret)
		goto out;

	sys->nr_copies = c;
	sys->flags = f;

	s = SD_STATUS_OK;
	if (!sys_flag_nohalt()) {
		nr_zones = get_zones_nr_from(sys->nodes, sys->nr_nodes);
		if (nr_zones < sys->nr_copies)
			s = SD_STATUS_HALT;
	}

	dprintf("flags %d, nr_zones %d, copies %d\n", sys->flags, nr_zones,
		sys->nr_copies);

	sys->epoch++; /* some nodes are left, so we get a new epoch */
	ret = update_epoch_log(sys->epoch);
	if (ret) {
		ret = SD_RES_EIO;
		sys->epoch--;
		goto out;
	}
	update_epoch_store(sys->epoch);
	sys_stat_set(s);
out:
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
	struct siocb iocb = { 0 };
	iocb.epoch = sys->epoch;

	if (node_in_recovery())
		return SD_RES_CLUSTER_RECOVERING;

	if (sd_store->cleanup)
		ret = sd_store->cleanup(&iocb);
	else
		ret = SD_RES_NO_SUPPORT;

	return ret;
}

static int cluster_restore(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data)
{
	const struct sd_obj_req *hdr = (const struct sd_obj_req *)req;
	int ret;
	struct siocb iocb = { .epoch = hdr->tgt_epoch };

	if (sd_store->restore)
		ret = sd_store->restore(&iocb);
	else
		ret = SD_RES_NO_SUPPORT;
	return ret;
}

static int local_get_snap_file(const struct sd_req *req, struct sd_rsp *rsp,
			    void *data)
{
	int ret;
	struct siocb iocb = { .buf = data };

	if (sd_store->get_snap_file) {
		ret = sd_store->get_snap_file(&iocb);
		rsp->data_length = iocb.length;
	} else
		ret = SD_RES_NO_SUPPORT;

	return ret;
}

static void flush_vdi_fn(struct work *work)
{
	struct flush_work *fw = container_of(work, struct flush_work, work);

	dprintf("flush vdi %"PRIx32"\n", fw->cache->vid);
	if (object_cache_push(fw->cache) != SD_RES_SUCCESS)
		eprintf("failed to flush vdi %"PRIx32"\n", fw->cache->vid);
}

static void flush_vdi_done(struct work *work)
{
	struct flush_work *fw = container_of(work, struct flush_work, work);
	dprintf("flush vdi %"PRIx32" done\n", fw->cache->vid);
	free(fw);
}

static int local_flush_vdi(const struct sd_req *req, struct sd_rsp *rsp, void *data)
{
	struct sd_obj_req *hdr = (struct sd_obj_req *)req;
	uint64_t oid = hdr->oid;
	uint32_t vid = oid_to_vid(oid);
	struct object_cache *cache = find_object_cache(vid, 0);

	if (cache) {
		if (!sys->async_flush)
			return object_cache_push(cache);
		else {
			struct flush_work *fw = xmalloc(sizeof(*fw));
			fw->work.fn = flush_vdi_fn;
			fw->work.done = flush_vdi_done;
			fw->cache = cache;
			queue_work(sys->flush_wqueue, &fw->work);
		}
	}

	return SD_RES_SUCCESS;
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

static int local_trace_cat_ops(const struct sd_req *req, struct sd_rsp *rsp, void *data)
{
	rsp->data_length = trace_copy_buffer(data);
	dprintf("%u\n", rsp->data_length);
	trace_reset_buffer();
	return SD_RES_SUCCESS;
}

static int read_copy_from_replica(struct request *req, uint32_t epoch,
				  uint64_t oid, char *buf)
{
	int i, nr_copies, ret;
	unsigned wlen, rlen;
	char name[128];
	struct sd_vnode *v;
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
	struct siocb iocb;
	int fd;

	nr_copies = get_nr_copies(req->vnodes);
	for (i = 0; i < nr_copies; i++) {
		v = oid_to_vnode(req->vnodes, oid, i);

		addr_to_str(name, sizeof(name), v->addr, 0);

		if (vnode_is_local(v)) {
			memset(&iocb, 0, sizeof(iocb));
			iocb.epoch = epoch;
			ret = sd_store->open(oid, &iocb, 0);
			if (ret != SD_RES_SUCCESS)
				continue;

			iocb.buf = buf;
			iocb.length = SD_DATA_OBJ_SIZE;
			iocb.offset = 0;
			ret = sd_store->read(oid, &iocb);
			if (ret != SD_RES_SUCCESS)
				continue;
			sd_store->close(oid, &iocb);
			goto out;
		}

		fd = connect_to(name, v->port);
		if (fd < 0)
			continue;

		memset(&hdr, 0, sizeof(hdr));
		hdr.opcode = SD_OP_READ_OBJ;
		hdr.oid = oid;
		hdr.epoch = epoch;

		rlen = SD_DATA_OBJ_SIZE;
		wlen = 0;
		hdr.flags = SD_FLAG_CMD_IO_LOCAL;
		hdr.data_length = rlen;
		hdr.offset = 0;

		ret = exec_req(fd, (struct sd_req *)&hdr, buf, &wlen, &rlen);

		close(fd);

		dprintf("%x, %x\n", ret, rsp->result);
		if (ret)
			continue;

		switch (rsp->result) {
		case SD_RES_SUCCESS:
			ret = SD_RES_SUCCESS;
			goto out;
		default:
			;
		}
	}

	ret = rsp->result;
out:
	return ret;
}

static int store_remove_obj(const struct sd_req *req, struct sd_rsp *rsp, void *data)
{
	struct sd_obj_req *hdr = (struct sd_obj_req *)req;
	uint32_t epoch = hdr->epoch;
	struct strbuf buf = STRBUF_INIT;
	int ret = SD_RES_SUCCESS;

	get_store_dir(&buf, epoch);
	strbuf_addf(&buf, "%016" PRIx64, hdr->oid);
	if (unlink(buf.buf) < 0) {
		if (errno == ENOENT) {
			ret = SD_RES_NO_OBJ;
			goto out;
		}
		eprintf("%m\n");
		ret =  SD_RES_EIO;
	}
	pthread_rwlock_wrlock(&obj_list_cache.lock);
	if (!objlist_cache_rb_remove(&obj_list_cache.root, hdr->oid))
		obj_list_cache.cache_size--;
	pthread_rwlock_unlock(&obj_list_cache.lock);
 out:
	strbuf_release(&buf);
	return ret;
}

static int store_read_obj(const struct sd_req *req, struct sd_rsp *rsp, void *data)
{
	struct sd_obj_req *hdr = (struct sd_obj_req *)req;
	struct sd_obj_rsp *rsps = (struct sd_obj_rsp *)rsp;
	struct request *request = (struct request *)data;
	int ret;
	uint32_t epoch = hdr->epoch;
	struct siocb iocb;

	memset(&iocb, 0, sizeof(iocb));
	iocb.epoch = epoch;
	iocb.flags = hdr->flags;
	ret = sd_store->open(hdr->oid, &iocb, 0);
	if (ret != SD_RES_SUCCESS)
		return ret;

	iocb.buf = request->data;
	iocb.length = hdr->data_length;
	iocb.offset = hdr->offset;
	ret = sd_store->read(hdr->oid, &iocb);
	if (ret != SD_RES_SUCCESS)
		goto out;

	rsps->data_length = hdr->data_length;
	rsps->copies = sys->nr_copies;
out:
	sd_store->close(hdr->oid, &iocb);
	return ret;
}

static int do_write_obj(struct siocb *iocb, struct sd_obj_req *req, uint32_t epoch, void *data)
{
	struct sd_obj_req *hdr = (struct sd_obj_req *)req;
	uint64_t oid = hdr->oid;
	int ret = SD_RES_SUCCESS;
	void *jd = NULL;

	iocb->buf = data;
	iocb->length = hdr->data_length;
	iocb->offset = hdr->offset;
	if (is_vdi_obj(oid)) {
		struct strbuf buf = STRBUF_INIT;

		get_store_dir(&buf, epoch);
		strbuf_addf(&buf, "%016" PRIx64, oid);
		jd = jrnl_begin(data, hdr->data_length,
				   hdr->offset, buf.buf, jrnl_path);
		if (!jd) {
			strbuf_release(&buf);
			return SD_RES_EIO;
		}
		ret = sd_store->write(oid, iocb);
		jrnl_end(jd);
		strbuf_release(&buf);
	} else
		ret = sd_store->write(oid, iocb);

	return ret;
}

static int store_write_obj(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data)
{
	struct sd_obj_req *hdr = (struct sd_obj_req *)req;
	struct request *request = (struct request *)data;
	int ret;
	uint32_t epoch = hdr->epoch;
	struct siocb iocb;

	memset(&iocb, 0, sizeof(iocb));
	iocb.epoch = epoch;
	iocb.flags = hdr->flags;
	ret = sd_store->open(hdr->oid, &iocb, 0);
	if (ret != SD_RES_SUCCESS)
		return ret;

	ret = do_write_obj(&iocb, hdr, epoch, request->data);

	sd_store->close(hdr->oid, &iocb);
	return ret;
}

static int store_create_and_write_obj(const struct sd_req *req,
				struct sd_rsp *rsp, void *data)
{
	struct sd_obj_req *hdr = (struct sd_obj_req *)req;
	struct request *request = (struct request *)data;
	struct sd_obj_req cow_hdr;
	int ret;
	uint32_t epoch = hdr->epoch;
	char *buf = NULL;
	struct siocb iocb;
	unsigned data_length;

	if (is_vdi_obj(hdr->oid))
		data_length = SD_INODE_SIZE;
	else if (is_vdi_attr_obj(hdr->oid))
		data_length = SD_ATTR_OBJ_SIZE;
	else
		data_length = SD_DATA_OBJ_SIZE;

	memset(&iocb, 0, sizeof(iocb));
	iocb.epoch = epoch;
	iocb.flags = hdr->flags;
	iocb.length = data_length;
	ret = sd_store->open(hdr->oid, &iocb, 1);
	if (ret != SD_RES_SUCCESS)
		return ret;
	if (hdr->flags & SD_FLAG_CMD_COW) {
		dprintf("%" PRIx64 ", %" PRIx64 "\n", hdr->oid, hdr->cow_oid);

		buf = valloc(SD_DATA_OBJ_SIZE);
		if (!buf) {
			eprintf("can not allocate memory\n");
			goto out;
		}
		if (hdr->data_length != SD_DATA_OBJ_SIZE) {
			ret = read_copy_from_replica(request, hdr->epoch, hdr->cow_oid, buf);
			if (ret != SD_RES_SUCCESS) {
				eprintf("failed to read cow object\n");
				goto out;
			}
		}

		memcpy(buf + hdr->offset, request->data, hdr->data_length);
		memcpy(&cow_hdr, hdr, sizeof(cow_hdr));
		cow_hdr.offset = 0;
		cow_hdr.data_length = SD_DATA_OBJ_SIZE;

		ret = do_write_obj(&iocb, &cow_hdr, epoch, buf);
	} else
		ret = do_write_obj(&iocb, hdr, epoch, request->data);

	if (SD_RES_SUCCESS == ret)
		check_and_insert_objlist_cache(hdr->oid);
out:
	if (buf)
		free(buf);
	sd_store->close(hdr->oid, &iocb);
	return ret;
}

static struct sd_op_template sd_ops[] = {

	/* cluster operations */
	[SD_OP_NEW_VDI] = {
		.type = SD_OP_TYPE_CLUSTER,
		.process_work = cluster_new_vdi,
		.process_main = post_cluster_new_vdi,
	},

	[SD_OP_DEL_VDI] = {
		.type = SD_OP_TYPE_CLUSTER,
		.process_work = cluster_del_vdi,
	},

	[SD_OP_GET_VDI_INFO] = {
		.type = SD_OP_TYPE_CLUSTER,
		.process_work = cluster_get_vdi_info,
	},

	[SD_OP_LOCK_VDI] = {
		.type = SD_OP_TYPE_CLUSTER,
		.process_work = cluster_get_vdi_info,
	},

	[SD_OP_MAKE_FS] = {
		.type = SD_OP_TYPE_CLUSTER,
		.force = 1,
		.process_main = cluster_make_fs,
	},

	[SD_OP_SHUTDOWN] = {
		.type = SD_OP_TYPE_CLUSTER,
		.process_main = cluster_shutdown,
	},

	[SD_OP_GET_VDI_ATTR] = {
		.type = SD_OP_TYPE_CLUSTER,
		.process_work = cluster_get_vdi_attr,
	},

	[SD_OP_RELEASE_VDI] = {
		.type = SD_OP_TYPE_CLUSTER,
	},

	[SD_OP_RECOVER] = {
		.type = SD_OP_TYPE_CLUSTER,
		.force = 1,
		.process_main = cluster_manual_recover,
	},

	[SD_OP_SNAPSHOT] = {
		.type = SD_OP_TYPE_CLUSTER,
		.force = 1,
		.process_main = cluster_snapshot,
	},

	[SD_OP_RESTORE] = {
		.type = SD_OP_TYPE_CLUSTER,
		.force = 1,
		.process_main = cluster_restore,
	},

	[SD_OP_CLEANUP] = {
		.type = SD_OP_TYPE_CLUSTER,
		.force = 1,
		.process_main = cluster_cleanup,
	},

	/* local operations */
	[SD_OP_GET_STORE_LIST] = {
		.type = SD_OP_TYPE_LOCAL,
		.force = 1,
		.process_work = local_get_store_list,
	},

	[SD_OP_READ_VDIS] = {
		.type = SD_OP_TYPE_LOCAL,
		.force = 1,
		.process_main = local_read_vdis,
	},

	[SD_OP_GET_NODE_LIST] = {
		.type = SD_OP_TYPE_LOCAL,
		.force = 1,
		.process_main = local_get_node_list,
	},

	[SD_OP_STAT_SHEEP] = {
		.type = SD_OP_TYPE_LOCAL,
		.process_work = local_stat_sheep,
	},

	[SD_OP_STAT_RECOVERY] = {
		.type = SD_OP_TYPE_LOCAL,
		.process_main = local_stat_recovery,
	},

	[SD_OP_STAT_CLUSTER] = {
		.type = SD_OP_TYPE_LOCAL,
		.force = 1,
		.process_work = local_stat_cluster,
	},

	[SD_OP_KILL_NODE] = {
		.type = SD_OP_TYPE_LOCAL,
		.force = 1,
		.process_work = local_kill_node,
	},

	[SD_OP_GET_OBJ_LIST] = {
		.type = SD_OP_TYPE_LOCAL,
		.process_work = local_get_obj_list,
	},

	[SD_OP_GET_EPOCH] = {
		.type = SD_OP_TYPE_LOCAL,
		.process_work = local_get_epoch,
	},

	[SD_OP_GET_SNAP_FILE] = {
		.type = SD_OP_TYPE_LOCAL,
		.force = 1,
		.process_work = local_get_snap_file,
	},

	[SD_OP_FLUSH_VDI] = {
		.type = SD_OP_TYPE_LOCAL,
		.process_work = local_flush_vdi,
	},

	[SD_OP_TRACE] = {
		.type = SD_OP_TYPE_LOCAL,
		.force = 1,
		.process_main = local_trace_ops,
	},

	[SD_OP_TRACE_CAT] = {
		.type = SD_OP_TYPE_LOCAL,
		.force = 1,
		.process_main = local_trace_cat_ops,
	},

	/* I/O operations */
	[SD_OP_CREATE_AND_WRITE_OBJ] = {
		.type = SD_OP_TYPE_IO,
		.process_work = store_create_and_write_obj,
	},

	[SD_OP_READ_OBJ] = {
		.type = SD_OP_TYPE_IO,
		.process_work = store_read_obj,
	},

	[SD_OP_WRITE_OBJ] = {
		.type = SD_OP_TYPE_IO,
		.process_work = store_write_obj,
	},

	[SD_OP_REMOVE_OBJ] = {
		.type = SD_OP_TYPE_IO,
		.process_work = store_remove_obj,
	},
};

struct sd_op_template *get_sd_op(uint8_t opcode)
{
	if (sd_ops[opcode].type == 0)
		return NULL;

	return sd_ops + opcode;
}

int is_cluster_op(struct sd_op_template *op)
{
	return op->type == SD_OP_TYPE_CLUSTER;
}

int is_local_op(struct sd_op_template *op)
{
	return op->type == SD_OP_TYPE_LOCAL;
}

int is_io_op(struct sd_op_template *op)
{
	return op->type == SD_OP_TYPE_IO;
}

int is_force_op(struct sd_op_template *op)
{
	return !!op->force;
}

int has_process_work(struct sd_op_template *op)
{
	return !!op->process_work;
}

int has_process_main(struct sd_op_template *op)
{
	return !!op->process_main;
}

int do_process_work(struct sd_op_template *op, const struct sd_req *req,
		    struct sd_rsp *rsp, void *data)
{
	return op->process_work(req, rsp, data);
}

int do_process_main(struct sd_op_template *op, const struct sd_req *req,
		    struct sd_rsp *rsp, void *data)
{
	return op->process_main(req, rsp, data);
}
