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

#include "sheep_priv.h"

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

static int cluster_new_vdi(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data)
{
	const struct sd_vdi_req *hdr = (const struct sd_vdi_req *)req;
	struct sd_vdi_rsp *vdi_rsp = (struct sd_vdi_rsp *)rsp;
	uint32_t vid = 0, nr_copies = sys->nr_sobjs;
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
	uint32_t vid = 0, nr_copies = sys->nr_sobjs;
	int ret;

	ret = del_vdi(hdr->epoch, data, hdr->data_length, &vid,
		      hdr->snapid, &nr_copies);

	vdi_rsp->vdi_id = vid;
	vdi_rsp->copies = nr_copies;

	return ret;
}

static int cluster_get_vdi_info(const struct sd_req *req, struct sd_rsp *rsp,
				void *data)
{
	const struct sd_vdi_req *hdr = (const struct sd_vdi_req *)req;
	struct sd_vdi_rsp *vdi_rsp = (struct sd_vdi_rsp *)rsp;
	uint32_t vid = 0, nr_copies = sys->nr_sobjs;
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

static int cluster_make_fs(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data)
{
	const struct sd_so_req *hdr = (const struct sd_so_req *)req;
	int i, latest_epoch, ret;
	uint64_t ctime;

	sys->nr_sobjs = hdr->copies;
	sys->flags = hdr->flags;
	if (!sys->nr_sobjs)
		sys->nr_sobjs = SD_DEFAULT_REDUNDANCY;

	ctime = hdr->ctime;
	set_cluster_ctime(ctime);

	latest_epoch = get_latest_epoch();
	for (i = 1; i <= latest_epoch; i++)
		remove_epoch(i);
	memset(sys->vdi_inuse, 0, sizeof(sys->vdi_inuse));

	sys->epoch = 1;
	sys->recovered_epoch = 1;

	ret = update_epoch_log(sys->epoch);
	if (ret)
		return SD_RES_EIO;

	update_epoch_store(sys->epoch);

	set_cluster_copies(sys->nr_sobjs);
	set_cluster_flags(sys->flags);

	if (sys_flag_nohalt())
		sys_stat_set(SD_STATUS_OK);
	else {
		int nr_zones = get_zones_nr_from(sys->nodes, sys->nr_nodes);

		if (nr_zones >= sys->nr_sobjs)
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
	uint32_t vid = 0, attrid = 0, nr_copies = sys->nr_sobjs;
	uint64_t ctime = 0;
	int ret;
	struct sheepdog_vdi_attr *vattr;

	vattr = data;
	ret = lookup_vdi(hdr->epoch, vattr->name, vattr->tag,
			 &vid, hdr->snapid, &nr_copies, &ctime);
	if (ret != SD_RES_SUCCESS)
		return ret;

	/* the current VDI id can change if we take a snapshot,
	   so we use the hash value of the VDI name as the VDI id */
	vid = fnv_64a_buf(vattr->name, strlen(vattr->name), FNV1A_64_INIT);
	vid &= SD_NR_VDIS - 1;
	ret = get_vdi_attr(hdr->epoch, data, hdr->data_length, vid,
			   &attrid, nr_copies, ctime,
			   hdr->flags & SD_FLAG_CMD_CREAT,
			   hdr->flags & SD_FLAG_CMD_EXCL,
			   hdr->flags & SD_FLAG_CMD_DEL);

	vdi_rsp->vdi_id = vid;
	vdi_rsp->attr_id = attrid;
	vdi_rsp->copies = nr_copies;

	return ret;
}

static int local_read_vdis(const struct sd_req *req, struct sd_rsp *rsp,
			   void *data)
{
	return read_vdis(data, req->data_length, &rsp->data_length);
}

static int get_node_idx(struct sheepdog_node_list_entry *ent,
			struct sheepdog_node_list_entry *entries, int nr_nodes)
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
	node_rsp->data_length = nr_nodes * sizeof(struct sheepdog_node_list_entry);
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

static int local_stat_cluster(const struct sd_req *req, struct sd_rsp *rsp,
			      void *data)
{
	struct epoch_log *log;
	int i, max_logs, epoch;
	uint32_t sys_stat = sys_stat_get();

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
	int epoch = obj_req->tgt_epoch;
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

	sys->nr_sobjs = c;
	sys->flags = f;

	s = SD_STATUS_OK;
	if (!sys_flag_nohalt()) {
		nr_zones = get_zones_nr_from(sys->nodes, sys->nr_nodes);
		if (nr_zones < sys->nr_sobjs)
			s = SD_STATUS_HALT;
	}

	dprintf("flags %d, nr_zones %d, copies %d\n", sys->flags, nr_zones, sys->nr_sobjs);

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

	/* local operations */
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
