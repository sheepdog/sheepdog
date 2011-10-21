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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/epoll.h>

#include "sheepdog_proto.h"
#include "sheep_priv.h"
#include "list.h"
#include "util.h"
#include "logger.h"
#include "work.h"
#include "cluster.h"

struct node {
	struct sheepdog_node_list_entry ent;
	struct list_head list;
};

struct join_message {
	uint8_t proto_ver;
	uint8_t nr_sobjs;
	uint16_t nr_nodes;
	uint16_t nr_leave_nodes;
	uint16_t cluster_flags;
	uint32_t cluster_status;
	uint32_t epoch;
	uint64_t ctime;
	uint32_t result;
	uint8_t inc_epoch; /* set non-zero when we increment epoch of all nodes */
	uint8_t pad[3];
	union {
		struct sheepdog_node_list_entry nodes[0];
		struct sheepdog_node_list_entry leave_nodes[0];
	};
};

struct vdi_op_message {
	struct sd_vdi_req req;
	struct sd_vdi_rsp rsp;
	uint8_t data[0];
};

struct work_notify {
	struct cpg_event cev;

	struct sheepdog_node_list_entry sender;

	struct message_header *msg;
};

struct work_join {
	struct cpg_event cev;

	struct sheepdog_node_list_entry *member_list;
	size_t member_list_entries;
	struct sheepdog_node_list_entry joined;

	struct join_message *jm;
};

struct work_leave {
	struct cpg_event cev;

	struct sheepdog_node_list_entry *member_list;
	size_t member_list_entries;
	struct sheepdog_node_list_entry left;
};

#define print_node_list(nodes, nr_nodes)			\
({								\
	char __name[128];					\
	int __i;						\
	for (__i = 0; __i < (nr_nodes); __i++) {		\
		dprintf("%c ip: %s, port: %d\n",		\
			is_myself(nodes[__i].addr, nodes[__i].port) ? 'l' : ' ', \
			addr_to_str(__name, sizeof(__name),	\
				    nodes[__i].addr, nodes[__i].port), \
			nodes[__i].port);			\
	}							\
})

static int cpg_event_running;

static size_t get_join_message_size(struct join_message *jm)
{
	/* jm->nr_nodes is always larger than jm->nr_leave_nodes, so
	 * it is safe to use jm->nr_nodes. */
	return sizeof(*jm) + jm->nr_nodes * sizeof(jm->nodes[0]);
}

static int get_node_idx(struct sheepdog_node_list_entry *ent,
			struct sheepdog_node_list_entry *entries, int nr_nodes)
{
	ent = bsearch(ent, entries, nr_nodes, sizeof(*ent), node_cmp);
	if (!ent)
		return -1;

	return ent - entries;
}

static int get_zones_nr_from(struct sheepdog_node_list_entry *nodes, int nr_nodes)
{
	int nr_zones = 0, i, j;
	uint32_t zones[SD_MAX_REDUNDANCY];

	for (i = 0; i < nr_nodes; i++) {
		for (j = 0; j < nr_zones; j++) {
			if (nodes[i].zone == zones[j])
				break;
		}
		if (j == nr_zones)
			zones[nr_zones++] = nodes[i].zone;

		if (nr_zones == ARRAY_SIZE(zones))
			break;
	}

	return nr_zones;
}

void get_ordered_sd_vnode_list(struct sheepdog_vnode_list_entry *entries,
			       int *nr_vnodes, int *nr_zones)
{
	*nr_zones = get_zones_nr_from(sys->nodes, sys->nr_nodes);

	memcpy(entries, sys->vnodes, sizeof(*entries) * sys->nr_vnodes);

	*nr_vnodes = sys->nr_vnodes;
}

void setup_ordered_sd_vnode_list(struct request *req)
{
	get_ordered_sd_vnode_list(req->entry, &req->nr_vnodes, &req->nr_zones);
}

static void get_node_list(struct sd_node_req *req,
			  struct sd_node_rsp *rsp, void *data)
{
	int nr_nodes;

	nr_nodes = sys->nr_nodes;
	memcpy(data, sys->nodes, sizeof(*sys->nodes) * nr_nodes);
	rsp->data_length = nr_nodes * sizeof(struct sheepdog_node_list_entry);
	rsp->nr_nodes = nr_nodes;
	rsp->local_idx = get_node_idx(&sys->this_node, data, nr_nodes);
	rsp->master_idx = -1;
}

static int get_epoch(struct sd_obj_req *req,
		      struct sd_obj_rsp *rsp, void *data)
{
	int epoch = req->tgt_epoch;
	int len, ret;
	dprintf("%d\n", epoch);
	len = epoch_log_read(epoch, (char *)data, req->data_length);
	if (len == -1) {
		ret = SD_RES_NO_TAG;
		rsp->data_length = 0;
	} else {
		ret = SD_RES_SUCCESS;
		rsp->data_length = len;
	}
	return ret;
}

static void vdi_op(void *arg);

void cluster_queue_request(struct work *work, int idx)
{
	struct request *req = container_of(work, struct request, work);
	struct sd_req *hdr = (struct sd_req *)&req->rq;
	struct sd_rsp *rsp = (struct sd_rsp *)&req->rp;
	struct vdi_op_message *msg;
	struct epoch_log *log;
	int ret = SD_RES_SUCCESS, i, max_logs, epoch;
	uint32_t sys_stat = sys_stat_get();
	size_t size;

	eprintf("%p %x\n", req, hdr->opcode);

	switch (hdr->opcode) {
	case SD_OP_GET_EPOCH:
		ret = get_epoch((struct sd_obj_req *)hdr,
			  (struct sd_obj_rsp *)rsp, req->data);
		break;
	case SD_OP_GET_NODE_LIST:
		get_node_list((struct sd_node_req *)hdr,
			      (struct sd_node_rsp *)rsp, req->data);
		break;
	case SD_OP_STAT_CLUSTER:
		max_logs = rsp->data_length / sizeof(*log);
		epoch = get_latest_epoch();
		rsp->data_length = 0;
		for (i = 0; i < max_logs; i++) {
			if (epoch <= 0)
				break;

			log = (struct epoch_log *)req->data + i;
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
			epoch--;
		}

		switch (sys_stat) {
		case SD_STATUS_OK:
			ret = SD_RES_SUCCESS;
			break;
		case SD_STATUS_WAIT_FOR_FORMAT:
			ret = SD_RES_WAIT_FOR_FORMAT;
			break;
		case SD_STATUS_WAIT_FOR_JOIN:
			ret = SD_RES_WAIT_FOR_JOIN;
			break;
		case SD_STATUS_SHUTDOWN:
			ret = SD_RES_SHUTDOWN;
			break;
		case SD_STATUS_JOIN_FAILED:
			ret = SD_RES_JOIN_FAILED;
			break;
		case SD_STATUS_HALT:
			ret = SD_RES_HALT;
			break;
		default:
			ret = SD_RES_SYSTEM_ERROR;
			break;
		}
		break;
	default:
		/* forward request to group */
		goto forward;
	}

	rsp->result = ret;
	return;

forward:
	if (hdr->flags & SD_FLAG_CMD_WRITE)
		size = sizeof(*msg);
	else
		size = sizeof(*msg) + hdr->data_length;

	msg = zalloc(size);
	if (!msg) {
		eprintf("out of memory\n");
		return;
	}

	msg->req = *((struct sd_vdi_req *)&req->rq);
	msg->rsp = *((struct sd_vdi_rsp *)&req->rp);

	list_add(&req->pending_list, &sys->pending_list);

	sys->cdrv->notify(msg, size, vdi_op);

	free(msg);
}

static void group_handler(int listen_fd, int events, void *data)
{
	int ret;
	if (events & EPOLLHUP) {
		eprintf("Receive EPOLLHUP event. Is corosync stopped running?\n");
		goto out;
	}

	ret = sys->cdrv->dispatch();
	if (ret == 0)
		return;
	else
		eprintf("oops...some error occured inside corosync\n");
out:
	log_close();
	exit(1);
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

static int get_nodes_nr_epoch(int epoch)
{
	struct sheepdog_node_list_entry nodes[SD_MAX_NODES];
	int nr;

	nr = epoch_log_read(epoch, (char *)nodes, sizeof(nodes));
	nr /= sizeof(nodes[0]);
	return nr;
}

static struct sheepdog_node_list_entry *find_entry_list(struct sheepdog_node_list_entry *entry,
							struct list_head *head)
{
	struct node *n;
	list_for_each_entry(n, head, list)
		if (node_cmp(&n->ent, entry) == 0)
			return entry;

	return NULL;

}

static struct sheepdog_node_list_entry *find_entry_epoch(struct sheepdog_node_list_entry *entry,
							 int epoch)
{
	struct sheepdog_node_list_entry nodes[SD_MAX_NODES];
	int nr, i;

	nr = epoch_log_read_nr(epoch, (char *)nodes, sizeof(nodes));

	for (i = 0; i < nr; i++)
		if (node_cmp(&nodes[i], entry) == 0)
			return entry;

	return NULL;
}

static int cluster_sanity_check(struct sheepdog_node_list_entry *entries,
			     int nr_entries, uint64_t ctime, uint32_t epoch)
{
	int ret = SD_RES_SUCCESS, nr_local_entries;
	struct sheepdog_node_list_entry local_entries[SD_MAX_NODES];
	uint32_t lepoch;

	if (sys_stat_wait_format() || sys_stat_shutdown())
		goto out;
	/* When the joinning node is newly created, we need to check nothing. */
	if (nr_entries == 0)
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

static int get_cluster_status(struct sheepdog_node_list_entry *from,
			      struct sheepdog_node_list_entry *entries,
			      int nr_entries, uint64_t ctime, uint32_t epoch,
			      uint32_t *status, uint8_t *inc_epoch)
{
	int i, j, ret = SD_RES_SUCCESS;
	int nr, nr_local_entries, nr_leave_entries;
	struct sheepdog_node_list_entry local_entries[SD_MAX_NODES];
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
		nr = sys->nr_nodes + 1;
		nr_local_entries = epoch_log_read_nr(epoch, (char *)local_entries,
						  sizeof(local_entries));

		if (nr != nr_local_entries) {
			nr_leave_entries = get_nodes_nr_from(&sys->leave_list);
			if (nr_local_entries == nr + nr_leave_entries) {
				/* Even though some nodes leave, we can make do with it.
				 * Order cluster to do recovery right now.
				 */
				if (inc_epoch)
					*inc_epoch = 1;
				*status = SD_STATUS_OK;
			}
			break;
		}

		for (i = 0; i < nr_local_entries; i++) {
			if (node_cmp(local_entries + i, from) == 0)
				goto next;
			for (j = 0; j < sys->nr_nodes; j++) {
				if (node_cmp(local_entries + i, sys->nodes + j) == 0)
					goto next;
			}
			break;
		next:
			;
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

static void join(struct sheepdog_node_list_entry *joining, struct join_message *msg)
{
	if (msg->proto_ver != SD_SHEEP_PROTO_VER) {
		eprintf("joining node send a wrong version message\n");
		msg->result = SD_RES_VER_MISMATCH;
		return;
	}

	msg->result = get_cluster_status(joining, msg->nodes, msg->nr_nodes,
					 msg->ctime, msg->epoch,
					 &msg->cluster_status, &msg->inc_epoch);
	msg->nr_sobjs = sys->nr_sobjs;
	msg->cluster_flags = sys->flags;
	msg->ctime = get_cluster_ctime();
}

static int get_vdi_bitmap_from(struct sheepdog_node_list_entry *node)
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
		vprintf(SDOG_ERR, "can't get the vdi bitmap %s, %m\n", host);
		ret = -SD_RES_EIO;
		goto out;
	}

	vprintf(SDOG_ERR, "get the vdi bitmap from %s\n", host);

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
		vprintf(SDOG_ERR, "can't get the vdi bitmap %d %d\n", ret,
				rsp->result);
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(sys->vdi_inuse); i++)
		sys->vdi_inuse[i] |= tmp_vdi_inuse[i];
out:
	return ret;
}

static void get_vdi_bitmap_from_sd_list(void)
{
	int i;
	/* fixme: we need this until starting up. */

	for (i = 0; i < sys->nr_nodes; i++)
		get_vdi_bitmap_from(sys->nodes + i);
}

static int update_epoch_log(int epoch)
{
	int ret;

	dprintf("update epoch, %d, %d\n", epoch, sys->nr_nodes);
	ret = epoch_log_write(epoch, (char *)sys->nodes,
			      sys->nr_nodes * sizeof(struct sheepdog_node_list_entry));
	if (ret < 0)
		eprintf("can't write epoch %u\n", epoch);

	return ret;
}

static void update_cluster_info(struct join_message *msg,
				struct sheepdog_node_list_entry *joined,
				struct sheepdog_node_list_entry *nodes,
				size_t nr_nodes)
{
	int i, le;
	int nr_leave_nodes;
	struct node *n;

	eprintf("status = %d, epoch = %d, %x, %d\n", msg->cluster_status, msg->epoch, msg->result, sys->join_finished);

	if (sys_stat_join_failed())
		return;

	if (sys->join_finished)
		goto join_finished;

	sys->nr_sobjs = msg->nr_sobjs;
	sys->epoch = msg->epoch;

	/* add nodes execept for newly joined one */
	for (i = 0; i < nr_nodes; i++) {
		if (node_cmp(nodes + i, joined) == 0)
			continue;

		sys->nodes[sys->nr_nodes++] = nodes[i];
	}
	qsort(sys->nodes, sys->nr_nodes, sizeof(*sys->nodes), node_cmp);

	if (msg->cluster_status != SD_STATUS_OK) {
		nr_leave_nodes = msg->nr_leave_nodes;
		le = get_latest_epoch();
		for (i = 0; i < nr_leave_nodes; i++) {
			n = zalloc(sizeof(*n));
			if (!n)
				panic("oom\n");

			if (find_entry_list(&msg->leave_nodes[i], &sys->leave_list)
			    || !find_entry_epoch(&msg->leave_nodes[i], le)) {
				free(n);
				continue;
			}

			n->ent = msg->leave_nodes[i];

			list_add_tail(&n->list, &sys->leave_list);
		}
	}

	sys->join_finished = 1;

	if ((msg->cluster_status == SD_STATUS_OK || msg->cluster_status == SD_STATUS_HALT)
	     && msg->inc_epoch)
		update_epoch_log(sys->epoch);

join_finished:
	sys->nodes[sys->nr_nodes++] = *joined;
	qsort(sys->nodes, sys->nr_nodes, sizeof(*sys->nodes), node_cmp);
	sys->nr_vnodes = nodes_to_vnodes(sys->nodes, sys->nr_nodes,
					 sys->vnodes);
	if (msg->cluster_status == SD_STATUS_OK ||
	    msg->cluster_status == SD_STATUS_HALT) {
		if (msg->inc_epoch) {
			sys->epoch++;
			update_epoch_log(sys->epoch);
			update_epoch_store(sys->epoch);
		}
		/* Fresh node */
		if (!sys_stat_ok() && !sys_stat_halt()) {
			set_cluster_copies(sys->nr_sobjs);
			set_cluster_flags(sys->flags);
			set_cluster_ctime(msg->ctime);
		}
	}

	print_node_list(sys->nodes, sys->nr_nodes);

	sys_stat_set(msg->cluster_status);
	return;
}

static void vdi_op(void *arg)
{
	struct vdi_op_message *msg = arg;
	const struct sd_vdi_req *hdr = &msg->req;
	struct sd_vdi_rsp *rsp = &msg->rsp;
	void *data, *tag;
	int ret = SD_RES_SUCCESS;
	struct sheepdog_vdi_attr *vattr;
	uint32_t vid = 0, attrid = 0, nr_copies = sys->nr_sobjs;
	uint64_t ctime = 0;
	struct request *req;

	req = list_first_entry(&sys->pending_list, struct request, pending_list);
	data = req->data;

	switch (hdr->opcode) {
	case SD_OP_NEW_VDI:
		ret = add_vdi(hdr->epoch, data, hdr->data_length, hdr->vdi_size, &vid,
			      hdr->base_vdi_id, hdr->copies,
			      hdr->snapid, &nr_copies);
		break;
	case SD_OP_DEL_VDI:
		ret = del_vdi(hdr->epoch, data, hdr->data_length, &vid,
			      hdr->snapid, &nr_copies);
		break;
	case SD_OP_LOCK_VDI:
	case SD_OP_GET_VDI_INFO:
		if (hdr->proto_ver != SD_PROTO_VER) {
			ret = SD_RES_VER_MISMATCH;
			break;
		}
		if (hdr->data_length == SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN)
			tag = (char *)data + SD_MAX_VDI_LEN;
		else if (hdr->data_length == SD_MAX_VDI_LEN)
			tag = NULL;
		else {
			ret = SD_RES_INVALID_PARMS;
			break;
		}
		ret = lookup_vdi(hdr->epoch, data, tag, &vid, hdr->snapid,
				 &nr_copies, NULL);
		if (ret != SD_RES_SUCCESS)
			break;
		break;
	case SD_OP_GET_VDI_ATTR:
		vattr = data;
		ret = lookup_vdi(hdr->epoch, vattr->name, vattr->tag,
				 &vid, hdr->snapid, &nr_copies, &ctime);
		if (ret != SD_RES_SUCCESS)
			break;
		/* the curernt vdi id can change if we take the snapshot,
		   so we use the hash value of the vdi name as the vdi id */
		vid = fnv_64a_buf(vattr->name, strlen(vattr->name), FNV1A_64_INIT);
		vid &= SD_NR_VDIS - 1;
		ret = get_vdi_attr(hdr->epoch, data, hdr->data_length, vid,
				   &attrid, nr_copies, ctime,
				   hdr->flags & SD_FLAG_CMD_CREAT,
				   hdr->flags & SD_FLAG_CMD_EXCL,
				   hdr->flags & SD_FLAG_CMD_DEL);
		break;
	case SD_OP_RELEASE_VDI:
		break;
	case SD_OP_MAKE_FS:
		ret = SD_RES_SUCCESS;
		break;
	case SD_OP_SHUTDOWN:
		break;
	default:
		ret = SD_RES_SYSTEM_ERROR;
		eprintf("opcode %d is not implemented\n", hdr->opcode);
		break;
	}

	rsp->vdi_id = vid;
	rsp->attr_id = attrid;
	rsp->copies = nr_copies;
	rsp->result = ret;
}

static void __sd_notify(struct cpg_event *cevent)
{
}

static void __sd_notify_done(struct cpg_event *cevent)
{
	struct work_notify *w = container_of(cevent, struct work_notify, cev);
	struct vdi_op_message *msg = (struct vdi_op_message *)w->msg;
	const struct sd_vdi_req *hdr = &msg->req;
	struct sd_vdi_rsp *rsp = &msg->rsp;
	void *data = msg->data;
	struct request *req;
	int ret = msg->rsp.result;
	int i, latest_epoch;
	uint64_t ctime;

	if (ret != SD_RES_SUCCESS)
		goto out;

	switch (hdr->opcode) {
	case SD_OP_NEW_VDI:
	{
		unsigned long nr = rsp->vdi_id;
		vprintf(SDOG_INFO, "done %d %ld\n", ret, nr);
		set_bit(nr, sys->vdi_inuse);
		break;
	}
	case SD_OP_DEL_VDI:
		break;
	case SD_OP_LOCK_VDI:
	case SD_OP_RELEASE_VDI:
	case SD_OP_GET_VDI_INFO:
	case SD_OP_GET_VDI_ATTR:
		break;
	case SD_OP_MAKE_FS:
		sys->nr_sobjs = ((struct sd_so_req *)hdr)->copies;
		sys->flags = ((struct sd_so_req *)hdr)->flags;
		if (!sys->nr_sobjs)
			sys->nr_sobjs = SD_DEFAULT_REDUNDANCY;

		ctime = ((struct sd_so_req *)hdr)->ctime;
		set_cluster_ctime(ctime);

		latest_epoch = get_latest_epoch();
		for (i = 1; i <= latest_epoch; i++)
			remove_epoch(i);
		memset(sys->vdi_inuse, 0, sizeof(sys->vdi_inuse));

		sys->epoch = 1;
		sys->recovered_epoch = 1;

		dprintf("write epoch log, %d, %d\n", sys->epoch, sys->nr_nodes);
		ret = epoch_log_write(sys->epoch, (char *)sys->nodes,
				      sys->nr_nodes * sizeof(struct sheepdog_node_list_entry));
		if (ret < 0)
			eprintf("can't write epoch %u\n", sys->epoch);
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
		break;
	case SD_OP_SHUTDOWN:
		sys_stat_set(SD_STATUS_SHUTDOWN);
		break;
	default:
		eprintf("unknown operation %d\n", hdr->opcode);
		ret = SD_RES_UNKNOWN;
	}
out:
	if (!is_myself(w->sender.addr, w->sender.port))
		return;

	req = list_first_entry(&sys->pending_list, struct request, pending_list);

	rsp->result = ret;
	memcpy(req->data, data, rsp->data_length);
	memcpy(&req->rp, rsp, sizeof(req->rp));
	list_del(&req->pending_list);
	req->done(req);
}

static void sd_notify_handler(struct sheepdog_node_list_entry *sender,
			      void *msg, size_t msg_len)
{
	struct cpg_event *cevent;
	struct work_notify *w;

	dprintf("size: %zd, from: %s\n", msg_len, node_to_str(sender));

	w = zalloc(sizeof(*w));
	if (!w)
		return;

	cevent = &w->cev;
	cevent->ctype = CPG_EVENT_NOTIFY;

	vprintf(SDOG_DEBUG, "allow new deliver, %p\n", cevent);

	w->sender = *sender;
	if (msg_len) {
		w->msg = zalloc(msg_len);
		if (!w->msg)
			return;
		memcpy(w->msg, msg, msg_len);
	} else
		w->msg = NULL;

	list_add_tail(&cevent->cpg_event_list, &sys->cpg_event_siblings);

	start_cpg_event_work();
}

/*
 * Check whether the majority of Sheepdog nodes are still alive or not
 */
static int check_majority(struct sheepdog_node_list_entry *nodes, int nr_nodes)
{
	int nr_majority, nr_reachable = 0, fd, i;
	char name[INET6_ADDRSTRLEN];

	nr_majority = nr_nodes / 2 + 1;

	/* we need at least 3 nodes to handle network partition
	 * failure */
	if (nr_nodes < 3)
		return 1;

	for (i = 0; i < nr_nodes; i++) {
		addr_to_str(name, sizeof(name), nodes[i].addr, 0);
		fd = connect_to(name, nodes[i].port);
		if (fd < 0)
			continue;

		close(fd);
		nr_reachable++;
		if (nr_reachable >= nr_majority) {
			dprintf("majority nodes are alive\n");
			return 1;
		}
	}
	dprintf("%d, %d, %d\n", nr_nodes, nr_majority, nr_reachable);
	eprintf("majority nodes are not alive\n");
	return 0;
}

static void __sd_join(struct cpg_event *cevent)
{
	struct work_join *w = container_of(cevent, struct work_join, cev);
	struct join_message *msg = w->jm;
	int i;

	if (msg->cluster_status != SD_STATUS_OK)
		return;

	if (sys_stat_ok())
		return;

	get_vdi_bitmap_from_sd_list();
	for (i = 0; i < w->member_list_entries; i++)
		get_vdi_bitmap_from(w->member_list + i);
}

static void __sd_leave(struct cpg_event *cevent)
{
	struct work_leave *w = container_of(cevent, struct work_leave, cev);

	if (!check_majority(w->member_list, w->member_list_entries)) {
		eprintf("perhaps network partition failure has occurred\n");
		abort();
	}
}

static enum cluster_join_result sd_check_join_cb(
	struct sheepdog_node_list_entry *joining, void *opaque)
{
	struct message_header *m = opaque;
	struct join_message *jm;
	struct node *node;

	jm = (struct join_message *)m;

	if (node_cmp(joining, &sys->this_node) == 0) {
		struct sheepdog_node_list_entry entries[SD_MAX_NODES];
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

	join(joining, jm);

	dprintf("%d, %d\n", jm->result, jm->cluster_status);
	if (jm->result == SD_RES_SUCCESS && jm->cluster_status != SD_STATUS_OK) {
		jm->nr_leave_nodes = 0;
		list_for_each_entry(node, &sys->leave_list, list) {
			jm->leave_nodes[jm->nr_leave_nodes] = node->ent;
			jm->nr_leave_nodes++;
		}
	} else if (jm->result != SD_RES_SUCCESS &&
			jm->epoch > sys->epoch &&
			jm->cluster_status == SD_STATUS_WAIT_FOR_JOIN) {
		eprintf("Transfer mastership. %d, %d\n", jm->epoch, sys->epoch);
		return CJ_RES_MASTER_TRANSFER;
	}
	jm->epoch = sys->epoch;

	if (jm->result == SD_RES_SUCCESS)
		return CJ_RES_SUCCESS;
	else if (jm->result == SD_RES_OLD_NODE_VER ||
		 jm->result == SD_RES_NEW_NODE_VER)
		return CJ_RES_JOIN_LATER;
	else
		return CJ_RES_FAIL;
}

static int send_join_request(struct sheepdog_node_list_entry *ent)
{
	struct join_message *msg;
	int nr_entries, ret;

	msg = zalloc(sizeof(*msg) + SD_MAX_NODES * sizeof(msg->nodes[0]));
	if (!msg)
		panic("oom\n");
	msg->proto_ver = SD_SHEEP_PROTO_VER;

	get_cluster_copies(&msg->nr_sobjs);
	get_cluster_flags(&msg->cluster_flags);

	nr_entries = SD_MAX_NODES;
	ret = read_epoch(&msg->epoch, &msg->ctime, msg->nodes, &nr_entries);
	if (ret == SD_RES_SUCCESS)
		msg->nr_nodes = nr_entries;

	ret = sys->cdrv->join(ent, sd_check_join_cb, msg,
			      get_join_message_size(msg));

	vprintf(SDOG_INFO, "%s\n", node_to_str(&sys->this_node));

	free(msg);

	return ret;
}

static void __sd_join_done(struct cpg_event *cevent)
{
	struct work_join *w = container_of(cevent, struct work_join, cev);
	struct join_message *jm = w->jm;
	struct node *node, *t;

	print_node_list(sys->nodes, sys->nr_nodes);

	update_cluster_info(jm, &w->joined, w->member_list, w->member_list_entries);

	if (sys_can_recover()) {
		list_for_each_entry_safe(node, t, &sys->leave_list, list) {
			list_del(&node->list);
		}
		start_recovery(sys->epoch);
	}

	if (sys_stat_halt()) {
		int nr_zones = get_zones_nr_from(sys->nodes, sys->nr_nodes);

		if (nr_zones >= sys->nr_sobjs)
			sys_stat_set(SD_STATUS_OK);
	}
}

static void __sd_leave_done(struct cpg_event *cevent)
{
	struct work_leave *w = container_of(cevent, struct work_leave, cev);

	sys->nr_nodes = w->member_list_entries;
	memcpy(sys->nodes, w->member_list, sizeof(*sys->nodes) * sys->nr_nodes);
	qsort(sys->nodes, sys->nr_nodes, sizeof(*sys->nodes), node_cmp);
	sys->nr_vnodes = nodes_to_vnodes(sys->nodes, sys->nr_nodes,
					 sys->vnodes);
	if (sys_can_recover()) {
		dprintf("update epoch, %d, %d\n", sys->epoch + 1, sys->nr_nodes);
		epoch_log_write(sys->epoch + 1, (char *)sys->nodes,
				sizeof(*sys->nodes) * sys->nr_nodes);

		sys->epoch++;

		update_epoch_store(sys->epoch);
	}

	print_node_list(sys->nodes, sys->nr_nodes);

	if (sys_can_recover())
		start_recovery(sys->epoch);

	if (sys_can_halt()) {
		int nr_zones = get_zones_nr_from(sys->nodes, sys->nr_nodes);

		if (nr_zones < sys->nr_sobjs)
			sys_stat_set(SD_STATUS_HALT);
	}
}

static void cpg_event_free(struct cpg_event *cevent)
{
	switch (cevent->ctype) {
	case CPG_EVENT_JOIN: {
		struct work_join *w = container_of(cevent, struct work_join, cev);
		free(w->member_list);
		free(w);
		break;
	}
	case CPG_EVENT_LEAVE: {
		struct work_leave *w = container_of(cevent, struct work_leave, cev);
		free(w->member_list);
		free(w);
		break;
	}
	case CPG_EVENT_NOTIFY: {
		struct work_notify *w = container_of(cevent, struct work_notify, cev);
		free(w->msg);
		free(w);
		break;
	}
	default:
		break;
	}
}

static struct work cpg_event_work;

static void cpg_event_fn(struct work *work, int idx)
{
	struct cpg_event *cevent = sys->cur_cevent;

	/*
	 * we can't touch sys->cpg_event_siblings because of a race
	 * with sd_deliver() and sd_confchg()...
	 */

	switch (cevent->ctype) {
	case CPG_EVENT_JOIN:
		__sd_join(cevent);
		break;
	case CPG_EVENT_LEAVE:
		__sd_leave(cevent);
		break;
	case CPG_EVENT_NOTIFY:
		__sd_notify(cevent);
		break;
	case CPG_EVENT_REQUEST:
		vprintf(SDOG_ERR, "should not happen\n");
		break;
	default:
		vprintf(SDOG_ERR, "unknown event %d\n", cevent->ctype);
	}
}

static void cpg_event_done(struct work *work, int idx)
{
	struct cpg_event *cevent;

	if (!sys->cur_cevent)
		vprintf(SDOG_ERR, "bug\n");

	cevent = sys->cur_cevent;
	sys->cur_cevent = NULL;

	vprintf(SDOG_DEBUG, "%p\n", cevent);

	switch (cevent->ctype) {
	case CPG_EVENT_JOIN:
		__sd_join_done(cevent);
		break;
	case CPG_EVENT_LEAVE:
		__sd_leave_done(cevent);
		break;
	case CPG_EVENT_NOTIFY:
		__sd_notify_done(cevent);
		break;
	case CPG_EVENT_REQUEST:
		vprintf(SDOG_ERR, "should not happen\n");
		break;
	default:
		vprintf(SDOG_ERR, "unknown event %d\n", cevent->ctype);
	}

	vprintf(SDOG_DEBUG, "free %p\n", cevent);
	cpg_event_free(cevent);
	cpg_event_running = 0;

	if (!list_empty(&sys->cpg_event_siblings))
		start_cpg_event_work();
}

static int check_epoch(struct request *req)
{
	uint32_t req_epoch = req->rq.epoch;
	uint32_t opcode = req->rq.opcode;
	int ret = SD_RES_SUCCESS;

	if (before(req_epoch, sys->epoch)) {
		ret = SD_RES_OLD_NODE_VER;
		eprintf("old node version %u %u, %x\n",
			sys->epoch, req_epoch, opcode);
	} else if (after(req_epoch, sys->epoch)) {
		ret = SD_RES_NEW_NODE_VER;
			eprintf("new node version %u %u %x\n",
				sys->epoch, req_epoch, opcode);
	}
	return ret;
}

int is_access_to_busy_objects(uint64_t oid)
{
	struct request *req;

	if (!oid)
		return 0;

	list_for_each_entry(req, &sys->outstanding_req_list, r_wlist) {
		if (req->rq.flags & SD_FLAG_CMD_RECOVERY) {
			if (req->rq.opcode != SD_OP_READ_OBJ)
				eprintf("bug\n");
			continue;
		}
		if (oid == req->local_oid)
				return 1;
	}
	return 0;
}

static int __is_access_to_recoverying_objects(struct request *req)
{
	if (req->rq.flags & SD_FLAG_CMD_RECOVERY) {
		if (req->rq.opcode != SD_OP_READ_OBJ)
			eprintf("bug\n");
		return 0;
	}

	if (is_recoverying_oid(req->local_oid))
		return 1;

	return 0;
}

static int __is_access_to_busy_objects(struct request *req)
{
	if (req->rq.flags & SD_FLAG_CMD_RECOVERY) {
		if (req->rq.opcode != SD_OP_READ_OBJ)
			eprintf("bug\n");
		return 0;
	}

	if (is_access_to_busy_objects(req->local_oid))
		return 1;

	return 0;
}

/* can be called only by the main process */
void start_cpg_event_work(void)
{
	struct cpg_event *cevent, *n;
	LIST_HEAD(failed_req_list);
	int retry;

	if (list_empty(&sys->cpg_event_siblings))
		vprintf(SDOG_ERR, "bug\n");

	cevent = list_first_entry(&sys->cpg_event_siblings,
				  struct cpg_event, cpg_event_list);
	/*
	 * we need to serialize cpg events so we don't call queue_work
	 * if a thread is still running for a cpg event; executing
	 * cpg_event_fn() or cpg_event_done().
	 */
	if (cpg_event_running && is_membership_change_event(cevent->ctype))
		return;
do_retry:
	retry = 0;

	list_for_each_entry_safe(cevent, n, &sys->cpg_event_siblings, cpg_event_list) {
		struct request *req = container_of(cevent, struct request, cev);

		if (cevent->ctype == CPG_EVENT_NOTIFY)
			continue;
		if (is_membership_change_event(cevent->ctype))
			break;

		list_del(&cevent->cpg_event_list);

		if (is_io_request(req->rq.opcode)) {
			int copies = sys->nr_sobjs;

			if (copies > req->nr_zones)
				copies = req->nr_zones;

			if (__is_access_to_recoverying_objects(req)) {
				if (req->rq.flags & SD_FLAG_CMD_DIRECT) {
					req->rp.result = SD_RES_NEW_NODE_VER;
					sys->nr_outstanding_io++; /* TODO: cleanup */
					list_add_tail(&req->r_wlist, &failed_req_list);
				} else
					list_add_tail(&req->r_wlist, &sys->req_wait_for_obj_list);
				continue;
			}
			if (__is_access_to_busy_objects(req)) {
				list_add_tail(&req->r_wlist, &sys->req_wait_for_obj_list);
				continue;
			}

			list_add_tail(&req->r_wlist, &sys->outstanding_req_list);

			sys->nr_outstanding_io++;

			if (is_access_local(req->entry, req->nr_vnodes,
					    ((struct sd_obj_req *)&req->rq)->oid, copies) ||
			    is_access_local(req->entry, req->nr_vnodes,
					    ((struct sd_obj_req *)&req->rq)->cow_oid, copies)) {
				int ret = check_epoch(req);
				if (ret != SD_RES_SUCCESS) {
					req->rp.result = ret;
					list_del(&req->r_wlist);
					list_add_tail(&req->r_wlist, &failed_req_list);
					continue;
				}
			}

			if (!(req->rq.flags & SD_FLAG_CMD_DIRECT) &&
			    req->rq.opcode == SD_OP_READ_OBJ) {
				struct sd_obj_req *hdr = (struct sd_obj_req *)&req->rq;
				uint32_t vdi_id = oid_to_vid(hdr->oid);
				struct data_object_bmap *bmap;

				req->check_consistency = 1;
				if (!is_vdi_obj(hdr->oid)) {
					list_for_each_entry(bmap, &sys->consistent_obj_list, list) {
						if (bmap->vdi_id == vdi_id) {
							if (test_bit(data_oid_to_idx(hdr->oid), bmap->dobjs))
								req->check_consistency = 0;
							break;
						}
					}
				}
			}
		}

		if (is_cluster_request(req->rq.opcode))
			queue_work(sys->cpg_wqueue, &req->work);
		else if (req->rq.flags & SD_FLAG_CMD_DIRECT)
			queue_work(sys->io_wqueue, &req->work);
		else
			queue_work(sys->gateway_wqueue, &req->work);
	}

	while (!list_empty(&failed_req_list)) {
		struct request *req = list_first_entry(&failed_req_list,
						       struct request, r_wlist);
		req->work.done(&req->work, 0);

		retry = 1;
	}

	if (retry)
		goto do_retry;

	if (cpg_event_running || list_empty(&sys->cpg_event_siblings))
		return;

	cevent = list_first_entry(&sys->cpg_event_siblings,
				  struct cpg_event, cpg_event_list);

	if (is_membership_change_event(cevent->ctype) && sys->nr_outstanding_io)
		return;

	list_del(&cevent->cpg_event_list);
	sys->cur_cevent = cevent;

	cpg_event_running = 1;

	INIT_LIST_HEAD(&cpg_event_work.w_list);
	cpg_event_work.fn = cpg_event_fn;
	cpg_event_work.done = cpg_event_done;

	queue_work(sys->cpg_wqueue, &cpg_event_work);
}

static void sd_join_handler(struct sheepdog_node_list_entry *joined,
			    struct sheepdog_node_list_entry *members,
			    size_t nr_members, enum cluster_join_result result,
			    void *opaque)
{
	struct cpg_event *cevent;
	struct work_join *w = NULL;
	int i, size;
	int nr, nr_local, nr_leave;
	struct node *n;
	struct join_message *jm;
	int le = get_latest_epoch();

	if (node_cmp(joined, &sys->this_node) == 0) {
		if (result == CJ_RES_FAIL) {
			eprintf("failed to join sheepdog\n");
			sys->cdrv->leave();
			exit(1);
		} else if (result == CJ_RES_JOIN_LATER) {
			eprintf("Restart me later when master is up, please .Bye.\n");
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

		w = zalloc(sizeof(*w));
		if (!w)
			panic("oom");

		cevent = &w->cev;
		cevent->ctype = CPG_EVENT_JOIN;

		vprintf(SDOG_DEBUG, "allow new confchg, %p\n", cevent);

		size = sizeof(struct sheepdog_node_list_entry) * nr_members;
		w->member_list = zalloc(size);
		if (!w->member_list)
			panic("oom");

		memcpy(w->member_list, members, size);
		w->member_list_entries = nr_members;

		w->joined = *joined;

		size = get_join_message_size(opaque);
		w->jm = zalloc(size);
		if (!w->jm)
			panic("oom\n");
		memcpy(w->jm, opaque, size);

		list_add_tail(&cevent->cpg_event_list, &sys->cpg_event_siblings);
		start_cpg_event_work();
		break;
	case CJ_RES_FAIL:
	case CJ_RES_JOIN_LATER:
		if (!sys_stat_wait_join())
			break;

		n = zalloc(sizeof(*n));
		if (!n)
			panic("oom\n");

		if (find_entry_list(joined, &sys->leave_list)
		    || !find_entry_epoch(joined, le)) {
			free(n);
			break;
		}

		n->ent = *joined;

		list_add_tail(&n->list, &sys->leave_list);

		nr_local = get_nodes_nr_epoch(sys->epoch);
		nr = nr_members;
		nr_leave = get_nodes_nr_from(&sys->leave_list);

		dprintf("%d == %d + %d \n", nr_local, nr, nr_leave);
		if (nr_local == nr + nr_leave) {
			sys_stat_set(SD_STATUS_OK);
			update_epoch_log(sys->epoch);
			update_epoch_store(sys->epoch);
		}
		break;
	case CJ_RES_MASTER_TRANSFER:
		jm = (struct join_message *)opaque;
		nr = jm->nr_leave_nodes;
		for (i = 0; i < nr; i++) {
			n = zalloc(sizeof(*n));
			if (!n)
				panic("oom\n");

			if (find_entry_list(&jm->leave_nodes[i], &sys->leave_list)
			    || !find_entry_epoch(&jm->leave_nodes[i], le)) {
				free(n);
				continue;
			}

			n->ent = jm->leave_nodes[i];

			list_add_tail(&n->list, &sys->leave_list);
		}

		/* Sheep needs this to identify itself as master.
		 * Now mastership transfer is done.
		 */
		if (!sys->join_finished) {
			sys->join_finished = 1;
			sys->nodes[sys->nr_nodes++] = sys->this_node;
			qsort(sys->nodes, sys->nr_nodes, sizeof(*sys->nodes), node_cmp);
			sys->nr_vnodes = nodes_to_vnodes(sys->nodes, sys->nr_nodes,
							 sys->vnodes);
			sys->epoch = get_latest_epoch();
		}

		nr_local = get_nodes_nr_epoch(sys->epoch);
		nr = nr_members;
		nr_leave = get_nodes_nr_from(&sys->leave_list);

		dprintf("%d == %d + %d \n", nr_local, nr, nr_leave);
		if (nr_local == nr + nr_leave) {
			sys_stat_set(SD_STATUS_OK);
			update_epoch_log(sys->epoch);
			update_epoch_store(sys->epoch);
		}
		break;
	}
}

static void sd_leave_handler(struct sheepdog_node_list_entry *left,
			     struct sheepdog_node_list_entry *members,
			     size_t nr_members)
{
	struct cpg_event *cevent;
	struct work_leave *w = NULL;
	int i, size;

	dprintf("leave %s\n", node_to_str(left));
	for (i = 0; i < nr_members; i++)
		dprintf("[%x] %s\n", i, node_to_str(members + i));

	if (sys_stat_shutdown())
		return;

	w = zalloc(sizeof(*w));
	if (!w)
		goto oom;

	cevent = &w->cev;
	cevent->ctype = CPG_EVENT_LEAVE;


	vprintf(SDOG_DEBUG, "allow new confchg, %p\n", cevent);

	size = sizeof(struct sheepdog_node_list_entry) * nr_members;
	w->member_list = zalloc(size);
	if (!w->member_list)
		goto oom;
	memcpy(w->member_list, members, size);
	w->member_list_entries = nr_members;

	w->left = *left;

	list_add_tail(&cevent->cpg_event_list, &sys->cpg_event_siblings);
	start_cpg_event_work();

	return;
oom:
	if (w) {
		if (w->member_list)
			free(w->member_list);
		free(w);
	}
	panic("failed to allocate memory for a confchg event\n");
}

int create_cluster(int port, int64_t zone)
{
	int fd, ret;
	struct cluster_driver *cdrv;
	struct cdrv_handlers handlers = {
		.join_handler = sd_join_handler,
		.leave_handler = sd_leave_handler,
		.notify_handler = sd_notify_handler,
	};

	if (!sys->cdrv) {
		FOR_EACH_CLUSTER_DRIVER(cdrv) {
			if (strcmp(cdrv->name, "corosync") == 0) {
				dprintf("use corosync driver as default\n");
				sys->cdrv = cdrv;
				break;
			}
		}
	}

	fd = sys->cdrv->init(&handlers, sys->this_node.addr);
	if (fd < 0)
		return -1;

	sys->this_node.port = port;
	sys->this_node.nr_vnodes = SD_DEFAULT_VNODES;
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

	INIT_LIST_HEAD(&sys->outstanding_req_list);
	INIT_LIST_HEAD(&sys->req_wait_for_obj_list);
	INIT_LIST_HEAD(&sys->consistent_obj_list);

	INIT_LIST_HEAD(&sys->cpg_event_siblings);

	ret = register_event(fd, group_handler, NULL);
	if (ret) {
		eprintf("Failed to register epoll events, %d\n", ret);
		return 1;
	}

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
