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
#include <corosync/cpg.h>
#include <corosync/cfg.h>

#include "sheepdog_proto.h"
#include "sheep_priv.h"
#include "list.h"
#include "util.h"
#include "logger.h"
#include "work.h"

struct node {
	uint32_t nodeid;
	uint32_t pid;
	struct sheepdog_node_list_entry ent;
	struct list_head list;
};

enum deliver_msg_state {
	DM_INIT = 1,
	DM_CONT,
	DM_FIN,
};

struct message_header {
	uint8_t proto_ver;
	uint8_t pad;
	uint8_t op;
	uint8_t state;
	uint32_t msg_length;
	uint32_t nodeid;
	uint32_t pid;
	struct sheepdog_node_list_entry from;
};

struct join_message {
	struct message_header header;
	uint32_t nr_nodes;
	uint32_t nr_sobjs;
	uint32_t cluster_status;
	uint32_t epoch;
	uint64_t ctime;
	uint32_t result;
	uint8_t inc_epoch; /* set non-zero when we increment epoch of all nodes */
	uint8_t pad[3];
	struct {
		uint32_t nodeid;
		uint32_t pid;
		struct sheepdog_node_list_entry ent;
	} nodes[SD_MAX_NODES];
	uint32_t nr_leave_nodes;
	struct {
		uint32_t nodeid;
		uint32_t pid;
		struct sheepdog_node_list_entry ent;
	} leave_nodes[SD_MAX_NODES];
};

struct leave_message {
	struct message_header header;
	uint32_t epoch;
};

struct vdi_op_message {
	struct message_header header;
	struct sd_vdi_req req;
	struct sd_vdi_rsp rsp;
	uint8_t data[0];
};

struct mastership_tx_message {
	struct message_header header;
	uint32_t epoch;
};

struct work_deliver {
	struct cpg_event cev;

	struct message_header *msg;
};

struct work_confchg {
	struct cpg_event cev;

	struct cpg_address *member_list;
	size_t member_list_entries;
	struct cpg_address *left_list;
	size_t left_list_entries;
	struct cpg_address *joined_list;
	size_t joined_list_entries;

	int first_cpg_node;
	int sd_node_left;
};

#define print_node_list(node_list)				\
({								\
	struct node *__node;					\
	char __name[128];						\
	list_for_each_entry(__node, node_list, list) {		\
		dprintf("%c nodeid: %x, pid: %d, ip: %s\n",	\
			is_myself(__node->ent.addr, __node->ent.port) ? 'l' : ' ',	\
			__node->nodeid, __node->pid,		\
			addr_to_str(__name, sizeof(__name),	\
			__node->ent.addr, __node->ent.port));	\
	}							\
})

enum cpg_event_work_bits {
	CPG_EVENT_WORK_RUNNING = 1,
	CPG_EVENT_WORK_SUSPENDED,
	CPG_EVENT_WORK_JOINING,
};

#define CPG_EVENT_WORK_FNS(bit, name)					\
static int cpg_event_##name(void)					\
{									\
	return test_bit(CPG_EVENT_WORK_##bit,				\
		&sys->cpg_event_work_flags);				\
}									\
static void cpg_event_clear_##name(void)				\
{									\
	clear_bit(CPG_EVENT_WORK_##bit, &sys->cpg_event_work_flags);	\
}									\
static void cpg_event_set_##name(void)					\
{									\
	set_bit(CPG_EVENT_WORK_##bit, &sys->cpg_event_work_flags);	\
}

CPG_EVENT_WORK_FNS(RUNNING, running)
CPG_EVENT_WORK_FNS(SUSPENDED, suspended)
CPG_EVENT_WORK_FNS(JOINING, joining)

static inline int join_message(struct message_header *m)
{
	return m->op == SD_MSG_JOIN;
}

static inline int vdi_op_message(struct message_header *m)
{
	return m->op == SD_MSG_VDI_OP;
}

static inline int master_chg_message(struct message_header *m)
{
	return m->op == SD_MSG_MASTER_CHANGED;
}

static inline int leave_message(struct message_header *m)
{
	return m->op == SD_MSG_LEAVE;
}

static inline int master_tx_message(struct message_header *m)
{
	return m->op == SD_MSG_MASTER_TRANSFER;
}

static int send_message(cpg_handle_t handle, struct message_header *msg)
{
	struct iovec iov;
	int ret;

	iov.iov_base = msg;
	iov.iov_len = msg->msg_length;
retry:
	ret = cpg_mcast_joined(handle, CPG_TYPE_AGREED, &iov, 1);
	switch (ret) {
	case CPG_OK:
		break;
	case CPG_ERR_TRY_AGAIN:
		dprintf("failed to send message. try again\n");
		sleep(1);
		goto retry;
	default:
		eprintf("failed to send message, %d\n", ret);
		return -1;
	}
	return 0;
}


static int get_node_idx(struct sheepdog_node_list_entry *ent,
			struct sheepdog_node_list_entry *entries, int nr_nodes)
{
	ent = bsearch(ent, entries, nr_nodes, sizeof(*ent), node_cmp);
	if (!ent)
		return -1;

	return ent - entries;
}

static void build_node_list(struct list_head *node_list,
			    struct sheepdog_node_list_entry *entries,
			    int *nr_nodes, int *nr_zones)
{
	struct node *node;
	int nr = 0, i;
	uint32_t zones[SD_MAX_REDUNDANCY];

	if (nr_zones)
		*nr_zones = 0;

	list_for_each_entry(node, node_list, list) {
		if (entries)
			memcpy(entries + nr, &node->ent, sizeof(*entries));
		nr++;

		if (nr_zones && *nr_zones < ARRAY_SIZE(zones)) {
			for (i = 0; i < *nr_zones; i++) {
				if (zones[i] == node->ent.zone)
					break;
			}
			if (i == *nr_zones)
				zones[(*nr_zones)++] = node->ent.zone;
		}
	}
	if (entries)
		qsort(entries, nr, sizeof(*entries), node_cmp);
	if (nr_nodes)
		*nr_nodes = nr;
}

int get_ordered_sd_node_list(struct sheepdog_node_list_entry *entries)
{
	int nr_nodes;

	build_node_list(&sys->sd_node_list, entries, &nr_nodes, NULL);

	return nr_nodes;
}

void get_ordered_sd_vnode_list(struct sheepdog_vnode_list_entry *entries,
			       int *nr_vnodes, int *nr_zones)
{
	struct sheepdog_node_list_entry nodes[SD_MAX_NODES];
	int nr;

	build_node_list(&sys->sd_node_list, nodes, &nr, nr_zones);

	if (sys->nr_vnodes == 0)
		sys->nr_vnodes = nodes_to_vnodes(nodes, nr, sys->vnodes);

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
	struct node *node;

	nr_nodes = get_ordered_sd_node_list(data);
	rsp->data_length = nr_nodes * sizeof(struct sheepdog_node_list_entry);
	rsp->nr_nodes = nr_nodes;
	rsp->local_idx = get_node_idx(&sys->this_node, data, nr_nodes);

	if (!nr_nodes) {
		rsp->master_idx = -1;
		return;
	}
	node = list_first_entry(&sys->sd_node_list, struct node, list);
	rsp->master_idx = get_node_idx(&node->ent, data, nr_nodes);
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

void cluster_queue_request(struct work *work, int idx)
{
	struct request *req = container_of(work, struct request, work);
	struct sd_req *hdr = (struct sd_req *)&req->rq;
	struct sd_rsp *rsp = (struct sd_rsp *)&req->rp;
	struct vdi_op_message *msg;
	struct epoch_log *log;
	int ret = SD_RES_SUCCESS, i, max_logs, epoch;

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

		switch (sys->status) {
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
	msg = zalloc(sizeof(*msg) + hdr->data_length);
	if (!msg) {
		eprintf("out of memory\n");
		return;
	}

	msg->header.op = SD_MSG_VDI_OP;
	msg->header.state = DM_INIT;
	msg->header.msg_length = sizeof(*msg) + hdr->data_length;
	msg->header.from = sys->this_node;
	msg->req = *((struct sd_vdi_req *)&req->rq);
	msg->rsp = *((struct sd_vdi_rsp *)&req->rp);
	if (hdr->flags & SD_FLAG_CMD_WRITE)
		memcpy(msg->data, req->data, hdr->data_length);

	list_add(&req->pending_list, &sys->pending_list);

	send_message(sys->handle, (struct message_header *)msg);

	free(msg);
}

static void group_handler(int listen_fd, int events, void *data)
{
	int ret;
	if (events & EPOLLHUP) {
		eprintf("Receive EPOLLHUP event. Is corosync stopped running?\n");
		goto out;
	}

	ret = cpg_dispatch(sys->handle, CPG_DISPATCH_ALL);

	if (ret == CPG_OK)
		return;
	else
		eprintf("oops...some error occured inside corosync\n");
out:
	log_close();
	exit(1);
}

static struct node *find_node(struct list_head *node_list, uint32_t nodeid, uint32_t pid)
{
	struct node *node;

	list_for_each_entry(node, node_list, list) {
		if (node->nodeid == nodeid && node->pid == pid)
			return node;
	}

	return NULL;
}

static int is_master(void)
{
	struct node *node;

	if (!sys->join_finished)
		return 0;

	node = list_first_entry(&sys->sd_node_list, struct node, list);
	if (is_myself(node->ent.addr, node->ent.port))
		return 1;
	return 0;
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

	nr = epoch_log_read(epoch, (char *)nodes, sizeof(nodes));
	nr /= sizeof(nodes[0]);

	for (i = 0; i < nr; i++)
		if (node_cmp(&nodes[i], entry) == 0)
			return entry;

	return NULL;
}

static int add_node_to_leave_list(struct message_header *msg)
{
	int ret = SD_RES_SUCCESS;
	int nr, i, le = get_latest_epoch();
	LIST_HEAD(tmp_list);
	struct node *n, *t;
	struct join_message *jm;

	if (leave_message(msg)) {
		n = zalloc(sizeof(*n));
		if (!n) {
			ret = SD_RES_NO_MEM;
			goto err;
		}

		if (find_entry_list(&msg->from, &sys->leave_list)
		    || !find_entry_epoch(&msg->from, le)) {
			free(n);
			goto ret;
		}

		n->nodeid = msg->nodeid;
		n->pid = msg->pid;
		n->ent = msg->from;

		list_add_tail(&n->list, &sys->leave_list);
		goto ret;
	} else if (join_message(msg)) {
		jm = (struct join_message *)msg;
		nr = jm->nr_leave_nodes;
		for (i = 0; i < nr; i++) {
			n = zalloc(sizeof(*n));
			if (!n) {
				ret = SD_RES_NO_MEM;
				goto free;
			}

			if (find_entry_list(&jm->leave_nodes[i].ent, &sys->leave_list)
			    || !find_entry_epoch(&jm->leave_nodes[i].ent, le)) {
				free(n);
				continue;
			}

			n->nodeid = jm->leave_nodes[i].nodeid;
			n->pid = jm->leave_nodes[i].pid;
			n->ent = jm->leave_nodes[i].ent;

			list_add_tail(&n->list, &tmp_list);
		}
		list_splice_init(&tmp_list, &sys->leave_list);
		goto ret;
	} else {
		ret = SD_RES_INVALID_PARMS;
		goto err;
	}
free:
	list_for_each_entry_safe(n, t, &tmp_list, list) {
		free(n);
	}
ret:
	dprintf("%d\n", get_nodes_nr_from(&sys->leave_list));
	print_node_list(&sys->leave_list);
err:
	return ret;
}

static int get_cluster_status(struct sheepdog_node_list_entry *from,
			      struct sheepdog_node_list_entry *entries,
			      int nr_entries, uint64_t ctime, uint32_t epoch,
			      uint32_t *status, uint8_t *inc_epoch)
{
	int i;
	int nr_local_entries, nr_leave_entries;
	struct sheepdog_node_list_entry local_entries[SD_MAX_NODES];
	struct node *node;
	uint32_t local_epoch;
	char str[256];

	*status = sys->status;
	if (inc_epoch)
		*inc_epoch = 0;

	switch (sys->status) {
	case SD_STATUS_OK:
		if (inc_epoch)
			*inc_epoch = 1;

		if (nr_entries == 0)
			break;

		if (ctime != get_cluster_ctime()) {
			eprintf("joining node has invalid ctime, %s\n",
				addr_to_str(str, sizeof(str), from->addr, from->port));
			return SD_RES_INVALID_CTIME;
		}

		local_epoch = get_latest_epoch();
		if (epoch > local_epoch) {
			eprintf("sheepdog is running with older epoch, %"PRIu32" %"PRIu32" %s\n",
				epoch, local_epoch,
				addr_to_str(str, sizeof(str), from->addr, from->port));
			return SD_RES_OLD_NODE_VER;
		}
		break;
	case SD_STATUS_WAIT_FOR_FORMAT:
		if (nr_entries != 0) {
			eprintf("joining node is not clean, %s\n",
				addr_to_str(str, sizeof(str), from->addr, from->port));
			return SD_RES_NOT_FORMATTED;
		}
		break;
	case SD_STATUS_WAIT_FOR_JOIN:
		if (ctime != get_cluster_ctime()) {
			eprintf("joining node has invalid ctime, %s\n",
				addr_to_str(str, sizeof(str), from->addr, from->port));
			return SD_RES_INVALID_CTIME;
		}

		local_epoch = get_latest_epoch();
		if (epoch > local_epoch) {
			eprintf("sheepdog is waiting with older epoch, %"PRIu32" %"PRIu32" %s\n",
				epoch, local_epoch,
				addr_to_str(str, sizeof(str), from->addr, from->port));
			return SD_RES_OLD_NODE_VER;
		} else if (epoch < local_epoch) {
			eprintf("sheepdog is waiting with newer epoch, %"PRIu32" %"PRIu32" %s\n",
				epoch, local_epoch,
				addr_to_str(str, sizeof(str), from->addr, from->port));
			return SD_RES_NEW_NODE_VER;
		}

		nr_local_entries = epoch_log_read(epoch, (char *)local_entries,
						  sizeof(local_entries));
		nr_local_entries /= sizeof(local_entries[0]);

		if (nr_entries != nr_local_entries) {
			eprintf("joining node has invalid epoch, %"PRIu32" %s\n",
				epoch,
				addr_to_str(str, sizeof(str), from->addr, from->port));
			return SD_RES_INVALID_EPOCH;
		}

		if (memcmp(entries, local_entries, sizeof(entries[0]) * nr_entries) != 0) {
			eprintf("joining node has invalid epoch, %s\n",
				addr_to_str(str, sizeof(str), from->addr, from->port));
			return SD_RES_INVALID_EPOCH;
		}

		nr_entries = get_nodes_nr_from(&sys->sd_node_list) + 1;

		if (nr_entries != nr_local_entries) {
			nr_leave_entries = get_nodes_nr_from(&sys->leave_list);
			if (nr_local_entries == nr_entries + nr_leave_entries) {
				/* Even though some nodes leave, we can make do with it.
				 * Order cluster to do recovery right now.
				 */
				*inc_epoch = 1;
				*status = SD_STATUS_OK;
				return SD_RES_SUCCESS;
			}
			return SD_RES_SUCCESS;
		}

		for (i = 0; i < nr_local_entries; i++) {
			if (node_cmp(local_entries + i, from) == 0)
				goto next;
			list_for_each_entry(node, &sys->sd_node_list, list) {
				if (node_cmp(local_entries + i, &node->ent) == 0)
					goto next;
			}
			return SD_RES_SUCCESS;
		next:
			;
		}

		*status = SD_STATUS_OK;
		break;
	case SD_STATUS_SHUTDOWN:
		return SD_RES_SHUTDOWN;
	default:
		break;
	}
	return SD_RES_SUCCESS;
}

static void join(struct join_message *msg)
{
	struct node *node;
	struct sheepdog_node_list_entry entry[SD_MAX_NODES];
	int i;

	if (msg->header.proto_ver != SD_SHEEP_PROTO_VER) {
		eprintf("joining node send a wrong version message\n");
		msg->result = SD_RES_VER_MISMATCH;
		return;
	}

	for (i = 0; i < msg->nr_nodes; i++)
		entry[i] = msg->nodes[i].ent;

	msg->result = get_cluster_status(&msg->header.from, entry,
					 msg->nr_nodes, msg->ctime,
					 msg->epoch, &msg->cluster_status,
					 &msg->inc_epoch);
	msg->nr_sobjs = sys->nr_sobjs;
	msg->ctime = get_cluster_ctime();
	msg->nr_nodes = 0;
	list_for_each_entry(node, &sys->sd_node_list, list) {
		msg->nodes[msg->nr_nodes].nodeid = node->nodeid;
		msg->nodes[msg->nr_nodes].pid = node->pid;
		msg->nodes[msg->nr_nodes].ent = node->ent;
		msg->nr_nodes++;
	}
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
		vprintf(SDOG_ERR "can't get the vdi bitmap %s, %m\n", host);
		ret = -SD_RES_EIO;
		goto out;
	}

	vprintf(SDOG_ERR "get the vdi bitmap from %s\n", host);

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
		vprintf(SDOG_ERR "can't get the vdi bitmap %d %d\n", ret,
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
	int i, nr_nodes;
	/* fixme: we need this until starting up. */
	struct sheepdog_node_list_entry nodes[SD_MAX_NODES];

	/*
	 * we don't need the proper order but this is the simplest
	 * way.
	 */
	nr_nodes = get_ordered_sd_node_list(nodes);

	for (i = 0; i < nr_nodes; i++)
		get_vdi_bitmap_from(&nodes[i]);
}

static int move_node_to_sd_list(uint32_t nodeid, uint32_t pid,
				struct sheepdog_node_list_entry ent)
{
	struct node *node;

	node = find_node(&sys->cpg_node_list, nodeid, pid);
	if (!node)
		return 1;

	node->ent = ent;

	list_del(&node->list);
	list_add_tail(&node->list, &sys->sd_node_list);
	sys->nr_vnodes = 0;

	return 0;
}

static int update_epoch_log(int epoch)
{
	int ret, nr_nodes;
	struct sheepdog_node_list_entry entry[SD_MAX_NODES];

	nr_nodes = get_ordered_sd_node_list(entry);

	dprintf("update epoch, %d, %d\n", epoch, nr_nodes);
	ret = epoch_log_write(epoch, (char *)entry,
			nr_nodes * sizeof(struct sheepdog_node_list_entry));
	if (ret < 0)
		eprintf("can't write epoch %u\n", epoch);

	return ret;
}

static void update_cluster_info(struct join_message *msg)
{
	int i;
	int ret, nr_nodes = msg->nr_nodes;

	eprintf("status = %d, epoch = %d, %d, %d\n", msg->cluster_status, msg->epoch, msg->result, sys->join_finished);
	if (msg->result != SD_RES_SUCCESS) {
		if (is_myself(msg->header.from.addr, msg->header.from.port)) {
			eprintf("failed to join sheepdog, %d\n", msg->result);
			leave_cluster();
			eprintf("Restart me later when master is up, please.Bye.\n");
			exit(1);
			/* sys->status = SD_STATUS_JOIN_FAILED; */
		}
		return;
	}

	if (sys->status == SD_STATUS_JOIN_FAILED)
		return;

	if (!sys->nr_sobjs)
		sys->nr_sobjs = msg->nr_sobjs;

	if (sys->join_finished)
		goto join_finished;

	sys->epoch = msg->epoch;
	for (i = 0; i < nr_nodes; i++) {
		ret = move_node_to_sd_list(msg->nodes[i].nodeid,
					   msg->nodes[i].pid,
					   msg->nodes[i].ent);
		/*
		 * the node belonged to sheepdog when the master build
		 * the JOIN response however it has gone.
		 */
		if (ret)
			vprintf(SDOG_INFO "nodeid: %x, pid: %d has gone\n",
				msg->nodes[i].nodeid, msg->nodes[i].pid);
	}

	if (msg->cluster_status != SD_STATUS_OK)
		add_node_to_leave_list((struct message_header *)msg);

	sys->join_finished = 1;

	if (msg->cluster_status == SD_STATUS_OK && msg->inc_epoch)
		update_epoch_log(sys->epoch);

join_finished:
	ret = move_node_to_sd_list(msg->header.nodeid, msg->header.pid, msg->header.from);
	/*
	 * this should not happen since __sd_deliver() checks if the
	 * host from msg on cpg_node_list.
	 */
	if (ret)
		vprintf(SDOG_ERR "nodeid: %x, pid: %d has gone\n",
			msg->header.nodeid, msg->header.pid);

	if (msg->cluster_status == SD_STATUS_OK) {
		if (msg->inc_epoch) {
			sys->epoch++;
			update_epoch_log(sys->epoch);
			update_epoch_store(sys->epoch);
		}
		if (sys->status != SD_STATUS_OK) {
			set_global_nr_copies(sys->nr_sobjs);
			set_cluster_ctime(msg->ctime);
		}
	}

	print_node_list(&sys->sd_node_list);

	sys->status = msg->cluster_status;
	return;
}

static void vdi_op(struct vdi_op_message *msg)
{
	const struct sd_vdi_req *hdr = &msg->req;
	struct sd_vdi_rsp *rsp = &msg->rsp;
	void *data = msg->data;
	int ret = SD_RES_SUCCESS;
	uint32_t vid = 0, attrid = 0, nr_copies = sys->nr_sobjs;

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
		ret = lookup_vdi(hdr->epoch, data, hdr->data_length, &vid,
				 hdr->snapid, &nr_copies);
		if (ret != SD_RES_SUCCESS)
			break;
		break;
	case SD_OP_GET_VDI_ATTR:
		ret = lookup_vdi(hdr->epoch, data,
				 min(SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN, hdr->data_length),
				 &vid, hdr->snapid, &nr_copies);
		if (ret != SD_RES_SUCCESS)
			break;
		/* the curernt vdi id can change if we take the snapshot,
		   so we use the hash value of the vdi name as the vdi id */
		vid = fnv_64a_buf(data, strlen(data), FNV1A_64_INIT);
		vid &= SD_NR_VDIS - 1;
		ret = get_vdi_attr(hdr->epoch, data, hdr->data_length, vid,
				   &attrid, nr_copies,
				   hdr->flags & SD_FLAG_CMD_CREAT,
				   hdr->flags & SD_FLAG_CMD_EXCL);
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

static void vdi_op_done(struct vdi_op_message *msg)
{
	const struct sd_vdi_req *hdr = &msg->req;
	struct sd_vdi_rsp *rsp = &msg->rsp;
	void *data = msg->data;
	struct request *req;
	int ret = msg->rsp.result;
	int i, latest_epoch, nr_nodes;
	struct sheepdog_node_list_entry entry[SD_MAX_NODES];
	uint64_t ctime;

	if (ret != SD_RES_SUCCESS)
		goto out;

	switch (hdr->opcode) {
	case SD_OP_NEW_VDI:
	{
		unsigned long nr = rsp->vdi_id;
		vprintf(SDOG_INFO "done %d %ld\n", ret, nr);
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
		nr_nodes = get_ordered_sd_node_list(entry);

		dprintf("write epoch log, %d, %d\n", sys->epoch, nr_nodes);
		ret = epoch_log_write(sys->epoch, (char *)entry,
				      nr_nodes * sizeof(struct sheepdog_node_list_entry));
		if (ret < 0)
			eprintf("can't write epoch %u\n", sys->epoch);
		update_epoch_store(sys->epoch);

		set_global_nr_copies(sys->nr_sobjs);

		sys->status = SD_STATUS_OK;
		break;
	case SD_OP_SHUTDOWN:
		sys->status = SD_STATUS_SHUTDOWN;
		break;
	default:
		eprintf("unknown operation %d\n", hdr->opcode);
		ret = SD_RES_UNKNOWN;
	}
out:
	if (!is_myself(msg->header.from.addr, msg->header.from.port))
		return;

	req = list_first_entry(&sys->pending_list, struct request, pending_list);

	rsp->result = ret;
	memcpy(req->data, data, rsp->data_length);
	memcpy(&req->rp, rsp, sizeof(req->rp));
	list_del(&req->pending_list);
	req->done(req);
}

static void __sd_deliver(struct cpg_event *cevent)
{
	struct work_deliver *w = container_of(cevent, struct work_deliver, cev);
	struct message_header *m = w->msg;
	char name[128];
	struct node *node;

	dprintf("op: %d, state: %u, size: %d, from: %s, pid: %d\n",
		m->op, m->state, m->msg_length,
		addr_to_str(name, sizeof(name), m->from.addr, m->from.port),
		m->pid);

	/*
	 * we don't want to perform any deliver events except mastership_tx event
	 * until we join; we wait for our JOIN message.
	 */
	if (!sys->join_finished && !master_tx_message(m)) {
		if (m->pid != sys->this_pid || m->nodeid != sys->this_nodeid) {
			cevent->skip = 1;
			return;
		}
	}

	if (join_message(m)) {
		uint32_t nodeid = m->nodeid;
		uint32_t pid = m->pid;

		node = find_node(&sys->cpg_node_list, nodeid, pid);
		if (!node) {
			dprintf("the node was left before join operation is finished\n");
			return;
		}

		node->ent = m->from;
	}

	if (m->state == DM_INIT && is_master()) {
		switch (m->op) {
		case SD_MSG_JOIN:
			break;
		case SD_MSG_VDI_OP:
			vdi_op((struct vdi_op_message *)m);
			break;
		default:
			eprintf("unknown message %d\n", m->op);
			break;
		}
	}

	if (m->state == DM_FIN) {
		switch (m->op) {
		case SD_MSG_JOIN:
			if (((struct join_message *)m)->cluster_status == SD_STATUS_OK)
				if (sys->status != SD_STATUS_OK) {
					struct join_message *msg = (struct join_message *)m;
					int i;

					get_vdi_bitmap_from_sd_list();
					get_vdi_bitmap_from(&m->from);
					for (i = 0; i < msg->nr_nodes;i++)
						get_vdi_bitmap_from(&msg->nodes[i].ent);
			}
			break;
		}
	}

}

static int tx_mastership(void)
{
	struct mastership_tx_message msg;
	memset(&msg, 0, sizeof(msg));
	msg.header.proto_ver = SD_SHEEP_PROTO_VER;
	msg.header.op = SD_MSG_MASTER_TRANSFER;
	msg.header.state = DM_FIN;
	msg.header.msg_length = sizeof(msg);
	msg.header.from = sys->this_node;
	msg.header.nodeid = sys->this_nodeid;
	msg.header.pid = sys->this_pid;

	return send_message(sys->handle, (struct message_header *)&msg);
}

static void send_join_response(struct work_deliver *w)
{
	struct message_header *m;
	struct join_message *jm;
	struct node *node;

	m = w->msg;
	jm = (struct join_message *)m;
	join(jm);
	m->state = DM_FIN;

	dprintf("%d, %d\n", jm->result, jm->cluster_status);
	if (jm->result == SD_RES_SUCCESS && jm->cluster_status != SD_STATUS_OK) {
		jm->nr_leave_nodes = 0;
		list_for_each_entry(node, &sys->leave_list, list) {
			jm->leave_nodes[jm->nr_leave_nodes].nodeid = node->nodeid;
			jm->leave_nodes[jm->nr_leave_nodes].pid = node->pid;
			jm->leave_nodes[jm->nr_leave_nodes].ent = node->ent;
			jm->nr_leave_nodes++;
		}
		print_node_list(&sys->leave_list);
	} else if (jm->result != SD_RES_SUCCESS &&
			jm->epoch > sys->epoch &&
			jm->cluster_status == SD_STATUS_WAIT_FOR_JOIN) {
		eprintf("Transfer mastership.\n");
		tx_mastership();
		eprintf("Restart me later when master is up, please.Bye.\n");
		exit(1);
	}
	jm->epoch = sys->epoch;
	send_message(sys->handle, m);
}

static void __sd_deliver_done(struct cpg_event *cevent)
{
	struct work_deliver *w = container_of(cevent, struct work_deliver, cev);
	struct message_header *m;
	char name[128];
	int do_recovery;
	struct node *node, *t;
	int nr, nr_local, nr_leave;

	m = w->msg;

	if (m->state == DM_FIN) {
		switch (m->op) {
		case SD_MSG_JOIN:
			update_cluster_info((struct join_message *)m);
			break;
		case SD_MSG_LEAVE:
			node = find_node(&sys->sd_node_list, m->nodeid, m->pid);
			if (node) {
				sys->nr_vnodes = 0;

				list_del(&node->list);
				free(node);
				if (sys->status == SD_STATUS_OK) {
					sys->epoch++;
					update_epoch_log(sys->epoch);
					update_epoch_store(sys->epoch);
				}
			}
		/* fall through */
		case SD_MSG_MASTER_TRANSFER:
			if (sys->status == SD_STATUS_WAIT_FOR_JOIN) {
				add_node_to_leave_list(m);

				/* Sheep needs this to identify itself as master.
				 * Now mastership transfer is done.
				 */
				if (!sys->join_finished) {
					sys->join_finished = 1;
					move_node_to_sd_list(sys->this_nodeid, sys->this_pid, sys->this_node);
					sys->epoch = get_latest_epoch();
				}

				nr_local = get_nodes_nr_epoch(sys->epoch);
				nr = get_nodes_nr_from(&sys->sd_node_list);
				nr_leave = get_nodes_nr_from(&sys->leave_list);

				dprintf("%d == %d + %d \n", nr_local, nr, nr_leave);
				if (nr_local == nr + nr_leave) {
					sys->status = SD_STATUS_OK;
					update_epoch_log(sys->epoch);
					update_epoch_store(sys->epoch);
				}
			}
			break;
		default:
			eprintf("unknown message %d\n", m->op);
			break;
		}
	}

	do_recovery = (m->state == DM_FIN &&
		       (join_message(m) || leave_message(m)));

	dprintf("op: %d, state: %u, size: %d, from: %s\n",
		m->op, m->state, m->msg_length,
		addr_to_str(name, sizeof(name), m->from.addr,
			    m->from.port));

	if (m->state == DM_INIT && is_master()) {
		switch (m->op) {
		case SD_MSG_JOIN:
			send_join_response(w);
			break;
		case SD_MSG_VDI_OP:
			m->state = DM_FIN;
			send_message(sys->handle, m);
			break;
		default:
			eprintf("unknown message %d\n", m->op);
			break;
		}
	}

	if (do_recovery && sys->status == SD_STATUS_OK) {
		list_for_each_entry_safe(node, t, &sys->leave_list, list) {
			list_del(&node->list);
		}
		start_recovery(sys->epoch);
	}
}

static void sd_deliver(cpg_handle_t handle, const struct cpg_name *group_name,
		       uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
	struct cpg_event *cevent;
	struct work_deliver *w;
	struct message_header *m = msg;
	char name[128];

	dprintf("op: %d, state: %u, size: %d, from: %s, nodeid: %x, pid: %u\n",
		m->op, m->state, m->msg_length,
		addr_to_str(name, sizeof(name), m->from.addr, m->from.port),
		nodeid, pid);

	w = zalloc(sizeof(*w));
	if (!w)
		return;

	cevent = &w->cev;
	cevent->ctype = CPG_EVENT_DELIVER;

	vprintf(SDOG_DEBUG "allow new deliver, %p\n", cevent);

	w->msg = zalloc(msg_len);
	if (!w->msg)
		return;
	memcpy(w->msg, msg, msg_len);

	if (cpg_event_suspended() && m->state == DM_FIN) {
		list_add(&cevent->cpg_event_list, &sys->cpg_event_siblings);
		cpg_event_clear_suspended();
		if (join_message(m))
			cpg_event_clear_joining();
	} else
		list_add_tail(&cevent->cpg_event_list, &sys->cpg_event_siblings);

	start_cpg_event_work();
}

static void for_each_node_list(struct cpg_address list[], int count,
			       void (*func)(struct cpg_address *addr,
					    struct work_confchg *w),
			       struct work_confchg *w)
{
	int i;
	for (i = 0; i < count; i++)
		func(&list[i], w);
}

static void add_node(struct cpg_address *addr, struct work_confchg *w)
{
	struct node *node;

	node = zalloc(sizeof(*node));
	if (!node)
		panic("failed to alloc memory for a new node\n");

	node->nodeid = addr->nodeid;
	node->pid = addr->pid;

	list_add_tail(&node->list, &sys->cpg_node_list);
}

static void del_node(struct cpg_address *addr, struct work_confchg *w)
{
	struct node *node;

	node = find_node(&sys->sd_node_list, addr->nodeid, addr->pid);
	if (node) {
		int nr;
		struct sheepdog_node_list_entry e[SD_MAX_NODES];

		w->sd_node_left++;
		sys->nr_vnodes = 0;

		list_del(&node->list);
		free(node);

		if (sys->status == SD_STATUS_OK) {
			nr = get_ordered_sd_node_list(e);
			dprintf("update epoch, %d, %d\n", sys->epoch + 1, nr);
			epoch_log_write(sys->epoch + 1, (char *)e,
					nr * sizeof(struct sheepdog_node_list_entry));

			sys->epoch++;

			update_epoch_store(sys->epoch);
		}
	} else {
		node = find_node(&sys->cpg_node_list, addr->nodeid, addr->pid);
		if (node) {
			list_del(&node->list);
			free(node);
		}
	}
}

static int is_my_cpg_addr(struct cpg_address *addr)
{
	return (sys->this_nodeid == addr->nodeid) &&
		(sys->this_pid == addr->pid);
}

/*
 * Check whether the majority of Sheepdog nodes are still alive or not
 */
static int check_majority(struct cpg_address *left_list,
			  size_t left_list_entries)
{
	int nr_nodes = 0, nr_majority, nr_reachable = 0, i, fd;
	struct node *node;
	char name[INET6_ADDRSTRLEN];

	if (left_list_entries == 0)
		return 1; /* we don't need this check in this case */

	nr_nodes = get_nodes_nr_from(&sys->sd_node_list);
	nr_majority = nr_nodes / 2 + 1;

	/* we need at least 3 nodes to handle network partition
	 * failure */
	if (nr_nodes < 3)
		return 1;

	list_for_each_entry(node, &sys->sd_node_list, list) {
		for (i = 0; i < left_list_entries; i++) {
			if (left_list[i].nodeid == node->nodeid &&
			    left_list[i].pid == node->pid)
				break;
		}
		if (i != left_list_entries)
			continue;

		addr_to_str(name, sizeof(name), node->ent.addr, 0);
		fd = connect_to(name, node->ent.port);
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

static void __sd_confchg(struct cpg_event *cevent)
{
	struct work_confchg *w = container_of(cevent, struct work_confchg, cev);

	if (!check_majority(w->left_list, w->left_list_entries)) {
		eprintf("perhaps network partition failure has occurred\n");
		abort();
	}
}

static void send_join_request(struct cpg_address *addr, struct work_confchg *w)
{
	struct join_message msg;
	struct sheepdog_node_list_entry entries[SD_MAX_NODES];
	int nr_entries, i, ret;

	/* if I've just joined in cpg, I'll join in sheepdog. */
	if (!is_my_cpg_addr(addr))
		return;

	memset(&msg, 0, sizeof(msg));
	msg.header.proto_ver = SD_SHEEP_PROTO_VER;
	msg.header.op = SD_MSG_JOIN;
	msg.header.state = DM_INIT;
	msg.header.msg_length = sizeof(msg);
	msg.header.from = sys->this_node;
	msg.header.nodeid = sys->this_nodeid;
	msg.header.pid = sys->this_pid;

	get_global_nr_copies(&msg.nr_sobjs);

	nr_entries = ARRAY_SIZE(entries);
	ret = read_epoch(&msg.epoch, &msg.ctime, entries, &nr_entries);
	if (ret == SD_RES_SUCCESS) {
		msg.nr_nodes = nr_entries;
		for (i = 0; i < nr_entries; i++)
			msg.nodes[i].ent = entries[i];
	}

	send_message(sys->handle, (struct message_header *)&msg);

	vprintf(SDOG_INFO "%x %u\n", sys->this_nodeid, sys->this_pid);
}

static void __sd_confchg_done(struct cpg_event *cevent)
{
	struct work_confchg *w = container_of(cevent, struct work_confchg, cev);
	int ret;

	if (w->member_list_entries ==
	    w->joined_list_entries - w->left_list_entries &&
	    is_my_cpg_addr(w->member_list)) {
		sys->join_finished = 1;
		get_global_nr_copies(&sys->nr_sobjs);
		w->first_cpg_node = 1;
	}

	if (list_empty(&sys->cpg_node_list))
		for_each_node_list(w->member_list, w->member_list_entries,
				   add_node, w);
	else
		for_each_node_list(w->joined_list, w->joined_list_entries,
				   add_node, w);

	for_each_node_list(w->left_list, w->left_list_entries,
			   del_node, w);

	if (w->first_cpg_node) {
		struct join_message msg;
		struct sheepdog_node_list_entry entries[SD_MAX_NODES];
		int nr_entries;
		uint64_t ctime;
		uint32_t epoch;

		/*
		 * If I'm the first sheep joins in colosync, I
		 * becomes the master without sending JOIN.
		 */

		vprintf(SDOG_DEBUG "%d %x\n", sys->this_pid, sys->this_nodeid);

		memset(&msg, 0, sizeof(msg));

		msg.header.from = sys->this_node;
		msg.header.nodeid = sys->this_nodeid;
		msg.header.pid = sys->this_pid;

		nr_entries = ARRAY_SIZE(entries);
		ret = read_epoch(&epoch, &ctime, entries, &nr_entries);
		if (ret == SD_RES_SUCCESS) {
			sys->epoch = epoch;
			msg.ctime = ctime;
			get_cluster_status(&msg.header.from, entries, nr_entries,
					   ctime, epoch, &msg.cluster_status, NULL);
		} else
			msg.cluster_status = SD_STATUS_WAIT_FOR_FORMAT;

		update_cluster_info(&msg);

		if (sys->status == SD_STATUS_OK) /* sheepdog starts with one node */
			start_recovery(sys->epoch);

		return;
	}

	print_node_list(&sys->sd_node_list);

	if (w->first_cpg_node)
		goto skip_join;

	for_each_node_list(w->joined_list, w->joined_list_entries,
			   send_join_request, w);

skip_join:
	if (w->sd_node_left && sys->status == SD_STATUS_OK) {
		if (w->sd_node_left > 1)
			panic("we can't handle the departure of multiple nodes %d, %Zd\n",
			      w->sd_node_left, w->left_list_entries);

		start_recovery(sys->epoch);
	}
}

static void cpg_event_free(struct cpg_event *cevent)
{
	switch (cevent->ctype) {
	case CPG_EVENT_CONCHG: {
		struct work_confchg *w = container_of(cevent, struct work_confchg, cev);
		free(w->member_list);
		free(w->left_list);
		free(w->joined_list);
		free(w);
		break;
	}
	case CPG_EVENT_DELIVER: {
		struct work_deliver *w = container_of(cevent, struct work_deliver, cev);
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

	vprintf(SDOG_DEBUG "%p, %d %lx\n", cevent, cevent->ctype,
		sys->cpg_event_work_flags);

	/*
	 * we can't touch sys->cpg_event_siblings because of a race
	 * with sd_deliver() and sd_confchg()...
	 */

	switch (cevent->ctype) {
	case CPG_EVENT_CONCHG:
		__sd_confchg(cevent);
		break;
	case CPG_EVENT_DELIVER:
	{
		struct work_deliver *w = container_of(cevent, struct work_deliver, cev);
		vprintf(SDOG_DEBUG "%d\n", w->msg->state);
		__sd_deliver(cevent);
		break;
	}
	case CPG_EVENT_REQUEST:
		vprintf(SDOG_ERR "should not happen\n");
		break;
	default:
		vprintf(SDOG_ERR "unknown event %d\n", cevent->ctype);
	}
}

static void cpg_event_done(struct work *work, int idx)
{
	struct cpg_event *cevent;

	if (!sys->cur_cevent)
		vprintf(SDOG_ERR "bug\n");

	cevent = sys->cur_cevent;
	sys->cur_cevent = NULL;

	vprintf(SDOG_DEBUG "%p\n", cevent);

	if (cpg_event_suspended())
		goto out;

	if (cevent->skip)
		goto out;

	switch (cevent->ctype) {
	case CPG_EVENT_CONCHG:
		__sd_confchg_done(cevent);
		break;
	case CPG_EVENT_DELIVER:
	{
		struct work_deliver *w = container_of(cevent, struct work_deliver, cev);

		if (w->msg->state == DM_FIN && vdi_op_message(w->msg))
			vdi_op_done((struct vdi_op_message *)w->msg);

		/*
		 * if we are in the process of the JOIN, we will not
		 * be suspended. So sd_deliver() links events to
		 * cpg_event_siblings in order. The events except for
		 * JOIN with DM_CONT and DM_FIN are skipped.
		 */
		if (sys->join_finished && w->msg->state == DM_INIT) {
			struct cpg_event *f_cevent;

			list_for_each_entry(f_cevent, &sys->cpg_event_siblings,
					    cpg_event_list) {
				struct work_deliver *fw =
					container_of(f_cevent, struct work_deliver, cev);
				if (f_cevent->ctype == CPG_EVENT_DELIVER &&
				    fw->msg->state == DM_FIN) {
					vprintf("already got fin %p\n",
						f_cevent);

					list_del(&f_cevent->cpg_event_list);
					list_add(&f_cevent->cpg_event_list,
						 &sys->cpg_event_siblings);
					goto got_fin;
				}
			}
			cpg_event_set_suspended();
			if (join_message(w->msg))
				cpg_event_set_joining();
		}
	got_fin:
		__sd_deliver_done(cevent);
		break;
	}
	case CPG_EVENT_REQUEST:
		vprintf(SDOG_ERR "should not happen\n");
	default:
		vprintf(SDOG_ERR "unknown event %d\n", cevent->ctype);
	}

out:
	vprintf(SDOG_DEBUG "free %p\n", cevent);
	cpg_event_free(cevent);
	cpg_event_clear_running();

	if (!list_empty(&sys->cpg_event_siblings)) {
		if (cpg_event_joining())
			/* io requests need to return SD_RES_NEW_NODE_VER */
			start_cpg_event_work();
		else if (!cpg_event_suspended())
			start_cpg_event_work();
	}
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
		vprintf(SDOG_ERR "bug\n");

	cevent = list_first_entry(&sys->cpg_event_siblings,
				  struct cpg_event, cpg_event_list);

	vprintf(SDOG_DEBUG "%lx %u\n", sys->cpg_event_work_flags,
		cevent->ctype);

	/*
	 * we need to serialize cpg events so we don't call queue_work
	 * if a thread is still running for a cpg event; executing
	 * cpg_event_fn() or cpg_event_done(). A exception: if a
	 * thread is running for a deliver for VDI, then we need to
	 * run io requests.
	 */
	if (cpg_event_running() && cevent->ctype == CPG_EVENT_CONCHG)
		return;

	/*
	 * we are in the processing of handling JOIN so we can't
	 * execute requests (or cpg events).
	 */
	if (cpg_event_joining()) {
		if (!cpg_event_suspended())
			panic("should not happen\n");

		if (cevent->ctype == CPG_EVENT_REQUEST) {
			struct request *req = container_of(cevent, struct request, cev);
			if (is_io_request(req->rq.opcode) && req->rq.flags & SD_FLAG_CMD_DIRECT) {
				list_del(&cevent->cpg_event_list);

				req->rp.result = SD_RES_NEW_NODE_VER;

				/* TODO: cleanup */
				list_add_tail(&req->r_wlist, &sys->outstanding_req_list);
				sys->nr_outstanding_io++;

				req->work.done(&req->work, 0);
			}
		}
		return;
	}

do_retry:
	retry = 0;

	list_for_each_entry_safe(cevent, n, &sys->cpg_event_siblings, cpg_event_list) {
		struct request *req = container_of(cevent, struct request, cev);

		if (cevent->ctype == CPG_EVENT_DELIVER)
			continue;
		if (cevent->ctype == CPG_EVENT_CONCHG)
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
		if (req->rq.flags & SD_FLAG_CMD_DIRECT)
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

	if (cpg_event_running() || cpg_event_suspended() ||
	    list_empty(&sys->cpg_event_siblings))
		return;

	cevent = list_first_entry(&sys->cpg_event_siblings,
				  struct cpg_event, cpg_event_list);

	if (cevent->ctype == CPG_EVENT_CONCHG && sys->nr_outstanding_io)
		return;

	list_del(&cevent->cpg_event_list);
	sys->cur_cevent = cevent;

	cpg_event_set_running();

	INIT_LIST_HEAD(&cpg_event_work.w_list);
	cpg_event_work.fn = cpg_event_fn;
	cpg_event_work.done = cpg_event_done;

	queue_work(sys->cpg_wqueue, &cpg_event_work);
}

static void sd_confchg(cpg_handle_t handle, const struct cpg_name *group_name,
		       const struct cpg_address *member_list,
		       size_t member_list_entries,
		       const struct cpg_address *left_list,
		       size_t left_list_entries,
		       const struct cpg_address *joined_list,
		       size_t joined_list_entries)
{
	struct cpg_event *cevent;
	struct work_confchg *w = NULL;
	int i, size;

	dprintf("confchg nodeid %x\n", member_list[0].nodeid);
	dprintf("%zd %zd %zd\n", member_list_entries, left_list_entries,
		joined_list_entries);
	for (i = 0; i < member_list_entries; i++) {
		dprintf("[%x] node_id: %x, pid: %d\n", i,
			member_list[i].nodeid, member_list[i].pid);
	}

	if (sys->status == SD_STATUS_SHUTDOWN)
		return;

	w = zalloc(sizeof(*w));
	if (!w)
		goto oom;

	cevent = &w->cev;
	cevent->ctype = CPG_EVENT_CONCHG;


	vprintf(SDOG_DEBUG "allow new confchg, %p\n", cevent);

	size = sizeof(struct cpg_address) * member_list_entries;
	w->member_list = zalloc(size);
	if (!w->member_list)
		goto oom;
	memcpy(w->member_list, member_list, size);
	w->member_list_entries = member_list_entries;

	size = sizeof(struct cpg_address) * left_list_entries;
	w->left_list = zalloc(size);
	if (!w->left_list)
		goto oom;
	memcpy(w->left_list, left_list, size);
	w->left_list_entries = left_list_entries;

	size = sizeof(struct cpg_address) * joined_list_entries;
	w->joined_list = zalloc(size);
	if (!w->joined_list)
		goto oom;
	memcpy(w->joined_list, joined_list, size);
	w->joined_list_entries = joined_list_entries;

	list_add_tail(&cevent->cpg_event_list, &sys->cpg_event_siblings);
	start_cpg_event_work();

	return;
oom:
	if (w) {
		if (w->member_list)
			free(w->member_list);
		if (w->left_list)
			free(w->left_list);
		if (w->joined_list)
			free(w->joined_list);
	}
	panic("failed to allocate memory for a confchg event\n");
}

static int set_addr(unsigned int nodeid, int port)
{
	int ret, nr;
	corosync_cfg_handle_t handle;
	corosync_cfg_node_address_t addr;
	struct sockaddr_storage *ss = (struct sockaddr_storage *)addr.address;
	struct sockaddr_in *sin = (struct sockaddr_in *)addr.address;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr.address;
	void *saddr;
	char tmp[INET6_ADDRSTRLEN];

	memset(sys->this_node.addr, 0, sizeof(sys->this_node.addr));

	ret = corosync_cfg_initialize(&handle, NULL);
	if (ret != CPG_OK) {
		vprintf(SDOG_ERR "failed to initiazize cfg %d\n", ret);
		return -1;
	}

	ret = corosync_cfg_get_node_addrs(handle, nodeid, 1, &nr, &addr);
	if (ret != CPG_OK) {
		vprintf(SDOG_ERR "failed to get addr %d\n", ret);
		return -1;
	}

	if (!nr) {
		vprintf(SDOG_ERR "we got no address\n");
		return -1;
	}

	if (ss->ss_family == AF_INET6) {
		saddr = &sin6->sin6_addr;
		memcpy(sys->this_node.addr, saddr, 16);
	} else if (ss->ss_family == AF_INET) {
		saddr = &sin->sin_addr;
		memcpy(sys->this_node.addr + 12, saddr, 4);
	} else {
		vprintf(SDOG_ERR "unknown protocol %d\n", ss->ss_family);
		return -1;
	}

	inet_ntop(ss->ss_family, saddr, tmp, sizeof(tmp));

	vprintf(SDOG_INFO "addr = %s, port = %d\n", tmp, port);
	return 0;
}

int create_cluster(int port, int64_t zone)
{
	int fd, ret;
	cpg_handle_t cpg_handle;
	struct cpg_name group = { 8, "sheepdog" };
	cpg_callbacks_t cb = {&sd_deliver, &sd_confchg};
	unsigned int nodeid = 0;

	ret = cpg_initialize(&cpg_handle, &cb);
	if (ret != CPG_OK) {
		eprintf("Failed to initialize cpg, %d\n", ret);
		eprintf("Is corosync running?\n");
		return -1;
	}

	ret = cpg_local_get(cpg_handle, &nodeid);
	if (ret != CPG_OK) {
		eprintf("Failed to get the local node's identifier, %d\n", ret);
		return 1;
	}

join_retry:
	ret = cpg_join(cpg_handle, &group);
	switch (ret) {
	case CPG_OK:
		break;
	case CPG_ERR_TRY_AGAIN:
		dprintf("Failed to join the sheepdog group, try again\n");
		sleep(1);
		goto join_retry;
	case CPG_ERR_SECURITY:
		eprintf("Permission error.\n");
		return -1;
	default:
		eprintf("Failed to join the sheepdog group, %d\n", ret);
		return -1;
	}

	sys->handle = cpg_handle;
	sys->this_nodeid = nodeid;
	sys->this_pid = getpid();

	ret = set_addr(nodeid, port);
	if (ret)
		return 1;
	sys->this_node.port = port;
	sys->this_node.nr_vnodes = SD_DEFAULT_VNODES;
	if (zone == -1)
		sys->this_node.zone = nodeid;
	else
		sys->this_node.zone = zone;
	dprintf("zone id = %u\n", sys->this_node.zone);

	if (get_latest_epoch() == 0)
		sys->status = SD_STATUS_WAIT_FOR_FORMAT;
	else
		sys->status = SD_STATUS_WAIT_FOR_JOIN;
	INIT_LIST_HEAD(&sys->sd_node_list);
	INIT_LIST_HEAD(&sys->cpg_node_list);
	INIT_LIST_HEAD(&sys->pending_list);
	INIT_LIST_HEAD(&sys->leave_list);

	INIT_LIST_HEAD(&sys->outstanding_req_list);
	INIT_LIST_HEAD(&sys->req_wait_for_obj_list);
	INIT_LIST_HEAD(&sys->consistent_obj_list);

	INIT_LIST_HEAD(&sys->cpg_event_siblings);

	ret = cpg_fd_get(cpg_handle, &fd);
	if (ret != CPG_OK) {
		eprintf("Failed to retrieve cpg file descriptor, %d\n", ret);
		return 1;
	}
	ret = register_event(fd, group_handler, NULL);
	if (ret) {
		eprintf("Failed to register epoll events, %d\n", ret);
		return 1;
	}
	return 0;
}

/* after this function is called, this node only works as a gateway */
int leave_cluster(void)
{
	struct leave_message msg;

	memset(&msg, 0, sizeof(msg));
	msg.header.proto_ver = SD_SHEEP_PROTO_VER;
	msg.header.op = SD_MSG_LEAVE;
	msg.header.state = DM_FIN;
	msg.header.msg_length = sizeof(msg);
	msg.header.from = sys->this_node;
	msg.header.nodeid = sys->this_nodeid;
	msg.header.pid = sys->this_pid;
	msg.epoch = get_latest_epoch();

	dprintf("%d\n", msg.epoch);
	return send_message(sys->handle, (struct message_header *)&msg);
}
