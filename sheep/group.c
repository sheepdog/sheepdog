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

#include "sheepdog_proto.h"
#include "sheep_priv.h"
#include "list.h"
#include "util.h"
#include "logger.h"
#include "work.h"
#include "cluster.h"

static int cdrv_fd;

struct node {
	struct sd_node ent;
	struct list_head list;
};

struct vnode_info {
	struct sd_vnode entries[SD_MAX_VNODES];
	int nr_vnodes;
	int nr_zones;
	int refcnt;
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
	struct sd_vdi_req req;
	struct sd_vdi_rsp rsp;
	uint8_t data[0];
};

struct work_notify {
	struct event_struct cev;

	struct sd_node sender;

	struct request *req;
	void *msg;
};

struct work_join {
	struct event_struct cev;

	struct sd_node *member_list;
	size_t member_list_entries;
	struct sd_node joined;

	struct join_message *jm;
};

struct work_leave {
	struct event_struct cev;

	struct sd_node *member_list;
	size_t member_list_entries;
	struct sd_node left;
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

static int event_running;
static struct vnode_info *current_vnode_info;

static size_t get_join_message_size(struct join_message *jm)
{
	/* jm->nr_nodes is always larger than jm->nr_leave_nodes, so
	 * it is safe to use jm->nr_nodes. */
	return sizeof(*jm) + jm->nr_nodes * sizeof(jm->nodes[0]);
}

int get_zones_nr_from(struct sd_node *nodes, int nr_nodes)
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

struct vnode_info *get_vnode_info(void)
{
	assert(current_vnode_info);
	current_vnode_info->refcnt++;
	return current_vnode_info;
}

void put_vnode_info(struct vnode_info *vnodes)
{
	if (vnodes && --vnodes->refcnt == 0)
		free(vnodes);
}

struct sd_vnode *oid_to_vnode(struct vnode_info *vnode_info, uint64_t oid,
		int copy_idx)
{
	int n;

	n = obj_to_sheep(vnode_info->entries, vnode_info->nr_vnodes,
			 oid, copy_idx);
	return &vnode_info->entries[n];
}


static int update_vnode_info(void)
{
	struct vnode_info *vnode_info;

	vnode_info = zalloc(sizeof(*vnode_info));
	if (!vnode_info) {
		eprintf("failed to allocate memory\n");
		return 1;
	}

	vnode_info->nr_vnodes = nodes_to_vnodes(sys->nodes, sys->nr_nodes,
						vnode_info->entries);
	vnode_info->nr_zones = get_zones_nr_from(sys->nodes, sys->nr_nodes);
	vnode_info->refcnt = 1;

	put_vnode_info(current_vnode_info);
	current_vnode_info = vnode_info;
	return 0;
}

/*
 * If we have less zones available than the desired redundancy we have to do
 * with nr_zones copies, sorry.
 */
int get_nr_copies(struct vnode_info *vnode_info)
{
	return min(vnode_info->nr_zones, sys->nr_copies);
}

static void do_cluster_op(void *arg)
{
	struct vdi_op_message *msg = arg;
	int ret;
	struct request *req;
	void *data;

	req = list_first_entry(&sys->pending_list, struct request, pending_list);

	if (has_process_main(req->op))
		data = msg->data;
	else
		data = req->data;
	ret = do_process_work(req->op, (const struct sd_req *)&msg->req,
			      (struct sd_rsp *)&msg->rsp, data);

	msg->rsp.result = ret;
}

void do_cluster_request(struct work *work)
{
	struct request *req = container_of(work, struct request, work);
	struct sd_req *hdr = (struct sd_req *)&req->rq;
	struct vdi_op_message *msg;
	size_t size;

	eprintf("%p %x\n", req, hdr->opcode);

	if (has_process_main(req->op))
		size = sizeof(*msg) + hdr->data_length;
	else
		size = sizeof(*msg);

	msg = zalloc(size);
	if (!msg) {
		eprintf("failed to allocate memory\n");
		return;
	}

	msg->req = *((struct sd_vdi_req *)&req->rq);
	msg->rsp = *((struct sd_vdi_rsp *)&req->rp);
	if (has_process_main(req->op))
		memcpy(msg->data, req->data, hdr->data_length);

	list_add_tail(&req->pending_list, &sys->pending_list);

	if (has_process_work(req->op))
		sys->cdrv->notify(msg, size, do_cluster_op);
	else {
		msg->rsp.result = SD_RES_SUCCESS;
		sys->cdrv->notify(msg, size, NULL);
	}

	free(msg);
}

static void group_handler(int listen_fd, int events, void *data)
{
	int ret;
	if (events & EPOLLHUP) {
		eprintf("received EPOLLHUP event: has corosync exited?\n");
		goto out;
	}

	ret = sys->cdrv->dispatch();
	if (ret == 0)
		return;
	else
		eprintf("oops... an error occurred inside corosync\n");
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
		if (node_cmp(&n->ent, entry) == 0)
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
		if (node_cmp(&nodes[i], entry) == 0)
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
	/* When the joining node is newly created, we need not check anything. */
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

static int get_cluster_status(struct sd_node *from,
			      struct sd_node *entries,
			      int nr_entries, uint64_t ctime, uint32_t epoch,
			      uint32_t *status, uint8_t *inc_epoch)
{
	int i, j, ret = SD_RES_SUCCESS;
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
		nr = sys->nr_nodes + 1;
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

static void join(struct sd_node *joining, struct join_message *msg)
{
	if (msg->proto_ver != SD_SHEEP_PROTO_VER) {
		eprintf("joining node sent a message with the wrong protocol version\n");
		msg->result = SD_RES_VER_MISMATCH;
		return;
	}

	msg->result = get_cluster_status(joining, msg->nodes, msg->nr_nodes,
					 msg->ctime, msg->epoch,
					 &msg->cluster_status, &msg->inc_epoch);
	msg->nr_copies = sys->nr_copies;
	msg->cluster_flags = sys->flags;
	msg->ctime = get_cluster_ctime();
	if (sd_store)
		strcpy((char *)msg->store, sd_store->name);
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

static void get_vdi_bitmap_from_sd_list(void)
{
	int i;
	/* fixme: we need this until starting up. */

	for (i = 0; i < sys->nr_nodes; i++)
		get_vdi_bitmap_from(sys->nodes + i);
}

static void finish_join(struct join_message *msg, struct sd_node *joined,
		struct sd_node *nodes, size_t nr_nodes)
{
	int i;

	sys->nr_copies = msg->nr_copies;
	sys->epoch = msg->epoch;

	/* add nodes execept for newly joined one */
	for (i = 0; i < nr_nodes; i++) {
		if (node_cmp(nodes + i, joined) == 0)
			continue;

		sys->nodes[sys->nr_nodes++] = nodes[i];
	}
	qsort(sys->nodes, sys->nr_nodes, sizeof(*sys->nodes), node_cmp);

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

	sys->join_finished = 1;

	if ((msg->cluster_status == SD_STATUS_OK ||
	     msg->cluster_status == SD_STATUS_HALT) && msg->inc_epoch)
		update_epoch_log(sys->epoch);

	if (!sd_store && strlen((char *)msg->store)) {
		sd_store = find_store_driver((char *)msg->store);
		if (sd_store) {
			sd_store->init(obj_path);
			if (set_cluster_store(sd_store->name) != SD_RES_SUCCESS)
				panic("failed to store into config file\n");
		} else
				panic("backend store %s not supported\n", msg->store);
	}
}

static void update_cluster_info(struct join_message *msg,
		struct sd_node *joined, struct sd_node *nodes, size_t nr_nodes)
{
	eprintf("status = %d, epoch = %d, %x, %d\n", msg->cluster_status,
		msg->epoch, msg->result, sys->join_finished);

	if (sys_stat_join_failed())
		return;

	if (!sys->join_finished)
		finish_join(msg, joined, nodes, nr_nodes);

	sys->nodes[sys->nr_nodes++] = *joined;
	qsort(sys->nodes, sys->nr_nodes, sizeof(*sys->nodes), node_cmp);

	if (msg->cluster_status == SD_STATUS_OK ||
	    msg->cluster_status == SD_STATUS_HALT) {
		if (msg->inc_epoch) {
			sys->epoch++;
			update_epoch_log(sys->epoch);
			update_epoch_store(sys->epoch);
		}
		/* Fresh node */
		if (!sys_stat_ok() && !sys_stat_halt()) {
			set_cluster_copies(sys->nr_copies);
			set_cluster_flags(sys->flags);
			set_cluster_ctime(msg->ctime);
		}
	}
	update_vnode_info();
	sys_stat_set(msg->cluster_status);

	print_node_list(sys->nodes, sys->nr_nodes);
}

static void __sd_notify(struct event_struct *cevent)
{
}

static void __sd_notify_done(struct event_struct *cevent)
{
	struct work_notify *w = container_of(cevent, struct work_notify, cev);
	struct vdi_op_message *msg = w->msg;
	struct request *req = w->req;
	int ret = msg->rsp.result;
	struct sd_op_template *op = get_sd_op(msg->req.opcode);

	if (ret == SD_RES_SUCCESS && has_process_main(op))
		ret = do_process_main(op, (const struct sd_req *)&msg->req,
				      (struct sd_rsp *)&msg->rsp, msg->data);

	if (!req)
		return;

	msg->rsp.result = ret;
	if (has_process_main(req->op))
		memcpy(req->data, msg->data, msg->rsp.data_length);
	memcpy(&req->rp, &msg->rsp, sizeof(req->rp));
	req->done(req);
}

void sd_notify_handler(struct sd_node *sender, void *msg, size_t msg_len)
{
	struct event_struct *cevent;
	struct work_notify *w;

	dprintf("size: %zd, from: %s\n", msg_len, node_to_str(sender));

	w = zalloc(sizeof(*w));
	if (!w)
		return;

	cevent = &w->cev;
	cevent->ctype = EVENT_NOTIFY;

	vprintf(SDOG_DEBUG, "allow new deliver %p\n", cevent);

	w->sender = *sender;
	if (msg_len) {
		w->msg = zalloc(msg_len);
		if (!w->msg)
			return;
		memcpy(w->msg, msg, msg_len);
	} else
		w->msg = NULL;

	if (is_myself(sender->addr, sender->port)) {
		w->req = list_first_entry(&sys->pending_list, struct request,
					  pending_list);
		list_del(&w->req->pending_list);
	}

	list_add_tail(&cevent->event_list, &sys->event_queue);

	process_request_event_queues();
}

/*
 * Check whether the majority of Sheepdog nodes are still alive or not
 */
static int check_majority(struct sd_node *nodes, int nr_nodes)
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
			dprintf("the majority of nodes are alive\n");
			return 1;
		}
	}
	dprintf("%d, %d, %d\n", nr_nodes, nr_majority, nr_reachable);
	eprintf("the majority of nodes are not alive\n");
	return 0;
}

static void __sd_join(struct event_struct *cevent)
{
	struct work_join *w = container_of(cevent, struct work_join, cev);
	struct join_message *msg = w->jm;
	int i;

	if (msg->cluster_status != SD_STATUS_OK &&
	    msg->cluster_status != SD_STATUS_HALT)
		return;

	if (sys_stat_ok())
		return;

	get_vdi_bitmap_from_sd_list();
	for (i = 0; i < w->member_list_entries; i++)
		get_vdi_bitmap_from(w->member_list + i);
}

static void __sd_leave(struct event_struct *cevent)
{
	struct work_leave *w = container_of(cevent, struct work_leave, cev);

	if (!check_majority(w->member_list, w->member_list_entries)) {
		eprintf("perhaps a network partition has occurred?\n");
		abort();
	}
}

enum cluster_join_result sd_check_join_cb(struct sd_node *joining, void *opaque)
{
	struct join_message *jm = opaque;
	struct node *node;

	if (node_cmp(joining, &sys->this_node) == 0) {
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
		eprintf("transfer mastership (%d, %d)\n", jm->epoch, sys->epoch);
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

static void __sd_join_done(struct event_struct *cevent)
{
	struct work_join *w = container_of(cevent, struct work_join, cev);
	struct join_message *jm = w->jm;
	struct node *node, *t;

	print_node_list(sys->nodes, sys->nr_nodes);

	if (!sys_stat_join_failed()) {
		update_cluster_info(jm, &w->joined, w->member_list,
				    w->member_list_entries);
	}

	if (sys_can_recover() && jm->inc_epoch) {
		list_for_each_entry_safe(node, t, &sys->leave_list, list) {
			list_del(&node->list);
		}
		start_recovery(sys->epoch);
	}

	if (sys_stat_halt()) {
		if (current_vnode_info->nr_zones >= sys->nr_copies)
			sys_stat_set(SD_STATUS_OK);
	}

	if (node_cmp(&w->joined, &sys->this_node) == 0)
		/* this output is used for testing */
		vprintf(SDOG_DEBUG, "join Sheepdog cluster\n");
}

static void __sd_leave_done(struct event_struct *cevent)
{
	struct work_leave *w = container_of(cevent, struct work_leave, cev);

	sys->nr_nodes = w->member_list_entries;
	memcpy(sys->nodes, w->member_list, sizeof(*sys->nodes) * sys->nr_nodes);
	qsort(sys->nodes, sys->nr_nodes, sizeof(*sys->nodes), node_cmp);

	if (sys_can_recover()) {
		sys->epoch++;
		update_epoch_store(sys->epoch);
		update_epoch_log(sys->epoch);
	}
	update_vnode_info();

	print_node_list(sys->nodes, sys->nr_nodes);

	if (sys_can_recover())
		start_recovery(sys->epoch);

	if (sys_can_halt()) {
		if (current_vnode_info->nr_zones < sys->nr_copies)
			sys_stat_set(SD_STATUS_HALT);
	}
}

static void event_free(struct event_struct *cevent)
{
	switch (cevent->ctype) {
	case EVENT_JOIN: {
		struct work_join *w = container_of(cevent, struct work_join, cev);
		free(w->member_list);
		free(w);
		break;
	}
	case EVENT_LEAVE: {
		struct work_leave *w = container_of(cevent, struct work_leave, cev);
		free(w->member_list);
		free(w);
		break;
	}
	case EVENT_NOTIFY: {
		struct work_notify *w = container_of(cevent, struct work_notify, cev);
		free(w->msg);
		free(w);
		break;
	}
	default:
		break;
	}
}

static struct work event_work;

static void event_fn(struct work *work)
{
	struct event_struct *cevent = sys->cur_cevent;

	/*
	 * we can't touch sys->event_queue because of a race
	 * with sd_deliver() and sd_confchg()...
	 */

	switch (cevent->ctype) {
	case EVENT_JOIN:
		__sd_join(cevent);
		break;
	case EVENT_LEAVE:
		__sd_leave(cevent);
		break;
	case EVENT_NOTIFY:
		__sd_notify(cevent);
		break;
	case EVENT_REQUEST:
		vprintf(SDOG_ERR, "should not happen\n");
		break;
	default:
		vprintf(SDOG_ERR, "unknown event %d\n", cevent->ctype);
	}
}

static void event_done(struct work *work)
{
	struct event_struct *cevent;
	int ret;

	if (!sys->cur_cevent)
		vprintf(SDOG_ERR, "bug\n");

	cevent = sys->cur_cevent;
	sys->cur_cevent = NULL;

	vprintf(SDOG_DEBUG, "%p\n", cevent);

	switch (cevent->ctype) {
	case EVENT_JOIN:
		__sd_join_done(cevent);
		break;
	case EVENT_LEAVE:
		__sd_leave_done(cevent);
		break;
	case EVENT_NOTIFY:
		__sd_notify_done(cevent);
		break;
	case EVENT_REQUEST:
		vprintf(SDOG_ERR, "should not happen\n");
		break;
	default:
		vprintf(SDOG_ERR, "unknown event %d\n", cevent->ctype);
	}

	vprintf(SDOG_DEBUG, "free %p\n", cevent);
	event_free(cevent);
	event_running = 0;
	ret = register_event(cdrv_fd, group_handler, NULL);
	if (ret)
		panic("failed to register event fd");

	process_request_event_queues();
}

int is_access_to_busy_objects(uint64_t oid)
{
	struct request *req;

	list_for_each_entry(req, &sys->outstanding_req_list, r_wlist) {
		if (oid == req->local_oid)
			return 1;
	}
	return 0;
}

static int need_consistency_check(uint8_t opcode, uint16_t flags)
{
	if (flags & SD_FLAG_CMD_IO_LOCAL)
		/* only gateway fixes data consistency */
		return 0;

	if (opcode != SD_OP_READ_OBJ)
		/* consistency is fixed when clients read data for the
		 * first time */
		return 0;

	if (flags & SD_FLAG_CMD_WEAK_CONSISTENCY)
		return 0;

	return 1;
}

static inline void set_consistency_check(struct request *req, uint64_t oid)
{
	uint32_t vdi_id = oid_to_vid(oid);
	struct data_object_bmap *bmap;

	if (is_vdi_obj(oid))
		return;

	req->check_consistency = 1;
	list_for_each_entry(bmap, &sys->consistent_obj_list, list) {
		if (bmap->vdi_id == vdi_id) {
			if (test_bit(data_oid_to_idx(oid), bmap->dobjs))
				req->check_consistency = 0;
			break;
		}
	}
}

static void process_request_queue(void)
{
	struct event_struct *cevent, *n;

	list_for_each_entry_safe(cevent, n, &sys->request_queue, event_list) {
		struct request *req = container_of(cevent, struct request, cev);
		struct sd_obj_req *hdr = (struct sd_obj_req *)&req->rq;

		list_del(&cevent->event_list);

		if (is_io_op(req->op)) {
			int copies = sys->nr_copies;

			if (copies > req->vnodes->nr_zones)
				copies = req->vnodes->nr_zones;

			if (!(req->rq.flags & SD_FLAG_CMD_IO_LOCAL) &&
			    object_is_cached(hdr->oid)) {
				/* If we have cache of it we are at its service. */
				list_add_tail(&req->r_wlist, &sys->outstanding_req_list);
				sys->nr_outstanding_io++;
				queue_work(sys->gateway_wqueue, &req->work);
				continue;
			}

			list_add_tail(&req->r_wlist, &sys->outstanding_req_list);
			sys->nr_outstanding_io++;

			if (need_consistency_check(req->rq.opcode, req->rq.flags))
				set_consistency_check(req, hdr->oid);

			if (req->rq.flags & SD_FLAG_CMD_IO_LOCAL)
				queue_work(sys->io_wqueue, &req->work);
			else
				queue_work(sys->gateway_wqueue, &req->work);
		} else /* (is_cluster_op(req->op) || is_local_op(req->op)) */
			queue_work(sys->io_wqueue, &req->work);
	}
}

static inline void process_event_queue(void)
{
	struct event_struct *cevent;
	/*
	 * we need to serialize events so we don't call queue_work
	 * if one event is running by executing event_fn() or event_done().
	 */
	if (event_running || sys->nr_outstanding_io)
		return;

	cevent = list_first_entry(&sys->event_queue,
			struct event_struct, event_list);
	list_del(&cevent->event_list);
	sys->cur_cevent = cevent;

	event_running = 1;

	event_work.fn = event_fn;
	event_work.done = event_done;

	unregister_event(cdrv_fd);
	queue_work(sys->event_wqueue, &event_work);
}

/* can be called only by the main process */
void process_request_event_queues(void)
{
	if (!list_empty(&sys->event_queue))
		process_event_queue();
	else
		process_request_queue();
}

void sd_join_handler(struct sd_node *joined, struct sd_node *members,
		size_t nr_members, enum cluster_join_result result,
		void *opaque)
{
	struct event_struct *cevent;
	struct work_join *w = NULL;
	int i, size;
	int nr, nr_local, nr_leave;
	struct node *n;
	struct join_message *jm;
	uint32_t le = get_latest_epoch();

	if (node_cmp(joined, &sys->this_node) == 0) {
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

		w = zalloc(sizeof(*w));
		if (!w)
			panic("failed to allocate memory");

		cevent = &w->cev;
		cevent->ctype = EVENT_JOIN;

		vprintf(SDOG_DEBUG, "allow new confchg %p\n", cevent);

		size = sizeof(struct sd_node) * nr_members;
		w->member_list = zalloc(size);
		if (!w->member_list)
			panic("failed to allocate memory");

		memcpy(w->member_list, members, size);
		w->member_list_entries = nr_members;

		w->joined = *joined;

		size = get_join_message_size(opaque);
		w->jm = zalloc(size);
		if (!w->jm)
			panic("failed to allocate memory\n");
		memcpy(w->jm, opaque, size);

		list_add_tail(&cevent->event_list, &sys->event_queue);
		process_request_event_queues();
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
			sys->nodes[sys->nr_nodes++] = sys->this_node;
			qsort(sys->nodes, sys->nr_nodes, sizeof(*sys->nodes), node_cmp);
			sys->epoch = get_latest_epoch();

			update_vnode_info();
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

		if (node_cmp(joined, &sys->this_node) == 0)
			/* this output is used for testing */
			vprintf(SDOG_DEBUG, "join Sheepdog cluster\n");
		break;
	}
}

void sd_leave_handler(struct sd_node *left, struct sd_node *members,
		size_t nr_members)
{
	struct event_struct *cevent;
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
	cevent->ctype = EVENT_LEAVE;


	vprintf(SDOG_DEBUG, "allow new confchg %p\n", cevent);

	size = sizeof(struct sd_node) * nr_members;
	w->member_list = zalloc(size);
	if (!w->member_list)
		goto oom;
	memcpy(w->member_list, members, size);
	w->member_list_entries = nr_members;

	w->left = *left;

	list_add_tail(&cevent->event_list, &sys->event_queue);
	process_request_event_queues();

	return;
oom:
	if (w) {
		if (w->member_list)
			free(w->member_list);
		free(w);
	}
	panic("failed to allocate memory for a confchg event\n");
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

	cdrv_fd = sys->cdrv->init(sys->cdrv_option, sys->this_node.addr);
	if (cdrv_fd < 0)
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

	INIT_LIST_HEAD(&sys->outstanding_req_list);
	INIT_LIST_HEAD(&sys->req_wait_for_obj_list);
	INIT_LIST_HEAD(&sys->consistent_obj_list);
	INIT_LIST_HEAD(&sys->blocking_conn_list);

	INIT_LIST_HEAD(&sys->request_queue);
	INIT_LIST_HEAD(&sys->event_queue);

	ret = register_event(cdrv_fd, group_handler, NULL);
	if (ret) {
		eprintf("failed to register epoll events (%d)\n", ret);
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
