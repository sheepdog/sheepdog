/*
 * Copyright (C) 2009 Nippon Telegraph and Telephone Corporation.
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
#include <sys/time.h>
#include <corosync/cpg.h>

#include "sheepdog_proto.h"
#include "collie.h"
#include "list.h"
#include "util.h"
#include "meta.h"
#include "logger.h"
#include "work.h"

struct vm {
	struct sheepdog_vm_list_entry ent;
	struct list_head list;
};

struct node {
	uint32_t nodeid;
	uint32_t pid;
	struct sheepdog_node_list_entry ent;
	struct list_head list;
};

struct message_header {
	uint8_t op;
	uint8_t done;
	uint8_t pad[2];
	uint32_t msg_length;
	struct sheepdog_node_list_entry from;
};

struct join_message {
	struct message_header header;
	uint32_t nodeid;
	uint32_t pid;
	struct sheepdog_node_list_entry master_node;
	uint32_t epoch;
	uint32_t nr_nodes;
	uint32_t nr_sobjs;
	uint32_t pad;
	struct {
		uint32_t nodeid;
		uint32_t pid;
		struct sheepdog_node_list_entry ent;
	} nodes[SD_MAX_NODES];
};

struct vdi_op_message {
	struct message_header header;
	struct sd_vdi_req req;
	struct sd_vdi_rsp rsp;
	uint8_t data[0];
};

struct work_deliver {
	struct message_header *msg;

	struct cluster_info *ci;
	struct work work;
};

struct work_confch {
	struct cpg_address *member_list;
	size_t member_list_entries;
	struct cpg_address *left_list;
	size_t left_list_entries;
	struct cpg_address *joined_list;
	size_t joined_list_entries;

	struct cluster_info *ci;
	struct work work;
};

struct work_queue *group_queue;

static int node_cmp(const void *a, const void *b)
{
	const struct sheepdog_node_list_entry *node1 = a;
	const struct sheepdog_node_list_entry *node2 = b;

	if (node1->id < node2->id)
		return -1;
	if (node1->id > node2->id)
		return 1;
	return 0;
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
	case CS_OK:
		break;
	case CS_ERR_TRY_AGAIN:
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

static void get_node_list(struct cluster_info *cluster, struct sd_node_req *req,
			  struct sd_node_rsp *rsp, void *data)
{
	int nr_nodes;
	struct node *node;

	nr_nodes = build_node_list(&cluster->node_list, data);
	rsp->data_length = nr_nodes * sizeof(struct sheepdog_node_list_entry);
	rsp->nr_nodes = nr_nodes;
	rsp->local_idx = get_node_idx(&cluster->this_node, data, nr_nodes);

	if (list_empty(&cluster->node_list)) {
		rsp->master_idx = -1;
		return;
	}
	node = list_first_entry(&cluster->node_list, struct node, list);
	rsp->master_idx = get_node_idx(&node->ent, data, nr_nodes);
}

static void get_vm_list(struct cluster_info *cluster, struct sd_rsp *rsp,
			void *data)
{
	int nr_vms;
	struct vm *vm;

	struct sheepdog_vm_list_entry *p = data;
	list_for_each_entry(vm, &cluster->vm_list, list) {
		*p++ = vm->ent;
	}

	nr_vms = p - (struct sheepdog_vm_list_entry *)data;
	rsp->data_length = nr_vms * sizeof(struct sheepdog_vm_list_entry);
}

void cluster_queue_request(struct work *work, int idx)
{
	struct request *req = container_of(work, struct request, work);
	struct sd_req *hdr = (struct sd_req *)&req->rq;
	struct sd_rsp *rsp = (struct sd_rsp *)&req->rp;
	struct cluster_info *cluster = req->ci->cluster;
	struct vdi_op_message *msg;
	int ret = SD_RES_SUCCESS;

	eprintf("%p %x\n", req, hdr->opcode);

	switch (hdr->opcode) {
	case SD_OP_GET_NODE_LIST:
		get_node_list(cluster, (struct sd_node_req *)hdr,
			      (struct sd_node_rsp *)rsp, req->data);
		break;
	case SD_OP_GET_VM_LIST:
		get_vm_list(cluster, rsp, req->data);
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
	msg->header.done = 0;
	msg->header.msg_length = sizeof(*msg) + hdr->data_length;
	msg->header.from = cluster->this_node;
	msg->req = *((struct sd_vdi_req *)&req->rq);
	msg->rsp = *((struct sd_vdi_rsp *)&req->rp);
	if (hdr->flags & SD_FLAG_CMD_WRITE)
		memcpy(msg->data, req->data, hdr->data_length);

	list_add(&req->pending_list, &cluster->pending_list);

	send_message(cluster->handle, (struct message_header *)msg);

	free(msg);
}

static struct vm *lookup_vm(struct list_head *entries, char *name)
{
	struct vm *vm;

	list_for_each_entry(vm, entries, list) {
		if (!strcmp((char *)vm->ent.name, name))
			return vm;
	}

	return NULL;
}

static void group_handler(int listen_fd, int events, void *data)
{
	struct cluster_info *ci = data;
	cpg_dispatch(ci->handle, CPG_DISPATCH_ALL);
}

static void print_node_list(struct cluster_info *ci)
{
	struct node *node;
	list_for_each_entry(node, &ci->node_list, list) {
		dprintf("%c nodeid: %x, pid: %d, ip: %d.%d.%d.%d:%d\n",
			node_cmp(&node->ent, &ci->this_node) ? ' ' : 'l',
			node->nodeid, node->pid,
			node->ent.addr[12], node->ent.addr[13],
			node->ent.addr[14], node->ent.addr[15], node->ent.port);
	}
}

static void add_node(struct cluster_info *ci, uint32_t nodeid, uint32_t pid,
		     struct sheepdog_node_list_entry *sd_ent)
{
	struct node *node;

	node = zalloc(sizeof(*node));
	if (!node) {
		eprintf("out of memory\n");
		return;
	}
	node->nodeid = nodeid;
	node->pid = pid;
	node->ent = *sd_ent;
	list_add_tail(&node->list, &ci->node_list);
}

static int is_master(struct cluster_info *ci)
{
	struct node *node;

	if (!ci->synchronized)
		return 0;

	if (list_empty(&ci->node_list))
		return 1;

	node = list_first_entry(&ci->node_list, struct node, list);
	if (node_cmp(&node->ent, &ci->this_node) == 0)
		return 1;

	return 0;
}

static void join(struct cluster_info *ci, struct join_message *msg)
{
	struct node *node;

	if (!ci->synchronized)
		return;

	if (!is_master(ci))
		return;

	if (msg->nr_sobjs)
		ci->nr_sobjs = msg->nr_sobjs;

	msg->epoch = ci->epoch;
	msg->nr_sobjs = ci->nr_sobjs;
	list_for_each_entry(node, &ci->node_list, list) {
		msg->nodes[msg->nr_nodes].nodeid = node->nodeid;
		msg->nodes[msg->nr_nodes].pid = node->pid;
		msg->nodes[msg->nr_nodes].ent = node->ent;
		msg->nr_nodes++;
	}
}

static void update_cluster_info(struct cluster_info *ci,
				struct join_message *msg)
{
	int i;
	int ret, nr_nodes = msg->nr_nodes;
	struct node *node, *e;
	struct sheepdog_node_list_entry entry[SD_MAX_NODES];

	if (!ci->nr_sobjs)
		ci->nr_sobjs = msg->nr_sobjs;

	if (ci->synchronized)
		goto out;

	list_for_each_entry_safe(node, e, &ci->node_list, list) {
		list_del(&node->list);
		free(node);
	}

	INIT_LIST_HEAD(&ci->node_list);
	for (i = 0; i < nr_nodes; i++)
		add_node(ci, msg->nodes[i].nodeid, msg->nodes[i].pid,
			 &msg->nodes[i].ent);

	ci->epoch = msg->epoch;
	ci->synchronized = 1;

	/* we are ready for object operations */
	update_epoch_store(ci->epoch);
	resume_work_queue(dobj_queue);
out:
	wait_work_queue_inactive(dobj_queue);

	add_node(ci, msg->nodeid, msg->pid, &msg->header.from);

	nr_nodes = build_node_list(&ci->node_list, entry);

	ret = epoch_log_write(ci->epoch + 1, (char *)entry,
			      nr_nodes * sizeof(struct sheepdog_node_list_entry));
	if (ret < 0)
		eprintf("can't write epoch %u\n", ci->epoch + 1);

	ci->epoch++;

	update_epoch_store(ci->epoch);

	resume_work_queue(dobj_queue);

	print_node_list(ci);
}

static void vdi_op(struct cluster_info *ci, struct vdi_op_message *msg)
{
	const struct sd_vdi_req *hdr = &msg->req;
	struct sd_vdi_rsp *rsp = &msg->rsp;
	void *data = msg->data;
	int ret = SD_RES_SUCCESS, is_current;
	uint64_t oid = 0;

	switch (hdr->opcode) {
	case SD_OP_NEW_VDI:
		ret = add_vdi(ci, data, strlen(data), hdr->vdi_size, &oid,
			      hdr->base_oid, hdr->tag, hdr->copies);
		break;
	case SD_OP_LOCK_VDI:
	case SD_OP_GET_VDI_INFO:
		ret = lookup_vdi(ci, data, &oid, hdr->tag, 1, &is_current);
		if (ret != SD_RES_SUCCESS)
			break;
		if (is_current)
			rsp->flags = SD_VDI_RSP_FLAG_CURRENT;
		break;
	case SD_OP_RELEASE_VDI:
		break;
	case SD_OP_MAKE_FS:
		ret = make_super_object(ci, &msg->req);
		break;
	default:
		ret = SD_RES_SYSTEM_ERROR;
		eprintf("opcode %d is not implemented\n", hdr->opcode);
		break;
	}

	rsp->oid = oid;
	rsp->result = ret;
}

static void vdi_op_done(struct cluster_info *ci, struct vdi_op_message *msg)
{
	const struct sd_vdi_req *hdr = &msg->req;
	struct sd_vdi_rsp *rsp = &msg->rsp;
	void *data = msg->data;
	struct vm *vm;
	struct request *req;
	int ret = msg->rsp.result;

	switch (hdr->opcode) {
	case SD_OP_NEW_VDI:
		break;
	case SD_OP_LOCK_VDI:
		if (lookup_vm(&ci->vm_list, (char *)data)) {
			ret = SD_RES_VDI_LOCKED;
			break;
		}

		vm = zalloc(sizeof(*vm));
		if (!vm) {
			ret = SD_RES_UNKNOWN;
			break;
		}
		strcpy((char *)vm->ent.name, (char *)data);
		memcpy(vm->ent.host_addr, msg->header.from.addr,
		       sizeof(vm->ent.host_addr));
		vm->ent.host_port = msg->header.from.port;

		list_add(&vm->list, &ci->vm_list);
		break;
	case SD_OP_RELEASE_VDI:
		vm = lookup_vm(&ci->vm_list, (char *)data);
		if (!vm) {
			ret = SD_RES_VDI_NOT_LOCKED;
			break;
		}

		list_del(&vm->list);
		free(vm);
		break;
	case SD_OP_GET_VDI_INFO:
		break;
	case SD_OP_MAKE_FS:
		if (ret == SD_RES_SUCCESS) {
			ci->nr_sobjs = ((struct sd_so_req *)hdr)->copies;
			eprintf("%d\n", ci->nr_sobjs);
		}

		break;
	default:
		eprintf("unknown operation %d\n", hdr->opcode);
		ret = SD_RES_UNKNOWN;
	}

	if (node_cmp(&ci->this_node, &msg->header.from) != 0)
		return;

	req = list_first_entry(&ci->pending_list, struct request, pending_list);

	rsp->result = ret;
	memcpy(req->data, data, rsp->data_length);
	memcpy(&req->rp, rsp, sizeof(req->rp));
	list_del(&req->pending_list);
	req->done(req);
}

static void __sd_deliver(struct work *work, int idx)
{
	struct work_deliver *w = container_of(work, struct work_deliver, work);
	struct message_header *m = w->msg;
	struct cluster_info *ci = w->ci;

	dprintf("op: %d, done: %d, size: %d, from: %d.%d.%d.%d:%d\n",
		m->op, m->done, m->msg_length,
		m->from.addr[12], m->from.addr[13],
		m->from.addr[14], m->from.addr[15], m->from.port);

	if (!m->done) {
		if (!is_master(ci))
			return;

		switch (m->op) {
		case SD_MSG_JOIN:
			join(ci, (struct join_message *)m);
			break;
		case SD_MSG_VDI_OP:
			vdi_op(ci, (struct vdi_op_message *)m);
			break;
		default:
			eprintf("unknown message %d\n", m->op);
			break;
		}

		m->done = 1;
		send_message(ci->handle, m);
	} else {
		switch (m->op) {
		case SD_MSG_JOIN:
			update_cluster_info(ci, (struct join_message *)m);
			break;
		case SD_MSG_VDI_OP:
			vdi_op_done(ci, (struct vdi_op_message *)m);
			break;
		default:
			eprintf("unknown message %d\n", m->op);
			break;
		}
	}
}

static void __sd_deliver_done(struct work *work, int idx)
{
	struct work_deliver *w = container_of(work, struct work_deliver, work);

	free(w->msg);
	free(w);
}

static void sd_deliver(cpg_handle_t handle, const struct cpg_name *group_name,
		       uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
	struct work_deliver *w;
	struct message_header *m = msg;
	struct cluster_info *ci;

	dprintf("op: %d, done: %d, size: %d, from: %d.%d.%d.%d:%d\n",
		m->op, m->done, m->msg_length,
		m->from.addr[12], m->from.addr[13],
		m->from.addr[14], m->from.addr[15], m->from.port);
	cpg_context_get(handle, (void **)&ci);

	w = zalloc(sizeof(*w));
	if (!w)
		return;

	w->msg = zalloc(msg_len);
	if (!w->msg)
		return;
	memcpy(w->msg, msg, msg_len);

	w->ci = ci;

	w->work.fn = __sd_deliver;
	w->work.done = __sd_deliver_done;

	if (m->op == SD_MSG_JOIN)
		queue_work(group_queue, &w->work);
	else
		queue_work(dobj_queue, &w->work);
}

static void __sd_confch(struct work *work, int idx)
{
	struct work_confch *w = container_of(work, struct work_confch, work);
	struct cluster_info *ci = w->ci;
	struct node *node, *e;
	int i;

	const struct cpg_address *member_list = w->member_list;
	size_t member_list_entries = w->member_list_entries;
	const struct cpg_address *left_list = w->left_list;
	size_t left_list_entries = w->left_list_entries;
	const struct cpg_address *joined_list = w->joined_list;
	size_t joined_list_entries = w->joined_list_entries;

	if (member_list_entries == joined_list_entries - left_list_entries &&
	    ci->this_nodeid == member_list[0].nodeid &&
	    ci->this_pid == member_list[0].pid) {
		ci->synchronized = 1;
		resume_work_queue(dobj_queue);
	}

	for (i = 0; i < left_list_entries; i++) {
		list_for_each_entry_safe(node, e, &ci->node_list, list) {
			int nr;
			unsigned pid;
			struct sheepdog_node_list_entry e[SD_MAX_NODES];

			if (node->nodeid != left_list[i].nodeid ||
			    node->pid != left_list[i].pid)
				continue;

			pid = node->pid;

			list_del(&node->list);
			free(node);

			nr = build_node_list(&ci->node_list, e);
			epoch_log_write(ci->epoch + 1, (char *)e,
					nr * sizeof(struct sheepdog_node_list_entry));

			ci->epoch++;
		}
	}

	for (i = 0; i < joined_list_entries; i++) {
		if (ci->this_nodeid == joined_list[0].nodeid &&
		    ci->this_pid == joined_list[0].pid) {
			struct join_message msg;

			msg.header.op = SD_MSG_JOIN;
			msg.header.done = 0;
			msg.header.msg_length = sizeof(msg);
			msg.header.from = ci->this_node;
			msg.nodeid = ci->this_nodeid;
			msg.pid = ci->this_pid;
			msg.nr_sobjs = nr_sobjs;

			send_message(ci->handle, (struct message_header *)&msg);
		}
	}

	if (left_list_entries == 0)
		return;

	print_node_list(ci);
}

static void __sd_confch_done(struct work *work, int idx)
{
	struct work_confch *w = container_of(work, struct work_confch, work);

	free(w->member_list);
	free(w->left_list);
	free(w->joined_list);
	free(w);
}

static void sd_confch(cpg_handle_t handle, const struct cpg_name *group_name,
		      const struct cpg_address *member_list,
		      size_t member_list_entries,
		      const struct cpg_address *left_list,
		      size_t left_list_entries,
		      const struct cpg_address *joined_list,
		      size_t joined_list_entries)
{
	struct work_confch *w = NULL;
	struct cluster_info *ci;
	int i, size;

	dprintf("confchg nodeid %x\n", member_list[0].nodeid);
	dprintf("%zd %zd %zd\n", member_list_entries, left_list_entries,
		joined_list_entries);
	for (i = 0; i < member_list_entries; i++) {
		dprintf("[%d] node_id: %d, pid: %d, reason: %d\n", i,
			member_list[i].nodeid, member_list[i].pid,
			member_list[i].reason);
	}

	cpg_context_get(handle, (void **)&ci);

	w = zalloc(sizeof(*w));
	if (!w)
		return;

	size = sizeof(struct cpg_address) * member_list_entries;
	w->member_list = zalloc(size);
	if (!w->member_list)
		goto err;
	memcpy(w->member_list, member_list, size);
	w->member_list_entries = member_list_entries;

	size = sizeof(struct cpg_address) * left_list_entries;
	w->left_list = zalloc(size);
	if (!w->left_list)
		goto err;
	memcpy(w->left_list, left_list, size);
	w->left_list_entries = left_list_entries;

	size = sizeof(struct cpg_address) * joined_list_entries;
	w->joined_list = zalloc(size);
	if (!w->joined_list)
		goto err;
	memcpy(w->joined_list, joined_list, size);
	w->joined_list_entries = joined_list_entries;

	w->ci = ci;

	w->work.fn = __sd_confch;
	w->work.done = __sd_confch_done;

	queue_work(group_queue, &w->work);

	return;
err:
	if (!w)
		return;

	if (w->member_list)
		free(w->member_list);
	if (w->left_list)
		free(w->left_list);
	if (w->joined_list)
		free(w->joined_list);
}

int build_node_list(struct list_head *node_list,
		    struct sheepdog_node_list_entry *entries)
{
	struct node *node;
	int nr = 0;

	list_for_each_entry(node, node_list, list) {
		if (entries)
			memcpy(entries + nr, &node->ent, sizeof(*entries));
		nr++;
	}
	if (entries)
		qsort(entries, nr, sizeof(*entries), node_cmp);

	return nr;
}

struct cluster_info *create_cluster(int port)
{
	int fd, ret;
	cpg_handle_t cpg_handle;
	struct cluster_info *ci;
	struct addrinfo hints, *res;
	char name[INET6_ADDRSTRLEN];
	struct cpg_name group = { 8, "sheepdog" };
	cpg_callbacks_t cb = { &sd_deliver, &sd_confch };
	unsigned int nodeid = 0;
	uint64_t hval;
	int i;

	ci = zalloc(sizeof(*ci));
	if (!ci)
		return NULL;

	ret = cpg_initialize(&cpg_handle, &cb);
	if (ret != CS_OK) {
		eprintf("Failed to initialize cpg, %d\n", ret);
		eprintf("Is corosync running?\n");
		return NULL;
	}

join_retry:
	ret = cpg_join(cpg_handle, &group);
	switch (ret) {
	case CS_OK:
		break;
	case CS_ERR_TRY_AGAIN:
		dprintf("Failed to join the sheepdog group, try again\n");
		sleep(1);
		goto join_retry;
	case CS_ERR_SECURITY:
		eprintf("Permission error.\n");
		exit(1);
	default:
		eprintf("Failed to join the sheepdog group, %d\n", ret);
		exit(1);
		break;
	}

	ret = cpg_local_get(cpg_handle, &nodeid);
	if (ret != CS_OK) {
		eprintf("Failed to get the local node's identifier, %d\n", ret);
		exit(1);
	}

	ci->handle = cpg_handle;
	ci->this_nodeid = nodeid;
	ci->this_pid = getpid();

	memset(&ci->this_node, 0, sizeof(ci->this_node));

	gethostname(name, sizeof(name));

	memset(&hints, 0, sizeof(hints));

	hints.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(name, NULL, &hints, &res);
	if (ret)
		exit(1);

	if (res->ai_family == AF_INET) {
		struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
		memset(ci->this_node.addr, 0, sizeof(ci->this_node.addr));
		memcpy(ci->this_node.addr + 12, &addr->sin_addr, 4);
	} else if (res->ai_family == AF_INET6) {
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *)res->ai_addr;
		memcpy(ci->this_node.addr, &addr->sin6_addr, 16);
	} else {
		eprintf("unknown address family\n");
		exit(1);
	}

	freeaddrinfo(res);

	ci->this_node.port = port;

	hval = fnv_64a_buf(&ci->this_node.port, sizeof(ci->this_node.port),
			   FNV1A_64_INIT);
	for (i = ARRAY_SIZE(ci->this_node.addr) - 1; i >= 0; i--)
		hval = fnv_64a_buf(&ci->this_node.addr[i], 1, hval);

	ci->this_node.id = hval;

	ci->synchronized = 0;
	INIT_LIST_HEAD(&ci->node_list);
	INIT_LIST_HEAD(&ci->vm_list);
	INIT_LIST_HEAD(&ci->pending_list);
	cpg_context_set(cpg_handle, ci);

	cpg_fd_get(cpg_handle, &fd);
	register_event(fd, group_handler, ci);
	return ci;
}
