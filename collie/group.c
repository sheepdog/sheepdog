/*
 * Copyright (C) 2009-2010 Nippon Telegraph and Telephone Corporation.
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
#include <corosync/cpg.h>
#include <corosync/cfg.h>

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

enum deliver_msg_state {
	DM_INIT = 1,
	DM_CONT,
	DM_FIN,
};

struct message_header {
	uint8_t op;
	uint8_t state;
	uint8_t pad[2];
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

	uint32_t *failed_vdis;
	int nr_failed_vdis;
	int first_cpg_node;
	int sd_node_left;
};

#define print_node_list(node_list)				\
({								\
	struct node *node;					\
	char name[128];						\
	list_for_each_entry(node, node_list, list) {		\
		dprintf("%c nodeid: %x, pid: %d, ip: %s\n",	\
			is_myself(&node->ent) ? 'l' : ' ',	\
			node->nodeid, node->pid,		\
			addr_to_str(name, sizeof(name),		\
			node->ent.addr, node->ent.port));	\
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

static int build_node_list(struct list_head *node_list,
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

int get_ordered_sd_node_list(struct sheepdog_node_list_entry *entries)
{
	return build_node_list(&sys->sd_node_list, entries);
}

int setup_ordered_sd_node_list(struct request *req)
{
	return get_ordered_sd_node_list(req->entry);
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

static void get_vm_list(struct sd_rsp *rsp, void *data)
{
	int nr_vms;
	struct vm *vm;

	struct sheepdog_vm_list_entry *p = data;
	list_for_each_entry(vm, &sys->vm_list, list) {
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
	struct vdi_op_message *msg;
	struct epoch_log *log;
	int ret = SD_RES_SUCCESS;

	eprintf("%p %x\n", req, hdr->opcode);

	switch (hdr->opcode) {
	case SD_OP_GET_NODE_LIST:
		get_node_list((struct sd_node_req *)hdr,
			      (struct sd_node_rsp *)rsp, req->data);
		break;
	case SD_OP_GET_VM_LIST:
		get_vm_list(rsp, req->data);
		break;
	case SD_OP_STAT_CLUSTER:
		log = (struct epoch_log *)req->data;

		((struct sd_vdi_rsp *)rsp)->rsvd = sys->status;
		log->ctime = get_cluster_ctime();
		log->epoch = get_latest_epoch();
		log->nr_nodes = epoch_log_read(log->epoch, (char *)log->nodes,
					       sizeof(log->nodes));
		if (log->nr_nodes == -1) {
			rsp->data_length = 0;
			log->nr_nodes = 0;
		} else{
			rsp->data_length = sizeof(*log);
			log->nr_nodes /= sizeof(log->nodes[0]);
		}

		rsp->result = SD_RES_SUCCESS;
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
	cpg_dispatch(sys->handle, CPG_DISPATCH_ALL);
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
	if (is_myself(&node->ent))
		return 1;
	return 0;
}

static int get_cluster_status(struct sheepdog_node_list_entry *node)
{
	struct sd_epoch_req hdr;
	struct sd_epoch_rsp *rsp = (struct sd_epoch_rsp *)&hdr;
	unsigned int rlen, wlen;
	int ret, fd, i, j;
	char name[128];
	uint64_t ctime;
	int nr_entries, nr_local_entries;
	struct sheepdog_node_list_entry entries[SD_MAX_NODES];
	struct sheepdog_node_list_entry local_entries[SD_MAX_NODES];
	uint32_t epoch;

	if (sys->status == SD_STATUS_INCONSISTENT_EPOCHS)
		return SD_STATUS_INCONSISTENT_EPOCHS;

	if (is_myself(node)) {
		nr_entries = ARRAY_SIZE(entries);
		ret = read_epoch(&epoch, &ctime, entries, &nr_entries);
	} else {
		addr_to_str(name, sizeof(name), node->addr, 0);

		fd = connect_to(name, node->port);
		if (fd < 0)
			return SD_STATUS_INCONSISTENT_EPOCHS;

		memset(&hdr, 0, sizeof(hdr));
		hdr.opcode = SD_OP_READ_EPOCH;
		hdr.epoch = sys->epoch;
		hdr.data_length = sizeof(entries);
		rlen = hdr.data_length;
		wlen = 0;

		ret = exec_req(fd, (struct sd_req *)&hdr, entries,
			       &wlen, &rlen);


		nr_entries = rlen / sizeof(*entries);
		if (ret != 0) {
			eprintf("failed to send request, %x, %s\n", ret, name);
			close(fd);
			return SD_STATUS_INCONSISTENT_EPOCHS;
		}
		epoch = rsp->latest_epoch;
		ctime = rsp->ctime;
		ret = rsp->result;

		close(fd);
	}

	if (ret != SD_RES_SUCCESS) {
		eprintf("failed to read epoch, %x\n", ret);
		return SD_STATUS_WAIT_FOR_FORMAT;
	}

	if (epoch != get_latest_epoch())
		return SD_STATUS_INCONSISTENT_EPOCHS;

	if (ctime != get_cluster_ctime())
		return SD_STATUS_INCONSISTENT_EPOCHS;

	nr_local_entries = epoch_log_read(epoch, (char *)local_entries,
					  sizeof(local_entries));
	nr_local_entries /= sizeof(local_entries[0]);

	if (nr_entries != nr_local_entries)
		return SD_STATUS_INCONSISTENT_EPOCHS;

	if (memcmp(entries, local_entries, sizeof(entries[0]) * nr_entries) != 0)
		return SD_STATUS_INCONSISTENT_EPOCHS;

	nr_entries = get_ordered_sd_node_list(entries);
	if (nr_entries + 1 != nr_local_entries)
		return SD_STATUS_WAIT_FOR_JOIN;

	for (i = 0; i < nr_local_entries; i++) {
		if (local_entries[i].id == node->id)
			goto next;
		for (j = 0; j < nr_entries; j++) {
			if (local_entries[i].id == entries[j].id)
				goto next;
		}
		return SD_STATUS_WAIT_FOR_JOIN;
	next:
		;
	}

	return SD_STATUS_OK;
}

static void join(struct join_message *msg)
{
	struct node *node;

	if (msg->nr_sobjs)
		sys->nr_sobjs = msg->nr_sobjs;

	msg->nr_sobjs = sys->nr_sobjs;
	msg->nr_nodes = 0;
	if (sys->status == SD_STATUS_OK)
		msg->epoch = sys->epoch;
	else
		msg->epoch = 0;

	list_for_each_entry(node, &sys->sd_node_list, list) {
		msg->nodes[msg->nr_nodes].nodeid = node->nodeid;
		msg->nodes[msg->nr_nodes].pid = node->pid;
		msg->nodes[msg->nr_nodes].ent = node->ent;
		msg->nr_nodes++;
	}

	if (sys->status == SD_STATUS_WAIT_FOR_JOIN)
		msg->cluster_status = get_cluster_status(&msg->header.from);
	else
		msg->cluster_status = sys->status;
}

static void get_vdi_bitmap_from_all(void)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int i, j, ret, nr_nodes, fd;
	/* fixme: we need this until starting up. */
	static DECLARE_BITMAP(tmp_vdi_inuse, SD_NR_VDIS);
	struct sheepdog_node_list_entry entry[SD_MAX_NODES];
	unsigned int rlen, wlen;
	char host[128];

	/*
	 * we don't need the proper order but this is the simplest
	 * way.
	 */
	nr_nodes = get_ordered_sd_node_list(entry);

	for (i = 0; i < nr_nodes; i++) {
		if (is_myself(&entry[i]))
			continue;

		addr_to_str(host, sizeof(host), entry[i].addr, 0);

		fd = connect_to(host, entry[i].port);
		if (fd < 0) {
			vprintf(SDOG_ERR "can't get the vdi bitmap %s, %m\n", host);
		}

		vprintf(SDOG_ERR "get the vdi bitmap %d %s\n", i, host);

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
		}

		for (j = 0; j < ARRAY_SIZE(sys->vdi_inuse); j++)
			sys->vdi_inuse[j] |= tmp_vdi_inuse[j];
	}
}

static int move_node_to_sd_list(uint32_t nodeid, uint32_t pid,
				struct sheepdog_node_list_entry ent)
{
	struct node *node;

	node = find_node(&sys->cpg_node_list, nodeid, pid);
	if (!node)
		return 1;

	if (!node->ent.id)
		node->ent = ent;

	list_del(&node->list);
	list_add_tail(&node->list, &sys->sd_node_list);

	return 0;
}

static void update_cluster_info(struct join_message *msg)
{
	int i;
	int ret, nr_nodes = msg->nr_nodes;
	struct sheepdog_node_list_entry entry[SD_MAX_NODES];

	if (!sys->nr_sobjs)
		sys->nr_sobjs = msg->nr_sobjs;

	if (sys->join_finished)
		goto out;

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

	sys->join_finished = 1;

	if (sys->status == SD_STATUS_WAIT_FOR_JOIN && msg->cluster_status == SD_STATUS_OK) {
		if (msg->epoch > 0) {
			sys->epoch = msg->epoch;
			sys->status = SD_STATUS_OK;
		}
	}

	eprintf("system status = %d, epoch = %d\n", msg->cluster_status, sys->epoch);
	if (sys->status == SD_STATUS_OK) {
		nr_nodes = get_ordered_sd_node_list(entry);

		dprintf("update epoch, %d, %d\n", sys->epoch, nr_nodes);
		ret = epoch_log_write(sys->epoch, (char *)entry,
				      nr_nodes * sizeof(struct sheepdog_node_list_entry));
		if (ret < 0)
			eprintf("can't write epoch %u\n", sys->epoch);
	}

out:
	ret = move_node_to_sd_list(msg->header.nodeid, msg->header.pid, msg->header.from);
	/*
	 * this should not happen since __sd_deliver() checks if the
	 * host from msg on cpg_node_list.
	 */
	if (ret)
		vprintf(SDOG_ERR "nodeid: %x, pid: %d has gone\n",
			msg->header.nodeid, msg->header.pid);

	if (sys->status == SD_STATUS_OK) {
		nr_nodes = get_ordered_sd_node_list(entry);

		dprintf("update epoch, %d, %d\n", sys->epoch + 1, nr_nodes);
		ret = epoch_log_write(sys->epoch + 1, (char *)entry,
				      nr_nodes * sizeof(struct sheepdog_node_list_entry));
		if (ret < 0)
			eprintf("can't write epoch %u\n", sys->epoch + 1);

		sys->epoch++;

		update_epoch_store(sys->epoch);
	}

	print_node_list(&sys->sd_node_list);

	if (sys->status == SD_STATUS_WAIT_FOR_JOIN && msg->cluster_status == SD_STATUS_OK) {
		if (msg->epoch == 0)
			sys->epoch = get_latest_epoch();
	}

	if (sys->status != SD_STATUS_INCONSISTENT_EPOCHS) {
		if (msg->cluster_status == SD_STATUS_OK) {
			get_vdi_bitmap_from_all();
			set_global_nr_copies(sys->nr_sobjs);
		}

		sys->status = msg->cluster_status;
	}
	return;
}

static void vdi_op(struct vdi_op_message *msg)
{
	const struct sd_vdi_req *hdr = &msg->req;
	struct sd_vdi_rsp *rsp = &msg->rsp;
	void *data = msg->data;
	int ret = SD_RES_SUCCESS;
	uint32_t vid = 0;

	switch (hdr->opcode) {
	case SD_OP_NEW_VDI:
		ret = add_vdi(hdr->epoch, data, hdr->data_length, hdr->vdi_size, &vid,
			      hdr->base_vdi_id, hdr->copies,
			      hdr->snapid);
		break;
	case SD_OP_DEL_VDI:
		if (lookup_vm(&sys->vm_list, (char *)data)) {
			ret = SD_RES_VDI_LOCKED;
			break;
		}
		ret = del_vdi(hdr->epoch, data, hdr->data_length, hdr->snapid);
		break;
	case SD_OP_LOCK_VDI:
	case SD_OP_GET_VDI_INFO:
		ret = lookup_vdi(hdr->epoch, data, hdr->data_length, &vid, hdr->snapid);
		if (ret != SD_RES_SUCCESS)
			break;
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
	rsp->result = ret;
}

static void vdi_op_done(struct vdi_op_message *msg)
{
	const struct sd_vdi_req *hdr = &msg->req;
	struct sd_vdi_rsp *rsp = &msg->rsp;
	void *data = msg->data;
	struct vm *vm;
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
		if (lookup_vm(&sys->vm_list, (char *)data)) {
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

		list_add(&vm->list, &sys->vm_list);
		break;
	case SD_OP_RELEASE_VDI:
		vm = lookup_vm(&sys->vm_list, (char *)data);
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
		sys->nr_sobjs = ((struct sd_so_req *)hdr)->copies;

		ctime = ((struct sd_so_req *)hdr)->ctime;
		set_cluster_ctime(ctime);

		latest_epoch = get_latest_epoch();
		for (i = 1; i <= latest_epoch; i++)
			remove_epoch(i);

		sys->epoch = 1;
		nr_nodes = get_ordered_sd_node_list(entry);

		dprintf("write epoch log, %d, %d\n", sys->epoch, nr_nodes);
		ret = epoch_log_write(sys->epoch, (char *)entry,
				      nr_nodes * sizeof(struct sheepdog_node_list_entry));
		if (ret < 0)
			eprintf("can't write epoch %u\n", sys->epoch);
		update_epoch_store(sys->epoch);

		set_nodeid(sys->this_node.id);
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
	if (!is_myself(&msg->header.from))
		return;

	req = list_first_entry(&sys->pending_list, struct request, pending_list);

	rsp->result = ret;
	memcpy(req->data, data, rsp->data_length);
	memcpy(&req->rp, rsp, sizeof(req->rp));
	list_del(&req->pending_list);
	req->done(req);
}

static void update_running_vm_state(struct cpg_event *cevent)
{
	struct work_deliver *w = container_of(cevent, struct work_deliver, cev);
	struct message_header *m = w->msg;
	struct sheepdog_vm_list_entry *e;
	int nr, i;
	struct vm *vm;

	if (sys->join_finished)
		goto out;

	/* This is my JOIN message. */
	vprintf(SDOG_DEBUG "we update the vm list\n");

	nr = (m->msg_length - sizeof(*m)) / sizeof(*e);
	e = (struct sheepdog_vm_list_entry *)(m + 1);

	for (i = 0; i < nr; i++) {
		vm = zalloc(sizeof(*vm));
		if (!vm)
			panic("failed to allocate memory for a vm\n");

		vm->ent = e[i];
		vprintf(SDOG_DEBUG "%d, got %s\n", i, e[i].name);
		list_add(&vm->list, &sys->vm_list);
	}
out:
	cevent->skip = 1;
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
	 * we don't want to perform any deliver events until we
	 * join; we wait for our JOIN message.
	 */
	if (!sys->join_finished) {
		if (m->pid != sys->this_pid || m->nodeid != sys->this_nodeid) {
			cevent->skip = 1;
			return;
		}
	}

	if (m->op == SD_MSG_JOIN) {
		uint32_t nodeid = m->nodeid;
		uint32_t pid = m->pid;

		node = find_node(&sys->cpg_node_list, nodeid, pid);
		if (!node) {
			dprintf("the node was left before join operation is finished\n");
			return;
		}

		if (!node->ent.id)
			node->ent = m->from;
	}

	if (m->state == DM_INIT && is_master()) {
		switch (m->op) {
		case SD_MSG_JOIN:
			join((struct join_message *)m);
			break;
		case SD_MSG_VDI_OP:
			vdi_op((struct vdi_op_message *)m);
			break;
		default:
			eprintf("unknown message %d\n", m->op);
			break;
		}
	}

	if (m->state == DM_CONT)
		update_running_vm_state(cevent);
	else if (m->state == DM_FIN) {
		switch (m->op) {
		case SD_MSG_JOIN:
			update_cluster_info((struct join_message *)m);
			break;
		case SD_MSG_VDI_OP:
			vdi_op_done((struct vdi_op_message *)m);
			break;
		default:
			eprintf("unknown message %d\n", m->op);
			break;
		}
	}
}

static void send_join_response(struct work_deliver *w)
{
	struct message_header *m;
	struct vm *vm;
	struct sheepdog_vm_list_entry *e;
	int i, nr = 2000;
	char *buf;

	/*
	 * FIXME: we need to inform the node of the JOIN failure in
	 * the case of OOM.
	 */
	buf = malloc(sizeof(*m) + sizeof(*e) * nr);
	m = (struct message_header *)buf;
	e = (struct sheepdog_vm_list_entry *)(buf + sizeof(*m));

	i = 0;
	m->state = DM_CONT;
	m->pid = w->msg->pid;
	m->nodeid = w->msg->nodeid;

	vprintf(SDOG_DEBUG "%u %u\n", m->pid, m->nodeid);

	list_for_each_entry(vm, &sys->vm_list, list) {
		*e = vm->ent;
		vprintf(SDOG_DEBUG "%d %s\n", i, e->name);
		e++;
		i++;

		if (!(i % nr)) {
			m->msg_length = sizeof(*m) + i * sizeof(*e);
			send_message(sys->handle, m);
			e = (struct sheepdog_vm_list_entry *)(buf + sizeof(*m));
			i = 0;
		}
	}

	if (i) {
		m->msg_length = sizeof(*m) + i * sizeof(*e);
		vprintf(SDOG_DEBUG "%d %d\n", i, m->msg_length);
		send_message(sys->handle, m);
	}

	m = w->msg;
	join((struct join_message *)m);
	m->state = DM_FIN;
	send_message(sys->handle, m);
}

static void __sd_deliver_done(struct cpg_event *cevent)
{
	struct work_deliver *w = container_of(cevent, struct work_deliver, cev);
	struct message_header *m;
	char name[128];

	m = w->msg;

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

	/*
	 * FIXME: we want to recover only after all nodes are fully
	 * synchronized
	 */

	if (m->state == DM_FIN && m->op == SD_MSG_JOIN && sys->epoch >= 2)
		start_recovery(sys->epoch, NULL, 0);
}

static void sd_deliver(cpg_handle_t handle, const struct cpg_name *group_name,
		       uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
	struct cpg_event *cevent;
	struct work_deliver *w;
	struct message_header *m = msg;
	char name[128];

	dprintf("op: %d, state: %u, size: %d, from: %s, nodeid: %u, pid: %u\n",
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
		if (m->op == SD_MSG_JOIN)
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
		struct vm *vm, *n;
		int ret, size;
		uint32_t vid;
		void *buf;

		w->sd_node_left++;

		size = sizeof(*w->failed_vdis) * 64;
		w->failed_vdis = malloc(size);
		list_for_each_entry_safe(vm, n, &sys->vm_list, list) {
			if (memcmp(vm->ent.host_addr, node->ent.addr,
				   sizeof(node->ent.addr)) != 0)
				continue;
			if (vm->ent.host_port != node->ent.port)
				continue;

			if (w->nr_failed_vdis * sizeof(*w->failed_vdis) >= size) {
				size *= 2;
				buf = realloc(w->failed_vdis, size);
				if (!buf) {
					eprintf("out of memory, %d\n", size);
					break;
				}
				w->failed_vdis = buf;
			}

			ret = lookup_vdi(sys->epoch, (char *)vm->ent.name,
					 sizeof(vm->ent.name), &vid, 0);
			if (ret == SD_RES_SUCCESS)
				w->failed_vdis[w->nr_failed_vdis++] = vid;
			else
				eprintf("cannot find vdi %s\n", vm->ent.name);

			list_del(&vm->list);
			free(vm);
		}

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

static void __sd_confchg(struct cpg_event *cevent)
{
	struct work_confchg *w = container_of(cevent, struct work_confchg, cev);

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

		/*
		 * If I'm the first collie joins in colosync, I
		 * becomes the master without sending JOIN.
		 */

		vprintf(SDOG_DEBUG "%d %x\n", sys->this_pid, sys->this_nodeid);

		memset(&msg, 0, sizeof(msg));

		msg.header.from = sys->this_node;
		msg.header.nodeid = sys->this_nodeid;
		msg.header.pid = sys->this_pid;
		msg.cluster_status = get_cluster_status(&msg.header.from);

		update_cluster_info(&msg);

		return;
	}

	print_node_list(&sys->sd_node_list);
}

static void send_join_request(struct cpg_address *addr, struct work_confchg *w)
{
	struct join_message msg;

	/* if I've just joined in cpg, I'll join in sheepdog. */
	if (!is_my_cpg_addr(addr))
		return;

	msg.header.op = SD_MSG_JOIN;
	msg.header.state = DM_INIT;
	msg.header.msg_length = sizeof(msg);
	msg.header.from = sys->this_node;
	msg.header.nodeid = sys->this_nodeid;
	msg.header.pid = sys->this_pid;

	get_global_nr_copies(&msg.nr_sobjs);

	send_message(sys->handle, (struct message_header *)&msg);

	vprintf(SDOG_INFO "%u %u\n", sys->this_nodeid, sys->this_pid);
}

static void __sd_confchg_done(struct cpg_event *cevent)
{
	struct work_confchg *w = container_of(cevent, struct work_confchg, cev);

	if (w->first_cpg_node)
		goto skip_join;

	for_each_node_list(w->joined_list, w->joined_list_entries,
			   send_join_request, w);

skip_join:
	if (w->sd_node_left) {
		if (w->sd_node_left > 1)
			panic("we can't handle the departure of multiple nodes %d, %Zd\n",
			      w->sd_node_left, w->left_list_entries);

		start_recovery(sys->epoch, w->failed_vdis, w->nr_failed_vdis);
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
		free(w->failed_vdis);
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

static void cpg_event_fn(struct work *w, int idx)
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

static void cpg_event_done(struct work *w, int idx)
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
			if (w->msg->op == SD_MSG_JOIN)
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

	if (!list_empty(&sys->cpg_event_siblings) && !cpg_event_suspended())
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

static int is_access_to_busy_objects(struct request *req)
{
	struct request *o_req;

	if (!req->local_oid[0] && !req->local_oid[1])
		return 0;

	list_for_each_entry(o_req, &sys->outstanding_req_list, r_wlist) {

		if (req->local_oid[0]) {
			if (req->local_oid[0] == o_req->local_oid[0] ||
			    req->local_oid[0] == o_req->local_oid[1])
				return 1;
		}

		if (req->local_oid[1]) {
			if (req->local_oid[1] == o_req->local_oid[0] ||
			    req->local_oid[1] == o_req->local_oid[1])
				return 1;
		}
	}
	return 0;
}

/* can be called only by the main process */
void start_cpg_event_work(void)
{
	struct cpg_event *cevent, *n;

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
		return;
	}

	list_for_each_entry_safe(cevent, n, &sys->cpg_event_siblings, cpg_event_list) {
		struct request *req = container_of(cevent, struct request, cev);

		if (cevent->ctype != CPG_EVENT_REQUEST)
			break;

		list_del(&cevent->cpg_event_list);

		if (is_io_request(req->rq.opcode)) {
			if (is_access_to_busy_objects(req)) {
				list_add_tail(&req->r_wlist, &sys->req_wait_for_obj_list);
				continue;
			}

			list_add_tail(&req->r_wlist, &sys->outstanding_req_list);

			sys->nr_outstanding_io++;

			if (req->rq.flags & SD_FLAG_CMD_DIRECT) {
				int ret = check_epoch(req);
				if (ret != SD_RES_SUCCESS) {
					req->rp.result = ret;
					req->done(req);
					continue;
				}
			}
		}
		queue_work(&req->work);
	}

	if (cpg_event_running() || cpg_event_suspended() ||
	    list_empty(&sys->cpg_event_siblings) || sys->nr_outstanding_io)
		return;

	cevent = list_first_entry(&sys->cpg_event_siblings,
				  struct cpg_event, cpg_event_list);

	list_del(&cevent->cpg_event_list);
	sys->cur_cevent = cevent;

	cpg_event_set_running();

	INIT_LIST_HEAD(&cpg_event_work.w_list);
	cpg_event_work.fn = cpg_event_fn;
	cpg_event_work.done = cpg_event_done;

	queue_work(&cpg_event_work);
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
		dprintf("[%d] node_id: %d, pid: %d, reason: %d\n", i,
			member_list[i].nodeid, member_list[i].pid,
			member_list[i].reason);
	}

	if (sys->status == SD_STATUS_SHUTDOWN || sys->status == SD_STATUS_INCONSISTENT_EPOCHS)
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

static void set_addr(unsigned int nodeid, int port)
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
	if (ret != CS_OK) {
		vprintf(SDOG_ERR "failed to initiazize cfg %d\n", ret);
		exit(1);
	}

	ret = corosync_cfg_get_node_addrs(handle, nodeid, 1, &nr, &addr);
	if (ret != CS_OK) {
		vprintf(SDOG_ERR "failed to get addr %d\n", ret);
		exit(1);
	}

	if (!nr) {
		vprintf(SDOG_ERR "we got no address\n");
		exit(1);
	}

	if (ss->ss_family == AF_INET6) {
		saddr = &sin6->sin6_addr;
		memcpy(sys->this_node.addr, saddr, 16);
	} else if (ss->ss_family == AF_INET) {
		saddr = &sin->sin_addr;
		memcpy(sys->this_node.addr + 12, saddr, 16);
	} else {
		vprintf(SDOG_ERR "unknown protocol %d\n", ss->ss_family);
		exit(1);
	}

	inet_ntop(ss->ss_family, saddr, tmp, sizeof(tmp));

	vprintf(SDOG_INFO "addr = %s, port = %d\n", tmp, port);
}

int create_cluster(int port)
{
	int fd, ret;
	cpg_handle_t cpg_handle;
	struct cpg_name group = { 8, "sheepdog" };
	cpg_callbacks_t cb = {&sd_deliver, &sd_confchg};
	unsigned int nodeid = 0;

	ret = cpg_initialize(&cpg_handle, &cb);
	if (ret != CS_OK) {
		eprintf("Failed to initialize cpg, %d\n", ret);
		eprintf("Is corosync running?\n");
		return -1;
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

	sys->handle = cpg_handle;
	sys->this_nodeid = nodeid;
	sys->this_pid = getpid();

	set_addr(nodeid, port);
	sys->this_node.port = port;

	ret = get_nodeid(&sys->this_node.id);
	if (!sys->this_node.id) {
		uint64_t hval;
		int i;

		hval = fnv_64a_buf(&sys->this_node.port,
				   sizeof(sys->this_node.port),
				   FNV1A_64_INIT);
		for (i = ARRAY_SIZE(sys->this_node.addr) - 1; i >= 0; i--)
			hval = fnv_64a_buf(&sys->this_node.addr[i], 1, hval);
		sys->this_node.id = hval;
	}

	if (get_latest_epoch() == 0)
		sys->status = SD_STATUS_WAIT_FOR_FORMAT;
	else
		sys->status = SD_STATUS_WAIT_FOR_JOIN;
	INIT_LIST_HEAD(&sys->sd_node_list);
	INIT_LIST_HEAD(&sys->cpg_node_list);
	INIT_LIST_HEAD(&sys->vm_list);
	INIT_LIST_HEAD(&sys->pending_list);

	INIT_LIST_HEAD(&sys->outstanding_req_list);
	INIT_LIST_HEAD(&sys->req_wait_for_obj_list);

	INIT_LIST_HEAD(&sys->cpg_event_siblings);
	cpg_context_set(cpg_handle, sys);

	cpg_fd_get(cpg_handle, &fd);
	register_event(fd, group_handler, NULL);
	return 0;
}
