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
#include <unistd.h>
#include <poll.h>
#include <sys/epoll.h>
#include <corosync/cpg.h>
#include <corosync/cfg.h>

#include "cluster.h"
#include "event.h"
#include "work.h"

#define CPG_INIT_RETRY_CNT 10

struct cpg_node {
	uint32_t nodeid;
	uint32_t pid;
	struct sd_node node;
};

static cpg_handle_t cpg_handle;
static struct cpg_name cpg_group = { 8, "sheepdog" };

static corosync_cfg_handle_t cfg_handle;
static struct cpg_node this_node;

static LIST_HEAD(corosync_block_event_list);
static LIST_HEAD(corosync_nonblock_event_list);

static struct cpg_node cpg_nodes[SD_MAX_NODES];
static size_t nr_cpg_nodes;
static bool self_elect;
static bool join_finished;
static int cpg_fd;
static size_t nr_majority; /* used for network partition detection */

/* event types which are dispatched in corosync_dispatch() */
enum corosync_event_type {
	COROSYNC_EVENT_TYPE_JOIN,
	COROSYNC_EVENT_TYPE_ACCEPT,
	COROSYNC_EVENT_TYPE_LEAVE,
	COROSYNC_EVENT_TYPE_BLOCK,
	COROSYNC_EVENT_TYPE_NOTIFY,
	COROSYNC_EVENT_TYPE_UPDATE_NODE,
};

/* multicast message type */
enum corosync_message_type {
	COROSYNC_MSG_TYPE_JOIN,
	COROSYNC_MSG_TYPE_ACCEPT,
	COROSYNC_MSG_TYPE_LEAVE,
	COROSYNC_MSG_TYPE_NOTIFY,
	COROSYNC_MSG_TYPE_BLOCK,
	COROSYNC_MSG_TYPE_UNBLOCK,
	COROSYNC_MSG_TYPE_UPDATE_NODE,
};

struct corosync_event {
	enum corosync_event_type type;

	struct cpg_node sender;
	void *msg;
	size_t msg_len;

	uint32_t nr_nodes;
	struct cpg_node nodes[SD_MAX_NODES];

	bool callbacked;

	struct list_head list;
};

struct corosync_message {
	struct cpg_node sender;
	enum corosync_message_type type:16;
	uint16_t nr_nodes;
	uint32_t msg_len;
	struct cpg_node nodes[SD_MAX_NODES];
	uint8_t msg[0];
};

static int cpg_node_cmp(struct cpg_node *a, struct cpg_node *b)
{
	int cmp = intcmp(a->nodeid, b->nodeid);
	if (cmp == 0)
		cmp = intcmp(a->pid, b->pid);
	return cmp;
}

static bool cpg_node_equal(struct cpg_node *a, struct cpg_node *b)
{
	return cpg_node_cmp(a, b) == 0;
}

static inline int find_sd_node(struct cpg_node *nodes, size_t nr_nodes,
			       struct sd_node *key)
{
	int i;

	for (i = 0; i < nr_nodes; i++)
		if (node_eq(&nodes[i].node, key))
			return i;

	return -1;
}

static inline void add_cpg_node(struct cpg_node *nodes, size_t nr_nodes,
				struct cpg_node *added)
{
	nodes[nr_nodes++] = *added;
}

static inline void del_cpg_node(struct cpg_node *nodes, size_t nr_nodes,
				struct cpg_node *deled)
{
	xlremove(deled, nodes, &nr_nodes, cpg_node_cmp);
}

static int corosync_get_local_addr(uint8_t *addr)
{
	int ret, nr;
	corosync_cfg_node_address_t caddr;
	struct sockaddr_storage *ss = (struct sockaddr_storage *)caddr.address;
	struct sockaddr_in *sin = (struct sockaddr_in *)caddr.address;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)caddr.address;
	void *saddr;

	ret = corosync_cfg_get_node_addrs(cfg_handle, this_node.nodeid, 1,
					  &nr, &caddr);
	if (ret != CS_OK) {
		sd_err("failed to get node addresses (%d)", ret);
		return -1;
	}

	if (!nr) {
		sd_err("no node addresses found");
		return -1;
	}

	if (ss->ss_family == AF_INET6) {
		saddr = &sin6->sin6_addr;
		memcpy(addr, saddr, 16);
	} else if (ss->ss_family == AF_INET) {
		saddr = &sin->sin_addr;
		memset(addr, 0, 16);
		memcpy(addr + 12, saddr, 4);
	} else {
		sd_err("unknown protocol %d", ss->ss_family);
		return -1;
	}

	return 0;
}

static int send_message(enum corosync_message_type type,
			struct cpg_node *sender, struct cpg_node *nodes,
			size_t nr_nodes, void *msg, size_t msg_len)
{
	struct iovec iov[2];
	int ret, iov_cnt = 1;
	struct corosync_message cmsg = {
		.type = type,
		.msg_len = msg_len,
		.sender = *sender,
		.nr_nodes = nr_nodes,
	};

	if (nodes)
		memcpy(cmsg.nodes, nodes, sizeof(*nodes) * nr_nodes);

	iov[0].iov_base = &cmsg;
	iov[0].iov_len = sizeof(cmsg);
	if (msg) {
		iov[1].iov_base = msg;
		iov[1].iov_len = msg_len;
		iov_cnt++;
	}
retry:
	ret = cpg_mcast_joined(cpg_handle, CPG_TYPE_AGREED, iov, iov_cnt);
	switch (ret) {
	case CS_OK:
		break;
	case CS_ERR_TRY_AGAIN:
		sd_debug("failed to send message: retrying");
		sleep(1);
		goto retry;
	default:
		sd_err("failed to send message (%d)", ret);
		return SD_RES_CLUSTER_ERROR;
	}
	return SD_RES_SUCCESS;
}

static inline struct corosync_event *
find_block_event(enum corosync_event_type type, struct cpg_node *sender)
{
	struct corosync_event *cevent;

	list_for_each_entry(cevent, &corosync_block_event_list, list) {
		if (cevent->type == type &&
		    cpg_node_equal(&cevent->sender, sender))
			return cevent;
	}

	return NULL;
}

static inline struct corosync_event *
find_nonblock_event(enum corosync_event_type type, struct cpg_node *sender)
{
	struct corosync_event *cevent;

	list_for_each_entry(cevent, &corosync_nonblock_event_list, list) {
		if (cevent->type == type &&
		    cpg_node_equal(&cevent->sender, sender))
			return cevent;
	}

	return NULL;
}

static inline struct corosync_event *
find_event(enum corosync_event_type type, struct cpg_node *sender)
{
	if (type == COROSYNC_EVENT_TYPE_BLOCK)
		return find_block_event(type, sender);
	else
		return find_nonblock_event(type, sender);
}

static void build_node_list(const struct cpg_node *nodes, size_t nr_nodes,
			    struct sd_node *entries)
{
	int i;

	for (i = 0; i < nr_nodes; i++)
		entries[i] = nodes[i].node;
}

/*
 * Process one dispatch event
 *
 * Returns true if the event is processed
 */
static bool __corosync_dispatch_one(struct corosync_event *cevent)
{
	struct sd_node entries[SD_MAX_NODES], *node;
	struct cpg_node *n;
	int idx;

	switch (cevent->type) {
	case COROSYNC_EVENT_TYPE_JOIN:
		if (!cevent->msg)
			/* we haven't receive JOIN yet */
			return false;

		if (cevent->callbacked)
			/* sd_join_handler() must be called only once */
			return false;

		build_node_list(cpg_nodes, nr_cpg_nodes, entries);
		if (sd_join_handler(&cevent->sender.node, entries,
				    nr_cpg_nodes, cevent->msg)) {
			send_message(COROSYNC_MSG_TYPE_ACCEPT, &cevent->sender,
				     cpg_nodes, nr_cpg_nodes, cevent->msg,
				     cevent->msg_len);

			cevent->callbacked = true;
		}
		return false;
	case COROSYNC_EVENT_TYPE_ACCEPT:
		add_cpg_node(cpg_nodes, nr_cpg_nodes, &cevent->sender);
		nr_cpg_nodes++;

		build_node_list(cpg_nodes, nr_cpg_nodes, entries);
		sd_accept_handler(&cevent->sender.node, entries, nr_cpg_nodes,
				  cevent->msg);
		break;
	case COROSYNC_EVENT_TYPE_LEAVE:
		n = xlfind(&cevent->sender, cpg_nodes, nr_cpg_nodes,
			   cpg_node_cmp);
		if (n == NULL)
			break;
		cevent->sender.node = n->node;

		del_cpg_node(cpg_nodes, nr_cpg_nodes, &cevent->sender);
		nr_cpg_nodes--;
		build_node_list(cpg_nodes, nr_cpg_nodes, entries);
		sd_leave_handler(&cevent->sender.node, entries, nr_cpg_nodes);
		break;
	case COROSYNC_EVENT_TYPE_BLOCK:
		if (cevent->callbacked)
			/*
			 * block events until the unblock message
			 * removes this event
			 */
			return false;
		cevent->callbacked = sd_block_handler(&cevent->sender.node);
		return false;
	case COROSYNC_EVENT_TYPE_NOTIFY:
		sd_notify_handler(&cevent->sender.node, cevent->msg,
						 cevent->msg_len);
		break;
	case COROSYNC_EVENT_TYPE_UPDATE_NODE:
		node = &cevent->sender.node;

		if (cpg_node_equal(&cevent->sender, &this_node))
			this_node = cevent->sender;

		idx = find_sd_node(cpg_nodes, nr_cpg_nodes, node);
		assert(idx >= 0);
		cpg_nodes[idx].node = *node;
		sd_update_node_handler(node);
		break;
	}

	return true;
}

static bool update_join_status(struct corosync_event *cevent)
{
	if (join_finished)
		return true;

	switch (cevent->type) {
	case COROSYNC_EVENT_TYPE_JOIN:
		if (self_elect) {
			nr_cpg_nodes = 0;
			return true;
		}
		break;
	case COROSYNC_EVENT_TYPE_ACCEPT:
		if (cpg_node_equal(&cevent->sender, &this_node)) {
			nr_cpg_nodes = cevent->nr_nodes;
			memcpy(cpg_nodes, cevent->nodes,
			       sizeof(*cevent->nodes) * cevent->nr_nodes);
			return true;
		}
		break;
	default:
		break;
	}

	return false;
}

static void __corosync_dispatch(void)
{
	struct corosync_event *cevent;
	struct pollfd pfd = {
		.fd = cpg_fd,
		.events = POLLIN,
	};

	if (poll(&pfd, 1, 0)) {
		/*
		 * Corosync dispatches leave events one by one even
		 * when network partition has occured.  To count the
		 * number of alive nodes correctly, we postpone
		 * processsing events if there are incoming ones.
		 */
		sd_debug("wait for a next dispatch event");
		return;
	}

	nr_majority = 0;

	while (!list_empty(&corosync_block_event_list) ||
	       !list_empty(&corosync_nonblock_event_list)) {
		if (!list_empty(&corosync_nonblock_event_list))
			cevent = list_first_entry(&corosync_nonblock_event_list,
						  typeof(*cevent), list);
		else
			cevent = list_first_entry(&corosync_block_event_list,
						  typeof(*cevent), list);

		join_finished = update_join_status(cevent);

		if (join_finished) {
			if (!__corosync_dispatch_one(cevent))
				return;
		} else {
			switch (cevent->type) {
			case COROSYNC_MSG_TYPE_JOIN:
			case COROSYNC_MSG_TYPE_BLOCK:
				return;
			default:
				break;
			}
		}

		list_del(&cevent->list);
		free(cevent->msg);
		free(cevent);
	}
}

static struct corosync_event *
update_event(enum corosync_event_type type, struct cpg_node *sender, void *msg,
	     size_t msg_len)
{
	struct corosync_event *cevent;

	cevent = find_event(type, sender);
	if (!cevent)
		/* block message was casted before this node joins */
		return NULL;

	cevent->msg_len = msg_len;
	if (msg_len) {
		cevent->msg = realloc(cevent->msg, msg_len);
		if (!cevent->msg)
			panic("failed to allocate memory");
		memcpy(cevent->msg, msg, msg_len);
	} else {
		free(cevent->msg);
		cevent->msg = NULL;
	}

	return cevent;
}

static void queue_event(struct corosync_event *cevent)
{
	if (cevent->type == COROSYNC_EVENT_TYPE_BLOCK)
		list_add_tail(&cevent->list, &corosync_block_event_list);
	else
		list_add_tail(&cevent->list, &corosync_nonblock_event_list);
}

static void cdrv_cpg_deliver(cpg_handle_t handle,
			     const struct cpg_name *group_name,
			     uint32_t nodeid, uint32_t pid,
			     void *msg, size_t msg_len)
{
	struct corosync_event *cevent;
	struct corosync_message *cmsg = msg;

	sd_debug("%d", cmsg->type);

	switch (cmsg->type) {
	case COROSYNC_MSG_TYPE_JOIN:
		cevent = update_event(COROSYNC_EVENT_TYPE_JOIN, &cmsg->sender,
				      cmsg->msg, cmsg->msg_len);
		if (!cevent)
			break;

		cevent->sender = cmsg->sender;
		cevent->msg_len = cmsg->msg_len;
		break;
	case COROSYNC_MSG_TYPE_UNBLOCK:
		cevent = update_event(COROSYNC_EVENT_TYPE_BLOCK, &cmsg->sender,
				      cmsg->msg, cmsg->msg_len);
		if (cevent) {
			list_del(&cevent->list);
			free(cevent->msg);
			free(cevent);
		}
		/* fall through */
	case COROSYNC_MSG_TYPE_BLOCK:
	case COROSYNC_MSG_TYPE_NOTIFY:
	case COROSYNC_MSG_TYPE_UPDATE_NODE:
		cevent = xzalloc(sizeof(*cevent));
		switch (cmsg->type) {
		case COROSYNC_MSG_TYPE_BLOCK:
			cevent->type = COROSYNC_EVENT_TYPE_BLOCK;
			break;
		case COROSYNC_MSG_TYPE_UPDATE_NODE:
			cevent->type = COROSYNC_EVENT_TYPE_UPDATE_NODE;
			break;
		default:
			cevent->type = COROSYNC_EVENT_TYPE_NOTIFY;
			break;
		}

		cevent->sender = cmsg->sender;
		cevent->msg_len = cmsg->msg_len;
		if (cmsg->msg_len) {
			cevent->msg = xzalloc(cmsg->msg_len);
			memcpy(cevent->msg, cmsg->msg, cmsg->msg_len);
		} else
			cevent->msg = NULL;

		queue_event(cevent);
		break;
	case COROSYNC_MSG_TYPE_LEAVE:
		cevent = xzalloc(sizeof(*cevent));
		cevent->type = COROSYNC_EVENT_TYPE_LEAVE;
		cevent->sender = cmsg->sender;
		cevent->msg_len = cmsg->msg_len;
		if (cmsg->msg_len) {
			cevent->msg = xzalloc(cmsg->msg_len);
			memcpy(cevent->msg, cmsg->msg, cmsg->msg_len);
		} else
			cevent->msg = NULL;

		queue_event(cevent);
		break;
	case COROSYNC_MSG_TYPE_ACCEPT:
		cevent = update_event(COROSYNC_EVENT_TYPE_JOIN, &cmsg->sender,
				      cmsg->msg, cmsg->msg_len);
		if (!cevent)
			break;

		cevent->type = COROSYNC_EVENT_TYPE_ACCEPT;
		cevent->nr_nodes = cmsg->nr_nodes;
		memcpy(cevent->nodes, cmsg->nodes,
		       sizeof(*cmsg->nodes) * cmsg->nr_nodes);

		break;
	}

	__corosync_dispatch();
}

static void build_cpg_node_list(struct cpg_node *nodes,
				const struct cpg_address *list, size_t nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		nodes[i].nodeid = list[i].nodeid;
		nodes[i].pid = list[i].pid;
	}
}

static void cdrv_cpg_confchg(cpg_handle_t handle,
			     const struct cpg_name *group_name,
			     const struct cpg_address *member_list,
			     size_t member_list_entries,
			     const struct cpg_address *left_list,
			     size_t left_list_entries,
			     const struct cpg_address *joined_list,
			     size_t joined_list_entries)
{
	struct corosync_event *cevent;
	int i;
	struct cpg_node member_sheep[SD_MAX_NODES];
	struct cpg_node joined_sheep[SD_MAX_NODES];
	struct cpg_node left_sheep[SD_MAX_NODES];
	bool promote = true;

	sd_debug("mem:%zu, joined:%zu, left:%zu", member_list_entries,
		 joined_list_entries, left_list_entries);

	/* check network partition */
	if (left_list_entries) {
		if (nr_majority == 0) {
			size_t total = member_list_entries + left_list_entries;

			/*
			 * we need at least 3 nodes to handle network
			 * partition failure
			 */
			if (total > 2)
				nr_majority = total / 2 + 1;
		}

		if (member_list_entries == 0)
			panic("NIC failure?");
		if (member_list_entries < nr_majority)
			panic("Network partition is detected");
	}

	/* convert cpg_address to cpg_node */
	build_cpg_node_list(member_sheep, member_list, member_list_entries);
	build_cpg_node_list(left_sheep, left_list, left_list_entries);
	build_cpg_node_list(joined_sheep, joined_list, joined_list_entries);

	/* dispatch leave_handler */
	for (i = 0; i < left_list_entries; i++) {
		cevent = find_event(COROSYNC_EVENT_TYPE_JOIN, left_sheep + i);
		if (cevent) {
			/* the node left before joining */
			list_del(&cevent->list);
			free(cevent->msg);
			free(cevent);
			continue;
		}

		cevent = find_event(COROSYNC_EVENT_TYPE_BLOCK, left_sheep + i);
		if (cevent) {
			/* the node left before sending UNBLOCK */
			list_del(&cevent->list);
			free(cevent->msg);
			free(cevent);
		}

		cevent = xzalloc(sizeof(*cevent));
		cevent->type = COROSYNC_EVENT_TYPE_LEAVE;
		cevent->sender = left_sheep[i];

		queue_event(cevent);
	}

	/* dispatch join_handler */
	for (i = 0; i < joined_list_entries; i++) {
		cevent = xzalloc(sizeof(*cevent));
		cevent->type = COROSYNC_EVENT_TYPE_JOIN;
		cevent->sender = joined_sheep[i];
		queue_event(cevent);
	}

	if (!join_finished) {
		/*
		 * Exactly one non-master member has seen join events for
		 * all other members, because events are ordered.
		 */
		for (i = 0; i < member_list_entries; i++) {
			cevent = find_event(COROSYNC_EVENT_TYPE_JOIN,
					    &member_sheep[i]);
			if (!cevent) {
				sd_debug("Not promoting because member is not "
					 "in our event list.");
				promote = false;
				break;
			}
		}

		/*
		 * If we see the join events for all nodes promote ourself to
		 * master right here.
		 */
		if (promote)
			self_elect = true;
	}
	__corosync_dispatch();
}

static int corosync_join(const struct sd_node *myself,
			 void *opaque, size_t opaque_len)
{
	int ret;

retry:
	ret = cpg_join(cpg_handle, &cpg_group);
	switch (ret) {
	case CS_OK:
		break;
	case CS_ERR_TRY_AGAIN:
		sd_debug("failed to join the sheepdog group: retrying");
		sleep(1);
		goto retry;
	case CS_ERR_SECURITY:
		sd_err("permission denied to join the sheepdog group");
		return -1;
	default:
		sd_err("failed to join the sheepdog group (%d)", ret);
		return -1;
	}

	this_node.node = *myself;

	ret = send_message(COROSYNC_MSG_TYPE_JOIN, &this_node, NULL, 0, opaque,
			   opaque_len);

	return ret;
}

static int corosync_leave(void)
{
	return send_message(COROSYNC_MSG_TYPE_LEAVE, &this_node, NULL, 0, NULL,
			    0);
}

static int corosync_block(void)
{
	return send_message(COROSYNC_MSG_TYPE_BLOCK, &this_node, NULL, 0, NULL,
			    0);
}

static int corosync_unblock(void *msg, size_t msg_len)
{
	return send_message(COROSYNC_MSG_TYPE_UNBLOCK, &this_node, NULL, 0, msg,
			    msg_len);
}

static int corosync_notify(void *msg, size_t msg_len)
{
	return send_message(COROSYNC_MSG_TYPE_NOTIFY, &this_node, NULL, 0, msg,
			    msg_len);
}

static void corosync_handler(int listen_fd, int events, void *data)
{
	int ret;

	if (events & EPOLLHUP) {
		sd_err("corosync driver received EPOLLHUP event, exiting.");
		goto out;
	}

	ret = cpg_dispatch(cpg_handle, CS_DISPATCH_ALL);
	if (ret != CS_OK) {
		sd_err("cpg_dispatch returned %d", ret);
		goto out;
	}

	return;
out:
	log_close();
	exit(1);
}

static int corosync_init(const char *option)
{
	int ret, retry_cnt = 0;
	uint32_t nodeid;
	cpg_callbacks_t cb = {
		.cpg_deliver_fn = cdrv_cpg_deliver,
		.cpg_confchg_fn = cdrv_cpg_confchg
	};

again:
	ret = cpg_initialize(&cpg_handle, &cb);
	switch (ret) {
	case CS_OK:
		/* success */
		break;
	case CS_ERR_TRY_AGAIN:
		if (retry_cnt++ == CPG_INIT_RETRY_CNT) {
			sd_err("failed to initialize cpg (%d) - "
			       "is corosync running?", ret);
			return -1;
		}
		sd_debug("retry cpg_initialize");
		usleep(200000);
		goto again;
	case CS_ERR_SECURITY:
		sd_err("failed to initialize cpg - permission denied");
		return -1;
	default:
		sd_err("failed to initialize cpg (%d)", ret);
		return -1;
	}

	ret = corosync_cfg_initialize(&cfg_handle, NULL);
	if (ret != CS_OK) {
		sd_err("failed to initialize cfg (%d)", ret);
		return -1;
	}

	ret = corosync_cfg_local_get(cfg_handle, &nodeid);
	if (ret != CS_OK) {
		sd_err("failed to get node id (%d)", ret);
		return -1;
	}

	this_node.nodeid = nodeid;
	this_node.pid = getpid();

	ret = cpg_fd_get(cpg_handle, &cpg_fd);
	if (ret != CS_OK) {
		sd_err("failed to get cpg file descriptor (%d)", ret);
		return -1;
	}

	ret = register_event(cpg_fd, corosync_handler, NULL);
	if (ret) {
		sd_err("failed to register corosync event handler (%d)", ret);
		return -1;
	}

	return 0;
}

static int corosync_update_node(struct sd_node *node)
{
	struct cpg_node cnode = this_node;

	cnode.node = *node;

	return send_message(COROSYNC_MSG_TYPE_UPDATE_NODE, &cnode, NULL, 0,
			    NULL, 0);
}

static struct cluster_driver cdrv_corosync = {
	.name		= "corosync",

	.init		= corosync_init,
	.get_local_addr	= corosync_get_local_addr,
	.join		= corosync_join,
	.leave		= corosync_leave,
	.notify		= corosync_notify,
	.block		= corosync_block,
	.unblock	= corosync_unblock,
	.update_node	= corosync_update_node,
};

cdrv_register(cdrv_corosync);
