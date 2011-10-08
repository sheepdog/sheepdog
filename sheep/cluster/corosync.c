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
#include <corosync/cpg.h>
#include <corosync/cfg.h>

#include "cluster.h"
#include "work.h"

static cpg_handle_t cpg_handle;
static struct cpg_name cpg_group = { 9, "sheepdog" };

static corosync_cfg_handle_t cfg_handle;
static struct sheepid this_sheepid;

static struct work_queue *corosync_block_wq;

static struct cdrv_handlers corosync_handlers;

static LIST_HEAD(corosync_event_list);
static LIST_HEAD(corosync_block_list);

/* event types which are dispatched in corosync_dispatch() */
enum corosync_event_type {
	COROSYNC_EVENT_TYPE_JOIN,
	COROSYNC_EVENT_TYPE_LEAVE,
	COROSYNC_EVENT_TYPE_NOTIFY,
};

/* multicast message type */
enum corosync_message_type {
	COROSYNC_MSG_TYPE_NOTIFY,
	COROSYNC_MSG_TYPE_BLOCK,
	COROSYNC_MSG_TYPE_UNBLOCK,
};

struct corosync_event {
	enum corosync_event_type type;

	struct sheepid members[SD_MAX_NODES];
	size_t nr_members;

	struct sheepid sender;
	void *msg;
	size_t msg_len;

	int blocked;
	int callbacked;

	struct list_head list;
};

struct corosync_block_msg {
	void *msg;
	size_t msg_len;
	void (*cb)(void *arg);

	struct work work;
	struct list_head list;
};

static int nodeid_to_addr(uint32_t nodeid, uint8_t *addr)
{
	int ret, nr;
	corosync_cfg_node_address_t caddr;
	struct sockaddr_storage *ss = (struct sockaddr_storage *)caddr.address;
	struct sockaddr_in *sin = (struct sockaddr_in *)caddr.address;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)caddr.address;
	void *saddr;

	ret = corosync_cfg_get_node_addrs(cfg_handle, nodeid, 1, &nr, &caddr);
	if (ret != CS_OK) {
		vprintf(SDOG_ERR, "failed to get addr %d\n", ret);
		return -1;
	}

	if (!nr) {
		vprintf(SDOG_ERR, "we got no address\n");
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
		vprintf(SDOG_ERR, "unknown protocol %d\n", ss->ss_family);
		return -1;
	}

	return 0;
}

static void cpg_addr_to_sheepid(const struct cpg_address *cpgs,
				struct sheepid *sheeps, size_t nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		nodeid_to_addr(cpgs[i].nodeid, sheeps[i].addr);
		sheeps[i].pid = cpgs[i].pid;
	}
}

static int send_message(uint64_t type, void *msg, size_t msg_len)
{
	struct iovec iov[2];
	int ret, iov_cnt = 1;

	iov[0].iov_base = &type;
	iov[0].iov_len = sizeof(type);
	if (msg) {
		iov[1].iov_base = msg;
		iov[1].iov_len = msg_len;
		iov_cnt++;
	}
retry:
	ret = cpg_mcast_joined(cpg_handle, CPG_TYPE_AGREED, iov, iov_cnt);
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

static void corosync_block(struct work *work, int idx)
{
	struct corosync_block_msg *bm = container_of(work, typeof(*bm), work);

	bm->cb(bm->msg);
}

static void corosync_block_done(struct work *work, int idx)
{
	struct corosync_block_msg *bm = container_of(work, typeof(*bm), work);

	send_message(COROSYNC_MSG_TYPE_UNBLOCK, bm->msg, bm->msg_len);

	free(bm->msg);
	free(bm);
}

static struct corosync_event *find_block_event(struct sheepid *sender)
{
	struct corosync_event *cevent;

	list_for_each_entry(cevent, &corosync_event_list, list) {
		if (!cevent->blocked)
			continue;

		if (cevent->type == COROSYNC_EVENT_TYPE_NOTIFY &&
		    sheepid_cmp(&cevent->sender, sender) == 0)
			return cevent;
	}

	return NULL;
}

static void __corosync_dispatch(void)
{
	struct corosync_event *cevent;
	struct corosync_block_msg *bm;

	while (!list_empty(&corosync_event_list)) {
		cevent = list_first_entry(&corosync_event_list, typeof(*cevent), list);

		switch (cevent->type) {
		case COROSYNC_EVENT_TYPE_JOIN:
			corosync_handlers.join_handler(&cevent->sender,
						       cevent->members,
						       cevent->nr_members);
			break;
		case COROSYNC_EVENT_TYPE_LEAVE:
			corosync_handlers.leave_handler(&cevent->sender,
							cevent->members,
							cevent->nr_members);
			break;
		case COROSYNC_EVENT_TYPE_NOTIFY:
			if (cevent->blocked) {
				if (sheepid_cmp(&cevent->sender, &this_sheepid) == 0 &&
				    !cevent->callbacked) {
					/* call a block callback function from a worker thread */
					if (list_empty(&corosync_block_list))
						panic("cannot call block callback\n");

					bm = list_first_entry(&corosync_block_list,
							      typeof(*bm), list);
					list_del(&bm->list);

					bm->work.fn = corosync_block;
					bm->work.done = corosync_block_done;
					queue_work(corosync_block_wq, &bm->work);

					cevent->callbacked = 1;
				}

				/* block the rest messages until unblock message comes */
				goto out;
			}

			corosync_handlers.notify_handler(&cevent->sender,
							 cevent->msg,
							 cevent->msg_len);
			break;
		}

		list_del(&cevent->list);
		free(cevent);
	}
out:
	return;
}

static void cdrv_cpg_deliver(cpg_handle_t handle,
			     const struct cpg_name *group_name,
			     uint32_t nodeid, uint32_t pid,
			     void *msg, size_t msg_len)
{
	struct corosync_event *cevent;
	uint64_t type;
	struct sheepid sender;

	nodeid_to_addr(nodeid, sender.addr);
	sender.pid = pid;

	memcpy(&type, msg, sizeof(type));
	msg = (uint8_t *)msg + sizeof(type);
	msg_len -= sizeof(type);

	cevent = zalloc(sizeof(*cevent));
	if (!cevent)
		panic("oom\n");

	switch (type) {
	case COROSYNC_MSG_TYPE_BLOCK:
		cevent->blocked = 1;
		/* fall through */
	case COROSYNC_MSG_TYPE_NOTIFY:
		cevent->type = COROSYNC_EVENT_TYPE_NOTIFY;
		cevent->sender = sender;
		cevent->msg_len = msg_len;
		if (msg_len) {
			cevent->msg = zalloc(msg_len);
			if (!cevent->msg)
				panic("oom\n");
			memcpy(cevent->msg, msg, msg_len);
		} else
			cevent->msg = NULL;

		list_add_tail(&cevent->list, &corosync_event_list);
		break;
	case COROSYNC_MSG_TYPE_UNBLOCK:
		free(cevent); /* we don't add a new cluster event in this case */

		cevent = find_block_event(&sender);
		if (!cevent)
			/* block message was casted before this node joins */
			break;

		cevent->blocked = 0;
		cevent->msg_len = msg_len;
		if (msg_len) {
			cevent->msg = realloc(cevent->msg, msg_len);
			if (!cevent->msg)
				panic("oom\n");
			memcpy(cevent->msg, msg, msg_len);
		} else {
			free(cevent->msg);
			cevent->msg = NULL;
		}
		break;
	}

	__corosync_dispatch();
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
	struct sheepid member_sheeps[SD_MAX_NODES];
	struct sheepid joined_sheeps[SD_MAX_NODES];
	struct sheepid left_sheeps[SD_MAX_NODES];

	/* convert cpg_address to sheepid*/
	cpg_addr_to_sheepid(member_list, member_sheeps, member_list_entries);
	cpg_addr_to_sheepid(left_list, left_sheeps, left_list_entries);
	cpg_addr_to_sheepid(joined_list, joined_sheeps, joined_list_entries);

	/* calculate a start member list */
	sheepid_del(member_sheeps, member_list_entries,
		    joined_sheeps, joined_list_entries);
	member_list_entries -= joined_list_entries;

	sheepid_add(member_sheeps, member_list_entries,
		    left_sheeps, left_list_entries);
	member_list_entries += left_list_entries;

	/* dispatch leave_handler */
	for (i = 0; i < left_list_entries; i++) {
		cevent = find_block_event(left_sheeps + i);
		if (cevent) {
			/* the node left before sending UNBLOCK */
			list_del(&cevent->list);
			free(cevent);
		}

		cevent = zalloc(sizeof(*cevent));
		if (!cevent)
			panic("oom\n");

		sheepid_del(member_sheeps, member_list_entries,
			    left_sheeps + i, 1);
		member_list_entries--;

		cevent->type = COROSYNC_EVENT_TYPE_LEAVE;
		cevent->sender = left_sheeps[i];
		memcpy(cevent->members, member_sheeps, sizeof(member_sheeps));
		cevent->nr_members = member_list_entries;

		list_add_tail(&cevent->list, &corosync_event_list);
	}

	/* dispatch join_handler */
	for (i = 0; i < joined_list_entries; i++) {
		cevent = zalloc(sizeof(*cevent));
		if (!cevent)
			panic("oom\n");

		sheepid_add(member_sheeps, member_list_entries,
			    joined_sheeps, 1);
		member_list_entries++;

		cevent->type = COROSYNC_EVENT_TYPE_JOIN;
		cevent->sender = joined_sheeps[i];
		memcpy(cevent->members, member_sheeps, sizeof(member_sheeps));
		cevent->nr_members = member_list_entries;

		list_add_tail(&cevent->list, &corosync_event_list);
	}

	__corosync_dispatch();
}

static int corosync_init(struct cdrv_handlers *handlers, struct sheepid *myid)
{
	int ret, fd;
	uint32_t nodeid;
	cpg_callbacks_t cb = {
		.cpg_deliver_fn = cdrv_cpg_deliver,
		.cpg_confchg_fn = cdrv_cpg_confchg
	};

	corosync_handlers = *handlers;

	ret = cpg_initialize(&cpg_handle, &cb);
	if (ret != CPG_OK) {
		eprintf("Failed to initialize cpg, %d\n", ret);
		eprintf("Is corosync running?\n");
		return -1;
	}

	ret = corosync_cfg_initialize(&cfg_handle, NULL);
	if (ret != CS_OK) {
		vprintf(SDOG_ERR, "failed to initiazize cfg %d\n", ret);
		return -1;
	}

	ret = corosync_cfg_local_get(cfg_handle, &nodeid);
	if (ret != CS_OK) {
		vprintf(SDOG_ERR, "failed to get nodeid %d\n", ret);
		return -1;
	}

	ret = nodeid_to_addr(nodeid, myid->addr);
	if (ret < 0) {
		eprintf("failed to get local address\n");
		return -1;
	}

	myid->pid = getpid();
	this_sheepid = *myid;

	ret = cpg_fd_get(cpg_handle, &fd);
	if (ret != CPG_OK) {
		eprintf("Failed to retrieve cpg file descriptor, %d\n", ret);
		return -1;
	}

	corosync_block_wq = init_work_queue(1);

	return fd;
}

static int corosync_join(void)
{
	int ret;
retry:
	ret = cpg_join(cpg_handle, &cpg_group);
	switch (ret) {
	case CPG_OK:
		break;
	case CPG_ERR_TRY_AGAIN:
		dprintf("Failed to join the sheepdog group, try again\n");
		sleep(1);
		goto retry;
	case CPG_ERR_SECURITY:
		eprintf("Permission error.\n");
		return -1;
	default:
		eprintf("Failed to join the sheepdog group, %d\n", ret);
		return -1;
	}

	return 0;
}

static int corosync_leave(void)
{
	int ret;

	ret = cpg_leave(cpg_handle, &cpg_group);
	if (ret != CPG_OK) {
		eprintf("failed to leave the sheepdog group\n, %d", ret);
		return -1;
	}

	return 0;
}

static int corosync_notify(void *msg, size_t msg_len, void (*block_cb)(void *))
{
	int ret;
	struct corosync_block_msg *bm;

	if (block_cb) {
		bm = zalloc(sizeof(*bm));
		if (!bm)
			panic("oom\n");
		bm->msg = zalloc(msg_len);
		if (!bm->msg)
			panic("oom\n");

		memcpy(bm->msg, msg, msg_len);
		bm->msg_len = msg_len;
		bm->cb = block_cb;
		list_add_tail(&bm->list, &corosync_block_list);

		ret = send_message(COROSYNC_MSG_TYPE_BLOCK, NULL, 0);
	} else
		ret = send_message(COROSYNC_MSG_TYPE_NOTIFY, msg, msg_len);

	return ret;
}

static int corosync_dispatch(void)
{
	int ret;

	ret = cpg_dispatch(cpg_handle, CPG_DISPATCH_ALL);
	if (ret != CPG_OK)
		return -1;

	return 0;
}

struct cluster_driver cdrv_corosync = {
	.name       = "corosync",

	.init       = corosync_init,
	.join       = corosync_join,
	.leave      = corosync_leave,
	.notify     = corosync_notify,
	.dispatch   = corosync_dispatch,
};

cdrv_register(cdrv_corosync);
