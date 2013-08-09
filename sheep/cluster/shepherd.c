/*
 * Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "cluster.h"
#include "event.h"
#include "shepherd.h"
#include "internal_proto.h"
#include "net.h"

static int sph_comm_fd;

static struct sd_node this_node;

static int nr_nodes;
static struct sd_node nodes[SD_MAX_NODES];

enum sph_driver_state {
	STATE_PRE_JOIN,
	STATE_JOINED,
};

static enum sph_driver_state state = STATE_PRE_JOIN;

static char *kept_opaque;
static size_t kept_opaque_len;

static int do_shepherd_join(void)
{
	int ret, msg_join_len;
	struct sph_msg msg;
	struct sph_msg_join *msg_join;

	msg_join_len = sizeof(struct sph_msg_join) + kept_opaque_len;

	memset(&msg, 0, sizeof(msg));
	msg.type = SPH_CLI_MSG_JOIN;
	msg.body_len = msg_join_len;

	msg_join = xzalloc(msg_join_len);
	msg_join->new_node = this_node;
	memcpy(msg_join->opaque, kept_opaque, kept_opaque_len);

	ret = writev2(sph_comm_fd, &msg, msg_join, msg_join_len);
	if (sizeof(msg) + msg_join_len != ret) {
		sd_err("do_shepherd_join() failed, %m");
		free(msg_join);

		return -1;
	}

	free(msg_join);
	return 0;
}

static void read_msg(struct sph_msg *rcv)
{
	int ret;

	ret = xread(sph_comm_fd, rcv, sizeof(*rcv));
	if (ret != sizeof(*rcv)) {
		sd_err("xread() failed: %m");
		exit(1);
	}
}

static void interpret_msg_pre_join(void)
{
	int ret;
	struct sph_msg snd, rcv;
	struct sph_msg_join_reply *join_reply;

retry:
	read_msg(&rcv);

	if (rcv.type == SPH_SRV_MSG_JOIN_RETRY) {
		sd_info("join request is rejected, retrying");

		do_shepherd_join();
		goto retry;
	} else if (rcv.type == SPH_SRV_MSG_NEW_NODE) {
		struct sph_msg_join *join;
		int join_len;

		join_len = rcv.body_len;
		join = xzalloc(join_len);
		ret = xread(sph_comm_fd, join, join_len);
		if (ret != join_len) {
			sd_err("xread() failed: %m");
			exit(1);
		}

		/*
		 * FIXME: member change events must be ordered with nonblocked
		 *        events
		 */
		if (!sd_join_handler(&join->new_node, NULL, 0, join->opaque))
			panic("sd_accept_handler() failed");

		snd.type = SPH_CLI_MSG_ACCEPT;
		snd.body_len = join_len;

		ret = writev2(sph_comm_fd, &snd, join, join_len);
		if (sizeof(snd) + join_len != ret) {
			sd_err("writev2() failed: %m");
			exit(1);
		}

		free(join);

		read_msg(&rcv);
	}

	if (rcv.type != SPH_SRV_MSG_JOIN_REPLY) {
		sd_err("unexpected message from shepherd, received message: %s",
		       sph_srv_msg_to_str(rcv.type));

		/*
		 * In this case, the state of this sheep in shepherd must be
		 * SHEEP_STATE_CONNECTED. Messages other than SPH_MSG_JOIN_REPLY
		 * mean bugs of shepherd.
		 */
		exit(1);
	}

	join_reply = xzalloc(rcv.body_len);
	ret = xread(sph_comm_fd, join_reply, rcv.body_len);
	if (ret != rcv.body_len) {
		sd_err("xread() failed: %m");
		exit(1);
	}

	sd_info("join reply arrived, nr_nodes: %d", join_reply->nr_nodes);

	memcpy(nodes, join_reply->nodes,
	       join_reply->nr_nodes * sizeof(struct sd_node));
	nr_nodes = join_reply->nr_nodes;

	/* FIXME: member change events must be ordered with nonblocked events */
	sd_accept_handler(&this_node, nodes, nr_nodes, join_reply->opaque);

	free(join_reply);

	sd_info("shepherd_join() succeed");
	state = STATE_JOINED;
}

struct sph_event {
	struct sd_node sender;

	void *msg;
	int msg_len;

	bool callbacked, removed;

	struct list_head event_list;
};

static LIST_HEAD(nonblocked_event_list);
static LIST_HEAD(blocked_event_list);

static int sph_event_fd;

static bool sph_process_event(void)
{
	struct sph_event *ev;
	bool nonblock;

	if (!list_empty(&nonblocked_event_list)) {
		ev = list_first_entry(&nonblocked_event_list,
				struct sph_event, event_list);
		nonblock = true;
	} else if (!list_empty(&blocked_event_list)) {
		ev = list_first_entry(&blocked_event_list,
				struct sph_event, event_list);
		nonblock = false;
	} else
		return false;

	if (ev->removed)
		goto remove;

	if (ev->callbacked)
		return false;

	if (nonblock) {
		sd_debug("processing nonblock event");

		sd_notify_handler(&ev->sender, ev->msg, ev->msg_len);
	} else {
		sd_debug("processing block event");

		ev->callbacked = sd_block_handler(&ev->sender);
		return false;
	}

remove:
	list_del(&ev->event_list);
	free(ev->msg);
	free(ev);

	return true;
}

static void push_sph_event(bool nonblock, struct sd_node *sender,
			void *msg, int msg_len)
{
	struct sph_event *ev;

	sd_debug("push_sph_event() called, pushing %sblocking event",
		 nonblock ? "non" : "");

	ev = xzalloc(sizeof(*ev));

	ev->sender = *sender;
	if (msg_len) {
		ev->msg = xzalloc(msg_len);
		memcpy(ev->msg, msg, msg_len);
		ev->msg_len = msg_len;
	}

	ev->removed = false;
	ev->callbacked = false;

	INIT_LIST_HEAD(&ev->event_list);

	if (nonblock)
		list_add_tail(&ev->event_list, &nonblocked_event_list);
	else
		list_add_tail(&ev->event_list, &blocked_event_list);

	eventfd_xwrite(sph_event_fd, 1);
}

static void remove_one_block_event(void)
{
	struct sph_event *ev;
	bool removed = false;

	if (list_empty(&blocked_event_list))
		/* FIXME: should I treat this case as an error? */
		return;

	list_for_each_entry(ev, &blocked_event_list, event_list) {
		if (ev->removed)
			continue;

		removed = ev->removed = true;
		break;
	}
	if (!removed)
		panic("removed is not true");

	eventfd_xwrite(sph_event_fd, 1);

	sd_debug("unblock a blocking event");
}

static void sph_event_handler(int fd, int events, void *data)
{
	eventfd_xread(fd);

	while (sph_process_event())
		;
}

static void msg_new_node(struct sph_msg *rcv)
{
	int ret;
	struct sph_msg_join *join;
	struct sph_msg snd;

	join = xzalloc(rcv->body_len);
	ret = xread(sph_comm_fd, join, rcv->body_len);
	if (ret != rcv->body_len) {
		sd_err("xread() failed: %m");
		exit(1);
	}

	/* FIXME: member change events must be ordered with nonblocked events */
	if (!sd_join_handler(&join->new_node, join->nodes, join->nr_nodes,
			     join->opaque))
		/*
		 * This should succeed always because shepherd should have sent
		 * SPH_SRV_MSG_NEW_NODE only to the already joined node.
		 */
		panic("sd_join_handler() failed");

	memset(&snd, 0, sizeof(snd));
	snd.type = SPH_CLI_MSG_ACCEPT;
	snd.body_len = rcv->body_len;

	ret = writev2(sph_comm_fd, &snd, join, rcv->body_len);
	if (sizeof(snd) + rcv->body_len != ret) {
		sd_err("writev() failed: %m");
		exit(1);
	}
	free(join);
}

static void msg_new_node_finish(struct sph_msg *rcv)
{
	int ret;
	struct sph_msg_join_node_finish *join_node_finish;

	join_node_finish = xzalloc(rcv->body_len);
	ret = xread(sph_comm_fd, join_node_finish, rcv->body_len);
	if (ret != rcv->body_len) {
		sd_err("xread() failed: %m");
		exit(1);
	}

	memcpy(nodes, join_node_finish->nodes,
	       join_node_finish->nr_nodes * sizeof(struct sd_node));
	nr_nodes = join_node_finish->nr_nodes;

	sd_info("new node: %s", node_to_str(&join_node_finish->new_node));

	/* FIXME: member change events must be ordered with nonblocked events */
	sd_accept_handler(&join_node_finish->new_node, nodes, nr_nodes,
			  join_node_finish->opaque);

	free(join_node_finish);
}

static void msg_notify_forward(struct sph_msg *rcv)
{
	int ret;
	struct sph_msg_notify_forward *notify_forward;

	notify_forward = xzalloc(rcv->body_len);
	ret = xread(sph_comm_fd, notify_forward, rcv->body_len);
	if (ret != rcv->body_len) {
		sd_err("xread() failed: %m");
		exit(1);
	}

	if (notify_forward->unblock)
		remove_one_block_event();

	push_sph_event(true, &notify_forward->from_node,
		notify_forward->notify_msg,
		rcv->body_len - sizeof(*notify_forward));

	free(notify_forward);
}

static void msg_block_forward(struct sph_msg *rcv)
{
	int ret;
	struct sd_node sender;

	ret = xread(sph_comm_fd, &sender, sizeof(sender));
	if (ret != sizeof(sender)) {
		sd_err("xread() failed: %m");
		exit(1);
	}

	push_sph_event(false, &sender, NULL, 0);
}

static void do_leave_sheep(void)
{
	int ret;
	struct sd_node sender;

	ret = xread(sph_comm_fd, &sender, sizeof(sender));
	if (ret != sizeof(sender)) {
		sd_err("xread() failed: %m");
		exit(1);
	}

	sd_info("removing node: %s", node_to_str(&sender));

	if (xlremove(&sender, nodes, &nr_nodes, node_cmp))
		goto removed;

	sd_info("leave message from unknown node: %s", node_to_str(&sender));
	return;

removed:
	sd_debug("calling sd_leave_handler(), sender: %s",
		 node_to_str(&sender));
	/* FIXME: member change events must be ordered with nonblocked events */
	sd_leave_handler(&sender, nodes, nr_nodes);
}

static void msg_remove(struct sph_msg *rcv)
{
	sd_info("sudden leaving of sheep is caused");
	do_leave_sheep();
}

static void msg_leave_forward(struct sph_msg *rcv)
{
	sd_info("intuitive leaving of sheep is caused");
	do_leave_sheep();
}

static void (*msg_handlers[])(struct sph_msg *) = {
	[SPH_SRV_MSG_NEW_NODE] = msg_new_node,
	[SPH_SRV_MSG_NEW_NODE_FINISH] = msg_new_node_finish,
	[SPH_SRV_MSG_NOTIFY_FORWARD] = msg_notify_forward,
	[SPH_SRV_MSG_BLOCK_FORWARD] = msg_block_forward,
	[SPH_SRV_MSG_REMOVE] = msg_remove,
	[SPH_SRV_MSG_LEAVE_FORWARD] = msg_leave_forward,
};

static void interpret_msg(struct sph_msg *rcv)
{
	if (!(0 <= rcv->type && rcv->type < ARRAY_SIZE(msg_handlers))) {
		sd_err("invalid message from shepherd: %s",
		       sph_srv_msg_to_str(rcv->type));
		exit(1);
	}

	msg_handlers[rcv->type](rcv);
}

static void read_msg_from_shepherd(void)
{
	struct sph_msg rcv;

	switch (state) {
	case STATE_PRE_JOIN:
		interpret_msg_pre_join();
		break;
	case STATE_JOINED:
		read_msg(&rcv);
		interpret_msg(&rcv);
		break;
	default:
		panic("invalid state of shepherd cluster driver: %d",
			state);
		break;
	};
}

static void shepherd_comm_handler(int fd, int events, void *data)
{
	assert(fd == sph_comm_fd);
	assert(data == NULL);

	if (events & EPOLLIN)
		read_msg_from_shepherd();
	else if (events & EPOLLHUP || events & EPOLLERR) {
		sd_err("connection to shepherd caused an error: %m");
		exit(1);
	}
}

static int shepherd_init(const char *option)
{
	int ret, port;
	char *copied, *s_addr, *s_port, *saveptr;

	if (!option) {
		sd_err("shepherd cluster driver requires at least IP"
		       " address of shepherd as an option");
		exit(1);
	}

	copied = strdup(option);
	if (!copied) {
		sd_err("strdup() failed: %m");
		exit(1);
	}

	s_addr = strtok_r(copied, ":", &saveptr);
	if (!s_addr) {
		sd_err("strdup() failed: %m");
		exit(1);
	}

	s_port = strtok_r(NULL, ":", &saveptr);
	if (s_port) {
		char *p;
		port = strtol(s_port, &p, 10);

		if (*p != '\0') {
			sd_err("invalid option for host and port: %s", option);
			exit(1);
		}
	} else
		port = SHEPHERD_PORT;

	sph_comm_fd = connect_to(s_addr, port);
	if (sph_comm_fd == -1) {
		sd_err("cannot connect to shepherd,"
		       " is shepherd running? errno: %m");
		return -1;
	}

	sph_event_fd = eventfd(0, EFD_NONBLOCK);
	ret = register_event(sph_event_fd, sph_event_handler, NULL);
	if (ret) {
		sd_err("register_event() failed: %m");
		exit(1);
	}

	free(copied);

	return 0;
}

static int shepherd_join(const struct sd_node *myself,
		      void *opaque, size_t opaque_len)
{
	int ret;
	static bool registered;

	/* keep opaque for retrying */
	kept_opaque = xzalloc(opaque_len);
	memcpy(kept_opaque, opaque, opaque_len);
	kept_opaque_len = opaque_len;
	this_node = *myself;

	sd_debug("shepherd_join() called, myself is %s", node_to_str(myself));

	ret = do_shepherd_join();

	if (!registered) {
		register_event(sph_comm_fd, shepherd_comm_handler, NULL);
		registered = true;
	}

	return ret;
}

static int shepherd_leave(void)
{
	int ret;
	struct sph_msg msg;

	msg.type = SPH_CLI_MSG_LEAVE;
	msg.body_len = 0;

	ret = xwrite(sph_comm_fd, &msg, sizeof(msg));
	if (ret != sizeof(msg)) {
		sd_info("xwrite() failed: %m");
		exit(1);
	}

	sd_debug("shepherd_leave() is completed");

	return 0;
}

static int do_shepherd_notify(bool unblock, void *msg, size_t msg_len)
{
	int ret;
	struct sph_msg snd;
	struct sph_msg_notify *notify;

	snd.type = SPH_CLI_MSG_NOTIFY;
	snd.body_len = msg_len + sizeof(*notify);

	notify = xzalloc(snd.body_len);
	notify->unblock = unblock;
	memcpy(notify->notify_msg, msg, msg_len);

	ret = writev2(sph_comm_fd, &snd, notify, snd.body_len);
	if (sizeof(snd) + snd.body_len != ret) {
		sd_err("writev() failed: %m");
		exit(1);
	}
	free(notify);

	sd_info("do_shepherd_notify() is completed");

	return 0;
}

static int shepherd_notify(void *msg, size_t msg_len)
{
	return do_shepherd_notify(false, msg, msg_len) == 0 ?
		SD_RES_SUCCESS : SD_RES_CLUSTER_ERROR;
}

static int shepherd_block(void)
{
	int ret;
	struct sph_msg msg;

	msg.type = SPH_CLI_MSG_BLOCK;
	msg.body_len = 0;

	ret = xwrite(sph_comm_fd, &msg, sizeof(msg));
	if (ret != sizeof(msg)) {
		sd_err("xwrite() failed: %m");
		exit(1);
	}

	return SD_RES_SUCCESS;
}

static int shepherd_unblock(void *msg, size_t msg_len)
{
	return do_shepherd_notify(true, msg, msg_len) == 0 ?
		SD_RES_SUCCESS : SD_RES_CLUSTER_ERROR;
}

/* FIXME: shepherd server also has to udpate node information */
static int shepherd_update_node(struct sd_node *node)
{
	return SD_RES_NO_SUPPORT;
}

static struct cluster_driver cdrv_shepherd = {
	.name		= "shepherd",

	.init		= shepherd_init,
	.join		= shepherd_join,
	.leave		= shepherd_leave,
	.notify		= shepherd_notify,
	.block		= shepherd_block,
	.unblock	= shepherd_unblock,
	.update_node	= shepherd_update_node,
	.get_local_addr = get_local_addr,
};

cdrv_register(cdrv_shepherd);
