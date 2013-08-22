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
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <getopt.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <sys/un.h>
#include <netinet/in.h>

#include "net.h"
#include "event.h"
#include "list.h"
#include "internal_proto.h"
#include "sheep.h"
#include "util.h"
#include "option.h"
#include "shepherd.h"

#define EPOLL_SIZE SD_MAX_NODES

enum shepherd_state {
	SPH_STATE_DEFAULT,
	SPH_STATE_JOINING,
};

static enum shepherd_state state = SPH_STATE_DEFAULT;

enum sheep_state {
	SHEEP_STATE_CONNECTED,	/* accept()ed */
	SHEEP_STATE_JOINED,
	SHEEP_STATE_LEAVING,
};

struct sheep {
	int fd;
	struct sd_node node;
	struct sockaddr_in addr;

	enum sheep_state state;

	struct list_head sheep_list;
	struct list_head join_wait_list;
};

static LIST_HEAD(sheep_list_head);

static bool running;
static const char *progname;

static bool is_sd_node_zero(struct sd_node *node)
{
	static struct sd_node zero_node;
	return !memcmp(node, &zero_node, sizeof(*node));
}

static int build_node_array(struct sd_node *nodes)
{
	int i;
	struct sheep *s;

	i = 0;
	list_for_each_entry(s, &sheep_list_head, sheep_list) {
		if (s->state != SHEEP_STATE_JOINED)
			continue;

		nodes[i++] = s->node;
	}

	return i;
}

static struct sheep *find_sheep_by_nid(struct node_id *id)
{
	struct sheep *s;

	list_for_each_entry(s, &sheep_list_head, sheep_list) {
		if (!node_id_cmp(&s->node.nid, id))
			return s;
	}

	return NULL;
}

static int remove_efd;

static inline void remove_sheep(struct sheep *sheep)
{
	sd_debug("remove_sheep() called, removing %s",
		 node_to_str(&sheep->node));

	sheep->state = SHEEP_STATE_LEAVING;
	eventfd_xwrite(remove_efd, 1);

	event_force_refresh();
}

static int notify_remove_sheep(struct sheep *leaving)
{
	int ret, failed = 0;
	struct sheep *s;
	struct sph_msg snd;

	snd.type = SPH_SRV_MSG_REMOVE;
	snd.body_len = sizeof(struct sd_node);

	list_for_each_entry(s, &sheep_list_head, sheep_list) {
		if (s->state != SHEEP_STATE_JOINED)
			continue;

		ret = writev2(s->fd, &snd,
			&leaving->node, sizeof(struct sd_node));

		if (sizeof(snd) + sizeof(struct sd_node) != ret) {
			sd_err("writev2() failed: %m");

			remove_sheep(s);
			failed++;
		}
	}

	return failed;
}

static void remove_handler(int fd, int events, void *data)
{
	struct sheep *s;
	int nr_removed, failed = 0;

	nr_removed = eventfd_xread(remove_efd);

	sd_debug("removed sheeps");
remove:
	list_for_each_entry(s, &sheep_list_head, sheep_list) {
		if (s->state != SHEEP_STATE_LEAVING)
			continue;

		sd_debug("removing the node: %s", node_to_str(&s->node));

		if (!is_sd_node_zero(&s->node))
			/*
			 * This condition can be false when the sheep had
			 * transited from CONNECTED to LEAVING directly.
			 * (sd_node of sheep in CONNECTED state doesn't have
			 * any information, because the member is initialized
			 * when SPH_MSG_NEW_NODE from master sheep is accepted.)
			 *
			 * sheep in CONNECTED state doesn't have to be removed
			 * with notify_remove_sheep(), because other sheeps
			 * don't know its existence.
			 */
			notify_remove_sheep(s);

		goto del;
	}

	goto end;

del:
	sd_info("removed node: %s", node_to_str(&s->node));

	unregister_event(s->fd);
	close(s->fd);

	list_del(&s->sheep_list);
	list_del(&s->join_wait_list);
	free(s);

	if (--nr_removed)
		goto remove;

end:
	sd_debug("nodes which failed during remove_handler(): %d", failed);
}

static LIST_HEAD(join_wait_queue);

static int release_joining_sheep(void)
{
	ssize_t wbytes;
	struct sheep *waiting;
	struct sph_msg snd;
	int nr_failed = 0;

retry:
	if (list_empty(&join_wait_queue))
		return nr_failed;

	waiting = list_first_entry(&join_wait_queue,
				struct sheep, join_wait_list);
	list_del(&waiting->join_wait_list);
	INIT_LIST_HEAD(&waiting->join_wait_list);

	memset(&snd, 0, sizeof(snd));
	snd.type = SPH_SRV_MSG_JOIN_RETRY;

	wbytes = xwrite(waiting->fd, &snd, sizeof(snd));
	if (sizeof(snd) != wbytes) {
		sd_err("xwrite() failed: %m");
		remove_sheep(waiting);

		sd_info("node %s is failed to join",
			node_to_str(&waiting->node));
		nr_failed++;

		goto retry;
	}

	return nr_failed;
}

static void sph_handle_join(struct sph_msg *msg, struct sheep *sheep)
{
	int fd = sheep->fd;
	ssize_t rbytes, wbytes;

	struct sph_msg snd;
	struct sph_msg_join *join;

	if (state == SPH_STATE_JOINING) {
		/* we have to trash opaque from the sheep */
		char *buf;
		buf = xzalloc(msg->body_len);
		rbytes = xread(fd, buf, msg->body_len);
		if (rbytes != msg->body_len) {
			sd_err("xread() failed: %m");
			goto purge_current_sheep;
		}
		free(buf);

		list_add(&sheep->join_wait_list, &join_wait_queue);

		sd_debug("there is already a joining sheep");
		return;
	}

	join = xzalloc(msg->body_len);
	rbytes = xread(fd, join, msg->body_len);
	if (msg->body_len != rbytes) {
		sd_err("xread() failed: %m");
		free(join);
		goto purge_current_sheep;
	}

	sheep->node = join->new_node;
	join->nr_nodes = build_node_array(join->nodes);

	snd.type = SPH_SRV_MSG_NEW_NODE;
	snd.body_len = msg->body_len;

	/* elect one node from the already joined nodes */
	if (join->nr_nodes > 0) {
		struct sd_node *n = join->nodes + rand() % join->nr_nodes;
		fd = find_sheep_by_nid(&n->nid)->fd;
	}

	wbytes = writev2(fd, &snd, join, msg->body_len);
	free(join);

	if (sizeof(snd) + msg->body_len != wbytes) {
		sd_err("writev2() failed: %m");

		goto purge_current_sheep;
	}

	state = SPH_STATE_JOINING;
	return;

purge_current_sheep:
	remove_sheep(sheep);
}

static void sph_handle_accept(struct sph_msg *msg, struct sheep *sheep)
{
	int fd = sheep->fd, removed = 0;
	ssize_t rbytes, wbytes;

	char *opaque;
	int opaque_len;

	struct sph_msg_join *join;
	struct sheep *s, *joining_sheep;
	struct sph_msg snd;
	struct sph_msg_join_reply *join_reply_body;
	struct sph_msg_join_node_finish *join_node_finish;

	sd_debug("new node reply from %s", node_to_str(&sheep->node));

	join = xzalloc(msg->body_len);
	rbytes = xread(fd, join, msg->body_len);
	if (msg->body_len != rbytes) {
		sd_err("xread() failed: %m");
		free(join);

		goto purge_current_sheep;
	}

	sd_debug("joining node is %s", node_to_str(&join->new_node));

	joining_sheep = find_sheep_by_nid(&join->new_node.nid);
	assert(joining_sheep != NULL);

	opaque_len = msg->body_len - sizeof(struct sph_msg_join);
	opaque = xzalloc(opaque_len);
	memcpy(opaque, join->opaque, opaque_len);

	sd_debug("length of opaque: %d", opaque_len);
	memset(&snd, 0, sizeof(snd));
	snd.type = SPH_SRV_MSG_JOIN_REPLY;
	snd.body_len = sizeof(struct sph_msg_join_reply) + opaque_len;

	join_reply_body = xzalloc(snd.body_len);

	join_reply_body->nr_nodes = build_node_array(join_reply_body->nodes);
	/*
	 * the below copy is required because joining sheep is in state
	 * SHEEP_STATE_CONNECTED
	 */
	join_reply_body->nodes[join_reply_body->nr_nodes++] =
		joining_sheep->node;
	memcpy(join_reply_body->opaque, opaque, opaque_len);

	wbytes = writev2(joining_sheep->fd, &snd,
			join_reply_body, snd.body_len);
	free(join_reply_body);
	free(join);

	if (sizeof(snd) + snd.body_len != wbytes) {
		sd_err("writev2() to master failed: %m");

		goto purge_current_sheep;
	}

	snd.type = SPH_SRV_MSG_NEW_NODE_FINISH;
	snd.body_len = sizeof(*join_node_finish) + opaque_len;

	join_node_finish = xzalloc(snd.body_len);
	join_node_finish->new_node = joining_sheep->node;
	memcpy(join_node_finish->opaque, opaque, opaque_len);
	join_node_finish->nr_nodes = build_node_array(join_node_finish->nodes);
	join_node_finish->nodes[join_node_finish->nr_nodes++] =
		joining_sheep->node;

	list_for_each_entry(s, &sheep_list_head, sheep_list) {
		if (s->state != SHEEP_STATE_JOINED)
			continue;

		if (s == joining_sheep)
			continue;

		wbytes = writev2(s->fd, &snd, join_node_finish, snd.body_len);

		if (sizeof(snd) + snd.body_len != wbytes) {
			sd_err("writev2() failed: %m");
			remove_sheep(s);
			removed++;
		}
	}

	free(join_node_finish);
	free(opaque);

	joining_sheep->state = SHEEP_STATE_JOINED;

	state = SPH_STATE_DEFAULT;

	removed += release_joining_sheep();
	return;

purge_current_sheep:
	state = SPH_STATE_DEFAULT;

	remove_sheep(sheep);
}

static void sph_handle_notify(struct sph_msg *msg, struct sheep *sheep)
{
	ssize_t rbytes, wbytes;
	int fd = sheep->fd, removed = 0;

	struct sph_msg snd;
	struct sph_msg_notify *notify;
	int notify_msg_len;
	struct sph_msg_notify_forward *notify_forward;
	struct sheep *s;

	notify = xzalloc(msg->body_len);
	rbytes = xread(fd, notify, msg->body_len);
	if (rbytes != msg->body_len) {
		sd_err("xread() failed: %m");
		goto purge_current_sheep;
	}

	notify_forward = xzalloc(msg->body_len + sizeof(*notify_forward));
	notify_msg_len = msg->body_len - sizeof(*notify);

	memcpy(notify_forward->notify_msg, notify->notify_msg, notify_msg_len);
	notify_forward->unblock = notify->unblock;
	free(notify);

	memset(&snd, 0, sizeof(snd));
	snd.type = SPH_SRV_MSG_NOTIFY_FORWARD;
	snd.body_len = notify_msg_len + sizeof(*notify_forward);

	notify_forward->from_node = sheep->node;

	list_for_each_entry(s, &sheep_list_head, sheep_list) {
		if (s->state != SHEEP_STATE_JOINED)
			continue;

		wbytes = writev2(s->fd, &snd, notify_forward, snd.body_len);
		if (sizeof(snd) + snd.body_len != wbytes) {
			sd_err("writev2() failed: %m");
			goto notify_failed;
		}

		continue;

notify_failed:
		remove_sheep(s);
		removed++;
	}

	free(notify_forward);
	return;

purge_current_sheep:
	remove_sheep(sheep);
}

static void sph_handle_block(struct sph_msg *msg, struct sheep *sheep)
{
	int removed = 0;
	struct sheep *s;
	struct sph_msg snd;

	memset(&snd, 0, sizeof(snd));
	snd.type = SPH_SRV_MSG_BLOCK_FORWARD;
	snd.body_len = sizeof(struct sd_node);

	list_for_each_entry(s, &sheep_list_head, sheep_list) {
		ssize_t wbytes;

		if (s->state != SHEEP_STATE_JOINED)
			continue;

		wbytes = writev2(s->fd, &snd,
				&sheep->node, sizeof(struct sd_node));
		if (sizeof(snd) + sizeof(struct sd_node) != wbytes) {
			sd_err("writev2() failed: %m");
			goto block_failed;
		}

		continue;

block_failed:	/* FIXME: is this correct behaviour? */
		remove_sheep(s);
		removed++;
	}

	return;
}

static void sph_handle_leave(struct sph_msg *msg, struct sheep *sheep)
{
	struct sheep *s;
	struct sph_msg snd;

	sd_info("%s is leaving", node_to_str(&sheep->node));

	memset(&snd, 0, sizeof(snd));
	snd.type = SPH_SRV_MSG_LEAVE_FORWARD;
	snd.body_len = sizeof(struct sd_node);

	list_for_each_entry(s, &sheep_list_head, sheep_list) {
		ssize_t wbytes;

		if (s->state != SHEEP_STATE_JOINED)
			continue;

		wbytes = writev2(s->fd, &snd,
				&sheep->node, sizeof(struct sd_node));
		if (sizeof(snd) + sizeof(struct sd_node) != wbytes) {
			sd_err("writev2() failed: %m");
			goto fwd_leave_failed;
		}

		continue;

fwd_leave_failed:
		remove_sheep(s);
	}
}

static void (*msg_handlers[])(struct sph_msg*, struct sheep *) = {
	[SPH_CLI_MSG_JOIN] = sph_handle_join,
	[SPH_CLI_MSG_ACCEPT] = sph_handle_accept,
	[SPH_CLI_MSG_NOTIFY] = sph_handle_notify,
	[SPH_CLI_MSG_BLOCK] = sph_handle_block,
	[SPH_CLI_MSG_LEAVE] = sph_handle_leave,
};

static void read_msg_from_sheep(struct sheep *sheep)
{
	int ret;
	struct sph_msg rcv;

	memset(&rcv, 0, sizeof(rcv));
	ret = xread(sheep->fd, &rcv, sizeof(rcv));

	if (ret != sizeof(rcv)) {
		sd_err("xread() failed: %m, ");
		goto remove;
	}

	if (!(0 <= rcv.type && rcv.type < ARRAY_SIZE(msg_handlers))) {
		sd_err("invalid message type: %d, ", rcv.type);
		sd_err("from node: %s", node_to_str(&sheep->node));
		sd_err("from node (sockaddr): %s",
		       sockaddr_in_to_str(&sheep->addr));
		sd_err("read bytes: %d, body length: %d", ret, rcv.body_len);
		goto remove;
	}

	sd_debug("received op: %s", sph_cli_msg_to_str(rcv.type));

	return msg_handlers[rcv.type](&rcv, sheep);

remove:
	sd_err("removing node: %s", node_to_str(&sheep->node));
	remove_sheep(sheep);
}

static void sheep_comm_handler(int fd, int events, void *data)
{
	if (events & EPOLLIN)
		read_msg_from_sheep(data);
	else if (events & EPOLLHUP || events & EPOLLERR) {
		sd_err("epoll() error: %s",
		       node_to_str(&((struct sheep *)data)->node));
		remove_sheep(data);
	}
}

static void sheep_accept_handler(int fd, int events, void *data)
{
	int ret;
	struct sheep *new_sheep;
	socklen_t len;

	new_sheep = xzalloc(sizeof(struct sheep));
	INIT_LIST_HEAD(&new_sheep->sheep_list);

	len = sizeof(struct sockaddr_in);
	new_sheep->fd = accept(fd, (struct sockaddr *)&new_sheep->addr, &len);
	if (new_sheep->fd < 0) {
		sd_err("accept() failed: %m");
		goto clean;
	}

	if (-1 == set_keepalive(new_sheep->fd)) {
		sd_err("set_keepalive() failed: %m");
		goto clean;
	}

	ret = register_event(new_sheep->fd, sheep_comm_handler, new_sheep);
	if (ret < 0) {
		sd_err("register_event() failed: %m");
		goto clean;
	}

	list_add_tail(&new_sheep->sheep_list, &sheep_list_head);
	new_sheep->state = SHEEP_STATE_CONNECTED;

	INIT_LIST_HEAD(&new_sheep->join_wait_list);

	sd_info("accepted new sheep connection");
	return;

clean:
	free(new_sheep);
}

static struct sd_option shepherd_options[] = {
	{ 'b', "bindaddr", true,
	  "specify IP address of interface to listen on" },
	{ 'd', "debug", false, "include debug messages in the log" },
	{ 'f', "foreground", false, "make the program run in the foreground" },
	{ 'F', "log-format", true, "specify log format" },
	{ 'h', "help", false, "display this help and exit" },
	{ 'l', "log-file", true,
	  "specify a log file for writing logs of shepherd" },
	{ 'p', "port", true, "specify TCP port on which to listen" },
	{ 0, NULL, false, NULL },
};

static void usage(void)
{
	struct sd_option *opt;

	printf("shepherd daemon:\n"
		"usage: %s <option>...\n"
		"options:\n", progname);

	sd_for_each_option(opt, shepherd_options) {
		printf("  -%c, --%-18s%s\n", opt->ch, opt->name,
			opt->desc);
	}
}

static void exit_handler(void)
{
	sd_info("exiting...");
}

static int set_listen_fd_cb(int fd, void *data)
{
	int ret;

	ret = register_event(fd, sheep_accept_handler, NULL);
	if (ret)
		panic("register_event() failed: %m");

	return 0;
}

static void crash_handler(int signo)
{
	sd_emerg("shepherd exits unexpectedly (%s).", strsignal(signo));

	sd_backtrace();

	reraise_crash_signal(signo, 1);
}

int main(int argc, char **argv)
{
	int ch, ret, longindex;
	char *p;
	bool daemonize = true;
	int log_level = SDOG_INFO;
	const char *log_file = "/var/log/shepherd.log";
	const char *log_format = "server";
	struct logger_user_info shepherd_info;

	int port = SHEPHERD_PORT;
	const char *bindaddr = NULL;

	struct option *long_options;
	const char *short_options;

	printf(TEXT_BOLD_RED "** WARNING: shepherd is still only suitable for "
	       "testing and review **" TEXT_NORMAL "\n");

	progname = argv[0];

	install_crash_handler(crash_handler);

	long_options = build_long_options(shepherd_options);
	short_options = build_short_options(shepherd_options);

	while ((ch = getopt_long(argc, argv, short_options, long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'b':
			bindaddr = optarg;
			break;
		case 'd':
			log_level = SDOG_DEBUG;
			break;
		case 'f':
			daemonize = false;
			break;
		case 'F':
			log_format = optarg;
			break;
		case 'h':
			usage();
			exit(0);
			break;
		case 'l':
			log_file = optarg;
			break;
		case 'p':
			port = strtol(optarg, &p, 10);
			if (p == optarg) {
				sd_err("invalid port: %s", optarg);
				exit(1);
			}
			break;
		default:
			sd_err("unknown option: %c", ch);
			usage();
			exit(1);
			break;
		}
	}

	if (daemonize) {
		ret = daemon(0, 0);

		if (-1 == ret) {
			sd_err("daemon() failed: %m");
			exit(1);
		}
	}

	shepherd_info.port = port;
	early_log_init(log_format, &shepherd_info);

	ret = log_init(progname, !daemonize, log_level, (char *)log_file);
	if (ret)
		panic("initialize logger failed: %m");

	atexit(exit_handler);
	init_event(EPOLL_SIZE);

	remove_efd = eventfd(0, EFD_NONBLOCK);
	if (remove_efd < 0)
		panic("eventfd() failed: %m");

	ret = register_event_prio(remove_efd, remove_handler, NULL,
				EVENT_PRIO_MAX);
	if (ret)
		panic("register_event() failed: %m");

	/* setup inet socket for communication with sheeps */
	ret = create_listen_ports(bindaddr, port, set_listen_fd_cb, NULL);
	if (ret)
		panic("create_listen_ports() failed: %m");

	running = true;

	while (running)
		event_loop_prio(-1);

	return 0;
}
