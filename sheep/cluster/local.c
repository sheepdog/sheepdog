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
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/file.h>
#include <signal.h>
#include <fcntl.h>

#include "cluster.h"
#include "event.h"
#include "work.h"
#include "util.h"

#define MAX_EVENTS 500
#define PROCESS_CHECK_INTERVAL 50 /* ms */

static const char *shmfile = "/tmp/sheepdog_shm";
static int shmfd;
static int sigfd;
static int block_event_pos;
static int nonblock_event_pos;
static struct local_node this_node;
static bool joined;

struct local_node {
	struct sd_node node;
	pid_t pid;
	bool gateway;
};

static char *lnode_to_str(struct local_node *lnode)
{
	char *s = node_to_str(&lnode->node);

	snprintf(s + strlen(s), MAX_NODE_STR_LEN - strlen(s), " pid:%d",
		 lnode->pid);

	return s;
}

static int lnode_cmp(const struct local_node *a, const struct local_node *b)
{
	return node_cmp(&a->node, &b->node);
}

static bool lnode_eq(const struct local_node *a, const struct local_node *b)
{
	return lnode_cmp(a, b) == 0;
}

enum local_event_type {
	EVENT_JOIN_REQUEST = 1,
	EVENT_JOIN_RESPONSE,
	EVENT_LEAVE,
	EVENT_GATEWAY,
	EVENT_BLOCK,
	EVENT_NOTIFY,
	EVENT_UPDATE_NODE,
};

struct local_event {
	enum local_event_type type;
	struct local_node sender;

	bool callbacked;
	bool removed;

	size_t buf_len;
	uint8_t buf[SD_MAX_EVENT_BUF_SIZE];

	size_t nr_lnodes; /* the number of sheep processes */
	struct local_node lnodes[SD_MAX_NODES];

	enum cluster_join_result join_result;
};


/* shared memory queue */

static struct shm_queue {
	int block_event_pos;
	struct local_event block_events[MAX_EVENTS];
	int nonblock_event_pos;
	struct local_event nonblock_events[MAX_EVENTS];
} *shm_queue;

static void shm_queue_lock(void)
{
	flock(shmfd, LOCK_EX);
}

static void shm_queue_unlock(void)
{
	flock(shmfd, LOCK_UN);
}

static size_t get_nodes(struct local_node *n)
{
	struct local_event *ev;

	ev = shm_queue->nonblock_events + shm_queue->nonblock_event_pos;

	if (n)
		memcpy(n, ev->lnodes, sizeof(ev->lnodes));

	return ev->nr_lnodes;
}

static int process_exists(pid_t pid)
{
	return kill(pid, 0) == 0;
}

static struct local_event *shm_queue_peek_block_event(void)
{
	return shm_queue->block_events + (block_event_pos + 1) % MAX_EVENTS;
}

static struct local_event *shm_queue_peek_nonblock_event(void)
{
	return shm_queue->nonblock_events +
		(nonblock_event_pos + 1) % MAX_EVENTS;
}

static struct local_event *shm_queue_peek(void)
{
	/* try to peek nonblock queue first */
	if (nonblock_event_pos != shm_queue->nonblock_event_pos)
		return shm_queue_peek_nonblock_event();
	else if (block_event_pos != shm_queue->block_event_pos)
		return shm_queue_peek_block_event();
	else
		return NULL;
}

static void shm_queue_push(struct local_event *ev)
{
	int pos;

	if (ev->type == EVENT_BLOCK) {
		pos = (shm_queue->block_event_pos + 1) % MAX_EVENTS;

		shm_queue->block_events[pos] = *ev;
		msync(shm_queue->block_events + pos, sizeof(*ev), MS_SYNC);

		shm_queue->block_event_pos = pos;
		msync(&shm_queue->block_event_pos, sizeof(pos), MS_SYNC);
	} else {
		pos = (shm_queue->nonblock_event_pos + 1) % MAX_EVENTS;

		shm_queue->nonblock_events[pos] = *ev;
		msync(shm_queue->nonblock_events + pos, sizeof(*ev), MS_SYNC);

		shm_queue->nonblock_event_pos = pos;
		msync(&shm_queue->nonblock_event_pos, sizeof(pos), MS_SYNC);
	}
}

static void shm_queue_remove(struct local_event *ev)
{
	if (ev == shm_queue_peek_block_event())
		block_event_pos = (block_event_pos + 1) % MAX_EVENTS;
	else
		nonblock_event_pos = (nonblock_event_pos + 1) % MAX_EVENTS;
}

static void shm_queue_notify(void)
{
	int i;
	size_t nr;
	struct local_node lnodes[SD_MAX_NODES];

	nr = get_nodes(lnodes);

	for (i = 0; i < nr; i++) {
		sd_dprintf("send signal to %s", lnode_to_str(lnodes + i));
		kill(lnodes[i].pid, SIGUSR1);
	}
}

static bool is_shm_queue_valid(void)
{
	int i;
	size_t nr;
	struct local_node lnodes[SD_MAX_NODES];

	nr = get_nodes(lnodes);

	if (nr == 0)
		return true;

	for (i = 0; i < nr; i++)
		if (process_exists(lnodes[i].pid))
			return true;

	return false;
}

static void shm_queue_init(void)
{
	int ret;

	shmfd = open(shmfile, O_CREAT | O_RDWR, 0644);
	if (shmfd < 0)
		panic("cannot open shared file, %s", shmfile);

	shm_queue_lock();

	ret = xftruncate(shmfd, sizeof(*shm_queue));
	if (ret != 0)
		panic("failed to truncate shmfile, %m");

	shm_queue = mmap(NULL, sizeof(*shm_queue),
			 PROT_READ | PROT_WRITE, MAP_SHARED, shmfd, 0);
	if (shm_queue == MAP_FAILED)
		panic("mmap error, %m");

	if (is_shm_queue_valid()) {
		block_event_pos = shm_queue->block_event_pos;
		nonblock_event_pos = shm_queue->nonblock_event_pos;
	} else {
		/* initialize shared memory */
		block_event_pos = 0;
		nonblock_event_pos = 0;
		ret = xftruncate(shmfd, 0);
		if (ret != 0)
			panic("failed to truncate shmfile, %m");
		ret = xftruncate(shmfd, sizeof(*shm_queue));
		if (ret != 0)
			panic("failed to truncate shmfile, %m");
	}

	shm_queue_unlock();
}

static void add_event(enum local_event_type type, struct local_node *lnode,
		void *buf, size_t buf_len)
{
	struct local_node *n;
	struct local_event ev = {
		.type = type,
		.sender = *lnode,
	};

	ev.buf_len = buf_len;
	if (buf)
		memcpy(ev.buf, buf, buf_len);

	ev.nr_lnodes = get_nodes(ev.lnodes);

	switch (type) {
	case EVENT_JOIN_REQUEST:
		ev.lnodes[ev.nr_lnodes] = *lnode;
		ev.nr_lnodes++;
		break;
	case EVENT_LEAVE:
		xlremove(lnode, ev.lnodes, &ev.nr_lnodes, lnode_cmp);
		break;
	case EVENT_GATEWAY:
		n = xlfind(lnode, ev.lnodes, ev.nr_lnodes, lnode_cmp);
		n->gateway = true;
		break;
	case EVENT_NOTIFY:
	case EVENT_BLOCK:
		break;
	case EVENT_UPDATE_NODE:
		n = xlfind(lnode, ev.lnodes, ev.nr_lnodes, lnode_cmp);
		n->node = lnode->node;
		break;
	case EVENT_JOIN_RESPONSE:
		abort();
	}

	sd_dprintf("type = %d, sender = %s", ev.type, lnode_to_str(&ev.sender));
	for (int i = 0; i < ev.nr_lnodes; i++)
		sd_dprintf("%d: %s", i, lnode_to_str(ev.lnodes + i));

	shm_queue_push(&ev);

	shm_queue_notify();
}

static void check_pids(void *arg)
{
	int i;
	size_t nr;
	struct local_node lnodes[SD_MAX_NODES];
	struct local_event *ev;

	shm_queue_lock();

	nr = get_nodes(lnodes);

	for (i = 0; i < nr; i++)
		if (!process_exists(lnodes[i].pid)) {
			add_event(EVENT_LEAVE, lnodes + i, NULL, 0);

			/* unblock blocking event if sender has gone */
			ev = shm_queue_peek_block_event();
			if (lnode_eq(lnodes + i, &ev->sender)) {
				ev->removed = true;
				msync(ev, sizeof(*ev), MS_SYNC);
			}
		}

	shm_queue_unlock();

	add_timer(arg, PROCESS_CHECK_INTERVAL);
}


/* Local driver APIs */

static int local_join(const struct sd_node *myself,
		      void *opaque, size_t opaque_len)
{
	this_node.node = *myself;
	this_node.pid = getpid();
	this_node.gateway = false;

	shm_queue_lock();

	add_event(EVENT_JOIN_REQUEST, &this_node, opaque, opaque_len);

	shm_queue_unlock();

	return 0;
}

static int local_leave(void)
{
	shm_queue_lock();

	add_event(EVENT_GATEWAY, &this_node, NULL, 0);

	shm_queue_unlock();

	return 0;
}

static int local_notify(void *msg, size_t msg_len)
{
	shm_queue_lock();

	add_event(EVENT_NOTIFY, &this_node, msg, msg_len);

	shm_queue_unlock();

	return SD_RES_SUCCESS;
}

static int local_block(void)
{
	shm_queue_lock();

	add_event(EVENT_BLOCK, &this_node, NULL, 0);

	shm_queue_unlock();

	return SD_RES_SUCCESS;
}

static int local_unblock(void *msg, size_t msg_len)
{
	struct local_event *ev;

	shm_queue_lock();

	ev = shm_queue_peek_block_event();

	ev->removed = true;
	msync(ev, sizeof(*ev), MS_SYNC);

	add_event(EVENT_NOTIFY, &this_node, msg, msg_len);

	shm_queue_unlock();

	return SD_RES_SUCCESS;
}

/* Returns true if an event is processed */
static bool local_process_event(void)
{
	struct local_event *ev;
	enum cluster_join_result res;
	int i;
	struct sd_node nodes[SD_MAX_NODES];
	size_t nr_nodes;

	ev = shm_queue_peek();
	if (!ev)
		return false;

	sd_dprintf("type = %d, sender = %s", ev->type,
		   lnode_to_str(&ev->sender));
	sd_dprintf("callbacked = %d, removed = %d", ev->callbacked,
		   ev->removed);

	nr_nodes = 0;
	for (i = 0; i < ev->nr_lnodes; i++) {
		sd_dprintf("%d: %s", i, lnode_to_str(ev->lnodes + i));
		if (!ev->lnodes[i].gateway)
			nodes[nr_nodes++] = ev->lnodes[i].node;
	}

	if (ev->removed)
		goto out;

	if (ev->callbacked)
		return false; /* wait for unblock event */

	if (ev->type == EVENT_JOIN_RESPONSE &&
	    lnode_eq(&this_node, &ev->sender)) {
		sd_dprintf("join Sheepdog");
		joined = true;
	}

	if (!joined) {
		if (ev->type == EVENT_JOIN_REQUEST &&
		    lnode_eq(&this_node, &ev->sender)) {
			struct local_node lnodes[SD_MAX_NODES];

			get_nodes(lnodes);

			if (!lnode_eq(&this_node, &lnodes[0])) {
				sd_dprintf("wait for another node"
					   " to accept this node");
				return false;
			}
		} else
			goto out;
	}

	switch (ev->type) {
	case EVENT_JOIN_REQUEST:
		/* nodes[nr_nodes - 1] is a sender, so don't include it */
		assert(node_eq(&ev->sender.node, &nodes[nr_nodes - 1]));
		res = sd_check_join_cb(&ev->sender.node, nodes, nr_nodes - 1,
				       ev->buf);
		ev->join_result = res;
		ev->type = EVENT_JOIN_RESPONSE;
		msync(ev, sizeof(*ev), MS_SYNC);

		shm_queue_notify();

		return false;
	case EVENT_JOIN_RESPONSE:
		sd_join_handler(&ev->sender.node, nodes, nr_nodes,
				ev->join_result, ev->buf);
		break;
	case EVENT_LEAVE:
		if (ev->sender.gateway) {
			sd_dprintf("gateway %s left sheepdog",
				   lnode_to_str(&ev->sender));
			break;
		}
		/* fall through */
	case EVENT_GATEWAY:
		sd_leave_handler(&ev->sender.node, nodes, nr_nodes);
		break;
	case EVENT_BLOCK:
		ev->callbacked = sd_block_handler(&ev->sender.node);
		msync(ev, sizeof(*ev), MS_SYNC);
		return false;
	case EVENT_NOTIFY:
		sd_notify_handler(&ev->sender.node, ev->buf, ev->buf_len);
		break;
	case EVENT_UPDATE_NODE:
		break;
	}
out:
	shm_queue_remove(ev);

	return true;
}

static void local_handler(int listen_fd, int events, void *data)
{
	struct signalfd_siginfo siginfo;
	int ret;

	if (events & EPOLLHUP) {
		sd_eprintf("local driver received EPOLLHUP event, exiting.");
		log_close();
		exit(1);
	}

	sd_dprintf("read siginfo");

	ret = read(sigfd, &siginfo, sizeof(siginfo));
	if (ret != sizeof(siginfo))
		panic("failed to read from sigfd, %m");

	shm_queue_lock();

	while (local_process_event())
		;

	shm_queue_unlock();
}

static int local_get_local_addr(uint8_t *myaddr)
{
	/* set 127.0.0.1 */
	memset(myaddr, 0, 16);
	myaddr[12] = 127;
	myaddr[15] = 1;
	return 0;
}

static int local_init(const char *option)
{
	sigset_t mask;
	int ret;
	static struct timer t = {
		.callback = check_pids,
		.data = &t,
	};

	if (option)
		shmfile = option;

	shm_queue_init();

	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	sigfd = signalfd(-1, &mask, SFD_NONBLOCK);
	if (sigfd < 0) {
		sd_eprintf("failed to create a signal fd: %m");
		return -1;
	}

	add_timer(&t, PROCESS_CHECK_INTERVAL);

	ret = register_event(sigfd, local_handler, NULL);
	if (ret) {
		sd_eprintf("failed to register local event handler (%d)", ret);
		return -1;
	}

	return 0;
}

/* FIXME: we have to call nr of nodes times to update nodes information */
static void local_update_node(struct sd_node *node)
{
	struct local_node n = {
		.node = *node,
	};

	shm_queue_lock();

	add_event(EVENT_UPDATE_NODE, &n, NULL, 0);

	shm_queue_unlock();
}

static struct cluster_driver cdrv_local = {
	.name		= "local",

	.init		= local_init,
	.get_local_addr	= local_get_local_addr,
	.join		= local_join,
	.leave		= local_leave,
	.notify		= local_notify,
	.block		= local_block,
	.unblock	= local_unblock,
	.update_node    = local_update_node,
};

cdrv_register(cdrv_local);
