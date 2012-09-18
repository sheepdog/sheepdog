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
#include <assert.h>

#include "cluster.h"
#include "event.h"
#include "work.h"

#define MAX_EVENTS 500
#define PROCESS_CHECK_INTERVAL 200 /* ms */

const char *shmfile = "/tmp/sheepdog_shm";
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

	sprintf(s + strlen(s), " pid:%d", lnode->pid);

	return s;
}

static bool lnode_eq(const struct local_node *a, const struct local_node *b)
{
	return node_eq(&a->node, &b->node);
}

enum local_event_type {
	EVENT_JOIN_REQUEST = 1,
	EVENT_JOIN_RESPONSE,
	EVENT_LEAVE,
	EVENT_GATEWAY,
	EVENT_BLOCK,
	EVENT_NOTIFY,
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

struct shm_queue {
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
		dprintf("send signal to %s\n", lnode_to_str(lnodes + i));
		kill(lnodes[i].pid, SIGUSR1);
	}
}

static int is_shm_queue_valid(void)
{
	int i;
	size_t nr;
	struct local_node lnodes[SD_MAX_NODES];

	nr = get_nodes(lnodes);

	if (nr == 0)
		return 1;

	for (i = 0; i < nr; i++)
		if (process_exists(lnodes[i].pid))
			return 1;

	return 0;
}

static void shm_queue_init(void)
{
	int ret;

	shmfd = open(shmfile, O_CREAT | O_RDWR, 0644);
	if (shmfd < 0)
		panic("cannot open shared file, %s\n", shmfile);

	shm_queue_lock();

	ret = ftruncate(shmfd, sizeof(*shm_queue));
	assert(ret == 0);

	shm_queue = mmap(0, sizeof(*shm_queue),
			 PROT_READ | PROT_WRITE, MAP_SHARED, shmfd, 0);
	assert(shm_queue != MAP_FAILED);

	if (is_shm_queue_valid()) {
		block_event_pos = shm_queue->block_event_pos;
		nonblock_event_pos = shm_queue->nonblock_event_pos;
	} else {
		/* initialize shared memory */
		block_event_pos = 0;
		nonblock_event_pos = 0;
		ret = ftruncate(shmfd, 0);
		assert(ret == 0);
		ret = ftruncate(shmfd, sizeof(*shm_queue));
		assert(ret == 0);
	}

	shm_queue_unlock();
}

static struct local_node *find_lnode(struct local_node *key, size_t nr_lnodes,
				     struct local_node *lnodes)
{
	int i;

	for (i = 0; i < nr_lnodes; i++)
		if (lnode_eq(key, lnodes + i))
			return lnodes + i;

	panic("internal error\n");
}

static void add_event(enum local_event_type type, struct local_node *lnode,
		void *buf, size_t buf_len)
{
	int idx, i;
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
		n = find_lnode(lnode, ev.nr_lnodes, ev.lnodes);
		idx = n - ev.lnodes;

		ev.nr_lnodes--;
		memmove(n, n + 1, sizeof(*n) * (ev.nr_lnodes - idx));
		break;
	case EVENT_GATEWAY:
		n = find_lnode(lnode, ev.nr_lnodes, ev.lnodes);
		n->gateway = true;
		break;
	case EVENT_NOTIFY:
	case EVENT_BLOCK:
		break;
	case EVENT_JOIN_RESPONSE:
		abort();
	}

	dprintf("type = %d, sender = %s\n", ev.type, lnode_to_str(&ev.sender));
	for (i = 0; i < ev.nr_lnodes; i++)
		dprintf("%d: %s\n", i, lnode_to_str(ev.lnodes + i));

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

static int local_join(struct sd_node *myself,
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

	return 0;
}

static void local_block(void)
{
	shm_queue_lock();

	add_event(EVENT_BLOCK, &this_node, NULL, 0);

	shm_queue_unlock();
}

static void local_unblock(void *msg, size_t msg_len)
{
	struct local_event *ev;

	shm_queue_lock();

	ev = shm_queue_peek_block_event();

	ev->removed = true;
	msync(ev, sizeof(*ev), MS_SYNC);

	add_event(EVENT_NOTIFY, &this_node, msg, msg_len);

	shm_queue_unlock();
}

/*
 * Returns true if an event is processed
 */
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

	dprintf("type = %d, sender = %s\n", ev->type,
		lnode_to_str(&ev->sender));
	dprintf("callbacked = %d, removed = %d\n", ev->callbacked, ev->removed);

	nr_nodes = 0;
	for (i = 0; i < ev->nr_lnodes; i++) {
		dprintf("%d: %s\n", i, lnode_to_str(ev->lnodes + i));
		if (!ev->lnodes[i].gateway)
			nodes[nr_nodes++] = ev->lnodes[i].node;
	}

	if (ev->removed)
		goto out;

	if (ev->callbacked)
		return false; /* wait for unblock event */

	if (ev->type == EVENT_JOIN_RESPONSE &&
	    lnode_eq(&this_node, &ev->sender)) {
		dprintf("join Sheepdog\n");
		joined = true;
	}

	if (!joined) {
		if (ev->type == EVENT_JOIN_REQUEST &&
		    lnode_eq(&this_node, &ev->sender)) {
			struct local_node lnodes[SD_MAX_NODES];

			get_nodes(lnodes);

			if (!lnode_eq(&this_node, &lnodes[0])) {
				dprintf("wait for another node to accept this "
					"node\n");
				return false;
			}
		} else
			goto out;
	}

	switch (ev->type) {
	case EVENT_JOIN_REQUEST:
		res = sd_check_join_cb(&ev->sender.node, ev->buf);
		ev->join_result = res;
		ev->type = EVENT_JOIN_RESPONSE;
		msync(ev, sizeof(*ev), MS_SYNC);

		shm_queue_notify();

		if (res == CJ_RES_MASTER_TRANSFER) {
			eprintf("failed to join sheepdog cluster: "
				"please retry when master is up\n");
			shm_queue_unlock();
			exit(1);
		}
		return false;
	case EVENT_JOIN_RESPONSE:
		if (ev->join_result == CJ_RES_MASTER_TRANSFER) {
			/* FIXME: This code is tricky, but Sheepdog assumes that */
			/* nr_nodes = 1 when join_result = MASTER_TRANSFER... */
			ev->nr_lnodes = 1;
			ev->lnodes[0] = this_node;
			nr_nodes = 1;
			nodes[0] = this_node.node;
			msync(ev, sizeof(*ev), MS_SYNC);
		}

		sd_join_handler(&ev->sender.node, nodes, nr_nodes,
				ev->join_result, ev->buf);
		break;
	case EVENT_LEAVE:
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
		eprintf("local driver received EPOLLHUP event, exiting.\n");
		log_close();
		exit(1);
	}

	dprintf("read siginfo\n");

	ret = read(sigfd, &siginfo, sizeof(siginfo));
	assert(ret == sizeof(siginfo));

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
		eprintf("failed to create a signal fd: %m\n");
		return -1;
	}

	add_timer(&t, PROCESS_CHECK_INTERVAL);

	ret = register_event(sigfd, local_handler, NULL);
	if (ret) {
		eprintf("failed to register local event handler (%d)\n", ret);
		return -1;
	}

	return 0;
}

struct cluster_driver cdrv_local = {
	.name		= "local",

	.init		= local_init,
	.get_local_addr	= local_get_local_addr,
	.join		= local_join,
	.leave		= local_leave,
	.notify		= local_notify,
	.block		= local_block,
	.unblock	= local_unblock,
};

cdrv_register(cdrv_local);
