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
#include <search.h>
#include <signal.h>
#include <fcntl.h>
#include <assert.h>

#include "cluster.h"
#include "event.h"
#include "work.h"

#define MAX_EVENTS 500

const char *shmfile = "/tmp/sheepdog_shm";
static int shmfd;
static int sigfd;
static int event_pos;
static struct sd_node this_node;

enum local_event_type {
	EVENT_JOIN_REQUEST = 1,
	EVENT_JOIN_RESPONSE,
	EVENT_LEAVE,
	EVENT_BLOCK,
	EVENT_NOTIFY,
};

struct local_event {
	enum local_event_type type;
	struct sd_node sender;

	size_t buf_len;
	uint8_t buf[SD_MAX_EVENT_BUF_SIZE];

	size_t nr_nodes; /* the number of sheep processes */
	struct sd_node nodes[SD_MAX_NODES];
	pid_t pids[SD_MAX_NODES];

	enum cluster_join_result join_result;

	int callbacked; /* set non-zero after sd_block_handler() was called */
};


/* shared memory queue */

struct shm_queue {
	uint64_t chksum;

	int pos;
	struct local_event events[MAX_EVENTS];
} *shm_queue;

static void shm_queue_lock(void)
{
	flock(shmfd, LOCK_EX);
}

static void shm_queue_unlock(void)
{
	flock(shmfd, LOCK_UN);
}

static int shm_queue_empty(void)
{
	return event_pos == shm_queue->pos;
}

static size_t get_nodes(struct sd_node *n, pid_t *p)
{
	struct local_event *ev;

	ev = shm_queue->events + shm_queue->pos;

	if (n)
		memcpy(n, ev->nodes, sizeof(ev->nodes));
	if (p)
		memcpy(p, ev->pids, sizeof(ev->pids));

	return ev->nr_nodes;
}

static int process_exists(pid_t pid)
{
	return kill(pid, 0) == 0;
}

static struct local_event *shm_queue_peek(void)
{
	if (shm_queue_empty())
		return NULL;

	return shm_queue->events + (event_pos + 1) % MAX_EVENTS;
}

static void shm_queue_push(struct local_event *ev)
{
	shm_queue->pos = (shm_queue->pos + 1) % MAX_EVENTS;
	shm_queue->events[shm_queue->pos] = *ev;

	msync(shm_queue->events + shm_queue->pos, sizeof(*ev), MS_SYNC);
	msync(&shm_queue->pos, sizeof(shm_queue->pos), MS_SYNC);
}

static struct local_event *shm_queue_pop(void)
{
	if (shm_queue_empty())
		return NULL;

	event_pos = (event_pos + 1) % MAX_EVENTS;

	return shm_queue->events + event_pos;
}

static uint64_t shm_queue_calc_chksum(void)
{
	return fnv_64a_buf(shm_queue->events + shm_queue->pos,
			   sizeof(*shm_queue->events), FNV1A_64_INIT);
}

static void shm_queue_set_chksum(void)
{
	shm_queue->chksum = shm_queue_calc_chksum();
	msync(&shm_queue->chksum, sizeof(shm_queue->chksum), MS_SYNC);
}

static void shm_queue_notify(void)
{
	int i;
	size_t nr;
	pid_t pids[SD_MAX_NODES];

	shm_queue_set_chksum();

	nr = get_nodes(NULL, pids);

	for (i = 0; i < nr; i++)
		kill(pids[i], SIGUSR1);
}

static int is_shm_queue_valid(void)
{
	int i;
	size_t nr;
	pid_t pids[SD_MAX_NODES];

	if (shm_queue->chksum != shm_queue_calc_chksum()) {
		dprintf("invalid shm queue\n");
		return 0;
	}

	nr = get_nodes(NULL, pids);

	if (nr == 0)
		return 1;

	for (i = 0; i < nr; i++)
		if (process_exists(pids[i]))
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

	if (is_shm_queue_valid())
		event_pos = shm_queue->pos;
	else {
		/* initialize shared memory */
		event_pos = 0;
		ret = ftruncate(shmfd, 0);
		assert(ret == 0);
		ret = ftruncate(shmfd, sizeof(*shm_queue));
		assert(ret == 0);

		shm_queue_set_chksum();
	}

	shm_queue_unlock();
}

static void add_event(enum local_event_type type, struct sd_node *node,
		void *buf, size_t buf_len)
{
	int idx;
	struct sd_node *n;
	pid_t *p;
	struct local_event ev = {
		.type = type,
		.sender = *node,
	};

	ev.buf_len = buf_len;
	if (buf)
		memcpy(ev.buf, buf, buf_len);

	ev.nr_nodes = get_nodes(ev.nodes, ev.pids);

	switch (type) {
	case EVENT_JOIN_REQUEST:
		ev.nodes[ev.nr_nodes] = *node;
		ev.pids[ev.nr_nodes] = getpid(); /* must be local node */
		ev.nr_nodes++;
		break;
	case EVENT_LEAVE:
		n = lfind(node, ev.nodes, &ev.nr_nodes, sizeof(*n), node_cmp);
		if (!n)
			panic("internal error\n");
		idx = n - ev.nodes;
		p = ev.pids + idx;

		ev.nr_nodes--;
		memmove(n, n + 1, sizeof(*n) * (ev.nr_nodes - idx));
		memmove(p, p + 1, sizeof(*p) * (ev.nr_nodes - idx));
		break;
	case EVENT_NOTIFY:
	case EVENT_BLOCK:
		break;
	case EVENT_JOIN_RESPONSE:
		abort();
	}

	shm_queue_push(&ev);

	shm_queue_notify();
}

static void check_pids(void *arg)
{
	int i;
	size_t nr;
	struct sd_node nodes[SD_MAX_NODES];
	pid_t pids[SD_MAX_NODES];

	shm_queue_lock();

	nr = get_nodes(nodes, pids);

	for (i = 0; i < nr; i++)
		if (!process_exists(pids[i]))
			add_event(EVENT_LEAVE, nodes + i, NULL, 0);

	shm_queue_unlock();

	add_timer(arg, 1);
}


/* Local driver APIs */

static int local_join(struct sd_node *myself,
		      void *opaque, size_t opaque_len)
{
	this_node = *myself;

	shm_queue_lock();

	add_event(EVENT_JOIN_REQUEST, &this_node, opaque, opaque_len);

	shm_queue_unlock();

	return 0;
}

static int local_leave(void)
{
	shm_queue_lock();

	add_event(EVENT_LEAVE, &this_node, NULL, 0);

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

	ev = shm_queue_peek();

	ev->type = EVENT_NOTIFY;
	ev->buf_len = msg_len;
	if (msg)
		memcpy(ev->buf, msg, msg_len);
	msync(ev, sizeof(*ev), MS_SYNC);

	shm_queue_notify();

	shm_queue_unlock();
}

static void local_handler(int listen_fd, int events, void *data)
{
	struct signalfd_siginfo siginfo;
	struct local_event *ev;
	enum cluster_join_result res;
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

	ev = shm_queue_peek();
	if (!ev)
		goto out;

	switch (ev->type) {
	case EVENT_JOIN_REQUEST:
		if (!node_eq(&ev->nodes[0], &this_node))
			break;

		res = sd_check_join_cb(&ev->sender, ev->buf);
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
		break;
	case EVENT_JOIN_RESPONSE:
		if (ev->join_result == CJ_RES_MASTER_TRANSFER) {
			/* FIXME: This code is tricky, but Sheepdog assumes that */
			/* nr_nodes = 1 when join_result = MASTER_TRANSFER... */
			ev->nr_nodes = 1;
			ev->nodes[0] = this_node;
			ev->pids[0] = getpid();

			shm_queue_set_chksum();
		}

		sd_join_handler(&ev->sender, ev->nodes, ev->nr_nodes,
				    ev->join_result, ev->buf);
		shm_queue_pop();
		break;
	case EVENT_LEAVE:
		sd_leave_handler(&ev->sender, ev->nodes, ev->nr_nodes);
		shm_queue_pop();
		break;
	case EVENT_BLOCK:
		if (node_eq(&ev->sender, &this_node) && !ev->callbacked) {
			sd_block_handler();
			ev->callbacked = 1;
		}
		break;
	case EVENT_NOTIFY:
		sd_notify_handler(&ev->sender, ev->buf, ev->buf_len);
		shm_queue_pop();
		break;
	}

out:
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

	add_timer(&t, 1);

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
