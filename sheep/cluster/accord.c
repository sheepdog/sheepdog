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
#include <netdb.h>
#include <search.h>
#include <assert.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <accord/accord.h>

#include "cluster.h"
#include "work.h"

#define MAX_EVENT_BUF_SIZE (64 * 1024)

#define BASE_FILE "/sheepdog"
#define LOCK_FILE BASE_FILE "/lock"
#define QUEUE_FILE BASE_FILE "/queue"

enum acrd_event_type {
	EVENT_JOIN = 1,
	EVENT_LEAVE,
	EVENT_NOTIFY,
};

struct acrd_event {
	enum acrd_event_type type;
	struct sd_node sender;

	size_t buf_len;
	uint8_t buf[MAX_EVENT_BUF_SIZE];

	size_t nr_nodes; /* the number of sheep */
	struct sd_node nodes[SD_MAX_NODES];
	uint64_t ids[SD_MAX_NODES];

	enum cluster_join_result join_result;

	void (*block_cb)(void *arg);

	int blocked; /* set non-zero when sheep must block this event */
	int callbacked; /* set non-zero if sheep already called block_cb() */
};

static struct sd_node this_node;
static uint64_t this_id;


/* misc functions */

struct acrd_path_list_entry {
	char *path;

	struct list_head list;
};

static void acrd_list_cb(struct acrd_handle *ah, const char *path, void *arg)
{
	struct acrd_path_list_entry *entry = malloc(sizeof(*entry));
	struct list_head *head = arg;

	entry->path = strdup(path);
	list_add_tail(&entry->list, head);
}

static void for_each_acrd_file(struct acrd_handle *ah, const char *parent,
			       void (*func)(struct acrd_handle *ah,
					    const char *path, void *arg),
			       void *arg)
{
	LIST_HEAD(path_list);
	struct acrd_path_list_entry *entry;
	struct acrd_listcb listcb = {
		.cb = acrd_list_cb,
		.arg = &path_list,
	};

	acrd_list(ah, parent, 0, &listcb);

	while (!list_empty(&path_list)) {
		entry = list_first_entry(&path_list, typeof(*entry), list);

		func(ah, entry->path, arg);

		list_del(&entry->list);
		free(entry->path);
		free(entry);
	}
}

static void __acrd_del(struct acrd_handle *ah, const char *path, void *arg)
{
	acrd_del(ah, path, 0);
}


/* Accord-based lock */

static void acrd_lock(struct acrd_handle *ah)
{
	int rc;
again:
	rc = acrd_write(ah, LOCK_FILE, &this_id, sizeof(this_id), 0,
			ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	if (rc == ACRD_SUCCESS)
		return;
	else if (rc == ACRD_ERR_EXIST) {
		dprintf("retry\n");
		usleep(10000); /* FIXME: use acrd notification */
		goto again;
	} else
		panic("failed to create a lock file\n");
}

static void acrd_unlock(struct acrd_handle *ah)
{
	int rc;

	rc = acrd_del(ah, LOCK_FILE, 0);
	if (rc != ACRD_SUCCESS)
		panic("failed to release lock\n");
}


/* Accord-based queue */

static int queue_start_pos;
static int queue_end_pos;

static int acrd_queue_empty(struct acrd_handle *ah)
{
	int rc;
	char path[256];
	uint32_t count = 0;

	sprintf(path, QUEUE_FILE "/%d", queue_start_pos);

	rc = acrd_read(ah, path, NULL, &count, 0, 0);
	if (rc == ACRD_SUCCESS)
		return 0;

	return 1;
}

static void acrd_queue_push(struct acrd_handle *ah, struct acrd_event *ev)
{
	int rc;
	char path[256];
again:
	queue_end_pos++;
	sprintf(path, "%s/%d", QUEUE_FILE, queue_end_pos);
	rc = acrd_write(ah, path, ev, sizeof(*ev), 0,
			ACRD_FLAG_CREATE | ACRD_FLAG_EXCL);
	if (rc == ACRD_ERR_EXIST)
		goto again;

	assert(rc == ACRD_SUCCESS);

	if (queue_start_pos < 0) {
		/* the first pushed data should be EVENT_JOIN */
		assert(ev->type == EVENT_JOIN);
		queue_start_pos = queue_end_pos;
	}
}

static int acrd_queue_push_back(struct acrd_handle *ah, struct acrd_event *ev)
{
	int rc;
	char path[256];

	queue_start_pos--;

	if (ev) {
		/* update the last popped data */
		sprintf(path, QUEUE_FILE "/%d", queue_start_pos);
		rc = acrd_write(ah, path, ev, sizeof(*ev), 0, 0);
		assert(rc == ACRD_SUCCESS);
	}

	return 0;
}

static int acrd_queue_pop(struct acrd_handle *ah, struct acrd_event *ev)
{
	int rc;
	char path[256];
	uint32_t len;

	if (acrd_queue_empty(ah))
		return -1;

	sprintf(path, QUEUE_FILE "/%d", queue_start_pos);
	len = sizeof(*ev);
	rc = acrd_read(ah, path, ev, &len, 0, 0);
	assert(rc == ACRD_SUCCESS);

	queue_start_pos++;

	return 0;
}


/* Accord driver APIs */

static struct acrd_handle *ahandle;
static int efd;

static struct work_queue *acrd_wq;

/* get node list from the last pushed data */
static size_t get_nodes(struct acrd_handle *ah,
			struct sd_node *nodes,
			uint64_t *ids)
{
	int rc;
	struct acrd_event ev;
	char path[256];
	uint32_t len;
again:
	len = sizeof(ev);
	sprintf(path, "%s/%d", QUEUE_FILE, queue_end_pos);
	rc = acrd_read(ah, path, &ev, &len, 0, 0);
	if (rc == ACRD_SUCCESS) {
		/* find the latest event */
		queue_end_pos++;
		goto again;
	}

	queue_end_pos--;

	memcpy(nodes, ev.nodes, sizeof(ev.nodes));
	memcpy(ids, ev.ids, sizeof(ev.ids));

	return ev.nr_nodes;
}

static int add_event(struct acrd_handle *ah, enum acrd_event_type type,
		     struct sd_node *node, void *buf,
		     size_t buf_len, void (*block_cb)(void *arg))
{
	int idx;
	struct sd_node *n;
	uint64_t *i;
	struct acrd_event ev;

	acrd_lock(ah);

	ev.type = type;
	ev.sender = *node;
	ev.buf_len = buf_len;
	if (buf)
		memcpy(ev.buf, buf, buf_len);

	ev.nr_nodes = get_nodes(ah, ev.nodes, ev.ids);

	switch (type) {
	case EVENT_JOIN:
		ev.blocked = 1;
		ev.nodes[ev.nr_nodes] = *node;
		ev.ids[ev.nr_nodes] = this_id; /* must be local node */
		ev.nr_nodes++;
		break;
	case EVENT_LEAVE:
		n = lfind(node, ev.nodes, &ev.nr_nodes, sizeof(*n), node_cmp);
		if (!n)
			goto out;
		idx = n - ev.nodes;
		i = ev.ids + idx;

		ev.nr_nodes--;
		memmove(n, n + 1, sizeof(*n) * (ev.nr_nodes - idx));
		memmove(i, i + 1, sizeof(*i) * (ev.nr_nodes - idx));
		break;
	case EVENT_NOTIFY:
		ev.blocked = !!block_cb;
		ev.block_cb = block_cb;
		break;
	}

	acrd_queue_push(ah, &ev);
out:
	acrd_unlock(ah);
	return 0;
}

static int get_addr(uint8_t *bytes)
{
	int ret;
	char name[INET6_ADDRSTRLEN];
	struct addrinfo hints, *res, *res0;

	gethostname(name, sizeof(name));

	memset(&hints, 0, sizeof(hints));

	hints.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(name, NULL, &hints, &res0);
	if (ret)
		exit(1);

	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family == AF_INET) {
			struct sockaddr_in *addr;
			addr = (struct sockaddr_in *)res->ai_addr;

			if (((char *) &addr->sin_addr)[0] == 127)
				continue;

			memset(bytes, 0, 12);
			memcpy(bytes + 12, &addr->sin_addr, 4);
			break;
		} else if (res->ai_family == AF_INET6) {
			struct sockaddr_in6 *addr;
			uint8_t localhost[16] = { 0, 0, 0, 0, 0, 0, 0, 0,
						  0, 0, 0, 0, 0, 0, 0, 1 };

			addr = (struct sockaddr_in6 *)res->ai_addr;

			if (memcmp(&addr->sin6_addr, localhost, 16) == 0)
				continue;

			memcpy(bytes, &addr->sin6_addr, 16);
			break;
		} else
			dprintf("unknown address family\n");
	}

	if (res == NULL) {
		eprintf("failed to get address info\n");
		return -1;
	}

	freeaddrinfo(res0);

	return 0;
}

static void find_queue_end(struct acrd_handle *ah, const char *path, void *arg)
{
	int max;

	sscanf(path, QUEUE_FILE "/%d", &max);
	if (max > *(int *)arg)
		*(int *)arg = max;
}

static pthread_mutex_t start_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t start_cond = PTHREAD_COND_INITIALIZER;

/* protect queue_start_pos */
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;

static int need_cleanup;

static void acrd_join_fn(struct acrd_handle *ah, const uint64_t *member_list,
			 size_t member_list_entries, uint64_t nodeid, void *arg)
{
	static int init = 0;

	if (!init) {
		this_id = nodeid;

		if (member_list_entries == 1)
			need_cleanup = 1;

		pthread_mutex_lock(&start_lock);
		pthread_cond_signal(&start_cond);
		pthread_mutex_unlock(&start_lock);

		init = 1;
	}
}

struct acrd_leave_info {
	struct acrd_handle *ah;
	uint64_t left_nodeid;
	struct work work;
};

static void __acrd_leave(struct work *work)
{
	struct acrd_leave_info *info = container_of(work, typeof(*info), work);
	struct acrd_handle *ah = info->ah;
	int i;
	size_t nr_nodes;
	uint64_t ids[SD_MAX_NODES];
	struct sd_node nodes[SD_MAX_NODES];
	struct acrd_tx *atx;

	pthread_mutex_lock(&queue_lock);

	/* unlock if left node is locking one */
	atx = acrd_tx_init(ah);
	acrd_tx_cmp(atx, LOCK_FILE, &info->left_nodeid,
		    sizeof(info->left_nodeid), 0);
	acrd_tx_del(atx, LOCK_FILE, 0);
	acrd_tx_commit(atx, 0);
	acrd_tx_close(atx);

	/* check the failed node */
	nr_nodes = get_nodes(ah, nodes, ids);

	for (i = 0; i < nr_nodes; i++) {
		if (ids[i] == info->left_nodeid) {
			add_event(ah, EVENT_LEAVE, nodes + i, NULL, 0,
				  NULL);
			break;
		}
	}

	pthread_mutex_unlock(&queue_lock);
}

static void __acrd_leave_done(struct work *work)
{
	struct acrd_leave_info *info = container_of(work, typeof(*info), work);

	free(info);
}

static void acrd_leave_fn(struct acrd_handle *ah, const uint64_t *member_list,
			  size_t member_list_entries, uint64_t nodeid, void *arg)
{
	struct acrd_leave_info *info;
	static int left;

	if (nodeid == this_id) {
		left = 1;
		close(efd);
	}

	if(left)
		return;

	info = zalloc(sizeof(*info));
	if (!info)
		panic("failed to allocate memory");

	info->ah = ah;
	info->left_nodeid = nodeid;
	info->work.fn = __acrd_leave;
	info->work.done = __acrd_leave_done;

	/* we cannot call accord APIs in the callback... */
	queue_work(acrd_wq, &info->work);
}

static void acrd_watch_fn(struct acrd_handle *ah, struct acrd_watch_info *info,
			  void *arg)
{
	eventfd_t value = 1;

	eventfd_write(efd, value);
}

static int accord_init(const char *option, uint8_t *myaddr)
{
	if (!option) {
		eprintf("specify one of the accord servers.\n");
		eprintf("e.g. sheep /store -c accord:127.0.0.1\n");
		return -1;
	}

	pthread_mutex_lock(&start_lock);

	ahandle = acrd_init(option, 9090, acrd_join_fn, acrd_leave_fn, NULL);
	if (!ahandle) {
		eprintf("failed to connect to accrd server %s\n", option);
		return -1;
	}

	if (get_addr(myaddr) < 0)
		return -1;

	efd = eventfd(0, EFD_NONBLOCK);
	if (efd < 0) {
		eprintf("failed to create an event fd: %m\n");
		return -1;
	}

	acrd_wq = init_work_queue(1);
	if (!acrd_wq)
		eprintf("failed to create accord workqueue: %m\n");
		return -1;
	}

	pthread_cond_wait(&start_cond, &start_lock);
	pthread_mutex_unlock(&start_lock);

	if (need_cleanup)
		for_each_acrd_file(ahandle, BASE_FILE, __acrd_del, NULL);
	else {
		queue_start_pos = -1;
		queue_end_pos = -1;
		for_each_acrd_file(ahandle, QUEUE_FILE, find_queue_end,
				   &queue_end_pos);
	}

	acrd_add_watch(ahandle, QUEUE_FILE, ACRD_EVENT_PREFIX | ACRD_EVENT_ALL,
		       acrd_watch_fn, NULL);

	return efd;
}

static int accord_join(struct sd_node *myself,
		       void *opaque, size_t opaque_len)
{
	this_node = *myself;

	return add_event(ahandle, EVENT_JOIN, &this_node, opaque, opaque_len, NULL);
}

static int accord_leave(void)
{
	return add_event(ahandle, EVENT_LEAVE, &this_node, NULL, 0, NULL);
}

static int accord_notify(void *msg, size_t msg_len, void (*block_cb)(void *arg))
{
	return add_event(ahandle, EVENT_NOTIFY, &this_node, msg, msg_len, block_cb);
}

static void acrd_block(struct work *work)
{
	struct acrd_event ev;

	pthread_mutex_lock(&queue_lock);

	acrd_queue_pop(ahandle, &ev);

	ev.block_cb(ev.buf);
	ev.blocked = 0;

	acrd_queue_push_back(ahandle, &ev);

	pthread_mutex_unlock(&queue_lock);
}

static void acrd_block_done(struct work *work)
{
}

static int accord_dispatch(void)
{
	int ret;
	eventfd_t value;
	struct acrd_event ev;
	enum cluster_join_result res;
	static struct work work = {
		.fn = acrd_block,
		.done = acrd_block_done,
	};

	dprintf("read event\n");
	ret = eventfd_read(efd, &value);
	if (ret < 0)
		return 0;

	pthread_mutex_lock(&queue_lock);

	ret = acrd_queue_pop(ahandle, &ev);
	if (ret < 0)
		goto out;

	switch (ev.type) {
	case EVENT_JOIN:
		if (ev.blocked) {
			if (node_cmp(&ev.nodes[0], &this_node) == 0) {
				res = sd_check_join_cb(&ev.sender, ev.buf);
				ev.join_result = res;
				ev.blocked = 0;

				acrd_queue_push_back(ahandle, &ev);

				if (res == CJ_RES_MASTER_TRANSFER) {
					eprintf("failed to join sheepdog cluster: "
						"please retry when master is up\n");
					exit(1);
				}
			} else
				acrd_queue_push_back(ahandle, NULL);

			goto out;
		}

		if (ev.join_result == CJ_RES_MASTER_TRANSFER) {
			/* FIXME: This code is tricky, but Sheepdog assumes that */
			/* nr_nodes = 1 when join_result = MASTER_TRANSFER... */
			ev.nr_nodes = 1;
			ev.nodes[0] = this_node;
			ev.ids[0] = this_id;
			acrd_queue_push_back(ahandle, &ev);
			acrd_queue_pop(ahandle, &ev);
		}

		sd_join_handler(&ev.sender, ev.nodes, ev.nr_nodes,
				    ev.join_result, ev.buf);
		break;
	case EVENT_LEAVE:
		sd_leave_handler(&ev.sender, ev.nodes, ev.nr_nodes);
		break;
	case EVENT_NOTIFY:
		if (ev.blocked) {
			if (node_cmp(&ev.sender, &this_node) == 0 && !ev.callbacked) {
				queue_work(acrd_wq, &work);

				ev.callbacked = 1;

				acrd_queue_push_back(ahandle, &ev);
			} else
				acrd_queue_push_back(ahandle, NULL);

			goto out;
		}

		sd_notify_handler(&ev.sender, ev.buf, ev.buf_len);
		break;
	}
out:
	pthread_mutex_unlock(&queue_lock);

	return 0;
}

struct cluster_driver cdrv_accord = {
	.name       = "accord",

	.init       = accord_init,
	.join       = accord_join,
	.leave      = accord_leave,
	.notify     = accord_notify,
	.dispatch   = accord_dispatch,
};

cdrv_register(cdrv_accord);
