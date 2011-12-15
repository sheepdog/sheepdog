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
#include <sys/eventfd.h>
#include <zookeeper/zookeeper.h>

#include "cluster.h"
#include "work.h"

#define MAX_EVENT_BUF_SIZE (64 * 1024)

#define BASE_ZNODE "/sheepdog"
#define LOCK_ZNODE BASE_ZNODE "/lock"
#define QUEUE_ZNODE BASE_ZNODE "/queue"
#define MEMBER_ZNODE BASE_ZNODE "/member"

/* iterate child znodes */
#define FOR_EACH_ZNODE(zh, parent, path, strs)			       \
	for (zoo_get_children(zh, parent, 1, strs),		       \
		     (strs)->data += (strs)->count;		       \
	     (strs)->count-- ?					       \
		     sprintf(path, "%s/%s", parent, *--(strs)->data) : \
		     (free((strs)->data), 0);			       \
	     free(*(strs)->data))

enum zk_event_type {
	EVENT_JOIN = 1,
	EVENT_LEAVE,
	EVENT_NOTIFY,
};

struct zk_event {
	enum zk_event_type type;
	struct sheepdog_node_list_entry sender;

	size_t buf_len;
	uint8_t buf[MAX_EVENT_BUF_SIZE];

	size_t nr_nodes; /* the number of sheep */
	struct sheepdog_node_list_entry nodes[SD_MAX_NODES];

	enum cluster_join_result join_result;

	void (*block_cb)(void *arg);

	int blocked; /* set non-zero when sheep must block this event */
	int callbacked; /* set non-zero if sheep already called block_cb() */
};


/* ZooKeeper-based lock */

static void zk_lock(zhandle_t *zh)
{
	int rc;
again:
	rc = zoo_create(zh, LOCK_ZNODE, "", 0, &ZOO_OPEN_ACL_UNSAFE,
			ZOO_EPHEMERAL, NULL, 0);
	if (rc == ZOK)
		return;
	else if (rc == ZNODEEXISTS) {
		dprintf("retry\n");
		usleep(10000); /* FIXME: use watch notification */
		goto again;
	} else
		panic("failed to create a lock znode\n");
}

static void zk_unlock(zhandle_t *zh)
{
	int rc;

	rc = zoo_delete(zh, LOCK_ZNODE, -1);
	if (rc != ZOK)
		panic("failed to release lock\n");
}


/* ZooKeeper-based queue */

static int queue_pos;

static int zk_queue_empty(zhandle_t *zh)
{
	int rc;
	char path[256];

	sprintf(path, QUEUE_ZNODE "/%010d", queue_pos);

	rc = zoo_exists(zh, path, 1, NULL);
	if (rc == ZOK)
		return 0;

	return 1;
}

static void zk_queue_push(zhandle_t *zh, struct zk_event *ev)
{
	int rc;
	char path[256], buf[256];

	sprintf(path, "%s/", QUEUE_ZNODE);
	rc = zoo_create(zh, path, (char *)ev, sizeof(*ev),
			&ZOO_OPEN_ACL_UNSAFE, ZOO_SEQUENCE, buf, sizeof(buf));

	if (queue_pos < 0) {
		/* the first pushed data should be EVENT_JOIN */
		assert(ev->type == EVENT_JOIN);
		sscanf(buf, QUEUE_ZNODE "/%010d", &queue_pos);

		/* watch */
		zoo_exists(zh, buf, 1, NULL);
	}
}

static int zk_queue_push_back(zhandle_t *zh, struct zk_event *ev)
{
	int rc;
	char path[256];

	queue_pos--;

	if (ev) {
		/* update the last popped data */
		sprintf(path, QUEUE_ZNODE "/%010d", queue_pos);
		rc = zoo_set(zh, path, (char *)ev, sizeof(*ev), -1);
	}

	return 0;
}

static int zk_queue_pop(zhandle_t *zh, struct zk_event *ev)
{
	int rc, len;
	char path[256];

	if (zk_queue_empty(zh))
		return -1;

	sprintf(path, QUEUE_ZNODE "/%010d", queue_pos);
	len = sizeof(*ev);
	rc = zoo_get(zh, path, 1, (char *)ev, &len, NULL);

	/* watch next data */
	queue_pos++;
	sprintf(path, QUEUE_ZNODE "/%010d", queue_pos);
	zoo_exists(zh, path, 1, NULL);

	return 0;
}

static int is_zk_queue_valid(zhandle_t *zh)
{
	int rc, len;
	struct String_vector strs;
	uint64_t joined;
	char path[256];

	FOR_EACH_ZNODE(zh, MEMBER_ZNODE, path, &strs) {
		len = sizeof(joined);
		rc = zoo_get(zh, path, 1, (char *)&joined, &len, NULL);
		assert(rc == ZOK);

		if (joined)
			return 1;
	}

	return 0;
}

static void zk_queue_init(zhandle_t *zh)
{
	int rc;
	struct String_vector strs;
	char path[256];

	zoo_create(zh, BASE_ZNODE, "", 0, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
	zoo_create(zh, QUEUE_ZNODE, "", 0, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
	zoo_create(zh, MEMBER_ZNODE, "", 0, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);

	zk_lock(zh);

	queue_pos = -1;

	if (!is_zk_queue_valid(zh)) {
		dprintf("clean zookeeper store\n");

		FOR_EACH_ZNODE(zh, MEMBER_ZNODE, path, &strs) {
			rc = zoo_delete(zh, path, -1);
			assert(rc == ZOK);
		}

		FOR_EACH_ZNODE(zh, QUEUE_ZNODE, path, &strs) {
			rc = zoo_delete(zh, path, -1);
			assert(rc == ZOK);
		}
	}

	zk_unlock(zh);
}


/* ZooKeeper driver APIs */

static zhandle_t *zhandle;
static int efd;

static struct work_queue *zk_block_wq;

static struct sheepdog_node_list_entry this_node;

static struct cdrv_handlers zk_hdlrs;
static enum cluster_join_result (*zk_check_join_cb)(
	struct sheepdog_node_list_entry *joining, void *opaque);

/* get node list from the last pushed data */
static size_t get_nodes(zhandle_t *zh, struct sheepdog_node_list_entry *nodes)
{
	int rc, len;
	struct zk_event ev;
	struct String_vector strs;
	char path[256], max[256] = "";

	FOR_EACH_ZNODE(zh, QUEUE_ZNODE, path, &strs) {
		if (strcmp(max, path) < 0)
			strcpy(max, path);
	}

	if (max[0] == '\0')
		return 0;

	len = sizeof(ev);
	rc = zoo_get(zh, max, 1, (char *)&ev, &len, NULL);
	assert(rc == ZOK);

	memcpy(nodes, ev.nodes, sizeof(ev.nodes));

	return ev.nr_nodes;
}

static int add_event(zhandle_t *zh, enum zk_event_type type,
		     struct sheepdog_node_list_entry *node, void *buf,
		     size_t buf_len, void (*block_cb)(void *arg))
{
	int idx;
	struct sheepdog_node_list_entry *n;
	struct zk_event ev;

	zk_lock(zh);

	ev.type = type;
	ev.sender = *node;
	ev.buf_len = buf_len;
	if (buf)
		memcpy(ev.buf, buf, buf_len);

	ev.nr_nodes = get_nodes(zh, ev.nodes);

	switch (type) {
	case EVENT_JOIN:
		ev.blocked = 1;
		ev.nodes[ev.nr_nodes] = *node;
		ev.nr_nodes++;
		break;
	case EVENT_LEAVE:
		n = lfind(node, ev.nodes, &ev.nr_nodes, sizeof(*n), node_cmp);
		if (!n)
			goto out;
		idx = n - ev.nodes;

		ev.nr_nodes--;
		memmove(n, n + 1, sizeof(*n) * (ev.nr_nodes - idx));
		break;
	case EVENT_NOTIFY:
		ev.blocked = !!block_cb;
		ev.block_cb = block_cb;
		break;
	}

	zk_queue_push(zh, &ev);
out:
	zk_unlock(zh);

	return 0;
}

static void watcher(zhandle_t *zh, int type, int state, const char *path, void* ctx)
{
	eventfd_t value = 1;
	char str[256];
	int ret, i;
	size_t nr_nodes;
	struct sheepdog_node_list_entry nodes[SD_MAX_NODES];

	if (type == ZOO_DELETED_EVENT) {
		ret = sscanf(path, MEMBER_ZNODE "/%[^\n]", str);
		if (ret != 1)
			goto out;

		/* check the failed node */
		nr_nodes = get_nodes(zh, nodes);
		for (i = 0; i < nr_nodes; i++) {
			if (strcmp(str, node_to_str(nodes + i)) == 0) {
				add_event(zh, EVENT_LEAVE, nodes + i, NULL, 0,
					  NULL);
				goto out;
			}
		}
	}
out:
	eventfd_write(efd, value);
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

static int zk_init(struct cdrv_handlers *handlers, const char *option,
		   uint8_t *myaddr)
{
	zk_hdlrs = *handlers;
	if (!option) {
		eprintf("specify comma separated host:port pairs, each corresponding to a zk server.\n");
		eprintf("e.g. sheep /store -c zookeeper:127.0.0.1:3000,127.0.0.1:3001,127.0.0.1:3002\n");
		return -1;
	}

	zhandle = zookeeper_init(option, watcher, 10000, 0, NULL, 0);
	if (!zhandle) {
		eprintf("failed to connect to zk server %s\n", option);
		return -1;
	}

	if (get_addr(myaddr) < 0)
		return -1;

	zk_queue_init(zhandle);

	efd = eventfd(0, EFD_NONBLOCK);
	if (efd < 0) {
		eprintf("failed to create an event fd: %m\n");
		return -1;
	}

	zk_block_wq = init_work_queue(1);

	return efd;
}

static int zk_join(struct sheepdog_node_list_entry *myself,
		   enum cluster_join_result (*check_join_cb)(
			   struct sheepdog_node_list_entry *joining,
			   void *opaque),
		   void *opaque, size_t opaque_len)
{
	int rc;
	uint64_t joined;
	char path[256];

	this_node = *myself;
	zk_check_join_cb = check_join_cb;

	sprintf(path, MEMBER_ZNODE "/%s", node_to_str(myself));
	joined = 0;
	rc = zoo_create(zhandle, path, (char *)&joined, sizeof(joined),
			&ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL, NULL, 0);
	if (rc != ZOK)
		panic("failed to create an ephemeral znode\n");

	return add_event(zhandle, EVENT_JOIN, &this_node, opaque, opaque_len, NULL);
}

static int zk_leave(void)
{
	return add_event(zhandle, EVENT_LEAVE, &this_node, NULL, 0, NULL);
}

static int zk_notify(void *msg, size_t msg_len, void (*block_cb)(void *arg))
{
	return add_event(zhandle, EVENT_NOTIFY, &this_node, msg, msg_len, block_cb);
}

static void zk_block(struct work *work)
{
	struct zk_event ev;

	zk_queue_pop(zhandle, &ev);

	ev.block_cb(ev.buf);
	ev.blocked = 0;

	zk_queue_push_back(zhandle, &ev);
}

static void zk_block_done(struct work *work)
{
}

static int zk_dispatch(void)
{
	int ret, rc;
	char path[256];
	uint64_t joined;
	eventfd_t value;
	struct zk_event ev;
	enum cluster_join_result res;
	static struct work work = {
		.fn = zk_block,
		.done = zk_block_done,
	};

	dprintf("read event\n");
	ret = eventfd_read(efd, &value);
	if (ret < 0)
		return 0;

	ret = zk_queue_pop(zhandle, &ev);
	if (ret < 0)
		goto out;

	switch (ev.type) {
	case EVENT_JOIN:
		if (ev.blocked) {
			if (node_cmp(&ev.nodes[0], &this_node) == 0) {
				res = zk_check_join_cb(&ev.sender, ev.buf);
				ev.join_result = res;
				ev.blocked = 0;

				sprintf(path, MEMBER_ZNODE "/%s", node_to_str(&ev.sender));
				joined = 1;
				rc = zoo_set(zhandle, path, (char *)&joined, sizeof(joined), -1);
				assert(rc == ZOK);

				zk_queue_push_back(zhandle, &ev);

				if (res == CJ_RES_MASTER_TRANSFER) {
					eprintf("failed to join sheepdog cluster: "
						"please retry when master is up\n");
					exit(1);
				}
			} else
				zk_queue_push_back(zhandle, NULL);

			goto out;
		}

		if (ev.join_result == CJ_RES_MASTER_TRANSFER) {
			/* FIXME: This code is tricky, but Sheepdog assumes that */
			/* nr_nodes = 1 when join_result = MASTER_TRANSFER... */
			ev.nr_nodes = 1;
			ev.nodes[0] = this_node;
			zk_queue_push_back(zhandle, &ev);
			zk_queue_pop(zhandle, &ev);
		}

		sprintf(path, MEMBER_ZNODE "/%s", node_to_str(&ev.sender));
		zoo_exists(zhandle, path, 1, NULL);

		zk_hdlrs.join_handler(&ev.sender, ev.nodes, ev.nr_nodes,
				    ev.join_result, ev.buf);
		break;
	case EVENT_LEAVE:
		zk_hdlrs.leave_handler(&ev.sender, ev.nodes, ev.nr_nodes);
		break;
	case EVENT_NOTIFY:
		if (ev.blocked) {
			if (node_cmp(&ev.sender, &this_node) == 0 && !ev.callbacked) {
				queue_work(zk_block_wq, &work);

				ev.callbacked = 1;

				zk_queue_push_back(zhandle, &ev);
			} else
				zk_queue_push_back(zhandle, NULL);

			goto out;
		}

		zk_hdlrs.notify_handler(&ev.sender, ev.buf, ev.buf_len);
		break;
	}
out:
	return 0;
}

struct cluster_driver cdrv_zookeeper = {
	.name       = "zookeeper",

	.init       = zk_init,
	.join       = zk_join,
	.leave      = zk_leave,
	.notify     = zk_notify,
	.dispatch   = zk_dispatch,
};

cdrv_register(cdrv_zookeeper);
