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
#define SESSION_TIMEOUT 30000		/* millisecond */
#define MEMBER_CREATE_TIMEOUT SESSION_TIMEOUT
#define MEMBER_CREATE_INTERVAL 10	/* millisecond */

#define BASE_ZNODE "/sheepdog"
#define QUEUE_ZNODE BASE_ZNODE "/queue"
#define MEMBER_ZNODE BASE_ZNODE "/member"


/* zookeeper API wrapper prototypes */
ZOOAPI int zk_create(zhandle_t *zh, const char *path, const char *value,
	int valuelen, const struct ACL_vector *acl, int flags,
	char *path_buffer, int path_buffer_len);

ZOOAPI int zk_delete(zhandle_t *zh, const char *path, int version);

ZOOAPI int zk_get(zhandle_t *zh, const char *path, int watch, char *buffer,
		   int *buffer_len, struct Stat *stat);

ZOOAPI int zk_set(zhandle_t *zh, const char *path, const char *buffer,
		   int buflen, int version);

ZOOAPI int zk_exists(zhandle_t *zh, const char *path, int watch, struct Stat *stat);

ZOOAPI int zk_get_children(zhandle_t *zh, const char *path, int watch,
			    struct String_vector *strings);

/* iterate child znodes */
#define FOR_EACH_ZNODE(zh, parent, path, strs)			       \
	for (zk_get_children(zh, parent, 1, strs),		       \
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

struct zk_node {
	int joined;
	clientid_t clientid;
	struct sd_node node;
};

struct zk_event {
	enum zk_event_type type;
	struct zk_node sender;

	enum cluster_join_result join_result;

	void (*block_cb)(void *arg);

	int blocked; /* set non-zero when sheep must block this event */
	int callbacked; /* set non-zero if sheep already called block_cb() */

	size_t buf_len;
	uint8_t buf[MAX_EVENT_BUF_SIZE];
};

static int zk_notify_blocked;

/* leave event circular array */
static struct zk_event zk_levents[SD_MAX_NODES];
static int nr_zk_levents;
static unsigned zk_levent_head;
static unsigned zk_levent_tail;

static void *zk_node_btroot;
static struct zk_node *zk_master;
static struct sd_node sd_nodes[SD_MAX_NODES];
static size_t nr_sd_nodes;
static size_t nr_zk_nodes;

/* zookeeper API wrapper */
inline ZOOAPI int zk_create(zhandle_t *zh, const char *path, const char *value,
	int valuelen, const struct ACL_vector *acl, int flags,
	char *path_buffer, int path_buffer_len)
{
	int rc;
	do {
		rc = zoo_create(zh, path, value, valuelen, acl,
				flags, path_buffer, path_buffer_len);
		if (rc != ZOK)
			dprintf("rc:%d\n", rc);
	} while (rc == ZOPERATIONTIMEOUT || rc == ZCONNECTIONLOSS);
	return rc;
}

inline ZOOAPI int zk_delete(zhandle_t *zh, const char *path, int version)
{
	int rc;
	do {
		rc = zoo_delete(zh, path, version);
		if (rc != ZOK)
			dprintf("rc:%d\n", rc);
	} while (rc == ZOPERATIONTIMEOUT || rc == ZCONNECTIONLOSS);
	return rc;
}

inline ZOOAPI int zk_get(zhandle_t *zh, const char *path, int watch, char *buffer,
		   int *buffer_len, struct Stat *stat)
{
	int rc;
	do {
		rc = zoo_get(zh, path, watch, buffer, buffer_len, stat);
		if (rc != ZOK)
			dprintf("rc:%d\n", rc);
	} while (rc == ZOPERATIONTIMEOUT || rc == ZCONNECTIONLOSS);
	return rc;
}

inline ZOOAPI int zk_set(zhandle_t *zh, const char *path, const char *buffer,
		   int buflen, int version)
{
	int rc;
	do {
		rc = zoo_set(zh, path, buffer, buflen, version);
		if (rc != ZOK)
			dprintf("rc:%d\n", rc);
	} while (rc == ZOPERATIONTIMEOUT || rc == ZCONNECTIONLOSS);
	return rc;
}

inline ZOOAPI int zk_exists(zhandle_t *zh, const char *path, int watch, struct Stat *stat)
{
	int rc;
	do {
		rc = zoo_exists(zh, path, watch, stat);
		if (rc != ZOK)
			dprintf("rc:%d\n", rc);
	} while (rc == ZOPERATIONTIMEOUT || rc == ZCONNECTIONLOSS);
	return rc;
}

inline ZOOAPI int zk_get_children(zhandle_t *zh, const char *path, int watch,
			    struct String_vector *strings)
{
	int rc;
	do {
		rc = zoo_get_children(zh, path, watch, strings);
		if (rc != ZOK)
			dprintf("rc:%d\n", rc);
	} while (rc == ZOPERATIONTIMEOUT || rc == ZCONNECTIONLOSS);
	return rc;
}

/* ZooKeeper-based queue */

static int efd;
static int32_t queue_pos;

static int zk_queue_empty(zhandle_t *zh)
{
	int rc;
	char path[256];

	sprintf(path, QUEUE_ZNODE "/%010d", queue_pos);

	rc = zk_exists(zh, path, 1, NULL);
	if (rc == ZOK)
		return 0;

	return 1;
}

static int32_t zk_queue_push(zhandle_t *zh, struct zk_event *ev)
{
	static int first_push = 1;
	int32_t seq;
	int rc, len;
	char path[256], buf[256];
	eventfd_t value = 1;

	len = (char *)(ev->buf) - (char *)ev + ev->buf_len;
	sprintf(path, "%s/", QUEUE_ZNODE);
	rc = zk_create(zh, path, (char *)ev, len,
		&ZOO_OPEN_ACL_UNSAFE, ZOO_SEQUENCE, buf, sizeof(buf));
	dprintf("create path:%s, nr_nodes:%ld, queue_pos:%010d, len:%d, rc:%d\n", buf, nr_zk_nodes, queue_pos, len, rc);
	if (rc != ZOK)
		panic("failed to zk_create path:%s, rc:%d\n", path, rc);

	sscanf(buf, QUEUE_ZNODE "/%d", &seq);
	dprintf("path:%s, seq:%010d\n", buf, seq);

	if (first_push) {
		queue_pos = seq;

		/* manual notify */
		dprintf("write event to efd:%d\n", efd);
		eventfd_write(efd, value);

		first_push = 0;
	}

	return seq;

}

static int zk_queue_push_back(zhandle_t *zh, struct zk_event *ev)
{
	int rc, len;
	char path[256];

	queue_pos--;

	dprintf("queue_pos:%010d\n", queue_pos);

	if (ev) {
		/* update the last popped data */
		len = (char *)(ev->buf) - (char *)ev + ev->buf_len;
		sprintf(path, QUEUE_ZNODE "/%010d", queue_pos);
		rc = zk_set(zh, path, (char *)ev, len, -1);
		dprintf("update path:%s, queue_pos:%010d, len:%d, rc:%d\n", path, queue_pos, len, rc);
		if (rc != ZOK)
			panic("failed to zk_set path:%s, rc:%d\n", path, rc);
	}

	return 0;
}

static int zk_queue_pop(zhandle_t *zh, struct zk_event *ev)
{
	int rc, len;
	int nr_levents;
	char path[256];
	struct zk_event *lev;
	eventfd_t value = 1;

	/* process leave event */
	if (!__sync_add_and_fetch(&zk_notify_blocked, 0)
		&& __sync_add_and_fetch(&nr_zk_levents, 0)) {
		nr_levents = __sync_sub_and_fetch(&nr_zk_levents, 1) + 1;
		dprintf("nr_zk_levents:%d, head:%u\n", nr_levents, zk_levent_head);

		lev = &zk_levents[zk_levent_head%SD_MAX_NODES];

		/* if the node pointed to by queue_pos was send by this leaver,
		 * and it have blocked whole cluster, we should ignore it. */
		len = sizeof(*ev);
		sprintf(path, QUEUE_ZNODE "/%010d", queue_pos);
		rc = zk_get(zh, path, 1, (char *)ev, &len, NULL);
		if (rc == ZOK && node_cmp(&ev->sender.node, &lev->sender.node) == 0 && ev->blocked) {
			dprintf("this queue_pos:%010d have blocked whole cluster, ignore it\n", queue_pos);
			queue_pos++;

			/* watch next data */
			sprintf(path, QUEUE_ZNODE "/%010d", queue_pos);
			rc = zk_exists(zh, path, 1, NULL);
			dprintf("watch path:%s, exists:%d\n", path, (rc == ZOK));
			if (rc == ZOK) {
				/* we lost this message, manual notify */
				dprintf("write event to efd:%d\n", efd);
				eventfd_write(efd, value);
			}
		}

		memcpy(ev, lev, sizeof(*ev));
		zk_levent_head++;

		if (__sync_add_and_fetch(&nr_zk_levents, 0) || rc == ZOK) {
			/* we have pending leave events
			 * or queue nodes, manual notify */
			dprintf("write event to efd:%d\n", efd);
			eventfd_write(efd, value);
		}

		return 0;
	}

	if (zk_queue_empty(zh))
		return -1;

	len = sizeof(*ev);
	sprintf(path, QUEUE_ZNODE "/%010d", queue_pos);
	rc = zk_get(zh, path, 1, (char *)ev, &len, NULL);
	dprintf("read path:%s, nr_nodes:%ld, type:%d, len:%d, rc:%d\n", path, nr_zk_nodes, ev->type, len, rc);
	if (rc != ZOK)
		panic("failed to zk_set path:%s, rc:%d\n", path, rc);

	queue_pos++;

	/* this event will be pushed back to the queue,
	 * we just wait for the arrival of its updated,
	 * not need to watch next data. */
	if (ev->blocked)
		goto out;

	/* watch next data */
	sprintf(path, QUEUE_ZNODE "/%010d", queue_pos);
	rc = zk_exists(zh, path, 1, NULL);
	dprintf("watch path:%s, exists:%d\n", path, (rc == ZOK));
	if (rc == ZOK) {
		/* we lost this message, manual notify */
		dprintf("write event to efd:%d\n", efd);
		eventfd_write(efd, value);
	}

out:
	return 0;
}

static int zk_member_empty(zhandle_t *zh)
{
	int rc;
	struct String_vector strs;

	rc = zk_get_children(zh, MEMBER_ZNODE, 1, &strs);
	if (rc != ZOK)
		panic("failed to zk_get_children path:%s, rc:%d\n", MEMBER_ZNODE, rc);

	return (strs.count == 0);
}

static inline int zk_node_cmp(const void *a, const void *b)
{
	const struct zk_node *znode1 = a;
	const struct zk_node *znode2 = b;
	return node_cmp(&znode1->node, &znode2->node);
}

static void node_btree_add(void **btroot, struct zk_node *znode)
{
	struct zk_node *n, **p;

	n = (struct zk_node *)malloc(sizeof(struct zk_node));
	if (n == NULL)
		panic("malloc, oom\n");

	*n = *znode;

	p = (struct zk_node **)tsearch((void *)n, btroot, zk_node_cmp);
	if (p == NULL)
		panic("tsearch, oom\n");
	else if (*p != n) {
		**p = *n;
		free(n);
	}
	nr_zk_nodes++;
}

static inline void node_btree_del(void **btroot, struct zk_node *znode)
{
	tdelete((void *)znode, btroot, zk_node_cmp);
	free(znode);
	nr_zk_nodes--;
}

static inline void node_btree_clear(void **btroot)
{
	tdestroy(*btroot, free);
	*btroot = NULL;
}

static struct zk_node *node_btree_find(void **btroot, struct zk_node *znode)
{
	struct zk_node **p;

	p = (struct zk_node **)tfind((void *)znode, btroot, zk_node_cmp);
	if (p)
		return *p;

	return NULL;
}

static void node_btree_build_list_fn(const void *nodep,
		const VISIT which, const int depth)
{
	struct zk_node *znode;

	switch (which) {
	case preorder:
		break;
	case postorder:
	case leaf:
		znode = *(struct zk_node **) nodep;
		sd_nodes[nr_sd_nodes++] = znode->node;
		break;
	case endorder:
		break;
	}
}

static inline void build_node_list(void *btroot)
{
	nr_sd_nodes = 0;
	twalk(btroot, node_btree_build_list_fn);
	assert(nr_sd_nodes == nr_zk_nodes);
	dprintf("nr_sd_nodes:%lu\n", nr_sd_nodes);
}

static void node_btree_find_master_fn(const void *nodep,
		const VISIT which, const int depth)
{
	switch (which) {
	case preorder:
		break;
	case postorder:
	case leaf:
		if (zk_master)
			break;
		zk_master = *(struct zk_node **) nodep;
		dprintf("master:%s\n", node_to_str(&zk_master->node));
		break;
	case endorder:
		break;
	}
}

static int is_master(zhandle_t *zh, struct zk_node *znode)
{
	zk_master = NULL;

	if (!zk_node_btroot) {
		if (zk_member_empty(zh))
			return 1;
		else
			return 0;
	}

	twalk(zk_node_btroot, node_btree_find_master_fn);
	if (node_cmp(&zk_master->node, &znode->node) == 0)
		return 1;

	return 0;
}

static void zk_queue_init(zhandle_t *zh)
{
	zk_create(zh, BASE_ZNODE, "", 0, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
	zk_create(zh, QUEUE_ZNODE, "", 0, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
	zk_create(zh, MEMBER_ZNODE, "", 0, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
}

static void zk_member_init(zhandle_t *zh)
{
	static int finished;
	int rc, len;
	struct String_vector strs;
	struct zk_node znode;
	char path[256];

	if (finished)
		return;

	finished = 1;

	if (!zk_member_empty(zh)) {
		FOR_EACH_ZNODE(zh, MEMBER_ZNODE, path, &strs) {
			len = sizeof(znode);
			rc = zk_get(zh, path, 1, (char *)&znode, &len, NULL);
			if (rc != ZOK)
				continue;

			switch (rc) {
			case ZOK:
				node_btree_add(&zk_node_btroot, &znode);
			case ZNONODE:
				break;
			default:
				panic("failed to zk_get path:%s, rc:%d\n", path, rc);
			}
		}
	}
	dprintf("nr_nodes:%ld\n", nr_zk_nodes);
}


/* ZooKeeper driver APIs */

static zhandle_t *zhandle;

static struct work_queue *zk_block_wq;

static struct zk_node this_node;

static int add_event(zhandle_t *zh, enum zk_event_type type,
		     struct zk_node *znode, void *buf,
		     size_t buf_len, void (*block_cb)(void *arg))
{
	int nr_levents;
	struct zk_event ev, *lev;
	eventfd_t value = 1;

	ev.type = type;
	ev.sender = *znode;
	ev.buf_len = buf_len;
	ev.callbacked = 0;
	ev.blocked = 0;
	if (buf)
		memcpy(ev.buf, buf, buf_len);

	switch (type) {
	case EVENT_JOIN:
		ev.blocked = 1;
		break;
	case EVENT_LEAVE:
		lev = &zk_levents[zk_levent_tail%SD_MAX_NODES];

		memcpy(lev, &ev, sizeof(ev));

		nr_levents = __sync_add_and_fetch(&nr_zk_levents, 1);
		dprintf("nr_zk_levents:%d, tail:%u\n", nr_levents, zk_levent_tail);

		zk_levent_tail++;

		/* manual notify */
		dprintf("write event to efd:%d\n", efd);
		eventfd_write(efd, value);
		goto out;
	case EVENT_NOTIFY:
		ev.blocked = !!block_cb;
		ev.block_cb = block_cb;
		break;
	}

	zk_queue_push(zh, &ev);
out:
	return 0;
}

static void watcher(zhandle_t *zh, int type, int state, const char *path, void* ctx)
{
	eventfd_t value = 1;
	const clientid_t *cid;
	char str[256], *p;
	int ret, rc;
	struct zk_node znode;

	dprintf("path:%s, type:%d\n", path, type);

	if (type == -1) {
		cid = zoo_client_id(zh);
		assert(cid != NULL);
		dprintf("session change, clientid:%ld\n", cid->client_id);
	}

	/* discard useless event */
	if (type < 0 || type == ZOO_CHILD_EVENT)
		return;

	if (type == ZOO_CREATED_EVENT || type == ZOO_CHANGED_EVENT) {
		ret = sscanf(path, MEMBER_ZNODE "/%s", str);
		if (ret == 1) {
			rc = zk_exists(zh, path, 1, NULL);
			dprintf("watch path:%s, exists:%d\n", path, (rc == ZOK));
		}
	}

	if (type == ZOO_DELETED_EVENT) {
		ret = sscanf(path, MEMBER_ZNODE "/%s", str);
		if (ret != 1)
			return;
		p = strrchr(path, '/');
		p++;

		str_to_node(p, &znode.node);
		dprintf("zk_nodes leave:%s\n", node_to_str(&znode.node));

		add_event(zh, EVENT_LEAVE, &znode, NULL, 0, NULL);
		return;
	}

	dprintf("write event to efd:%d\n", efd);
	eventfd_write(efd, value);
}

static int get_addr(uint8_t *bytes)
{
	int ret;
	char name[INET6_ADDRSTRLEN];
	struct addrinfo hints, *res, *res0;

	gethostname(name, sizeof(name));

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_INET;
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

static int zk_init(const char *option, uint8_t *myaddr)
{
	if (!option) {
		eprintf("specify comma separated host:port pairs, each corresponding to a zk server.\n");
		eprintf("e.g. sheep /store -c zookeeper:127.0.0.1:3000,127.0.0.1:3001,127.0.0.1:3002\n");
		return -1;
	}

	zhandle = zookeeper_init(option, watcher, SESSION_TIMEOUT, 0, NULL, 0);
	if (!zhandle) {
		eprintf("failed to connect to zk server %s\n", option);
		return -1;
	}
	dprintf("request session timeout:%dms, negotiated session timeout:%dms\n",
			SESSION_TIMEOUT, zoo_recv_timeout(zhandle));

	if (get_addr(myaddr) < 0)
		return -1;

	zk_queue_init(zhandle);

	efd = eventfd(0, EFD_NONBLOCK);
	if (efd < 0) {
		eprintf("failed to create an event fd: %m\n");
		return -1;
	}

	zk_block_wq = init_work_queue(1);
	if (!zk_block_wq) {
		eprintf("failed to create zookeeper workqueue: %m\n");
		return -1;
	}

	return efd;
}

static int zk_join(struct sd_node *myself,
		   void *opaque, size_t opaque_len)
{
	int rc;
	char path[256];
	const clientid_t *cid;

	this_node.node = *myself;

	sprintf(path, MEMBER_ZNODE "/%s", node_to_str(myself));
	rc = zk_exists(zhandle, path, 1, NULL);
	if (rc == ZOK)
		panic("previous zookeeper session exist, shutdown\n");

	this_node.joined = 0;
	cid = zoo_client_id(zhandle);
	assert(cid != NULL);
	this_node.clientid = *cid;

	dprintf("clientid:%ld\n", cid->client_id);

	rc = add_event(zhandle, EVENT_JOIN, &this_node, opaque, opaque_len, NULL);

	return rc;
}

static int zk_leave(void)
{
	char path[256];
	sprintf(path, MEMBER_ZNODE "/%s", node_to_str(&this_node.node));
	dprintf("try to delete member path:%s\n", path);
	return zk_delete(zhandle, path, -1);
}

static int zk_notify(void *msg, size_t msg_len, void (*block_cb)(void *arg))
{
	return add_event(zhandle, EVENT_NOTIFY, &this_node, msg, msg_len, block_cb);
}

static void zk_block(struct work *work)
{
	int rc;
	struct zk_event ev;
	eventfd_t value = 1;

	rc = zk_queue_pop(zhandle, &ev);
	assert(rc == 0);

	ev.block_cb(ev.buf);
	ev.blocked = 0;

	zk_queue_push_back(zhandle, &ev);

	__sync_sub_and_fetch(&zk_notify_blocked, 1);

	/* this notify is necessary */
	dprintf("write event to efd:%d\n", efd);
	eventfd_write(efd, value);
}

static void zk_block_done(struct work *work)
{
}

static int zk_dispatch(void)
{
	int ret, rc, retry;
	char path[256];
	eventfd_t value;
	struct zk_event ev;
	struct zk_node *n;
	enum cluster_join_result res;
	static struct work work = {
		.fn = zk_block,
		.done = zk_block_done,
	};

	dprintf("read event\n");
	ret = eventfd_read(efd, &value);
	if (ret < 0)
		return 0;

	if (__sync_add_and_fetch(&zk_notify_blocked, 0))
		return 0;

	ret = zk_queue_pop(zhandle, &ev);
	if (ret < 0)
		goto out;

	switch (ev.type) {
	case EVENT_JOIN:
		dprintf("JOIN EVENT, blocked:%d\n", ev.blocked);
		if (ev.blocked) {
			dprintf("one sheep joined[up], nr_nodes:%ld, sender:%s, joined:%d\n",
					nr_zk_nodes, node_to_str(&ev.sender.node), ev.sender.joined);
			if (is_master(zhandle, &this_node)) {
				res = sd_check_join_cb(&ev.sender.node, ev.buf);
				ev.join_result = res;
				ev.blocked = 0;
				ev.sender.joined = 1;

				dprintf("I'm master, push back join event\n");
				zk_queue_push_back(zhandle, &ev);

				if (res == CJ_RES_MASTER_TRANSFER) {
					eprintf("failed to join sheepdog cluster: "
						"please retry when master is up\n");
					exit(1);
				}
			} else
				zk_queue_push_back(zhandle, NULL);

			goto out;
		} else if (is_master(zhandle, &this_node)
			&& node_cmp(&ev.sender.node, &this_node.node) != 0) {
			/* wait util member have been created */
			sprintf(path, MEMBER_ZNODE "/%s", node_to_str(&ev.sender.node));
			retry = MEMBER_CREATE_TIMEOUT/MEMBER_CREATE_INTERVAL;
			while (retry && zk_exists(zhandle, path, 1, NULL) == ZNONODE) {
				usleep(MEMBER_CREATE_INTERVAL*1000);
				retry--;
			}
			if (retry <= 0) {
				dprintf("Sender:%s failed to create member, ignore it\n",
						node_to_str(&ev.sender.node));
				goto out;
			}
		}

		if (node_cmp(&ev.sender.node, &this_node.node) == 0)
			zk_member_init(zhandle);

		if (ev.join_result == CJ_RES_MASTER_TRANSFER) {
			/* FIXME: This code is tricky, but Sheepdog assumes that
			 * nr_nodes = 1 when join_result = MASTER_TRANSFER... */
			node_btree_clear(&zk_node_btroot);
			node_btree_add(&zk_node_btroot, &this_node);

			zk_queue_push_back(zhandle, &ev);
			zk_queue_pop(zhandle, &ev);
		}

		node_btree_add(&zk_node_btroot, &ev.sender);
		dprintf("one sheep joined[down], nr_nodes:%ld, sender:%s, joined:%d\n",
				nr_zk_nodes, node_to_str(&ev.sender.node), ev.sender.joined);

		if (ev.join_result == CJ_RES_SUCCESS) {
			sprintf(path, MEMBER_ZNODE "/%s", node_to_str(&ev.sender.node));
			if (node_cmp(&ev.sender.node, &this_node.node) == 0) {
				dprintf("create path:%s\n", path);
				rc = zk_create(zhandle, path, (char *)&ev.sender, sizeof(ev.sender),
					&ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL, NULL, 0);
				if (rc != ZOK)
					panic("failed to create an ephemeral znode, rc:%d\n", rc);
			} else {
				rc = zk_exists(zhandle, path, 1, NULL);
				dprintf("watch path:%s, exists:%d\n", path, (rc == ZOK));
			}
		}

		build_node_list(zk_node_btroot);
		sd_join_handler(&ev.sender.node, sd_nodes, nr_sd_nodes,
				    ev.join_result, ev.buf);
		break;
	case EVENT_LEAVE:
		dprintf("LEAVE EVENT, blocked:%d\n", ev.blocked);
		n = node_btree_find(&zk_node_btroot, &ev.sender);
		if (!n) {
			dprintf("can't find this leave node:%s, ignore it.\n", node_to_str(&ev.sender.node));
			goto out;
		}

		node_btree_del(&zk_node_btroot, n);
		dprintf("one sheep left, nr_nodes:%ld\n", nr_zk_nodes);

		build_node_list(zk_node_btroot);
		sd_leave_handler(&ev.sender.node, sd_nodes, nr_sd_nodes);
		break;
	case EVENT_NOTIFY:
		dprintf("NOTIFY, blocked:%d\n", ev.blocked);
		if (ev.blocked) {
			if (node_cmp(&ev.sender.node, &this_node.node) == 0 && !ev.callbacked) {
				ev.callbacked = 1;

				__sync_add_and_fetch(&zk_notify_blocked, 1);

				zk_queue_push_back(zhandle, &ev);

				queue_work(zk_block_wq, &work);
			} else
				zk_queue_push_back(zhandle, NULL);

			goto out;
		}

		sd_notify_handler(&ev.sender.node, ev.buf, ev.buf_len);
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
