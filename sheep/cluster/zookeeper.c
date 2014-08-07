/*
 * Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
 *
 * Copyright (C) 2012 Taobao Inc.
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
#include <zookeeper/zookeeper.h>
#include <pthread.h>
#include <semaphore.h>

#include "cluster.h"
#include "config.h"
#include "event.h"
#include "work.h"
#include "util.h"
#include "rbtree.h"

#define SESSION_TIMEOUT 30000		/* millisecond */

#define BASE_ZNODE "/sheepdog"
#define QUEUE_ZNODE BASE_ZNODE "/queue"
#define MEMBER_ZNODE BASE_ZNODE "/member"
#define MASTER_ZNODE BASE_ZNODE "/master"
#define LOCK_ZNODE BASE_ZNODE "/lock"

static int zk_timeout = SESSION_TIMEOUT;
static int my_master_seq;

/* structure for distributed lock */
struct cluster_lock {
	struct hlist_node hnode;
	/* id is passed by users to represent a lock handle */
	uint64_t id;
	/* referenced by different threads in one sheepdog daemon */
	uint64_t ref;
	/* wait for the release of id by other lock owner */
	sem_t wait_wakeup;
	/* lock for different threads of the same node on the same id */
	struct sd_mutex id_lock;
	char lock_path[MAX_NODE_STR_LEN];
};

#define WAIT_TIME	1		/* second */

#define HASH_BUCKET_NR	1021
static struct hlist_head *cluster_locks_table;
static struct sd_mutex table_locks[HASH_BUCKET_NR];

/*
 * Wait a while when create, delete or get_children fail on
 * zookeeper lock so it will not print too much loop log
 */
static void zk_wait(void)
{
	sleep(WAIT_TIME);
}

/* iterate child znodes */
#define FOR_EACH_ZNODE(parent, path, strs)			       \
	for ((strs)->data += (strs)->count;			       \
	     (strs)->count-- ?					       \
		     snprintf(path, sizeof(path), "%s/%s", parent,     \
			      *--(strs)->data) : (free((strs)->data), 0); \
	     free(*(strs)->data))

enum zk_event_type {
	EVENT_JOIN = 1,
	EVENT_ACCEPT,
	EVENT_LEAVE,
	EVENT_BLOCK,
	EVENT_UNBLOCK,
	EVENT_NOTIFY,
	EVENT_UPDATE_NODE,
};

struct zk_node {
	struct list_node list;
	struct rb_node rb;
	struct sd_node node;
	bool callbacked;
	bool gone;
};

#define ZK_MAX_BUF_SIZE (1*1024*1024) /* 1M */

struct zk_event {
	uint64_t id;
	enum zk_event_type type;
	struct zk_node sender;
	size_t msg_len;
	size_t nr_nodes;
	size_t buf_len;
	uint8_t buf[ZK_MAX_BUF_SIZE];
};

static struct rb_root sd_node_root = RB_ROOT;
static size_t nr_sd_nodes;
static struct rb_root zk_node_root = RB_ROOT;
static struct sd_rw_lock zk_tree_lock = SD_RW_LOCK_INITIALIZER;
static struct sd_rw_lock zk_compete_master_lock = SD_RW_LOCK_INITIALIZER;
static LIST_HEAD(zk_block_list);
static uatomic_bool is_master;
static uatomic_bool stop;
static bool joined;
static bool first_push = true;

static void zk_compete_master(void);

static int zk_node_cmp(const struct zk_node *a, const struct zk_node *b)
{
	return node_id_cmp(&a->node.nid, &b->node.nid);
}

static struct zk_node *zk_tree_insert(struct zk_node *new)
{
	return rb_insert(&zk_node_root, new, rb, zk_node_cmp);
}

static struct zk_node *zk_tree_search_nolock(const struct node_id *nid)
{
	struct zk_node key = { .node.nid = *nid };

	return rb_search(&zk_node_root, &key, rb, zk_node_cmp);
}

static inline struct zk_node *zk_tree_search(const struct node_id *nid)
{
	struct zk_node *n;

	sd_read_lock(&zk_tree_lock);
	n = zk_tree_search_nolock(nid);
	sd_rw_unlock(&zk_tree_lock);
	return n;
}

/* zookeeper API wrapper */
static zhandle_t *zhandle;
static struct zk_node this_node;

#define CHECK_ZK_RC(rc, path)						\
	switch (rc) {							\
	case ZNONODE:							\
	case ZNODEEXISTS:						\
	case ZNOTEMPTY:							\
		break;							\
	case ZINVALIDSTATE:						\
	case ZSESSIONEXPIRED:						\
	case ZOPERATIONTIMEOUT:						\
	case ZCONNECTIONLOSS:						\
		sd_err("failed, path:%s, %s", path, zerror(rc));	\
	case ZOK:							\
		break;							\
	case ZNOCHILDRENFOREPHEMERALS:					\
		/*							\
		 * Because code has guaranteed that parent nodes are	\
		 * always non-ephemeral, this could happen only when	\
		 * sheep joins a cluster in an incompatible version.	\
		 */							\
		sd_err("incompatible version of sheep %s",		\
		       PACKAGE_VERSION);				\
	default:							\
		panic("failed, path:%s, %s", path, zerror(rc));		\
	}
#define RETURN_IF_ERROR(stmt, fmt, ...)					\
	do {								\
		int __rc = stmt;					\
		if (__rc != ZOK) {					\
			sd_err("failed, " fmt ", %s",			\
			       ##__VA_ARGS__, zerror(__rc));		\
			return __rc;					\
		}							\
	} while (0)
#define RETURN_VOID_IF_ERROR(stmt, fmt, ...)				\
	do {								\
		int __rc = stmt;					\
		if (__rc != ZOK) {					\
			sd_err("failed, " fmt ", %s",			\
			       ##__VA_ARGS__, zerror(__rc));		\
			return;						\
		}							\
	} while (0)

static inline ZOOAPI int zk_delete_node(const char *path, int version)
{
	int rc;
	do {
		rc = zoo_delete(zhandle, path, version);
	} while (rc == ZOPERATIONTIMEOUT || rc == ZCONNECTIONLOSS);
	CHECK_ZK_RC(rc, path);

	return rc;
}

static inline ZOOAPI int
zk_init_node(const char *path)
{
	int rc;
	do {
		rc = zoo_create(zhandle, path, "", 0, &ZOO_OPEN_ACL_UNSAFE, 0,
				NULL, 0);
	} while (rc == ZOPERATIONTIMEOUT || rc == ZCONNECTIONLOSS);
	CHECK_ZK_RC(rc, path);

	if (rc == ZNODEEXISTS)
		rc = ZOK;
	return rc;
}

static inline ZOOAPI int
zk_create_node(const char *path, const char *value, int valuelen,
	       const struct ACL_vector *acl, int flags, char *path_buffer,
	       int path_buffer_len)
{
	int rc;
	do {
		rc = zoo_create(zhandle, path, value, valuelen, acl,
				flags, path_buffer, path_buffer_len);
	} while (rc == ZOPERATIONTIMEOUT || rc == ZCONNECTIONLOSS);
	CHECK_ZK_RC(rc, path);

	return rc;
}

/*
 * Create a znode after adding a unique monotonically increasing sequence number
 * to the path name.
 *
 * Note that the caller has to retry this function when this returns
 * ZOPERATIONTIMEOUT or ZCONNECTIONLOSS and the znode is not created.
 */
static inline ZOOAPI int
zk_create_seq_node(const char *path, const char *value, int valuelen,
		   char *path_buffer, int path_buffer_len, bool ephemeral)
{
	int rc;
	int flags = ZOO_SEQUENCE;
	if (ephemeral)
		flags = flags | ZOO_EPHEMERAL;
	rc = zoo_create(zhandle, path, value, valuelen, &ZOO_OPEN_ACL_UNSAFE,
			flags, path_buffer, path_buffer_len);
	CHECK_ZK_RC(rc, path);

	return rc;
}

static inline ZOOAPI int zk_get_data(const char *path, void *buffer,
				     int *buffer_len)
{
	int rc;
	do {
		rc = zoo_get(zhandle, path, 1, (char *)buffer,
			     buffer_len, NULL);
	} while (rc == ZOPERATIONTIMEOUT || rc == ZCONNECTIONLOSS);
	CHECK_ZK_RC(rc, path);

	return rc;
}

static inline ZOOAPI int
zk_set_data(const char *path, const char *buffer, int buflen, int version)
{
	int rc;
	do {
		rc = zoo_set(zhandle, path, buffer, buflen, version);
	} while (rc == ZOPERATIONTIMEOUT || rc == ZCONNECTIONLOSS);
	CHECK_ZK_RC(rc, path);

	return rc;
}

static inline ZOOAPI int zk_node_exists(const char *path)
{
	int rc;
	do {
		rc = zoo_exists(zhandle, path, 1, NULL);
	} while (rc == ZOPERATIONTIMEOUT || rc == ZCONNECTIONLOSS);
	CHECK_ZK_RC(rc, path);

	return rc;
}

static inline ZOOAPI int zk_get_children(const char *path,
					 struct String_vector *strings)
{
	int rc;
	do {
		rc = zoo_get_children(zhandle, path, 1, strings);
	} while (rc == ZOPERATIONTIMEOUT || rc == ZCONNECTIONLOSS);
	CHECK_ZK_RC(rc, path);

	return rc;
}

/*
 * All the operations of the lock table is protected by
 * cluster_lock->id_lock so we don't need to add lock here
 */

static int lock_table_lookup_wakeup(uint64_t lock_id)
{
	uint64_t hval = sd_hash_64(lock_id) % HASH_BUCKET_NR;
	int res = -1;
	struct hlist_node *iter;
	struct cluster_lock *lock;

	sd_mutex_lock(table_locks + hval);
	hlist_for_each_entry(lock, iter, cluster_locks_table + hval, hnode) {
		if (lock->id == lock_id) {
			sem_post(&lock->wait_wakeup);
			res = 0;
			break;
		}
	}
	sd_mutex_unlock(table_locks + hval);
	return res;
}

static struct cluster_lock *lock_table_lookup_acquire(uint64_t lock_id)
{
	uint64_t hval = sd_hash_64(lock_id) % HASH_BUCKET_NR;
	int rc;
	struct hlist_node *iter;
	struct cluster_lock *lock, *ret_lock = NULL;
	char path[MAX_NODE_STR_LEN];

	sd_mutex_lock(table_locks + hval);
	hlist_for_each_entry(lock, iter, cluster_locks_table + hval, hnode) {
		if (lock->id == lock_id) {
			ret_lock = lock;
			ret_lock->ref++;
			break;
		}
	}

	if (!ret_lock) {
		/* create lock and add it to hash table */
		ret_lock = xzalloc(sizeof(*ret_lock));
		ret_lock->id = lock_id;
		ret_lock->ref = 1;
		snprintf(path, MAX_NODE_STR_LEN, LOCK_ZNODE "/%"PRIu64,
			 ret_lock->id);
		rc = zk_init_node(path);
		if (rc)
			panic("Failed to init node %s", path);

		sem_init(&ret_lock->wait_wakeup, 0, 1);
		sd_init_mutex(&ret_lock->id_lock);

		hlist_add_head(&(ret_lock->hnode), cluster_locks_table + hval);
	}
	sd_mutex_unlock(table_locks + hval);

	/*
	 * if many threads use locks with same id, we should use
	 * ->id_lock to avoid the only zookeeper handler to
	 * create many seq-ephemeral files.
	 */
	sd_mutex_lock(&ret_lock->id_lock);
	return ret_lock;
}

static void lock_table_lookup_release(uint64_t lock_id)
{
	uint64_t hval = sd_hash_64(lock_id) % HASH_BUCKET_NR;
	int rc;
	struct hlist_node *iter;
	struct cluster_lock *lock;
	char path[MAX_NODE_STR_LEN];

	sd_mutex_lock(table_locks + hval);
	hlist_for_each_entry(lock, iter, cluster_locks_table + hval, hnode) {
		if (lock->id != lock_id)
			continue;
		while (true) {
			rc = zk_delete_node(lock->lock_path, -1);
			if (rc == ZOK || rc == ZNONODE) {
				sd_debug("delete path: %s ok", lock->lock_path);
				break;
			}
			sd_err("Failed to delete path: %s %s", lock->lock_path,
			       zerror(rc));
			zk_wait();
		}
		lock->lock_path[0] = '\0';
		sd_mutex_unlock(&lock->id_lock);
		lock->ref--;
		if (!lock->ref) {
			hlist_del(iter);
			/* free all resource used by this lock */
			sd_destroy_mutex(&lock->id_lock);
			sem_destroy(&lock->wait_wakeup);
			snprintf(path, MAX_NODE_STR_LEN, LOCK_ZNODE "/%"PRIu64,
				 lock->id);
			/*
			 * If deletion of directory 'lock_id' fail, we only get
			 * a * empty directory in zookeeper. That's unharmful
			 * so we don't need to retry it.
			 */
			rc = zk_delete_node(path, -1);
			if (rc != ZOK)
				sd_err("Failed to delete path: %s %s", path,
				      zerror(rc));
			free(lock);
		}
		break;
	}
	sd_mutex_unlock(table_locks + hval);
}

/*
 * If this node leave the cluster, we need to delete the znode which created
 * for distributed lock. Otherwise, the lock will never be released.
 */
static void lock_table_remove_znodes(void)
{
	uint64_t hval;
	int rc;
	struct hlist_node *iter;
	struct cluster_lock *lock;

	for (hval = 0; hval < HASH_BUCKET_NR; hval++) {
		sd_mutex_lock(table_locks + hval);
		hlist_for_each_entry(lock, iter, cluster_locks_table + hval,
				     hnode) {
			while (true) {
				rc = zk_delete_node(lock->lock_path, -1);
				if (rc == ZOK || rc == ZNONODE) {
					sd_debug("delete path: %s ok",
						 lock->lock_path);
					break;
				}
				sd_err("Failed to delete path: %s %s",
				       lock->lock_path,
				       zerror(rc));
				zk_wait();
			}
		}
		sd_mutex_unlock(table_locks + hval);
	}
}

/* ZooKeeper-based queue give us an totally ordered events */
static int efd;
static int32_t queue_pos;

static int zk_queue_peek(bool *peek)
{
	int rc;
	char path[MAX_NODE_STR_LEN];

	snprintf(path, sizeof(path), QUEUE_ZNODE "/%010"PRId32, queue_pos);

	rc = zk_node_exists(path);
	switch (rc) {
	case ZOK:
		*peek = true;
		return ZOK;
	case ZNONODE:
		*peek = false;
		return ZOK;
	default:
		sd_err("failed, %s", zerror(rc));
		return rc;
	}
}

/* return true if there is a node with 'id' in the queue. */
static int zk_find_seq_node(uint64_t id, char *seq_path, int seq_path_len,
			    bool *found)
{
	int rc, len;

	for (int seq = queue_pos; ; seq++) {
		struct zk_event ev;

		snprintf(seq_path, seq_path_len, QUEUE_ZNODE"/%010"PRId32, seq);
		len = offsetof(typeof(ev), id) + sizeof(ev.id);
		rc = zk_get_data(seq_path, &ev, &len);
		switch (rc) {
		case ZOK:
			if (ev.id == id) {
				sd_debug("id %" PRIx64 " is found in %s", id,
					 seq_path);
				*found = true;
				return ZOK;
			}
			break;
		case ZNONODE:
			sd_debug("id %"PRIx64" is not found", id);
			*found = false;
			return ZOK;
		default:
			sd_err("failed, %s", zerror(rc));
			return rc;
		}
	}
}

static int zk_queue_push(struct zk_event *ev)
{
	int rc, len;
	char path[MAX_NODE_STR_LEN], buf[MAX_NODE_STR_LEN];
	bool found;

	len = offsetof(typeof(*ev), buf) + ev->buf_len;
	snprintf(path, sizeof(path), "%s/", QUEUE_ZNODE);
again:
	rc = zk_create_seq_node(path, (char *)ev, len, buf, sizeof(buf), false);
	switch (rc) {
	case ZOK:
		/* Success */
		break;
	case ZOPERATIONTIMEOUT:
	case ZCONNECTIONLOSS:
		if (zk_find_seq_node(ev->id, buf, sizeof(buf), &found) == ZOK) {
			if (found)
				break;
			else
				/* retry if seq_node was not created */
				goto again;
		}
		/* fall through */
	default:
		sd_err("failed, path:%s, %s", path, zerror(rc));
		return rc;
	}
	if (first_push) {
		int32_t seq;

		sscanf(buf, QUEUE_ZNODE "/%"PRId32, &seq);
		queue_pos = seq;
		eventfd_xwrite(efd, 1);
		first_push = false;
	}

	sd_debug("create path:%s, queue_pos:%010" PRId32 ", len:%d", buf,
		 queue_pos, len);
	return ZOK;
}

static inline void *zk_event_sd_nodes(struct zk_event *ev)
{
	return (char *)ev->buf + ev->msg_len;
}

/* Change the join event in place and piggyback the nodes information. */
static int push_join_response(struct zk_event *ev)
{
	char path[MAX_NODE_STR_LEN];
	struct sd_node *n, *np = zk_event_sd_nodes(ev);
	int len;

	ev->type = EVENT_ACCEPT;
	ev->nr_nodes = nr_sd_nodes;
	rb_for_each_entry(n, &sd_node_root, rb) {
		memcpy(np++, n, sizeof(struct sd_node));
	}
	queue_pos--;

	len = offsetof(typeof(*ev), buf) + ev->buf_len;
	snprintf(path, sizeof(path), QUEUE_ZNODE "/%010"PRId32, queue_pos);

	RETURN_IF_ERROR(zk_set_data(path, (char *)ev, len, -1), "");
	sd_debug("update path:%s, queue_pos:%010" PRId32 ", len:%d", path,
		 queue_pos, len);
	return ZOK;
}

static int zk_queue_pop_advance(struct zk_event *ev)
{
	int len;
	char path[MAX_NODE_STR_LEN];

	len = sizeof(*ev);
	snprintf(path, sizeof(path), QUEUE_ZNODE "/%010"PRId32, queue_pos);

	RETURN_IF_ERROR(zk_get_data(path, ev, &len), "path %s", path);
	sd_debug("%s, type:%d, len:%d, pos:%" PRId32, path, ev->type, len,
		 queue_pos);
	queue_pos++;
	return ZOK;
}

static inline void zk_tree_add(struct zk_node *node)
{
	struct zk_node *zk = xzalloc(sizeof(*zk));
	*zk = *node;
	sd_write_lock(&zk_tree_lock);
	if (zk_tree_insert(zk)) {
		free(zk);
		goto out;
	}
	/*
	 * Even node list will be built later, we need this because in master
	 * transfer case, we need this information to destroy the tree.
	 */
	rb_insert(&sd_node_root, &zk->node, rb, node_cmp);
	nr_sd_nodes++;
out:
	sd_rw_unlock(&zk_tree_lock);
}

static inline void zk_tree_del(struct zk_node *node)
{
	sd_write_lock(&zk_tree_lock);
	rb_erase(&node->rb, &zk_node_root);
	free(node);
	sd_rw_unlock(&zk_tree_lock);
}

static inline void zk_tree_destroy(void)
{
	sd_write_lock(&zk_tree_lock);
	rb_destroy(&zk_node_root, struct zk_node, rb);
	sd_rw_unlock(&zk_tree_lock);
}

static inline void build_node_list(void)
{
	struct zk_node *zk;

	nr_sd_nodes = 0;
	INIT_RB_ROOT(&sd_node_root);
	rb_for_each_entry(zk, &zk_node_root, rb) {
		rb_insert(&sd_node_root, &zk->node, rb, node_cmp);
		nr_sd_nodes++;
	}

	sd_debug("nr_sd_nodes:%zu", nr_sd_nodes);
}

static int zk_queue_init(void)
{
	RETURN_IF_ERROR(zk_init_node(BASE_ZNODE), "path %s", BASE_ZNODE);
	RETURN_IF_ERROR(zk_init_node(MASTER_ZNODE), "path %s", MASTER_ZNODE);
	RETURN_IF_ERROR(zk_init_node(QUEUE_ZNODE), "path %s", QUEUE_ZNODE);
	RETURN_IF_ERROR(zk_init_node(MEMBER_ZNODE), "path %s", MEMBER_ZNODE);
	return ZOK;
}

/* Calculate a unique 64 bit integer from this_node and the sequence number. */
static uint64_t get_uniq_id(void)
{
	static int seq;
	struct {
		uint64_t n;
		struct zk_node node;
	} id = {
		.n = uatomic_add_return(&seq, 1),
		.node = this_node,
	};

	return sd_hash(&id, sizeof(id));
}

static int add_event(enum zk_event_type type, struct zk_node *znode, void *buf,
		     size_t buf_len)
{
	struct zk_event ev;
	int rc;

	memset(&ev, 0, sizeof(ev));
	ev.id = get_uniq_id();
	ev.type = type;
	ev.sender = *znode;
	ev.buf_len = buf_len;
	if (buf)
		memcpy(ev.buf, buf, buf_len);
	rc = zk_queue_push(&ev);
	if (rc == ZOK)
		return SD_RES_SUCCESS;
	else {
		sd_err("failed, type: %d, %s", type, zerror(rc));
		return SD_RES_CLUSTER_ERROR;
	}
}

static void zk_watcher(zhandle_t *zh, int type, int state, const char *path,
		       void *ctx)
{
	struct zk_node znode;
	char str[MAX_NODE_STR_LEN], *p;
	uint64_t lock_id;
	int ret;

	if (type == ZOO_SESSION_EVENT && state == ZOO_EXPIRED_SESSION_STATE) {
		/*
		 * do reconnect in main thread to avoid on-the-fly zookeeper
		 * operations.
		 */
		eventfd_xwrite(efd, 1);
		return;
	}

/* CREATED_EVENT 1, DELETED_EVENT 2, CHANGED_EVENT 3, CHILD_EVENT 4 */
	sd_debug("path:%s, type:%d, state:%d", path, type, state);
	if (type == ZOO_CREATED_EVENT || type == ZOO_CHANGED_EVENT) {
		ret = sscanf(path, MEMBER_ZNODE "/%s", str);
		if (ret == 1)
			zk_node_exists(path);
		/* kick off the event handler */
		eventfd_xwrite(efd, 1);
	} else if (type == ZOO_DELETED_EVENT) {
		struct zk_node *n;

		/* process distributed lock */
		ret = sscanf(path, LOCK_ZNODE "/%"PRIu64"/%s", &lock_id, str);
		if (ret == 2) {
			ret = lock_table_lookup_wakeup(lock_id);
			if (ret)
				sd_debug("release lock %"PRIu64" %s",
					 lock_id, str);
			return;
		}

		ret = sscanf(path, MASTER_ZNODE "/%s", str);
		if (ret == 1) {
			zk_compete_master();
			return;
		}

		ret = sscanf(path, MEMBER_ZNODE "/%s", str);
		if (ret != 1)
			return;
		p = strrchr(path, '/');
		p++;
		str_to_node(p, &znode.node);
		/* FIXME: remove redundant leave events */
		sd_read_lock(&zk_tree_lock);
		n = zk_tree_search_nolock(&znode.node.nid);
		if (n)
			n->gone = true;
		sd_rw_unlock(&zk_tree_lock);
		if (n)
			add_event(EVENT_LEAVE, &znode, NULL, 0);
	}
}

/*
 * We placehold the enough space to piggyback the nodes information on join
 * response message so that every node can see the same membership view.
 *
 * We have to preallocate enough space and set msg_len as
 * sizeof(struct cluster_info) because of piggyback.
 */
static int add_join_event(void *msg, size_t msglen)
{
	struct zk_event ev;
	size_t len = msglen + sizeof(struct sd_node) * SD_MAX_NODES;

	if (unlikely((offsetof(struct zk_event, buf) + len) > ZK_MAX_BUF_SIZE))
		panic("Zookeeper can't send message more than 1M");
	ev.id = get_uniq_id();
	ev.type = EVENT_JOIN;
	ev.sender = this_node;
	ev.msg_len = msglen;
	ev.buf_len = len;
	if (msg)
		memcpy(ev.buf, msg, msglen);
	return zk_queue_push(&ev);
}

static int zk_get_least_seq(const char *parent, char *least_seq_path,
			    int path_len, void *buf, int *buf_len)
{
	char path[MAX_NODE_STR_LEN], *p, *tmp;
	struct String_vector strs;
	int rc, least_seq, seq;

	while (true) {
		/*
		 * If first loop fail, the least_seq may be a very small number
		 * which had been deleted in zookeeper, the new create file will
		 * be all larger than it and it will cause dead loop.
		 * Therefore we need to set least_seq to INT_MAX in every loop.
		 */
		least_seq = INT_MAX;

		RETURN_IF_ERROR(zk_get_children(parent, &strs), "");

		FOR_EACH_ZNODE(parent, path, &strs) {
			p = strrchr(path, '/');
			seq = strtol(++p, &tmp, 10);
			if (seq < least_seq)
				least_seq = seq;
		}

		snprintf(path, MAX_NODE_STR_LEN, "%s/%010"PRId32,
			 parent, least_seq);
		rc = zk_get_data(path, buf, buf_len);
		switch (rc) {
		case ZOK:
			strncpy(least_seq_path, path, path_len);
			return ZOK;
		case ZNONODE:
			break;
		default:
			sd_err("failed, %s", zerror(rc));
			return rc;
		}
	}
}

static int zk_find_master(int *master_seq, char *master_name)
{
	int rc, len = MAX_NODE_STR_LEN;
	char master_compete_path[MAX_NODE_STR_LEN];

	if (*master_seq < 0) {
		RETURN_IF_ERROR(zk_get_least_seq(MASTER_ZNODE,
						 master_compete_path,
						 MAX_NODE_STR_LEN, master_name,
						 &len), "");
		sscanf(master_compete_path, MASTER_ZNODE "/%"PRId32,
		       master_seq);
		return ZOK;
	} else {
		while (true) {
			snprintf(master_compete_path, len,
				 MASTER_ZNODE "/%010"PRId32, *master_seq);
			rc = zk_get_data(master_compete_path, master_name,
					 &len);
			switch (rc) {
			case ZOK:
				return ZOK;
			case ZNONODE:
				sd_info("detect master leave, "
					"start to compete master");
				(*master_seq)++;
				break;
			default:
				sd_err("failed, %s", zerror(rc));
				return rc;
			}
		}
	}
}

/*
 * block until last sheep joined
 * last_sheep returns sequence number of last sheep or -1 if no previous sheep
 */
static int zk_verify_last_sheep_join(int seq, int *last_sheep)
{
	int rc, len = MAX_NODE_STR_LEN;
	char path[MAX_NODE_STR_LEN], name[MAX_NODE_STR_LEN];

	for (*last_sheep = seq - 1; *last_sheep >= 0; (*last_sheep)--) {
		snprintf(path, MAX_NODE_STR_LEN, MASTER_ZNODE "/%010"PRId32,
			 *last_sheep);
		rc = zk_get_data(path, name, &len);
		switch (rc) {
		case ZNONODE:
			continue;
		case ZOK:
			break;
		default:
			sd_err("failed, %s", zerror(rc));
			return rc;
		}

		if (!strcmp(name, node_to_str(&this_node.node)))
			continue;

		snprintf(path, MAX_NODE_STR_LEN, MEMBER_ZNODE "/%s", name);
		rc = zk_node_exists(path);
		switch (rc) {
		case ZOK:
			return ZOK;
		case ZNONODE:
			(*last_sheep)++;
			break;
		default:
			sd_err("failed, %s", zerror(rc));
			return rc;
		}
	}
	return ZOK;
}

/*
 * Create sequential node under MASTER_ZNODE.
 * Sheep with least sequential number win the competition.
 */
static void zk_compete_master(void)
{
	int rc, last_joined_sheep;
	char master_name[MAX_NODE_STR_LEN];
	char my_compete_path[MAX_NODE_STR_LEN];
	static int master_seq = -1, my_seq;

	/*
	 * This is to protect master_seq and my_seq because this function will
	 * be called by both main thread and zookeeper's event thread.
	 */
	sd_write_lock(&zk_compete_master_lock);

	if (uatomic_is_true(&is_master) || uatomic_is_true(&stop))
		goto out_unlock;

	if (!joined) {
		sd_debug("start to compete master for the first time");
		do {
			if (uatomic_is_true(&stop))
				goto out_unlock;
			/* duplicate sequential node has no side-effect */
			rc = zk_create_seq_node(MASTER_ZNODE "/",
						node_to_str(&this_node.node),
						MAX_NODE_STR_LEN,
						my_compete_path,
						MAX_NODE_STR_LEN, true);
		} while (rc == ZOPERATIONTIMEOUT || rc == ZCONNECTIONLOSS);
		CHECK_ZK_RC(rc, MASTER_ZNODE "/");
		if (rc != ZOK)
			goto out_unlock;

		sd_debug("my compete path: %s", my_compete_path);
		sscanf(my_compete_path, MASTER_ZNODE "/%"PRId32,
		       &my_seq);
	}

	if (zk_find_master(&master_seq, master_name) != ZOK)
		goto out_unlock;

	if (!strcmp(master_name, node_to_str(&this_node.node)))
		goto success;
	else if (joined) {
		sd_debug("lost");
		goto out_unlock;
	} else {
		if (zk_verify_last_sheep_join(my_seq,
					      &last_joined_sheep) != ZOK)
			goto out_unlock;

		if (last_joined_sheep < 0) {
			/* all previous sheep has quit, i'm master */
			master_seq = my_seq;
			goto success;
		} else {
			sd_debug("lost");
			goto out_unlock;
		}
	}
success:
	uatomic_set_true(&is_master);
	my_master_seq = master_seq;
	sd_debug("success");
out_unlock:
	sd_rw_unlock(&zk_compete_master_lock);
}

static int zk_join(const struct sd_node *myself,
		   void *opaque, size_t opaque_len)
{
	int rc;
	char path[MAX_NODE_STR_LEN];

	this_node.node = *myself;

	snprintf(path, sizeof(path), MEMBER_ZNODE "/%s", node_to_str(myself));
	rc = zk_node_exists(path);
	if (rc == ZOK) {
		sd_err("Previous zookeeper session exist, shoot myself. Please "
			"wait for %d seconds to join me again.",
			DIV_ROUND_UP(zk_timeout, 1000));
		exit(1);
	}

	zk_compete_master();
	RETURN_IF_ERROR(add_join_event(opaque, opaque_len), "");

	return ZOK;
}

static int zk_leave(void)
{
	char path[PATH_MAX];

	sd_info("leaving from cluster");
	uatomic_set_true(&stop);

	if (uatomic_is_true(&is_master)) {
		snprintf(path, sizeof(path), MASTER_ZNODE "/%010"PRId32,
				my_master_seq);
		zk_delete_node(path, -1);
	}

	snprintf(path, sizeof(path), MEMBER_ZNODE"/%s",
		 node_to_str(&this_node.node));
	add_event(EVENT_LEAVE, &this_node, NULL, 0);
	lock_table_remove_znodes();
	zk_delete_node(path, -1);
	return 0;
}

static int zk_notify(void *msg, size_t msg_len)
{
	return add_event(EVENT_NOTIFY, &this_node, msg, msg_len);
}

static int zk_block(void)
{
	return add_event(EVENT_BLOCK, &this_node, NULL, 0);
}

static int zk_unblock(void *msg, size_t msg_len)
{
	return add_event(EVENT_UNBLOCK, &this_node, msg, msg_len);
}

static void zk_handle_join(struct zk_event *ev)
{
	sd_debug("sender: %s", node_to_str(&ev->sender.node));
	if (!uatomic_is_true(&is_master)) {
		/* Let's await master acking the join-request */
		queue_pos--;
		return;
	}

	sd_join_handler(&ev->sender.node, &sd_node_root, nr_sd_nodes, ev->buf);
	push_join_response(ev);

	sd_debug("I'm the master now");
}

static void watch_all_nodes(void)
{
	struct String_vector strs;
	char path[MAX_NODE_STR_LEN];

	RETURN_VOID_IF_ERROR(zk_get_children(MEMBER_ZNODE, &strs), "");

	FOR_EACH_ZNODE(MEMBER_ZNODE, path, &strs) {
		RETURN_VOID_IF_ERROR(zk_node_exists(path), "");
	}
}

static void init_node_list(struct zk_event *ev)
{
	uint8_t *p = zk_event_sd_nodes(ev);
	size_t node_nr = ev->nr_nodes;
	int i;

	sd_debug("%zu", node_nr);
	for (i = 0; i < node_nr; i++) {
		struct zk_node zk;
		mempcpy(&zk.node, p, sizeof(struct sd_node));
		zk_tree_add(&zk);
		p += sizeof(struct sd_node);
	}

	watch_all_nodes();
}

static void zk_handle_accept(struct zk_event *ev)
{
	char path[MAX_NODE_STR_LEN];
	int rc;

	sd_debug("ACCEPT");
	if (node_eq(&ev->sender.node, &this_node.node))
		/* newly joined node */
		init_node_list(ev);

	sd_debug("%s", node_to_str(&ev->sender.node));

	snprintf(path, sizeof(path), MEMBER_ZNODE"/%s",
		 node_to_str(&ev->sender.node));
	if (node_eq(&ev->sender.node, &this_node.node)) {
		joined = true;
		sd_debug("create path:%s", path);
		rc = zk_create_node(path,
				    (char *)zoo_client_id(zhandle),
				    sizeof(clientid_t),
				    &ZOO_OPEN_ACL_UNSAFE,
				    ZOO_EPHEMERAL, NULL, 0);
		RETURN_VOID_IF_ERROR(rc, "");
	} else
		zk_node_exists(path);

	zk_tree_add(&ev->sender);

	build_node_list();
	sd_accept_handler(&ev->sender.node, &sd_node_root, nr_sd_nodes,
			  ev->buf);
}

static void kick_block_event(void)
{
	struct zk_node *block;

	if (list_empty(&zk_block_list))
		return;
	block = list_first_entry(&zk_block_list, typeof(*block), list);
	if (!block->callbacked)
		block->callbacked = sd_block_handler(&block->node);
}

static void block_event_list_del(struct zk_node *n)
{
	struct zk_node *ev;

	list_for_each_entry(ev, &zk_block_list, list) {
		if (node_eq(&ev->node, &n->node)) {
			list_del(&ev->list);
			free(ev);
		}
	}
}

static void zk_handle_leave(struct zk_event *ev)
{
	struct zk_node *n = zk_tree_search(&ev->sender.node.nid);

	if (!n) {
		sd_debug("can't find this leave node:%s, ignore it.",
			 node_to_str(&ev->sender.node));
		return;
	}
	block_event_list_del(n);
	zk_tree_del(n);
	build_node_list();
	sd_leave_handler(&ev->sender.node, &sd_node_root, nr_sd_nodes);
}

static void zk_handle_block(struct zk_event *ev)
{
	struct zk_node *block = xzalloc(sizeof(*block));

	sd_debug("BLOCK");
	block->node = ev->sender.node;
	list_add_tail(&block->list, &zk_block_list);
	block = list_first_entry(&zk_block_list, typeof(*block), list);
	if (!block->callbacked)
		block->callbacked = sd_block_handler(&block->node);
}

static void zk_handle_unblock(struct zk_event *ev)
{
	struct zk_node *block;

	sd_debug("UNBLOCK");
	if (list_empty(&zk_block_list))
		return;
	block = list_first_entry(&zk_block_list, typeof(*block), list);
	sd_notify_handler(&ev->sender.node, ev->buf, ev->buf_len);

	list_del(&block->list);
	free(block);
}

static void zk_handle_notify(struct zk_event *ev)
{
	sd_debug("NOTIFY");
	sd_notify_handler(&ev->sender.node, ev->buf, ev->buf_len);
}

static void zk_handle_update_node(struct zk_event *ev)
{
	struct zk_node *t;
	struct sd_node *snode = &ev->sender.node;

	sd_debug("%s", node_to_str(snode));

	if (node_eq(snode, &this_node.node))
		this_node.node = *snode;

	sd_read_lock(&zk_tree_lock);
	t = zk_tree_search_nolock(&snode->nid);
	assert(t);
	t->node = *snode;
	build_node_list();
	sd_rw_unlock(&zk_tree_lock);
	sd_update_node_handler(snode);
}

static void (*const zk_event_handlers[])(struct zk_event *ev) = {
	[EVENT_JOIN]		= zk_handle_join,
	[EVENT_ACCEPT]		= zk_handle_accept,
	[EVENT_LEAVE]		= zk_handle_leave,
	[EVENT_BLOCK]		= zk_handle_block,
	[EVENT_UNBLOCK]		= zk_handle_unblock,
	[EVENT_NOTIFY]		= zk_handle_notify,
	[EVENT_UPDATE_NODE]	= zk_handle_update_node,
};

static const int zk_max_event_handlers = ARRAY_SIZE(zk_event_handlers);

/*
 * This method should be done in main thread and triggered when zk_watcher()
 * receives a session timeout event.
 * All other zk operations who receive 'ZINVALIDSTATE' return code should drop
 * control of main thread as soon as possible. So that this method can be
 * executed and re-establish a new session with zookeeper server.
 */
static inline void handle_session_expire(void)
{
	/* clean memory states */
	close(efd);
	zk_tree_destroy();
	INIT_RB_ROOT(&zk_node_root);
	INIT_LIST_HEAD(&zk_block_list);
	nr_sd_nodes = 0;
	INIT_RB_ROOT(&sd_node_root);
	first_push = true;
	joined = false;

	while (sd_reconnect_handler()) {
		sd_err("failed to reconnect. sleep and retry...");
		sleep(1);
	}
}

static void zk_event_handler(int listen_fd, int events, void *data)
{
	struct zk_event ev;
	bool peek;

	sd_debug("%d, %d", events, queue_pos);
	if (events & EPOLLHUP) {
		sd_err("zookeeper driver received EPOLLHUP event, exiting.");
		log_close();
		exit(1);
	}

	eventfd_xread(efd);

	if (zoo_state(zhandle) == ZOO_EXPIRED_SESSION_STATE) {
		sd_err("detect a session timeout. reconnecting...");
		handle_session_expire();
		sd_info("reconnected");
		eventfd_xwrite(efd, 1);
		return;
	}

	RETURN_VOID_IF_ERROR(zk_queue_peek(&peek), "");
	if (!peek)
		goto kick_block_event;

	RETURN_VOID_IF_ERROR(zk_queue_pop_advance(&ev), "");
	if (ev.type < zk_max_event_handlers && zk_event_handlers[ev.type])
		zk_event_handlers[ev.type](&ev);
	else
		panic("unhandled type %d", ev.type);

	RETURN_VOID_IF_ERROR(zk_queue_peek(&peek), "");
	if (peek) {
		/* Someone has created next event, go kick event handler. */
		eventfd_xwrite(efd, 1);
		return;
	}
kick_block_event:
	/*
	 * Kick block event only if there is no nonblock event. We perfer to
	 * handle nonblock event becasue:
	 *
	 * 1. Sheep assuems that unblock() and notify() is a transaction, so we
	 *    can only kick next block event after sd_notify_handler() is called
	 * 2. We should process leave/join event as soon as possible.
	 */
	kick_block_event();
}

/*
 * This operation will create a seq-ephemeral znode in lock directory
 * of zookeeper (use lock-id as dir name). The smallest file path in
 * this directory wil be the owner of the lock; the other threads will
 * wait on a sem_t (cluster_lock->wait_wakeup)
 */
static void zk_lock(uint64_t lock_id)
{
	int rc, len = MAX_NODE_STR_LEN;
	char *my_path;
	char parent[MAX_NODE_STR_LEN];
	char parent_node[MAX_NODE_STR_LEN];
	char lowest_seq_path[MAX_NODE_STR_LEN];
	char owner_name[MAX_NODE_STR_LEN];
	struct cluster_lock *cluster_lock;

	cluster_lock = lock_table_lookup_acquire(lock_id);

	my_path = cluster_lock->lock_path;

	snprintf(parent, MAX_NODE_STR_LEN, LOCK_ZNODE "/%"PRIu64"/",
		 cluster_lock->id);
	/*
	 * It need using path without end of '/' to create node of lock_id in
	 * zookeeper's API, so we use 'parent_node'.
	 */
	snprintf(parent_node, MAX_NODE_STR_LEN, LOCK_ZNODE "/%"PRIu64,
		 cluster_lock->id);
create_seq_node:
	/* compete owner of lock is just like zk_compete_master() */
	while (true) {
		rc = zk_create_seq_node(parent, node_to_str(&this_node.node),
					MAX_NODE_STR_LEN, my_path,
					MAX_NODE_STR_LEN, true);
		if (rc == ZOK)
			break;
		if (rc == ZNONODE) {
			zk_init_node(parent_node);
			/*
			 * We don't need to check the return code of
			 * zk_init_node() because the routine must stay in loop
			 * if it doesn't take the lock, no matter what kind of
			 * error happed.
			 */
			continue;
		}
		sd_err("failed to create path:%s, %s", my_path, zerror(rc));
		zk_wait();
	}
	sd_debug("create path %s success", my_path);

	/* create node ok now */
	while (true) {
		rc = zk_get_least_seq(parent_node, lowest_seq_path,
				      MAX_NODE_STR_LEN, owner_name, &len);
		/* may be expired */
		if (rc == ZNONODE) {
			sd_debug("Recreate seq node");
			goto create_seq_node;
		}
		/* I got the lock */
		if (!strncmp(lowest_seq_path, my_path, strlen(my_path))) {
			sd_debug("I am master now. %s", lowest_seq_path);
			return;
		}

		/* I failed to get the lock */
		rc = zk_node_exists(lowest_seq_path);
		if (rc == ZOK) {
			sd_debug("call zoo_exists success %s", lowest_seq_path);
			/* Use wait_timeout to avoid missing wakeup signal */
			sem_wait(&cluster_lock->wait_wakeup);
		} else {
			sd_debug("failed to call zoo_exists %s", zerror(rc));
			if (rc != ZNONODE)
				zk_wait();
		}
	}
}

static void zk_unlock(uint64_t lock_id)
{
	lock_table_lookup_release(lock_id);
	sd_debug("unlock %"PRIu64, lock_id);
}

static int zk_init(const char *option)
{
	char *hosts, *to, *p;
	int ret, interval, retry = 0, max_retry;

	if (!option) {
		sd_err("You must specify zookeeper servers.");
		return -1;
	}

	hosts = strtok((char *)option, "=");
	if ((to = strtok(NULL, "="))) {
		if (sscanf(to, "%u", &zk_timeout) != 1) {
			sd_err("Invalid paramter for timeout");
			return -1;
		}
		p = strstr(hosts, "timeout");
		*--p = '\0';
	}
	sd_debug("version %d.%d.%d, address %s, timeout %d", ZOO_MAJOR_VERSION,
		 ZOO_MINOR_VERSION, ZOO_PATCH_VERSION, hosts, zk_timeout);
	zhandle = zookeeper_init(hosts, zk_watcher, zk_timeout, NULL, NULL, 0);
	if (!zhandle) {
		sd_err("failed to initialize zk server %s", option);
		return -1;
	}

	/* the simplest way to wait and check zk connection */
	interval = 100;
	max_retry = zk_timeout / interval;
	while (zoo_state(zhandle) != ZOO_CONNECTED_STATE) {
		usleep(interval * 1000);
		if (++retry >= max_retry) {
			sd_err("failed to connect to zk server %s "
					"after %d retries", option, retry);
			return -1;
		}
	}

	uatomic_set_false(&stop);
	uatomic_set_false(&is_master);
	if (zk_queue_init() != ZOK)
		return -1;

	efd = eventfd(0, EFD_NONBLOCK);
	if (efd < 0) {
		sd_err("failed to create an event fd: %m");
		return -1;
	}

	ret = register_event(efd, zk_event_handler, NULL);
	if (ret) {
		sd_err("failed to register zookeeper event handler (%d)", ret);
		return -1;
	}

	/* init distributed lock structures */
	cluster_locks_table = xzalloc(sizeof(struct list_head) *
				      HASH_BUCKET_NR);
	for (uint64_t i = 0; i < HASH_BUCKET_NR; i++) {
		INIT_HLIST_HEAD(cluster_locks_table + i);
		sd_init_mutex(table_locks + i);
	}

	ret = zk_init_node(LOCK_ZNODE);
	if (ret != ZOK) {
		sd_err("Failed to create %s %s", LOCK_ZNODE, zerror(ret));
		free(cluster_locks_table);
		return -1;
	}
	return 0;
}

static int zk_update_node(struct sd_node *node)
{
	struct zk_node znode = {
		.node = *node,
	};
	return add_event(EVENT_UPDATE_NODE, &znode, NULL, 0);
}

static struct cluster_driver cdrv_zookeeper = {
	.name       = "zookeeper",

	.init       = zk_init,
	.join       = zk_join,
	.leave      = zk_leave,
	.notify     = zk_notify,
	.block      = zk_block,
	.unblock    = zk_unblock,
	.lock         = zk_lock,
	.unlock       = zk_unlock,
	.update_node  = zk_update_node,
	.get_local_addr = get_local_addr,
};

cdrv_register(cdrv_zookeeper);
