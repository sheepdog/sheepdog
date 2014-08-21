/*
 * Copyright (C) 2013 Zelin.io
 *
 * Kai Zhang <kyle@zelin.io>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <zookeeper/zookeeper.h>
#include <string.h>
#include <arpa/inet.h>

#include "list.h"
#include "rbtree.h"
#include "internal_proto.h"

#define QUEUE_ZNODE "/sheepdog/queue"
#define MIN_THRESHOLD 86400

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

static const char *hosts = "127.0.0.1:2181";
static zhandle_t *zk_handle;

static const char *evtype_to_str(int type)
{
	switch (type) {
	case EVENT_JOIN:
		return "JOIN";
	case EVENT_ACCEPT:
		return "ACCEPT";
	case EVENT_LEAVE:
		return "LEAVE";
	case EVENT_BLOCK:
		return "BLOCK";
	case EVENT_UNBLOCK:
		return "UNBLOCK";
	case EVENT_NOTIFY:
		return "NOTIFY";
	case EVENT_UPDATE_NODE:
		return "UPDATE_NODE";
	default:
		return "UNKNOWN";
	}
}

static const char *addr_to_str(const uint8_t *addr, uint16_t port)
{
	static __thread char str[HOST_NAME_MAX + 8];
	int af = AF_INET6;
	int addr_start_idx = 0;
	const char *ret;

	/* Find address family type */
	if (addr[12]) {
		int  oct_no = 0;
		while (!addr[oct_no] && oct_no++ < 12)
			;
		if (oct_no == 12) {
			af = AF_INET;
			addr_start_idx = 12;
		}
	}
	ret = inet_ntop(af, addr + addr_start_idx, str, sizeof(str));
	if (unlikely(ret == NULL))
		fprintf(stderr, "failed to convert addr to string, %m\n");

	if (port) {
		int  len = strlen(str);
		snprintf(str + len, sizeof(str) - len, ":%d", port);
	}

	return str;
}

static inline ZOOAPI int zk_delete_node(const char *path)
{
	int rc;
	do {
		rc = zoo_delete(zk_handle, path, -1);
	} while (rc == ZOPERATIONTIMEOUT || rc == ZCONNECTIONLOSS);

	return rc;
}

static inline ZOOAPI int zk_get_children(const char *path,
					 struct String_vector *strings)
{
	int rc;
	do {
		rc = zoo_get_children(zk_handle, path, 1, strings);
	} while (rc == ZOPERATIONTIMEOUT || rc == ZCONNECTIONLOSS);

	return rc;
}

static inline ZOOAPI int zk_get_data(const char *path, void *buffer,
				     int *buffer_len, struct Stat *stat)
{
	int rc;
	do {
		rc = zoo_get(zk_handle, path, 1, (char *)buffer,
			     buffer_len, stat);
	} while (rc == ZOPERATIONTIMEOUT || rc == ZCONNECTIONLOSS);

	return rc;
}

static int do_kill(int argc, char **argv)
{
	char *path;
	clientid_t cid;
	int len = sizeof(clientid_t), rc;

	if (argc != 3) {
		fprintf(stderr, "kill: need specify path\n");
		return -1;
	}

	path = argv[2];

	while (zoo_state(zk_handle) != ZOO_CONNECTED_STATE)
		;

	rc = zoo_get(zk_handle, path, 0, (char *)&cid, &len, NULL);
	switch (rc) {
	case ZOK:
		break;
	case ZNONODE:
		return 0;
	default:
		fprintf(stderr, "failed to get data for %s, %s\n", path,
			zerror(rc));
		return -1;
	}

	zk_handle = zookeeper_init(hosts, NULL, 1000, &cid, NULL, 0);

	if (!zk_handle) {
		fprintf(stderr, "failed to re-init zookeeper\n");
		return -1;
	}

	while (zoo_state(zk_handle) != ZOO_CONNECTED_STATE)
		;
	return 0;
}

static int do_remove(int argc, char **argv)
{
	struct String_vector strs;
	int rc;
	char *node;
	char path[256];

	if (argc != 3) {
		fprintf(stderr, "remove: need specify path\n");
		return -1;
	}

	node = argv[2];

	rc = zk_get_children(node, &strs);
	switch (rc) {
	case ZOK:
		FOR_EACH_ZNODE(node, path, &strs) {
			rc = zk_delete_node(path);
			if (rc != ZOK && rc != ZNONODE) {
				fprintf(stderr, "failed to delete child "
					"%s, %s\n",
					path, zerror(rc));
				goto err;
			}
		}
		break;
	case ZNOCHILDRENFOREPHEMERALS:
		break;
	case ZNONODE:
		return 0;
	default:
		goto err;
	}

	rc = zk_delete_node(node);
	if (rc != ZOK && rc != ZNONODE)
		goto err;

	return 0;
err:
	fprintf(stderr, "failed to delete %s, %s\n", node, zerror(rc));
	return -1;
}

static int do_list(int argc, char **argv)
{
	struct String_vector strs;
	int rc, len, total = 0;
	char path[256], str_ctime[128], str_mtime[128];
	time_t t1, t2;
	struct tm tm_ctime, tm_mtime;
	struct zk_event ev;
	struct Stat stat;
	int32_t seq;
	struct node_id *nid;

	fprintf(stdout, "     QUEUE                ID          TYPE"
		"                 SENDER  MSG LEN    NR  BUF LEN"
		"          CREATE TIME          MODIFY TIME\n");
	rc = zk_get_children(QUEUE_ZNODE, &strs);
	switch (rc) {
	case ZOK:
		FOR_EACH_ZNODE(QUEUE_ZNODE, path, &strs) {
			len = sizeof(struct zk_event);
			rc = zk_get_data(path, &ev, &len, &stat);
			if (rc != ZOK) {
				fprintf(stderr, "failed to get data "
					"%s, %s\n",
					path, zerror(rc));
				goto err;
			}

			t1 = stat.ctime / 1000;
			localtime_r(&t1, &tm_ctime);
			strftime(str_ctime, sizeof(str_ctime),
					"%Y-%m-%d %H:%M:%S", &tm_ctime);

			t2 = stat.mtime / 1000;
			localtime_r(&t2, &tm_mtime);
			strftime(str_mtime, sizeof(str_mtime),
					"%Y-%m-%d %H:%M:%S", &tm_mtime);

			sscanf(path, QUEUE_ZNODE "/%"PRId32, &seq);
			nid = &ev.sender.node.nid;
			fprintf(stdout, "%010"PRId32"  %016"PRIx64
				"  %12s  %21s  %7zd  %4zd  %7zd  %s  %s\n",
				seq, ev.id, evtype_to_str(ev.type),
				addr_to_str(nid->addr, nid->port),
				ev.msg_len, ev.nr_nodes, ev.buf_len,
				str_ctime, str_mtime);
			total++;
		}
		break;
	default:
		goto err;
	}

	fprintf(stdout, "\ntotal nodes: %d\n", total);
	return 0;
err:
	fprintf(stderr, "failed to list %s, %s\n", QUEUE_ZNODE, zerror(rc));
	return -1;
}

static int do_purge(int argc, char **argv)
{
	struct String_vector strs;
	int rc, len, threshold, deleted = 0;
	char *p, path[256];
	struct zk_event ev;
	struct Stat stat;
	struct timeval tv;

	if (argc != 3) {
		fprintf(stderr, "remove queue: need specify "
				"threshold in seconds\n");
		return -1;
	}

	threshold = strtol(argv[2], &p, 10);
	if (p == argv[2]) {
		fprintf(stderr, "threshold must be a number\n");
		return -1;
	}
	if (threshold < MIN_THRESHOLD) {
		threshold = MIN_THRESHOLD;
		fprintf(stdout, "threshold is less than %d seconds, "
			"set it to %d\n", MIN_THRESHOLD, MIN_THRESHOLD);
	}

	gettimeofday(&tv, NULL);

	rc = zk_get_children(QUEUE_ZNODE, &strs);
	switch (rc) {
	case ZOK:
		FOR_EACH_ZNODE(QUEUE_ZNODE, path, &strs) {
			len = sizeof(struct zk_event);
			rc = zk_get_data(path, &ev, &len, &stat);
			if (rc != ZOK) {
				fprintf(stderr, "failed to get data "
					"%s, %s\n",
					path, zerror(rc));
				goto err;
			}
			if (stat.mtime / 1000 >= tv.tv_sec - threshold)
				continue;

			rc = zk_delete_node(path);
			if (rc != ZOK) {
				fprintf(stderr, "failed to delete "
					"%s, %s\n",
					path, zerror(rc));
				goto err;
			}

			deleted++;
			if (deleted % 100 == 0)
				fprintf(stdout, "%d queue nodes are deleted\n",
						deleted);
		}
		break;
	default:
		goto err;
	}

	fprintf(stdout, "completed. %d queue nodes are deleted\n", deleted);
	return 0;
err:
	fprintf(stderr, "failed to purge %s, %s\n", QUEUE_ZNODE, zerror(rc));
	return -1;
}

static struct control_handler {
	const char *name;
	int (*execute)(int, char **);
	const char *help;
} handlers[] = {
	{ "kill", do_kill, "Kill the session" },
	{ "remove", do_remove, "Remove the node recursively" },
	{ "list", do_list, "List the data in queue node" },
	{ "purge", do_purge, "Remove the data in queue node" },
	{ NULL, NULL, NULL },
};

static void usage(char *prog)
{
	struct control_handler *h;

	fprintf(stderr, "Usage:\n\t%s command [parameters]\n", prog);
	fprintf(stderr, "Available commands:\n");
	for (h = handlers; h->name; h++)
		fprintf(stderr, "\t%s\t%s\n", h->name, h->help);
}

int main(int argc, char **argv)
{
	struct control_handler *h, *cmd = NULL;

	if (argc < 2) {
		usage(argv[0]);
		exit(0);
	}
	for (h = handlers; h->name; h++)
		if (strcmp(h->name, argv[1]) == 0) {
			cmd = h;
			break;
		}

	if (!cmd) {
		usage(argv[0]);
		exit(1);
	}

	zoo_set_debug_level(0);

	zk_handle = zookeeper_init(hosts, NULL, 1000, NULL, NULL, 0);
	if (!zk_handle) {
		fprintf(stderr, "failed to init zookeeper\n");
		exit(1);
	}

	if (cmd->execute(argc, argv) < 0)
		fprintf(stderr, "%s failed\n", cmd->name);

	if (zookeeper_close(zk_handle) != ZOK) {
		fprintf(stderr, "failed to close zookeeper session\n");
		exit(1);
	}

	return 0;
}
