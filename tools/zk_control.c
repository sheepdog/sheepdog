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
#include <stdlib.h>
#include <getopt.h>

#include "list.h"
#include "rbtree.h"
#include "internal_proto.h"

#define DEFAULT_BASE "/sheepdog"
#define QUEUE_ZNODE "/queue"
#define QUEUE_POS_ZNODE "/queue_pos"
#define DEFAULT_THRESHOLD 86400L

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

static int seq_cmp(const void *a, const void *b)
{
	return -strcmp(*(const char **)a, *(const char **)b);
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
		if (strs.count > 1) {
			qsort(strs.data, strs.count, sizeof(*(strs.data)),
				(comparison_fn_t)seq_cmp);
		}
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
	int rc, len, deleted = 0;
	long threshold = DEFAULT_THRESHOLD;
	char *p, path[256];
	struct zk_event ev;
	struct Stat stat;
	struct timeval tv;

	if (argc < 3) {
		fprintf(stderr, "threshold not given; use default %ld\n",
		        threshold);
	} else {
		threshold = strtol(argv[2], &p, 10);
		if (*p != '\0' || threshold < 0L) {
			fprintf(stderr,
			        "threshold must be a non-negative number\n");
			return -1;
		} else if (errno == ERANGE) {
			fprintf(stderr, "threshold too large\n");
			return -1;
		}
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
	if (deleted > 0) {
		fprintf(stderr, "%d queue nodes are deleted, but ", deleted);
	}
	fprintf(stderr, "failed to purge %s, %s\n", QUEUE_ZNODE, zerror(rc));
	return -1;
}

static int do_delete(int argc, char **argv)
{
	struct String_vector strs;
	int rc, len, deleted = 0;
	int32_t pos, min_pos = INT32_MAX;
	char path[256];
	struct zk_event ev;
	struct Stat stat;
	if (argc != 2) {
		fprintf(stderr, "remove queue, no more arguments\n");
		return -1;
	}

	rc = zk_get_children(QUEUE_POS_ZNODE, &strs);
	switch (rc) {
	case ZOK:
		FOR_EACH_ZNODE(QUEUE_POS_ZNODE, path, &strs) {
			len = sizeof(int32_t);
			rc = zk_get_data(path, &pos, &len, &stat);
			if (rc != ZOK) {
				fprintf(stderr, "failed to get data "
					"%s, %s\n",
					path, zerror(rc));
				goto err;
			}

			if (pos < min_pos && pos != -1)
				min_pos = pos;
		}
		break;
	default:
		goto err;
	}

	fprintf(stdout, "queue nodes seq < %d will be deleted\n", min_pos);

	if (min_pos == INT32_MAX) {
		fprintf(stdout, "no queue nodes to be deleted\n");
		return 0;
	}

	rc = zk_get_children(QUEUE_ZNODE, &strs);
	fprintf(stdout, "There are %d znode in queue\n", strs.count);
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

			sscanf(path, QUEUE_ZNODE "/%"PRId32, &pos);
			if (pos >= min_pos)
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
	fprintf(stderr, "failed to delete %s, %s\n", QUEUE_ZNODE, zerror(rc));
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
	{ "purge", do_purge, "Remove the data in queue node by time" },
	{ "delete", do_delete, "Remove the data in queue node not used" },
	{ NULL, NULL, NULL },
};

static struct zkc_option {
	char ch;
	const char *name;
	bool has_arg;
	const char *help;
} zkc_options[] = {
	{ 'c', "cluster", true, "specified the sheep cluster" },
	{ 0, 0, 0, 0},
};

#define zkc_for_each_option(opt, opts)		\
	for (opt = (opts); opt->name; opt++)

static struct option *build_long_options(const struct zkc_option *zkc_opts)
{
	static struct option lopts[256], *p;
	const struct zkc_option *opt;

	p = lopts;
	zkc_for_each_option(opt, zkc_opts) {
		p->name = opt->name;
		p->has_arg = opt->has_arg;
		p->flag = NULL;
		p->val = opt->ch;
		p++;
	}
	memset(p, 0, sizeof(struct option));

	return lopts;
}

static char *build_short_options(const struct zkc_option *zkc_opts)
{
	static char sopts[256], *p;
	const struct zkc_option *opt;

	p = sopts;
	zkc_for_each_option(opt, zkc_opts) {
		*p++ = opt->ch;
		if (opt->has_arg)
			*p++ = ':';
	}
	*p = '\0';

	return sopts;
}

static char *prepare_cluster(char *cluster)
{
	char *hosts_cluster = NULL;
	if (cluster != NULL) {
		hosts_cluster = calloc(1, strlen(hosts) + strlen(cluster) + 2);
		if (NULL == hosts_cluster) {
			fprintf(stderr, "out of memory\n");
			exit(1);
		}
		strncat(hosts_cluster, hosts, strlen(hosts));
		strncat(hosts_cluster, "/", 1);
		strncat(hosts_cluster, cluster, strlen(cluster));
	} else {
		hosts_cluster = calloc(1, strlen(hosts)
					+ strlen(DEFAULT_BASE) + 1);
		if (NULL == hosts_cluster) {
			fprintf(stderr, "out of memory\n");
			exit(1);
		}
		strncat(hosts_cluster, hosts, strlen(hosts));
		strncat(hosts_cluster, DEFAULT_BASE, strlen(DEFAULT_BASE));
	}
	return hosts_cluster;
}

static void usage(char *prog)
{
	struct control_handler *h;
	struct zkc_option *o;

	fprintf(stderr, "Usage:\n\t%s command [parameters] [options]\n", prog);
	fprintf(stderr, "Available commands:\n");
	for (h = handlers; h->name; h++)
		fprintf(stderr, "\t%s\t%s\n", h->name, h->help);
	fprintf(stderr, "Available options:\n");
	for (o = zkc_options; o->name; o++)
		fprintf(stderr, "\t-%c --%s\t%s\n", o->ch, o->name, o->help);
}

int main(int argc, char **argv)
{
	struct control_handler *h, *cmd = NULL;
	const char *short_options;
	struct option *long_options;
	int longindex, nr_arg, i;
	char *hosts_cluster = NULL, ch, *cluster = NULL, *argp[256];

	long_options = build_long_options(zkc_options);
	short_options = build_short_options(zkc_options);
	while ((ch = getopt_long(argc, argv, short_options, long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'c':
			cluster = optarg;
			break;
		default:
			usage(argv[0]);
			exit(0);
		}
	}

	if (argc > 256) {
		fprintf(stderr, "too many arguments\n");
		exit(1);
	}
	argp[0] = argv[0];
	nr_arg = 1;
	i = optind;
	while (i < argc)
		argp[nr_arg++] = argv[i++];

	hosts_cluster = prepare_cluster(cluster);

	if (nr_arg < 2) {
		usage(argp[0]);
		exit(0);
	}

	for (h = handlers; h->name; h++)
		if (strcmp(h->name, argp[1]) == 0) {
			cmd = h;
			break;
		}

	if (!cmd) {
		usage(argv[0]);
		exit(1);
	}

	zoo_set_debug_level(0);

	zk_handle = zookeeper_init(hosts_cluster, NULL, 1000, NULL, NULL, 0);
	if (!zk_handle) {
		fprintf(stderr, "failed to init zookeeper\n");
		exit(1);
	}

	if (cmd->execute(nr_arg, argp) < 0)
		fprintf(stderr, "%s failed\n", cmd->name);

	if (zookeeper_close(zk_handle) != ZOK) {
		fprintf(stderr, "failed to close zookeeper session\n");
		exit(1);
	}

	free(hosts_cluster);
	return 0;
}
