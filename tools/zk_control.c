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

static const char *hosts = "127.0.0.1:2181";
static zhandle_t *zk_handle;

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
	return 0;
}

static struct control_handler {
	const char *name;
	int (*execute)(int, char **);
	const char *help;
} handlers[] = {
	{ "kill", do_kill, "Kill the session" },
	{ "remove", do_remove, "Remove the node recursively" },
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
