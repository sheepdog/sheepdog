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

static void print_usage(void)
{
	fprintf(stderr,
		"Usage:\n"
		"\tkill_zk_session \"zk_path\"\n");
}

int main(int argc, char **argv)
{
	const char *hosts = "127.0.0.1:2181";
	char *path;
	clientid_t cid;
	int len = sizeof(clientid_t), rc;
	zhandle_t *zh;

	if (argc != 2) {
		print_usage();
		exit(1);
	}

	path = argv[1];

	zoo_set_debug_level(0);

	zh = zookeeper_init(hosts, NULL, 1000, NULL, NULL, 0);
	if (!zh) {
		fprintf(stderr, "failed to init zookeeper\n");
		exit(1);
	}

	while (zoo_state(zh) != ZOO_CONNECTED_STATE)
		;

	rc = zoo_get(zh, path, 0, (char *)&cid, &len, NULL);
	switch (rc) {
	case ZOK:
		break;
	case ZNONODE:
		return 0;
	default:
		fprintf(stderr, "failed to get data for %s, %s\n", path,
			zerror(rc));
		exit(1);
	}

	zh = zookeeper_init(hosts, NULL, 1000, &cid, NULL, 0);

	if (!zh) {
		fprintf(stderr, "failed to re-init zookeeper\n");
		exit(1);
	}

	while (zoo_state(zh) != ZOO_CONNECTED_STATE)
		;

	if (zookeeper_close(zh) != ZOK) {
		fprintf(stderr, "failed to close zookeeper session\n");
		exit(1);
	}

	return 0;
}
