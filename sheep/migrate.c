/*
 * Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "sheep_priv.h"

extern char *config_path;

/* sheepdog 0.4.0 */
struct node_id_v0 {
	uint8_t addr[16];
	uint16_t port;
};

struct sd_node_v0 {
	struct node_id_v0  nid;
	uint16_t	nr_vnodes;
	uint32_t	zone;
};

struct sheepdog_config_v0 {
	uint64_t ctime;
	uint16_t flags;
	uint8_t copies;
	uint8_t store[STORE_LEN];
};

/* sheepdog 0.5.1 */
struct node_id_v1 {
	uint8_t addr[16];
	uint16_t port;
};

struct sd_node_v1 {
	struct node_id_v1  nid;
	uint16_t	nr_vnodes;
	uint32_t	zone;
	uint64_t        space;
};

struct sheepdog_config_v1 {
	uint64_t ctime;
	uint16_t flags;
	uint8_t copies;
	uint8_t store[STORE_LEN];
	uint8_t __pad[3];
	uint16_t version;
	uint64_t space;
};


static int migrate_from_v0_to_v1(void)
{
	int fd, ret, epoch, le, i;
	char path[PATH_MAX];
	struct sheepdog_config_v1 config;

	fd = open(config_path, O_RDWR);
	if (fd < 0) {
		eprintf("failed to open config file, %m\n");
		return -1;
	}

	memset(&config, 0, sizeof(config));
	ret = xread(fd, &config, sizeof(config));
	if (ret < 0) {
		eprintf("failed to read config file, %m\n");
		close(fd);
		return ret;
	}

	/* If the config file contains a space field, the store layout
	 * is compatible with v1.  In this case, what we need to do is
	 * only adding version number to the config file. */
	if (config.space > 0) {
		config.version = 1;
		ret = xwrite(fd, &config, sizeof(config));
		if (ret != sizeof(config)) {
			eprintf("failed to write config data, %m\n");
			close(fd);
			return -1;
		}

		close(fd);
		return 0;
	}

	/* upgrade epoch log */
	le = get_latest_epoch();
	for (epoch = 1; epoch <= le; epoch++) {
		struct sd_node_v0 nodes_v0[SD_MAX_NODES];
		struct sd_node_v1 nodes_v1[SD_MAX_NODES];
		size_t nr_nodes;
		time_t *t;
		int len;

		snprintf(path, sizeof(path), "%s%08u", epoch_path, epoch);
		fd = open(path, O_RDWR | O_DSYNC);
		if (fd < 0) {
			if (errno == ENOENT)
				continue;

			eprintf("failed to open epoch %"PRIu32" log\n", epoch);
			return -1;
		}

		ret = xread(fd, nodes_v0, sizeof(nodes_v0));
		if (ret < 0) {
			eprintf("failed to read epoch %"PRIu32" log\n", epoch);
			close(fd);
			return ret;
		}

		nr_nodes = ret / sizeof(nodes_v0[0]);
		for (i = 0; i < nr_nodes; i++) {
			memcpy(&nodes_v1[i].nid, &nodes_v0[i].nid,
			       sizeof(struct node_id_v1));
			nodes_v1[i].nr_vnodes = nodes_v0[i].nr_vnodes;
			nodes_v1[i].zone = nodes_v0[i].zone;
			nodes_v1[i].space = 0;
		}

		len = sizeof(nodes_v1[0]) * nr_nodes;
		ret = xpwrite(fd, nodes_v1, len, 0);
		if (ret != len) {
			eprintf("failed to write epoch %"PRIu32" log\n", epoch);
			close(fd);
			return -1;
		}

		t = (time_t *)&nodes_v0[nr_nodes];

		ret = xpwrite(fd, t, sizeof(*t), len);
		if (ret != sizeof(*t)) {
			eprintf("failed to write time to epoch %"PRIu32" log\n",
				epoch);
			close(fd);
			return -1;
		}

		close(fd);
	}

	return ret;
}

static int (*migrate[])(void) = {
	migrate_from_v0_to_v1, /* from 0.4.0 or 0.5.0 to 0.5.1 */
};

int sd_migrate_store(int from, int to)
{
	int ver, ret;

	assert(to <= sizeof(migrate));

	for (ver = from; ver < to; ver++) {
		ret = migrate[ver]();
		if (ret < 0)
			return ret;
	}

	/* success */
	return 0;
}
