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

#include "sheep_priv.h"

#define SD_FORMAT_VERSION 0x0002
#define SD_CONFIG_SIZE 40

static struct sheepdog_config {
	uint64_t ctime;
	uint16_t flags;
	uint8_t copies;
	uint8_t store[STORE_LEN];
	uint8_t __pad[3];
	uint16_t version;
	uint64_t space;
} config;

char *config_path;

#define CONFIG_PATH "/config"

static int write_config(void)
{
	int ret;

	ret = atomic_create_and_write(config_path, (char *)&config,
				      sizeof(config), true);
	if (ret < 0) {
		sd_err("atomic_create_and_write() failed");
		return SD_RES_EIO;
	}

	return SD_RES_SUCCESS;
}

static void check_tmp_config(void)
{
	int ret;
	char tmp_config_path[PATH_MAX];

	snprintf(tmp_config_path, PATH_MAX, "%s.tmp", config_path);

	ret = unlink(tmp_config_path);
	if (!ret || ret != ENOENT)
		return;

	sd_info("removed temporal config file");
}

int init_config_file(void)
{
	int fd, ret;

	check_tmp_config();

	fd = open(config_path, O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT) {
			sd_err("failed to read config file, %m");
			return -1;
		}
		goto create;
	}

	ret = xread(fd, &config, sizeof(config));
	if (ret == 0) {
		close(fd);
		goto create;
	}
	if (ret < 0) {
		sd_err("failed to read config file, %m");
		goto out;
	}

	if (config.version != SD_FORMAT_VERSION) {
		sd_err("This sheep version is not compatible with"
		       " the existing data layout, %d", config.version);
		if (sys->upgrade) {
			/* upgrade sheep store */
			ret = sd_migrate_store(config.version, SD_FORMAT_VERSION);
			if (ret == 0) {
				/* reload config file */
				ret = xpread(fd, &config, sizeof(config), 0);
				if (ret != sizeof(config)) {
					sd_err("failed to reload config file,"
					       " %m");
					ret = -1;
				} else
					ret = 0;
			}
			goto out;
		}

		sd_err("use '-u' option to upgrade sheep store");
		ret = -1;
		goto out;
	}
	ret = 0;
	get_cluster_config(&sys->cinfo);
out:
	close(fd);

	return ret;
create:
	config.version = SD_FORMAT_VERSION;
	if (write_config() != SD_RES_SUCCESS)
		return -1;

	return 0;
}

void init_config_path(const char *base_path)
{
	int len = strlen(base_path) + strlen(CONFIG_PATH) + 1;

	config_path = xzalloc(len);
	snprintf(config_path, len, "%s" CONFIG_PATH, base_path);
}

int set_cluster_config(const struct cluster_info *cinfo)
{
	config.ctime = cinfo->ctime;
	config.copies = cinfo->nr_copies;
	config.flags = cinfo->flags;
	memset(config.store, 0, sizeof(config.store));
	pstrcpy((char *)config.store, sizeof(config.store),
		(char *)cinfo->store);

	return write_config();
}

int get_cluster_config(struct cluster_info *cinfo)
{
	cinfo->ctime = config.ctime;
	cinfo->nr_copies = config.copies;
	cinfo->flags = config.flags;
	memcpy(cinfo->store, config.store, sizeof(config.store));

	return SD_RES_SUCCESS;
}

int set_node_space(uint64_t space)
{
	config.space = space;

	return write_config();
}

int get_node_space(uint64_t *space)
{
	*space = config.space;

	return SD_RES_SUCCESS;
}

bool is_cluster_formatted(void)
{
	struct cluster_info cinfo;

	get_cluster_config(&cinfo);

	return cinfo.ctime != 0;
}

static inline __attribute__((used)) void __sd_config_format_build_bug_ons(void)
{
	/* never called, only for checking BUILD_BUG_ON()s */
	BUILD_BUG_ON(sizeof(struct sheepdog_config) != SD_CONFIG_SIZE);
}
