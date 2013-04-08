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
#include <unistd.h>
#include <errno.h>

#include "sheep_priv.h"

#define SD_FORMAT_VERSION 0x0001

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
	int fd, ret;

	if (uatomic_is_true(&sys->use_journal) &&
	    journal_write_config((char *)&config, sizeof(config))
	    != SD_RES_SUCCESS) {
		sd_eprintf("turn off journaling");
		uatomic_set_false(&sys->use_journal);
		sync();
	}

	fd = open(config_path, O_DSYNC | O_WRONLY | O_CREAT, def_fmode);
	if (fd < 0) {
		sd_eprintf("failed to open config file, %m");
		return SD_RES_EIO;
	}

	ret = xwrite(fd, &config, sizeof(config));
	if (ret != sizeof(config)) {
		sd_eprintf("failed to write config data, %m");
		ret = SD_RES_EIO;
	} else
		ret = SD_RES_SUCCESS;
	close(fd);

	return ret;
}

int init_config_file(void)
{
	int fd, ret;

	fd = open(config_path, O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT) {
			sd_eprintf("failed to read config file, %m");
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
		sd_eprintf("failed to read config file, %m");
		goto out;
	}

	if (config.version != SD_FORMAT_VERSION) {
		sd_eprintf("This sheep version is not compatible with"
			   " the existing data layout, %d", config.version);
		if (sys->upgrade) {
			/* upgrade sheep store */
			ret = sd_migrate_store(config.version, SD_FORMAT_VERSION);
			if (ret == 0) {
				/* reload config file */
				ret = xpread(fd, &config, sizeof(config), 0);
				if (ret != sizeof(config)) {
					sd_eprintf("failed to reload config"
						   " file, %m");
					ret = -1;
				} else
					ret = 0;
			}
			goto out;
		}

		sd_eprintf("use '-u' option to upgrade sheep store");
		ret = -1;
		goto out;
	}
	ret = 0;
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

int set_cluster_ctime(uint64_t ct)
{
	config.ctime = ct;

	return write_config();
}

uint64_t get_cluster_ctime(void)
{
	return config.ctime;
}

int set_cluster_copies(uint8_t copies)
{
	config.copies = copies;

	return write_config();
}

int get_cluster_copies(uint8_t *copies)
{
	*copies = config.copies;

	return SD_RES_SUCCESS;
}

int set_cluster_flags(uint16_t flags)
{
	config.flags = flags;

	return write_config();
}

int get_cluster_flags(uint16_t *flags)
{
	*flags = config.flags;

	return SD_RES_SUCCESS;
}

int set_cluster_store(const char *name)
{
	memset(config.store, 0, sizeof(config.store));
	pstrcpy((char *)config.store, sizeof(config.store), name);

	return write_config();
}

int get_cluster_store(char *buf)
{
	memcpy(buf, config.store, sizeof(config.store));

	return SD_RES_SUCCESS;
}

int set_cluster_space(uint64_t space)
{
	config.space = space;

	return write_config();
}

int get_cluster_space(uint64_t *space)
{
	*space = config.space;

	return SD_RES_SUCCESS;
}
