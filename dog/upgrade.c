/*
 * Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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
#include <stdlib.h>
#include <string.h>

#include "dog.h"

static struct sd_option upgrade_options[] = {
	{'o', "orig-version", true, "version of converting file"},
	{ 0, NULL, false, NULL },
};

enum orig_version {
	ORIG_VERSION_0_7 = 1,
	ORIG_VERSION_0_8,
};

static struct upgrade_cmd_data {
	enum orig_version orig;
} upgrade_cmd_data = { ~0, };

static int upgrade_inode_convert(int argc, char **argv)
{
	const char *orig_file = argv[optind++], *dst_file = NULL;
	int orig_fd, dst_fd, ret;
	struct sd_inode_0_7 *orig_0_7;
	struct sd_inode_0_8 *orig_0_8;
	struct stat orig_stat;
	struct sd_inode *dst;

	if (optind < argc)
		dst_file = argv[optind++];
	else {
		sd_info("please specify destination file path");
		return EXIT_USAGE;
	}

	orig_fd = open(orig_file, O_RDONLY);
	if (orig_fd < 0) {
		sd_err("failed to open original inode file: %m");
		return EXIT_SYSFAIL;
	}

	memset(&orig_stat, 0, sizeof(orig_stat));
	ret = fstat(orig_fd, &orig_stat);
	if (ret < 0) {
		sd_err("failed to stat original inode file: %m");
		return EXIT_SYSFAIL;
	}

	dst = xzalloc(sizeof(*dst));

	if (upgrade_cmd_data.orig == ORIG_VERSION_0_7) {
		orig_0_7 = xzalloc(sizeof(*orig_0_7));
		ret = xread(orig_fd, orig_0_7, orig_stat.st_size);
		if (ret != orig_stat.st_size) {
			sd_err("failed to read original inode file: %m");
			return EXIT_SYSFAIL;
		}

		if (orig_0_7->snap_ctime) {
			sd_err("snapshot cannot be converted");
			return EXIT_USAGE;
		}

		memcpy(dst->name, orig_0_7->name, SD_MAX_VDI_LEN);
		memcpy(dst->tag, orig_0_7->tag, SD_MAX_VDI_TAG_LEN);
		dst->create_time = orig_0_7->create_time;
		dst->vm_clock_nsec = orig_0_7->vm_clock_nsec;
		dst->vdi_size = orig_0_7->vdi_size;
		dst->vm_state_size = orig_0_7->vm_state_size;
		dst->copy_policy = orig_0_7->copy_policy;
		dst->nr_copies = orig_0_7->nr_copies;
		dst->block_size_shift = orig_0_7->block_size_shift;
		dst->vdi_id = orig_0_7->vdi_id;

		memcpy(dst->data_vdi_id, orig_0_7->data_vdi_id,
		       sizeof(uint32_t) * SD_INODE_DATA_INDEX);
	} else if (upgrade_cmd_data.orig == ORIG_VERSION_0_8) {
		orig_0_8 = xzalloc(sizeof(*orig_0_8));
		ret = xread(orig_fd, orig_0_8, orig_stat.st_size);

		if (ret != orig_stat.st_size) {
			sd_err("failed to read original inode file: %m");
			return EXIT_SYSFAIL;
		}

		if (orig_0_8->snap_ctime) {
			sd_err("snapshot cannot be converted");
			return EXIT_USAGE;
		}

		memcpy(dst->name, orig_0_8->name, SD_MAX_VDI_LEN);
		memcpy(dst->tag, orig_0_8->tag, SD_MAX_VDI_TAG_LEN);
		dst->create_time = orig_0_8->create_time;
		dst->vm_clock_nsec = orig_0_8->vm_clock_nsec;
		dst->vdi_size = orig_0_8->vdi_size;
		dst->vm_state_size = orig_0_8->vm_state_size;
		dst->copy_policy = orig_0_8->copy_policy;
		dst->nr_copies = orig_0_8->nr_copies;
		dst->block_size_shift = orig_0_8->block_size_shift;
		dst->vdi_id = orig_0_8->vdi_id;

		memcpy(dst->data_vdi_id, orig_0_8->data_vdi_id,
		       sizeof(uint32_t) * SD_INODE_DATA_INDEX);
	} else {
		sd_info("please specify original version of inode file");
		return EXIT_FAILURE;
	}

	dst_fd = open(dst_file, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (dst_fd < 0) {
		sd_err("failed to create converted inode file: %m");
		return EXIT_SYSFAIL;
	}

	ret = xwrite(dst_fd, dst, sizeof(*dst));
	if (ret != sizeof(*dst)) {
		sd_err("failed to write converted inode file: %m");
		return EXIT_SYSFAIL;
	}

	return EXIT_SUCCESS;
}

static struct subcommand upgrade_cmd[] = {
	{"inode-convert", "<path of original inode file>"
	 " <path of new inode file>",
	 "hTo", "upgrade inode object file",
	 NULL, CMD_NEED_ARG, upgrade_inode_convert, upgrade_options},
	{NULL,},
};

static int upgrade_parser(int ch, const char *opt)
{
	switch (ch) {
	case 'o':
		if (!strcmp(opt, "v0.7"))
			upgrade_cmd_data.orig = ORIG_VERSION_0_7;
		else if (!strcmp(opt, "v0.8"))
			upgrade_cmd_data.orig = ORIG_VERSION_0_8;
		else {
			sd_info("unknown original version: %s", opt);
			sd_info("valid versions are v0.7 or v0.8");
			exit(EXIT_FAILURE);
		}

		break;
	}

	return 0;
}

struct command upgrade_command = {
	"upgrade",
	upgrade_cmd,
	upgrade_parser
};

