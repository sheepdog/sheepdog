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

static int upgrade_epoch_convert(int argc, char **argv)
{
	const char *orig_file = argv[optind++], *dst_file = NULL;
	struct stat epoch_stat;
	time_t timestamp;
	int fd, new_fd, buf_len, ret, nr_nodes;
	struct sd_node_0_7 *nodes_0_7 = NULL;
	struct sd_node_0_8 *nodes_0_8 = NULL;
	int node_size = -1;
	struct sd_node *new_nodes;

	if (optind < argc)
		dst_file = argv[optind++];
	else {
		sd_info("please specify destination file path");
		return EXIT_USAGE;
	}

	if (upgrade_cmd_data.orig == ORIG_VERSION_0_7)
		node_size = sizeof(struct sd_node_0_7);
	else if (upgrade_cmd_data.orig == ORIG_VERSION_0_8)
		node_size = sizeof(struct sd_node_0_8);
	else {
		sd_info("please specify original version of epoch file");
		return EXIT_USAGE;
	}

	fd = open(orig_file, O_RDONLY);
	if (fd < 0) {
		sd_err("failed to open epoch log file: %m");
		return EXIT_SYSFAIL;
	}

	memset(&epoch_stat, 0, sizeof(epoch_stat));
	ret = fstat(fd, &epoch_stat);
	if (ret < 0) {
		sd_err("failed to stat epoch log file: %m");
		return EXIT_SYSFAIL;
	}

	buf_len = epoch_stat.st_size - sizeof(timestamp);
	if (buf_len < 0) {
		sd_err("invalid epoch log file: %m");
		return EXIT_SYSFAIL;
	}

	if (upgrade_cmd_data.orig == ORIG_VERSION_0_7) {
		nodes_0_7 = xzalloc(buf_len);
		ret = xread(fd, nodes_0_7, buf_len);
	} else {
		sd_assert(upgrade_cmd_data.orig == ORIG_VERSION_0_8);
		nodes_0_8 = xzalloc(buf_len);
		ret = xread(fd, nodes_0_8, buf_len);
	}

	if (ret < 0) {
		sd_err("failed to read epoch log file: %m");
		return EXIT_SYSFAIL;
	}

	if (ret % node_size != 0) {
		sd_err("invalid epoch log file size");
		return EXIT_SYSFAIL;
	}

	nr_nodes = ret / node_size;
	new_nodes = xcalloc(nr_nodes, sizeof(struct sd_node));

	ret = xread(fd, &timestamp, sizeof(timestamp));
	if (ret != sizeof(timestamp)) {
		sd_err("invalid epoch log file, failed to read timestamp: %m");
		return EXIT_SYSFAIL;
	}

	for (int i = 0; i < nr_nodes; i++) {
		if (upgrade_cmd_data.orig == ORIG_VERSION_0_7) {
			memcpy(&new_nodes[i].nid, &nodes_0_7[i].nid,
			       sizeof(struct node_id));
			new_nodes[i].nr_vnodes = nodes_0_7[i].nr_vnodes;
			new_nodes[i].zone = nodes_0_7[i].zone;
			new_nodes[i].space = nodes_0_7[i].space;
		} else {
			sd_assert(upgrade_cmd_data.orig == ORIG_VERSION_0_8);

			memcpy(&new_nodes[i].nid, &nodes_0_8[i].nid,
			       sizeof(struct node_id));
			new_nodes[i].nr_vnodes = nodes_0_8[i].nr_vnodes;
			new_nodes[i].zone = nodes_0_8[i].zone;
			new_nodes[i].space = nodes_0_8[i].space;
		}
	}

	new_fd = open(dst_file, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (new_fd < 0) {
		sd_err("failed to create a new epoch log file: %m");
		return EXIT_SYSFAIL;
	}

	ret = xwrite(new_fd, new_nodes, sizeof(struct sd_node) * nr_nodes);
	if (ret != sizeof(struct sd_node) * nr_nodes) {
		sd_err("failed to write node list to a new epoch log file: %m");
		return EXIT_SYSFAIL;
	}

	ret = xwrite(new_fd, &timestamp, sizeof(timestamp));
	if (ret != sizeof(timestamp)) {
		sd_err("failed to write timestamp to a new epoch log file: %m");
		return EXIT_SYSFAIL;
	}

	sd_info("number of vnodes of each nodes:");
	for (int i = 0; i < nr_nodes; i++)
		sd_info("\t%s == %"PRIu16, node_to_str(&new_nodes[i]),
			new_nodes[i].nr_vnodes);

	sd_info("please supply the above numbers to sheeps with -V option");

	return EXIT_SUCCESS;
}

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
	{"epoch-convert", "<path of original epoch log file>"
	 " <path of new epoch log file>",
	 "hTo", "upgrade epoch log file",
	 NULL, CMD_NEED_ARG, upgrade_epoch_convert, upgrade_options},
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

