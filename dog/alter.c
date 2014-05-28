/*
 * Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <time.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>

#include "dog.h"
#include "treeview.h"

static struct sd_option alter_options[] = {
	{'c', "copies", true, "specify the data redundancy level"},
	{ 0, NULL, false, NULL },
};

static struct alter_cmd_data {
	uint8_t copies;
	uint8_t copy_policy;
} alter_cmd_data;

#define ALTER_CLUSTER_COPY_PRINT				\
	"    __\n"				\
	"   ()'`;\n"				\
	"   /\\|`  Caution! Changing cluster's redundancy level will affect\n" \
	"  /  |   all the VDIs to be created later.\n" \
	"(/_)_|_  Are you sure you want to continue? [yes/no]: "

static int alter_cluster_copy(int argc, char **argv)
{
	int ret, log_length;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	struct epoch_log *logs;

	if (alter_cmd_data.copy_policy != 0) {
		sd_err("Changing redundancy level of erasure coded vdi "
			   "is not supported yet.");
		return EXIT_USAGE;
	}
	if (!alter_cmd_data.copies) {
		alter_cmd_data.copies = SD_DEFAULT_COPIES;
		printf("The cluster's redundancy level is not specified, "
			   "use %d as default.\n", SD_DEFAULT_COPIES);
	}

	if (alter_cmd_data.copies > sd_nodes_nr) {
		char info[1024];
		snprintf(info, sizeof(info), "Number of copies (%d) is larger "
			 "than number of nodes (%d).\n"
			 "Are you sure you want to continue? [yes/no]: ",
			 alter_cmd_data.copies, sd_nodes_nr);
		confirm(info);
	}

	log_length = sd_epoch * sizeof(struct epoch_log);
	logs = xmalloc(log_length);
	sd_init_req(&hdr, SD_OP_STAT_CLUSTER);
	hdr.data_length = log_length;
	ret = dog_exec_req(&sd_nid, &hdr, logs);
	if (ret < 0)
		goto failure;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Response's result: %s", sd_strerror(rsp->result));
		goto failure;
	}
	if (logs->copy_policy) {
		sd_err("The cluster's copy policy is erasure code, "
			   "changing it is not supported yet.");
		goto failure;
	}
	if (logs->nr_copies == alter_cmd_data.copies) {
		sd_err("The cluster's redundancy level is already set to %d, "
			   "nothing changed.", alter_cmd_data.copies);
		goto failure;
	}

	confirm(ALTER_CLUSTER_COPY_PRINT);

	sd_init_req(&hdr, SD_OP_ALTER_CLUSTER_COPY);
	hdr.cluster.copies = alter_cmd_data.copies;
	hdr.cluster.copy_policy = alter_cmd_data.copy_policy;
	ret = send_light_req(&sd_nid, &hdr);
	if (ret == 0) {
		sd_info("The cluster's redundancy level is set to %d, "
				"the old one was %d.",
				alter_cmd_data.copies, logs->nr_copies);
		goto success;
	} else {
		sd_err("Changing the cluster's redundancy level failure.");
		goto failure;
	}

success:
	free(logs);
	return EXIT_SUCCESS;
failure:
	free(logs);
	return EXIT_FAILURE;
}

static void construct_vdi_tree(uint32_t vid, const char *name, const char *tag,
			       uint32_t snapid, uint32_t flags,
			       const struct sd_inode *i, void *data)
{
	add_vdi_tree(name, tag, vid, i->parent_vdi_id, false);
}

static bool is_vdi_standalone(uint32_t vid, const char *name)
{
	struct vdi_tree *vdi;

	init_tree();
	if (parse_vdi(construct_vdi_tree, SD_INODE_HEADER_SIZE, NULL) < 0)
		return EXIT_SYSFAIL;

	vdi = find_vdi_from_root(vid, name);
	if (!vdi) {
		sd_err("failed to construct vdi tree");
		return false;
	}

	return !vdi->pvid && list_empty(&vdi->children);
}

#define ALTER_VDI_COPY_PRINT				\
	"    __\n"				\
	"   ()'`;\n"				\
	"   /\\|`  Caution! Changing VDI's redundancy level will affect\n" \
	"  /  |   the VDI itself only and trigger recovery.\n" \
	"(/_)_|_  Are you sure you want to continue? [yes/no]: "

static int alter_vdi_copy(int argc, char **argv)
{
	int ret, old_nr_copies;
	uint32_t vid;
	const char *vdiname = argv[optind++];
	char buf[SD_INODE_HEADER_SIZE];
	struct sd_inode *inode = (struct sd_inode *)buf;
	struct sd_req hdr;

	if (alter_cmd_data.copy_policy != 0) {
		sd_err("Changing redundancy level of erasure coded vdi "
			   "is not supported yet.");
		return EXIT_USAGE;
	}
	if (!alter_cmd_data.copies) {
		alter_cmd_data.copies = SD_DEFAULT_COPIES;
		printf("The vdi's redundancy level is not specified, "
			   "use %d as default.\n", SD_DEFAULT_COPIES);
	}

	if (alter_cmd_data.copies > sd_nodes_nr) {
		char info[1024];
		snprintf(info, sizeof(info), "Number of copies (%d) is larger "
			 "than number of nodes (%d).\n"
			 "Are you sure you want to continue? [yes/no]: ",
			 alter_cmd_data.copies, sd_nodes_nr);
		confirm(info);
	}

	ret = read_vdi_obj(vdiname, 0, "", &vid, inode, SD_INODE_HEADER_SIZE);
	if (ret != EXIT_SUCCESS) {
		sd_err("Reading %s's vdi object failure.", vdiname);
		return EXIT_FAILURE;
	}

	if (inode->copy_policy) {
		sd_err("%s's copy policy is erasure code, "
			   "changing it is not supported yet.", vdiname);
		return EXIT_FAILURE;
	}

	old_nr_copies = inode->nr_copies;
	if (old_nr_copies == alter_cmd_data.copies) {
		sd_err("%s's redundancy level is already set to %d, "
			   "nothing changed.", vdiname, old_nr_copies);
		return EXIT_FAILURE;
	}

	if (!is_vdi_standalone(vid, inode->name)) {
		sd_err("Only standalone vdi supports "
			   "changing redundancy level.");
		sd_err("Please clone %s with -n (--no-share) "
			   "option first.", vdiname);
		return EXIT_FAILURE;
	}

	confirm(ALTER_VDI_COPY_PRINT);

	inode->nr_copies = alter_cmd_data.copies;
	ret = dog_write_object(vid_to_vdi_oid(vid), 0, inode,
			SD_INODE_HEADER_SIZE, 0, 0, old_nr_copies,
			inode->copy_policy, false, true);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Overwrite the vdi object's header of %s failure "
			   "while setting its redundancy level.", vdiname);
		return EXIT_FAILURE;
	}

	sd_init_req(&hdr, SD_OP_ALTER_VDI_COPY);
	hdr.vdi_state.new_vid = vid;
	hdr.vdi_state.copies = alter_cmd_data.copies;
	hdr.vdi_state.copy_policy = alter_cmd_data.copy_policy;

	ret = send_light_req(&sd_nid, &hdr);
	if (ret == 0) {
		sd_info("%s's redundancy level is set to %d, the old one was %d.",
				vdiname, alter_cmd_data.copies, old_nr_copies);
		return EXIT_SUCCESS;
	}
	sd_err("Changing %s's redundancy level failure.", vdiname);
	return EXIT_FAILURE;
}

static struct subcommand alter_cmd[] = {
	{"cluster-copy", NULL, "caph", "set the cluster's redundancy level",
	 NULL, CMD_NEED_NODELIST, alter_cluster_copy, alter_options},
	{"vdi-copy", "<vdiname>", "caph", "set the vdi's redundancy level",
	 NULL, CMD_NEED_ARG|CMD_NEED_NODELIST, alter_vdi_copy, alter_options},
	{NULL,},
};

static int alter_parser(int ch, const char *opt)
{
	switch (ch) {
	case 'c':
		alter_cmd_data.copies =
			parse_copy(opt, &alter_cmd_data.copy_policy);
		if (!alter_cmd_data.copies) {
			sd_err("Invalid redundancy level %s.", opt);
			exit(EXIT_FAILURE);
		}
		break;
	}

	return 0;
}

struct command alter_command = {
	"alter",
	alter_cmd,
	alter_parser
};
