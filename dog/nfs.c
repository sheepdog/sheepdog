/*
 * Copyright (C) 2014 Taobao Inc.
 *
 * Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "dog.h"

static int nfs_create_delete(char *name, bool create)
{
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

	if (create)
		sd_init_req(&hdr, SD_OP_NFS_CREATE);
	else
		sd_init_req(&hdr, SD_OP_NFS_DELETE);

	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = strlen(name) + 1;
	ret = dog_exec_req(&sd_nid, &hdr, name);
	if (ret < 0)
		return EXIT_SYSFAIL;

	switch (rsp->result) {
	case SD_RES_SUCCESS:
		break;
	default:
		sd_err("failed to create nfs %s, %s", name,
		       sd_strerror(rsp->result));
		return EXIT_SYSFAIL;
	}

	return EXIT_SUCCESS;
}

static int nfs_create(int argc, char **argv)
{
	return nfs_create_delete(argv[optind], true);
}

static int nfs_delete(int argc, char **argv)
{
	return nfs_create_delete(argv[optind], false);
}

static int nfs_parser(int ch, const char *opt)
{
	return 0;
}

static struct subcommand nfs_cmd[] = {
	{"create", "<name>", "aph", "create a NFS file system", NULL,
	 CMD_NEED_ARG, nfs_create},
	{"delete", "<name>", "aph", "delete a NFS file system", NULL,
	 CMD_NEED_ARG, nfs_delete},
	{NULL},
};

struct command nfs_command = {
	"nfs",
	nfs_cmd,
	nfs_parser,
};
