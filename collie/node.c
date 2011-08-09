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

#include "collie.h"

static void cal_total_vdi_size(uint32_t vid, char *name, char * tag,
			       uint32_t snapid, uint32_t flags,
			       struct sheepdog_inode *i, void *data)
{
	uint64_t *size = data;

	if (is_current(i))
		*size += i->vdi_size;
}

static int node_list(int argc, char **argv)
{
	int i;

	if (!raw_output) {
		printf("   Idx - Host:Port          Vnodes       Zone\n");
		printf("---------------------------------------------\n");
	}
	for (i = 0; i < nr_nodes; i++) {
		char data[128];

		addr_to_str(data, sizeof(data), node_list_entries[i].addr,
			    node_list_entries[i].port);

		if (i == master_idx) {
			if (highlight)
				printf(TEXT_BOLD);
			printf(raw_output ? "* %d %s %d %d\n" : "* %4d - %-20s\t%d%11d\n",
			       i, data, node_list_entries[i].nr_vnodes,
			       node_list_entries[i].zone);
			if (highlight)
				printf(TEXT_NORMAL);
		} else
			printf(raw_output ? "- %d %s %d %d\n" : "  %4d - %-20s\t%d%11d\n",
			       i, data, node_list_entries[i].nr_vnodes,
			       node_list_entries[i].zone);
	}

	return EXIT_SUCCESS;
}

static int node_info(int argc, char **argv)
{
	int i, ret, success = 0;
	uint64_t total_size = 0, total_avail = 0, total_vdi_size = 0;
	char total_str[8], avail_str[8], vdi_size_str[8];

	if (!raw_output)
		printf("Id\tSize\tUsed\tUse%%\n");

	for (i = 0; i < nr_nodes; i++) {
		char name[128];
		int fd;
		unsigned wlen, rlen;
		struct sd_node_req req;
		struct sd_node_rsp *rsp = (struct sd_node_rsp *)&req;
		char store_str[8], free_str[8];

		addr_to_str(name, sizeof(name), node_list_entries[i].addr, 0);

		fd = connect_to(name, node_list_entries[i].port);
		if (fd < 0)
			return 1;

		memset(&req, 0, sizeof(req));

		req.opcode = SD_OP_STAT_SHEEP;
		req.epoch = node_list_version;

		wlen = 0;
		rlen = 0;
		ret = exec_req(fd, (struct sd_req *)&req, NULL, &wlen, &rlen);
		close(fd);

		size_to_str(rsp->store_size, store_str, sizeof(store_str));
		size_to_str(rsp->store_size - rsp->store_free, free_str,
			    sizeof(free_str));
		if (!ret && rsp->result == SD_RES_SUCCESS) {
			printf(raw_output ? "%d %s %s %d%%\n" : "%2d\t%s\t%s\t%3d%%\n",
			       i, store_str, free_str,
			       (int)(((double)(rsp->store_size - rsp->store_free) / rsp->store_size) * 100));
			success++;
		}

		total_size += rsp->store_size;
		total_avail += rsp->store_free;
	}

	if (success == 0) {
		fprintf(stderr, "cannot get information from any nodes\n");
		return EXIT_SYSFAIL;
	}

	parse_vdi(cal_total_vdi_size, SD_INODE_HEADER_SIZE, &total_vdi_size);

	size_to_str(total_size, total_str, sizeof(total_str));
	size_to_str(total_size - total_avail, avail_str, sizeof(avail_str));
	size_to_str(total_vdi_size, vdi_size_str, sizeof(vdi_size_str));
	printf(raw_output ? "Total %s %s %d%% %s\n"
			  : "\nTotal\t%s\t%s\t%3d%%, total virtual VDI Size\t%s\n",
	       total_str, avail_str,
	       (int)(((double)(total_size - total_avail) / total_size) * 100),
	       vdi_size_str);

	return EXIT_SUCCESS;
}

static struct subcommand node_cmd[] = {
	{"list", NULL, "aprh", "list nodes",
	 SUBCMD_FLAG_NEED_NODELIST, node_list},
	{"info", NULL, "aprh", "show each node information",
	 SUBCMD_FLAG_NEED_NODELIST, node_info},
	{NULL,},
};

struct command node_command = {
	"node",
	node_cmd,
};
