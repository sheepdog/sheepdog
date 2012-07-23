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

	if (!raw_output)
		printf("M   Id   Host:Port         V-Nodes       Zone\n");
	for (i = 0; i < sd_nodes_nr; i++) {
		char data[128];

		addr_to_str(data, sizeof(data), sd_nodes[i].nid.addr,
			    sd_nodes[i].nid.port);

		if (i == master_idx) {
			if (highlight)
				printf(TEXT_BOLD);
			printf(raw_output ? "* %d %s %d %d\n" : "* %4d   %-20s\t%2d%11d\n",
			       i, data, sd_nodes[i].nr_vnodes,
			       sd_nodes[i].zone);
			if (highlight)
				printf(TEXT_NORMAL);
		} else
			printf(raw_output ? "- %d %s %d %d\n" : "- %4d   %-20s\t%2d%11d\n",
			       i, data, sd_nodes[i].nr_vnodes,
			       sd_nodes[i].zone);
	}

	return EXIT_SUCCESS;
}

static int node_info(int argc, char **argv)
{
	int i, ret, success = 0;
	uint64_t total_size = 0, total_avail = 0, total_vdi_size = 0;
	char total_str[UINT64_DECIMAL_SIZE], avail_str[UINT64_DECIMAL_SIZE], vdi_size_str[UINT64_DECIMAL_SIZE];

	if (!raw_output)
		printf("Id\tSize\tUsed\tUse%%\n");

	for (i = 0; i < sd_nodes_nr; i++) {
		char name[128];
		int fd;
		unsigned wlen, rlen;
		struct sd_node_req req;
		struct sd_node_rsp *rsp = (struct sd_node_rsp *)&req;
		char store_str[UINT64_DECIMAL_SIZE], free_str[UINT64_DECIMAL_SIZE];

		addr_to_str(name, sizeof(name), sd_nodes[i].nid.addr, 0);

		fd = connect_to(name, sd_nodes[i].nid.port);
		if (fd < 0)
			return 1;

		sd_init_req((struct sd_req *)&req, SD_OP_STAT_SHEEP);
		req.epoch = sd_epoch;

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
		fprintf(stderr, "Cannot get information from any nodes\n");
		return EXIT_SYSFAIL;
	}

	if (parse_vdi(cal_total_vdi_size, SD_INODE_HEADER_SIZE,
			&total_vdi_size) < 0)
		return EXIT_SYSFAIL;

	size_to_str(total_size, total_str, sizeof(total_str));
	size_to_str(total_size - total_avail, avail_str, sizeof(avail_str));
	size_to_str(total_vdi_size, vdi_size_str, sizeof(vdi_size_str));
	printf(raw_output ? "Total %s %s %d%% %s\n"
			  : "Total\t%s\t%s\t%3d%%\n\nTotal virtual image size\t%s\n",
	       total_str, avail_str,
	       (int)(((double)(total_size - total_avail) / total_size) * 100),
	       vdi_size_str);

	return EXIT_SUCCESS;
}

static int node_recovery(int argc, char **argv)
{
	int i, ret;

	if (!raw_output) {
		printf("Nodes In Recovery:\n");
		printf("  Id   Host:Port         V-Nodes       Zone\n");
	}

	for (i = 0; i < sd_nodes_nr; i++) {
		char host[128];
		int fd;
		unsigned wlen, rlen;
		struct sd_node_req req;
		struct sd_node_rsp *rsp = (struct sd_node_rsp *)&req;

		addr_to_str(host, sizeof(host), sd_nodes[i].nid.addr, 0);

		fd = connect_to(host, sd_nodes[i].nid.port);
		if (fd < 0)
			return EXIT_FAILURE;

		sd_init_req((struct sd_req *)&req, SD_OP_STAT_RECOVERY);

		wlen = 0;
		rlen = 0;
		ret = exec_req(fd, (struct sd_req *)&req, NULL, &wlen, &rlen);
		close(fd);

		if (!ret && rsp->result == SD_RES_SUCCESS) {
			addr_to_str(host, sizeof(host),
					sd_nodes[i].nid.addr, sd_nodes[i].nid.port);
			printf(raw_output ? "%d %s %d %d\n" : "%4d   %-20s%5d%11d\n",
				   i, host, sd_nodes[i].nr_vnodes,
				   sd_nodes[i].zone);
		}
	}

	return EXIT_SUCCESS;
}

static int node_kill(int argc, char **argv)
{
	char host[128];
	int fd, node_id, ret;
	unsigned wlen, rlen;
	struct sd_node_req req;
	struct sd_node_rsp *rsp = (struct sd_node_rsp *)&req;

	node_id = strtol(argv[optind++], NULL, 10);
	if (node_id < 0 || node_id >= sd_nodes_nr) {
		fprintf(stderr, "Invalid node id '%d'\n", node_id);
		exit(EXIT_USAGE);
	}

	addr_to_str(host, sizeof(host), sd_nodes[node_id].nid.addr, 0);

	fd = connect_to(host, sd_nodes[node_id].nid.port);
	if (fd < 0)
		return EXIT_FAILURE;

	sd_init_req((struct sd_req *)&req, SD_OP_KILL_NODE);

	wlen = 0;
	rlen = 0;
	ret = exec_req(fd, (struct sd_req *)&req, NULL, &wlen, &rlen);
	close(fd);

	if (ret || rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to execute request\n");
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

static struct subcommand node_cmd[] = {
	{"kill", "<node id>", "aprh", "kill node",
	 SUBCMD_FLAG_NEED_NODELIST|SUBCMD_FLAG_NEED_THIRD_ARG, node_kill},
	{"list", NULL, "aprh", "list nodes",
	 SUBCMD_FLAG_NEED_NODELIST, node_list},
	{"info", NULL, "aprh", "show information about each node",
	 SUBCMD_FLAG_NEED_NODELIST, node_info},
	{"recovery", NULL, "aprh", "show nodes in recovery",
	 SUBCMD_FLAG_NEED_NODELIST, node_recovery},
	{NULL,},
};

struct command node_command = {
	"node",
	node_cmd,
};
