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
		char host[128];
		struct sd_node_req req;
		struct sd_node_rsp *rsp = (struct sd_node_rsp *)&req;
		char store_str[UINT64_DECIMAL_SIZE], free_str[UINT64_DECIMAL_SIZE];

		addr_to_str(host, sizeof(host), sd_nodes[i].nid.addr, 0);

		sd_init_req((struct sd_req *)&req, SD_OP_STAT_SHEEP);
		req.epoch = sd_epoch;

		ret = send_light_req((struct sd_req *)&req, host,
				     sd_nodes[i].nid.port);

		size_to_str(rsp->store_size, store_str, sizeof(store_str));
		size_to_str(rsp->store_size - rsp->store_free, free_str,
			    sizeof(free_str));
		if (!ret) {
			printf(raw_output ? "%d %s %s %d%%\n" : "%2d\t%s\t%s\t%3d%%\n",
			       i, store_str, free_str,
			       rsp->store_size == 0 ? 0 :
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
		struct sd_node_req req;

		addr_to_str(host, sizeof(host), sd_nodes[i].nid.addr, 0);

		sd_init_req((struct sd_req *)&req, SD_OP_STAT_RECOVERY);

		ret = send_light_req_get_response((struct sd_req *)&req, host,
						  sd_nodes[i].nid.port);
		if (ret == SD_RES_NODE_IN_RECOVERY) {
			addr_to_str(host, sizeof(host),
					sd_nodes[i].nid.addr, sd_nodes[i].nid.port);
			printf(raw_output ? "%d %s %d %d\n" : "%4d   %-20s%5d%11d\n",
				   i, host, sd_nodes[i].nr_vnodes,
				   sd_nodes[i].zone);
		}
	}

	return EXIT_SUCCESS;
}

static int node_cache(int argc, char **argv)
{
	char *p;
	int fd, ret;
	uint32_t cache_size;
	unsigned int wlen, rlen = 0;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

	cache_size = strtol(argv[optind], &p, 10);
	if (argv[optind] == p || cache_size < 0) {
		fprintf(stderr, "Invalid cache size %s\n", argv[optind]);
		return EXIT_FAILURE;
	}

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return EXIT_FAILURE;

	wlen = sizeof(cache_size);

	sd_init_req(&hdr, SD_OP_SET_CACHE_SIZE);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = wlen;

	ret = exec_req(fd, &hdr, (void *)&cache_size, &wlen, &rlen);
	close(fd);

	if (ret) {
		fprintf(stderr, "Failed to connect\n");
		return EXIT_FAILURE;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "specify max cache size failed: %s\n",
				sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	printf("Max cache size set to %dM\n", cache_size);

	return EXIT_SUCCESS;
}

static int node_kill(int argc, char **argv)
{
	char host[128];
	int node_id, ret;
	struct sd_node_req req;

	node_id = strtol(argv[optind++], NULL, 10);
	if (node_id < 0 || node_id >= sd_nodes_nr) {
		fprintf(stderr, "Invalid node id '%d'\n", node_id);
		exit(EXIT_USAGE);
	}

	addr_to_str(host, sizeof(host), sd_nodes[node_id].nid.addr, 0);

	sd_init_req((struct sd_req *)&req, SD_OP_KILL_NODE);

	ret = send_light_req((struct sd_req *)&req, host,
			     sd_nodes[node_id].nid.port);
	if (ret) {
		fprintf(stderr, "Failed to execute request\n");
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

static struct subcommand node_cmd[] = {
	{"kill", "<node id>", "aprh", "kill node", NULL,
	 SUBCMD_FLAG_NEED_THIRD_ARG, node_kill},
	{"list", NULL, "aprh", "list nodes", NULL,
	 SUBCMD_FLAG_NEED_NODELIST, node_list},
	{"info", NULL, "aprh", "show information about each node", NULL,
	 SUBCMD_FLAG_NEED_NODELIST, node_info},
	{"recovery", NULL, "aprh", "show nodes in recovery", NULL,
	 SUBCMD_FLAG_NEED_NODELIST, node_recovery},
	{"cache", "<cache size>", "aprh", "specify max cache size", NULL,
	 SUBCMD_FLAG_NEED_THIRD_ARG, node_cache},
	{NULL,},
};

struct command node_command = {
	"node",
	node_cmd,
};
