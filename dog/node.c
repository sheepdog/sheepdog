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

#include "dog.h"

static struct node_cmd_data {
	bool all_nodes;
	bool recovery_progress;
} node_cmd_data;

static void cal_total_vdi_size(uint32_t vid, const char *name, const char *tag,
			       uint32_t snapid, uint32_t flags,
			       const struct sd_inode *i, void *data)
{
	uint64_t *size = data;

	if (!vdi_is_snapshot(i))
		*size += i->vdi_size;
}

static int node_list(int argc, char **argv)
{
	int i;

	if (!raw_output)
		printf("  Id   Host:Port         V-Nodes       Zone\n");
	for (i = 0; i < sd_nodes_nr; i++) {
		const char *host = addr_to_str(sd_nodes[i].nid.addr,
					       sd_nodes[i].nid.port);

		printf(raw_output ? "%d %s %d %u\n" : "%4d   %-20s\t%2d%11u\n",
		       i, host, sd_nodes[i].nr_vnodes, sd_nodes[i].zone);
	}

	return EXIT_SUCCESS;
}

static int node_info(int argc, char **argv)
{
	int i, ret, success = 0;
	uint64_t total_size = 0, total_avail = 0, total_vdi_size = 0;
	char total_str[UINT64_DECIMAL_SIZE], use_str[UINT64_DECIMAL_SIZE],
	     avail_str[UINT64_DECIMAL_SIZE], vdi_size_str[UINT64_DECIMAL_SIZE];

	if (!raw_output)
		printf("Id\tSize\tUsed\tAvail\tUse%%\n");

	for (i = 0; i < sd_nodes_nr; i++) {
		struct sd_req req;
		struct sd_rsp *rsp = (struct sd_rsp *)&req;
		char store_str[UINT64_DECIMAL_SIZE],
		     used_str[UINT64_DECIMAL_SIZE],
		     free_str[UINT64_DECIMAL_SIZE];

		sd_init_req(&req, SD_OP_STAT_SHEEP);

		ret = send_light_req(&req, sd_nodes[i].nid.addr,
				     sd_nodes[i].nid.port);

		size_to_str(rsp->node.store_size, store_str, sizeof(store_str));
		size_to_str(rsp->node.store_free, free_str, sizeof(free_str));
		size_to_str(rsp->node.store_size - rsp->node.store_free,
			    used_str, sizeof(used_str));
		if (!ret) {
			int ratio = (int)(((double)(rsp->node.store_size -
						    rsp->node.store_free) /
					   rsp->node.store_size) * 100);
			printf(raw_output ? "%d %s %s %s %d%%\n" :
					"%2d\t%s\t%s\t%s\t%3d%%\n",
			       i, store_str, used_str, free_str,
			       rsp->node.store_size == 0 ? 0 : ratio);
			success++;
		}

		total_size += rsp->node.store_size;
		total_avail += rsp->node.store_free;
	}

	if (success == 0) {
		sd_err("Cannot get information from any nodes");
		return EXIT_SYSFAIL;
	}

	if (parse_vdi(cal_total_vdi_size, SD_INODE_HEADER_SIZE,
			&total_vdi_size) < 0)
		return EXIT_SYSFAIL;

	size_to_str(total_size, total_str, sizeof(total_str));
	size_to_str(total_avail, avail_str, sizeof(avail_str));
	size_to_str(total_size - total_avail, use_str, sizeof(use_str));
	size_to_str(total_vdi_size, vdi_size_str, sizeof(vdi_size_str));
	printf(raw_output ? "Total %s %s %s %d%% %s\n"
			  : "Total\t%s\t%s\t%s\t%3d%%\n\n"
			  "Total virtual image size\t%s\n",
	       total_str, use_str, avail_str,
	       (int)(((double)(total_size - total_avail) / total_size) * 100),
	       vdi_size_str);

	return EXIT_SUCCESS;
}

static int get_recovery_state(struct recovery_state *state)
{
	int ret;
	struct sd_req req;

	sd_init_req(&req, SD_OP_STAT_RECOVERY);
	req.data_length = sizeof(*state);

	ret = dog_exec_req(sdhost, sdport, &req, state);
	if (ret < 0) {
		sd_err("Failed to execute request");
		return -1;
	}

	return 0;
}

static int node_recovery_progress(void)
{
	int result;
	unsigned int prev_nr_total;
	struct recovery_state rstate;

	/*
	 * ToDos
	 *
	 * 1. Calculate size of actually copied objects.
	 *    For doing this, not so trivial changes for recovery process are
	 *    required.
	 *
	 * 2. Print remaining physical time.
	 *    Even if it is not so acculate, the information is helpful for
	 *    administrators.
	 */

	result = get_recovery_state(&rstate);
	if (result < 0)
		return EXIT_SYSFAIL;

	if (!rstate.in_recovery)
		return EXIT_SUCCESS;

	do {
		prev_nr_total = rstate.nr_total;

		result = get_recovery_state(&rstate);
		if (result < 0)
			break;

		if (!rstate.in_recovery) {
			show_progress(prev_nr_total, prev_nr_total, true);
			break;
		}

		switch (rstate.state) {
		case RW_PREPARE_LIST:
			printf("\rpreparing a checked object list...");
			break;
		case RW_NOTIFY_COMPLETION:
			printf("\rnotifying a completion of recovery...");
			break;
		case RW_RECOVER_OBJ:
			show_progress(rstate.nr_finished, rstate.nr_total,
				      true);
			break;
		default:
			panic("unknown state of recovery: %d", rstate.state);
			break;
		}

		sleep(1);
	} while (true);

	return result < 0 ? EXIT_SYSFAIL : EXIT_SUCCESS;
}

static int node_recovery(int argc, char **argv)
{
	int i, ret;

	if (node_cmd_data.recovery_progress)
		return node_recovery_progress();

	if (!raw_output) {
		printf("Nodes In Recovery:\n");
		printf("  Id   Host:Port         V-Nodes       Zone"
		       "       Progress\n");
	}

	for (i = 0; i < sd_nodes_nr; i++) {
		struct sd_req req;
		struct recovery_state state;

		memset(&state, 0, sizeof(state));

		sd_init_req(&req, SD_OP_STAT_RECOVERY);
		req.data_length = sizeof(state);

		ret = dog_exec_req(sd_nodes[i].nid.addr,
				      sd_nodes[i].nid.port, &req, &state);
		if (ret < 0)
			return EXIT_SYSFAIL;

		if (state.in_recovery) {
			const char *host = addr_to_str(sd_nodes[i].nid.addr,
						       sd_nodes[i].nid.port);
			if (raw_output)
				printf("%d %s %d %d %"PRIu64" %"PRIu64"\n", i,
				       host, sd_nodes[i].nr_vnodes,
				       sd_nodes[i].zone, state.nr_finished,
				       state.nr_total);
			else
				printf("%4d   %-20s%5d%11d%11.1f%%\n", i, host,
				       sd_nodes[i].nr_vnodes, sd_nodes[i].zone,
				       100 * (float)state.nr_finished
				       / state.nr_total);
		}
	}

	return EXIT_SUCCESS;
}

static int node_kill(int argc, char **argv)
{
	int node_id, ret;
	struct sd_req req;
	const char *p = argv[optind++];

	if (!is_numeric(p)) {
		sd_err("Invalid node id '%s', please specify a numeric value",
		       p);
		exit(EXIT_USAGE);
	}

	node_id = strtol(p, NULL, 10);
	if (node_id < 0 || node_id >= sd_nodes_nr) {
		sd_err("Invalid node id '%d'", node_id);
		exit(EXIT_USAGE);
	}

	sd_init_req(&req, SD_OP_KILL_NODE);

	ret = send_light_req(&req, sd_nodes[node_id].nid.addr,
			     sd_nodes[node_id].nid.port);
	if (ret) {
		sd_err("Failed to execute request");
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

static int node_md_info(struct node_id *nid)
{
	struct sd_md_info info = {};
	char size_str[UINT64_DECIMAL_SIZE], used_str[UINT64_DECIMAL_SIZE],
	     avail_str[UINT64_DECIMAL_SIZE];
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret, i;

	sd_init_req(&hdr, SD_OP_MD_INFO);
	hdr.data_length = sizeof(info);

	ret = dog_exec_req(nid->addr, nid->port, &hdr, &info);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("failed to get multi-disk infomation: %s",
		       sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	for (i = 0; i < info.nr; i++) {
		uint64_t size = info.disk[i].free + info.disk[i].used;
		int ratio = (int)(((double)info.disk[i].used / size) * 100);

		size_to_str(size, size_str, sizeof(size_str));
		size_to_str(info.disk[i].used, used_str, sizeof(used_str));
		size_to_str(info.disk[i].free, avail_str, sizeof(avail_str));
		fprintf(stdout, "%2d\t%s\t%s\t%s\t%3d%%\t%s\n",
			info.disk[i].idx, size_str, used_str, avail_str, ratio,
			info.disk[i].path);
	}
	return EXIT_SUCCESS;
}

static int md_info(int argc, char **argv)
{
	int i, ret;

	fprintf(stdout, "Id\tSize\tUsed\tAvail\tUse%%\tPath\n");

	if (!node_cmd_data.all_nodes) {
		struct node_id nid = {.port = sdport};

		memcpy(nid.addr, sdhost, sizeof(nid.addr));

		return node_md_info(&nid);
	}

	for (i = 0; i < sd_nodes_nr; i++) {
		fprintf(stdout, "Node %d:\n", i);
		ret = node_md_info(&sd_nodes[i].nid);
		if (ret != EXIT_SUCCESS)
			return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int do_plug_unplug(char *disks, bool plug)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret;

	if (!strlen(disks)) {
		sd_err("Empty path isn't allowed");
		return EXIT_FAILURE;
	}

	if (plug)
		sd_init_req(&hdr, SD_OP_MD_PLUG);
	else
		sd_init_req(&hdr, SD_OP_MD_UNPLUG);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = strlen(disks) + 1;

	ret = dog_exec_req(sdhost, sdport, &hdr, disks);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Failed to execute request, look for sheep.log"
		       " for more information");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int md_plug(int argc, char **argv)
{
	return do_plug_unplug(argv[optind], true);
}

static int md_unplug(int argc, char **argv)
{
	return do_plug_unplug(argv[optind], false);
}

static struct subcommand node_md_cmd[] = {
	{"info", NULL, NULL, "show multi-disk information",
	 NULL, CMD_NEED_NODELIST, md_info},
	{"plug", NULL, NULL, "plug more disk(s) into node",
	 NULL, CMD_NEED_ARG, md_plug},
	{"unplug", NULL, NULL, "unplug disk(s) from node",
	 NULL, CMD_NEED_ARG, md_unplug},
	{NULL},
};

static int node_md(int argc, char **argv)
{
	return do_generic_subcommand(node_md_cmd, argc, argv);
}


static int node_parser(int ch, char *opt)
{
	switch (ch) {
	case 'A':
		node_cmd_data.all_nodes = true;
		break;
	case 'P':
		node_cmd_data.recovery_progress = true;
		break;
	}

	return 0;
}

static struct sd_option node_options[] = {
	{'A', "all", false, "show md information of all the nodes"},
	{'P', "progress", false, "show progress of recovery in the node"},

	{ 0, NULL, false, NULL },
};

static struct subcommand node_cmd[] = {
	{"kill", "<node id>", "aprh", "kill node", NULL,
	 CMD_NEED_ARG | CMD_NEED_NODELIST, node_kill},
	{"list", NULL, "aprh", "list nodes", NULL,
	 CMD_NEED_NODELIST, node_list},
	{"info", NULL, "aprh", "show information about each node", NULL,
	 CMD_NEED_NODELIST, node_info},
	{"recovery", NULL, "aphPr", "show recovery information of nodes", NULL,
	 CMD_NEED_NODELIST, node_recovery, node_options},
	{"md", "[disks]", "apAh", "See 'dog node md' for more information",
	 node_md_cmd, CMD_NEED_ARG, node_md, node_options},
	{NULL,},
};

struct command node_command = {
	"node",
	node_cmd,
	node_parser
};
