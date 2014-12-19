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
	bool watch;
	bool local;
	bool force;
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
	struct sd_node *n;
	int i = 0;

	if (!raw_output)
		printf("  Id   Host:Port         V-Nodes       Zone\n");
	rb_for_each_entry(n, &sd_nroot, rb) {
		const char *host = addr_to_str(n->nid.addr, n->nid.port);

		printf(raw_output ? "%d %s %d %u\n" : "%4d   %-20s\t%2d%11u\n",
		       i++, host, n->nr_vnodes, n->zone);
	}

	return EXIT_SUCCESS;
}

static int node_info(int argc, char **argv)
{
	int ret, success = 0, i = 0;
	uint64_t total_size = 0, total_avail = 0, total_vdi_size = 0;
	struct sd_node *n;

	if (!raw_output)
		printf("Id\tSize\tUsed\tAvail\tUse%%\n");

	rb_for_each_entry(n, &sd_nroot, rb) {
		struct sd_req req;
		struct sd_rsp *rsp = (struct sd_rsp *)&req;

		sd_init_req(&req, SD_OP_STAT_SHEEP);

		ret = send_light_req(&n->nid, &req);
		if (!ret) {
			int ratio = (int)(((double)(rsp->node.store_size -
						    rsp->node.store_free) /
					   rsp->node.store_size) * 100);
			printf(raw_output ? "%d %s %s %s %d%%\n" :
					"%2d\t%s\t%s\t%s\t%3d%%\n",
			       i++,
			       strnumber(rsp->node.store_size),
			       strnumber(rsp->node.store_size -
					   rsp->node.store_free),
			       strnumber(rsp->node.store_free),
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
			&total_vdi_size, true) < 0)
		return EXIT_SYSFAIL;

	printf(raw_output ? "Total %s %s %s %d%% %s\n"
			  : "Total\t%s\t%s\t%s\t%3d%%\n\n"
			  "Total virtual image size\t%s\n",
	       strnumber(total_size),
	       strnumber(total_size - total_avail),
	       strnumber(total_avail),
	       (int)(((double)(total_size - total_avail) / total_size) * 100),
	       strnumber(total_vdi_size));

	return EXIT_SUCCESS;
}

static int get_recovery_state(struct recovery_state *state)
{
	int ret;
	struct sd_req req;
	struct sd_rsp *rsp = (struct sd_rsp *)&req;

	sd_init_req(&req, SD_OP_STAT_RECOVERY);
	req.data_length = sizeof(*state);

	ret = dog_exec_req(&sd_nid, &req, state);
	if (ret < 0) {
		sd_err("Failed to execute request");
		return -1;
	}
	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("%s", sd_strerror(rsp->result));
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
	 *    Even if it is not so accurate, the information is helpful for
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

static int node_recovery_info(int argc, char **argv)
{
	struct sd_node *n;
	int ret, i = 0;

	if (node_cmd_data.recovery_progress)
		return node_recovery_progress();

	if (!raw_output) {
		printf("Nodes In Recovery:\n");
		printf("  Id   Host:Port         V-Nodes       Zone"
		       "       Progress\n");
	}

	rb_for_each_entry(n, &sd_nroot, rb) {
		struct sd_req req;
		struct sd_rsp *rsp = (struct sd_rsp *)&req;
		struct recovery_state state;

		memset(&state, 0, sizeof(state));

		sd_init_req(&req, SD_OP_STAT_RECOVERY);
		req.data_length = sizeof(state);

		ret = dog_exec_req(&n->nid, &req, &state);
		if (ret < 0)
			return EXIT_SYSFAIL;
		if (rsp->result != SD_RES_SUCCESS) {
			sd_err("%s", sd_strerror(rsp->result));
			return EXIT_FAILURE;
		}

		if (state.in_recovery) {
			const char *host = addr_to_str(n->nid.addr,
						       n->nid.port);
			if (raw_output)
				printf("%d %s %d %d %"PRIu64" %"PRIu64"\n", i,
				       host, n->nr_vnodes,
				       n->zone, state.nr_finished,
				       state.nr_total);
			else
				printf("%4d   %-20s%5d%11d%11.1f%%\n", i, host,
				       n->nr_vnodes, n->zone,
				       100 * (float)state.nr_finished
				       / state.nr_total);
		}
		i++;
	}

	return EXIT_SUCCESS;
}

static int node_recovery_set(int argc, char **argv)
{
	char *p;
	struct recovery_throttling *rthrottling;

	rthrottling = xmalloc(sizeof(struct recovery_throttling));

	if (!argv[optind] || !argv[optind + 1]) {
		sd_err("Invalid interval max (%s), interval (%s)",
		 argv[optind], argv[optind + 1]);
		exit(EXIT_USAGE);
	}

	rthrottling->max_exec_count = strtoul(argv[optind], &p, 10);
	if (argv[optind] == p || rthrottling->max_exec_count < 0 ||
	 UINT32_MAX <= rthrottling->max_exec_count || errno != 0 ||
	 *p != '\0') {
		sd_err("Invalid max (%s)", argv[optind]);
		exit(EXIT_USAGE);
	}

	optind++;

	rthrottling->queue_work_interval = strtoull(argv[optind], &p, 10);
	if (argv[optind] == p || rthrottling->queue_work_interval < 0 ||
	 UINT64_MAX <= rthrottling->queue_work_interval || errno != 0 ||
	 *p != '\0') {
		sd_err("Invalid interval (%s)", argv[optind]);
		exit(EXIT_USAGE);
	}

	if ((rthrottling->max_exec_count == 0 &&
	 rthrottling->queue_work_interval != 0) ||
	 (rthrottling->max_exec_count != 0 &&
	 rthrottling->queue_work_interval == 0)) {
		sd_err("Invalid interval max (%"PRIu32"), interval (%"PRIu64")",
		rthrottling->max_exec_count, rthrottling->queue_work_interval);
		exit(EXIT_USAGE);
	}

	int ret = 0;
	struct sd_req req;
	struct sd_rsp *rsp = (struct sd_rsp *)&req;

	sd_init_req(&req, SD_OP_SET_RECOVERY);
	req.flags = SD_FLAG_CMD_WRITE;
	req.data_length = sizeof(struct recovery_throttling);
	ret = dog_exec_req(&sd_nid, &req, rthrottling);

	if (ret < 0)
		ret = EXIT_SYSFAIL;

	if (rsp->result == SD_RES_SUCCESS)
		ret = EXIT_SUCCESS;
	else
		ret = EXIT_FAILURE;

	switch (ret) {
	case EXIT_FAILURE:
	case EXIT_SYSFAIL:
		sd_err("Failed to execute request");
		ret = -1;
		break;
	case EXIT_SUCCESS:
		/* do nothing */
		break;
	default:
		sd_err("unknown return code: %d", ret);
		ret = -1;
		break;
	}

	free(rthrottling);
	return ret;
}

static int node_recovery_get(int argc, char **argv)
{
	struct recovery_throttling rthrottling;
	int ret = 0;

	struct sd_req req;
	struct sd_rsp *rsp = (struct sd_rsp *)&req;

	sd_init_req(&req, SD_OP_GET_RECOVERY);
	req.data_length = sizeof(rthrottling);

	ret = dog_exec_req(&sd_nid, &req, &rthrottling);
	if (ret < 0)
		ret = EXIT_SYSFAIL;

	if (rsp->result == SD_RES_SUCCESS)
		ret = EXIT_SUCCESS;
	else
		ret = EXIT_FAILURE;

	switch (ret) {
	case EXIT_FAILURE:
	case EXIT_SYSFAIL:
		sd_err("Failed to execute request");
		ret = -1;
		break;
	case EXIT_SUCCESS:
		sd_info("max (%"PRIu32"), interval (%"PRIu64")",
		 rthrottling.max_exec_count, rthrottling.queue_work_interval);
		break;
	default:
		sd_err("unknown return code: %d", ret);
		ret = -1;
		break;
	}
	return ret;
}

static struct sd_node *idx_to_node(struct rb_root *nroot, int idx)
{
	struct sd_node *n = rb_entry(rb_first(nroot), struct sd_node, rb);

	while (idx--)
		n = rb_entry(rb_next(&n->rb), struct sd_node, rb);

	return n;
}

static int node_kill(int argc, char **argv)
{
	int node_id, ret;
	struct sd_req req;
	const char *p;
	struct node_id *nid = NULL;

	if (node_cmd_data.local)
		nid = &sd_nid;	/* issue kill request to local node */

	if (optind < argc) {
		if (nid) {
			sd_err("don't use -l option and specify node id at the"
			       " same time");
			exit(EXIT_USAGE);
		}

		p = argv[optind++];

		if (!is_numeric(p)) {
			sd_err("Invalid node id '%s', please specify a numeric"
			       " value", p);
			exit(EXIT_USAGE);
		}

		node_id = strtol(p, NULL, 10);
		if (node_id < 0 || node_id >= sd_nodes_nr) {
			sd_err("Invalid node id '%d'", node_id);
			exit(EXIT_USAGE);
		}

		nid = &idx_to_node(&sd_nroot, node_id)->nid;
	}

	if (!nid) {
		sd_err("please specify -l option or node id");
		exit(EXIT_USAGE);
	}

	sd_init_req(&req, SD_OP_KILL_NODE);
	ret = send_light_req(nid, &req);
	if (ret) {
		sd_err("Failed to execute request");
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

static int node_stat(int argc, char **argv)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	struct sd_stat stat, last = { { 0 } };
	int ret;
	bool watch = node_cmd_data.watch ? true : false, first = true;

again:
	sd_init_req(&hdr, SD_OP_STAT);
	hdr.data_length = sizeof(stat);
	ret = dog_exec_req(&sd_nid, &hdr, &stat);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("failed to get stat information: %s",
		       sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	if (watch) {
		if (first) {
			last = stat;
			first = false;
		}
		printf("%s%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t"
		       "%"PRIu64"\t%"PRIu64"\t%s\t%s\t%s\t%s\t%s\n",
		       raw_output ? "" :
		       "Request\tActive\tTotal\tWrite\tRead\tRemove\tFlush\t"
		       "All WR\tAll RD\tWRBW\tRDBW\tRPS\nClient\t",
		       stat.r.gway_active_nr, stat.r.gway_total_nr,
		       stat.r.gway_total_write_nr, stat.r.gway_total_read_nr,
		       stat.r.gway_total_remove_nr, stat.r.gway_total_flush_nr,
		       strnumber(stat.r.gway_total_rx),
		       strnumber(stat.r.gway_total_tx),
		       strnumber(stat.r.gway_total_rx - last.r.gway_total_rx),
		       strnumber(stat.r.gway_total_tx - last.r.gway_total_tx),
		       strnumber_raw(stat.r.gway_total_nr -
				     last.r.gway_total_nr, true));
		printf("%s%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t"
		       "%"PRIu64"\t%"PRIu64"\t%s\t%s\t%s\t%s\t%s\n",
		       raw_output ? "" : "Peer\t",
		       stat.r.peer_active_nr, stat.r.peer_total_nr,
		       stat.r.peer_total_write_nr, stat.r.peer_total_read_nr,
		       stat.r.peer_total_remove_nr, 0UL,
		       strnumber(stat.r.peer_total_rx),
		       strnumber(stat.r.peer_total_tx),
		       strnumber(stat.r.peer_total_rx - last.r.peer_total_rx),
		       strnumber(stat.r.peer_total_tx - last.r.peer_total_tx),
		       strnumber_raw(stat.r.peer_total_nr -
				     last.r.peer_total_nr, true));
		last = stat;
		sleep(1);
		goto again;
	} else {
		printf("%s%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t"
		       "%"PRIu64"\t%"PRIu64"\t%s\t%s\n",
		       raw_output ? "" :
		       "Request\tActive\tTotal\tWrite\tRead\tRemove\tFlush\t"
		       "All WR\tAll RD\nClient\t",
		       stat.r.gway_active_nr, stat.r.gway_total_nr,
		       stat.r.gway_total_read_nr, stat.r.gway_total_write_nr,
		       stat.r.gway_total_remove_nr, stat.r.gway_total_flush_nr,
		       strnumber(stat.r.gway_total_rx),
		       strnumber(stat.r.gway_total_tx));
		printf("%s%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t"
		       "%"PRIu64"\t%"PRIu64"\t%s\t%s\n",
		       raw_output ? "" : "Peer\t",
		       stat.r.peer_active_nr, stat.r.peer_total_nr,
		       stat.r.peer_total_read_nr, stat.r.peer_total_write_nr,
		       stat.r.peer_total_remove_nr, 0UL,
		       strnumber(stat.r.peer_total_rx),
		       strnumber(stat.r.peer_total_tx));
	}

	return EXIT_SUCCESS;
}

static int node_md_info(struct node_id *nid)
{
	struct sd_md_info info = {};
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret, i;

	sd_init_req(&hdr, SD_OP_MD_INFO);
	hdr.data_length = sizeof(info);

	ret = dog_exec_req(nid, &hdr, &info);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("failed to get multi-disk information: %s",
		       sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	for (i = 0; i < info.nr; i++) {
		uint64_t size = info.disk[i].free + info.disk[i].used;
		int ratio = (int)(((double)info.disk[i].used / size) * 100);

		if (raw_output)
			fprintf(stdout, "%s %d %s %s %s %d%% %s\n",
				addr_to_str(nid->addr, nid->port),
				info.disk[i].idx, strnumber(size),
				strnumber(info.disk[i].used),
				strnumber(info.disk[i].free),
				ratio, info.disk[i].path);
		else
			fprintf(stdout, "%2d\t%s\t%s\t%s\t%3d%%\t%s\n",
				info.disk[i].idx, strnumber(size),
				strnumber(info.disk[i].used),
				strnumber(info.disk[i].free),
				ratio, info.disk[i].path);
	}
	return EXIT_SUCCESS;
}

static int md_info(int argc, char **argv)
{
	struct sd_node *n;
	int ret, i = 0;

	if (!raw_output)
		fprintf(stdout, "Id\tSize\tUsed\tAvail\tUse%%\tPath\n");

	if (!node_cmd_data.all_nodes)
		return node_md_info(&sd_nid);

	rb_for_each_entry(n, &sd_nroot, rb) {
		if (!raw_output)
			fprintf(stdout, "Node %d:\n", i++);
		ret = node_md_info(&n->nid);
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

	if (plug)
		sd_init_req(&hdr, SD_OP_MD_PLUG);
	else
		sd_init_req(&hdr, SD_OP_MD_UNPLUG);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = strlen(disks) + 1;

	ret = dog_exec_req(&sd_nid, &hdr, disks);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Failed to execute request, look for sheep.log"
		       " for more information");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

#define MD_PLUG_PRINT				\
	"    __\n"				\
	"   ()'`;\n"				\
	"   /\\|`\n"				\
	"  /  |   Caution! The directories to be plugged will be purged.\n" \
	"(/_)_|_  Are you sure you want to continue? [yes/no]: "

static int md_plug(int argc, char **argv)
{
	if (!node_cmd_data.force)
		confirm(MD_PLUG_PRINT);

	return do_plug_unplug(argv[optind], true);
}

#define MD_UNPLUG_PRINT				\
	"    __\n"				\
	"   ()'`;\n"				\
	"   /\\|`\n"				\
	"  /  |   Caution! Recovery will be triggered after unplugging.\n" \
	"(/_)_|_  Are you sure you want to continue? [yes/no]: "

static int md_unplug(int argc, char **argv)
{
	if (!node_cmd_data.force)
		confirm(MD_UNPLUG_PRINT);

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

static int node_parser(int ch, const char *opt)
{
	switch (ch) {
	case 'A':
		node_cmd_data.all_nodes = true;
		break;
	case 'P':
		node_cmd_data.recovery_progress = true;
		break;
	case 'w':
		node_cmd_data.watch = true;
		break;
	case 'l':
		node_cmd_data.local = true;
		break;
	case 'f':
		node_cmd_data.force = true;
		break;
	}

	return 0;
}

static struct sd_option node_options[] = {
	{'A', "all", false, "show md information of all the nodes"},
	{'P', "progress", false, "show progress of recovery in the node"},
	{'w', "watch", false, "watch the stat every second"},
	{'l', "local", false, "issue request to local node"},
	{'f', "force", false, "ignore the confirmation"},
	{ 0, NULL, false, NULL },
};

static struct subcommand node_recovery_cmd[] = {
	{"info", NULL, "aphPrT", "show recovery information of nodes (default)",
	 NULL, CMD_NEED_NODELIST, node_recovery_info, node_options},
	{"set-throttle", "<max> <interval>", NULL, "set new throttling", NULL,
	 CMD_NEED_ARG|CMD_NEED_NODELIST, node_recovery_set, node_options},
	{"get-throttle", NULL, NULL, "get current throttling", NULL,
	 CMD_NEED_NODELIST, node_recovery_get, node_options},
	{NULL},
};

static int node_recovery(int argc, char **argv)
{
	int ret;
	if (argc == optind) {
		ret = update_node_list(SD_MAX_NODES);
		if (ret < 0) {
			sd_err("Failed to get node list");
			exit(EXIT_SYSFAIL);
		}
		return node_recovery_info(argc, argv);
	}

	return do_generic_subcommand(node_recovery_cmd, argc, argv);
}

static int node_log_level_set(int argc, char **argv)
{
	int ret = 0;
	char *loglevel_str = argv[optind];

	ret = do_loglevel_set(&sd_nid, loglevel_str);
	switch (ret) {
	case EXIT_USAGE:
		sd_err("invalid loglevel: %s", loglevel_str);
		sd_err("available loglevels:");
		dump_loglevels(true);

		ret = -1;
		break;
	case EXIT_FAILURE:
	case EXIT_SYSFAIL:
		sd_err("Failed to execute request");
		ret = -1;
		break;
	case EXIT_SUCCESS:
		/* do nothing */
		break;
	default:
		sd_err("unknown return code of do_loglevel_set(): %d", ret);
		ret = -1;
		break;
	}

	return ret;
}

static int node_log_level_get(int argc, char **argv)
{
	int ret = 0, loglevel = -1;

	ret = do_loglevel_get(&sd_nid, &loglevel);
	switch (ret) {
	case EXIT_FAILURE:
	case EXIT_SYSFAIL:
		sd_err("Failed to execute request");
		ret = -1;
		break;
	case EXIT_SUCCESS:
		sd_info("%s (%d)", loglevel_to_str(loglevel), loglevel);
		break;
	default:
		sd_err("unknown return code of do_loglevel_get(): %d", ret);
		ret = -1;
		break;
	}

	return ret;
}

static int node_log_level_list(int argc, char **argv)
{
	dump_loglevels(false);

	return EXIT_SUCCESS;
}

static struct subcommand node_log_level_cmd[] = {
	{"set", "<log level>", NULL, "set new loglevel",
	 NULL, CMD_NEED_ARG, node_log_level_set},
	{"get", NULL, NULL, "get current loglevel",
	 NULL, 0, node_log_level_get},
	{"list", NULL, NULL, "list available loglevels",
	 NULL, 0, node_log_level_list},
	{NULL},
};

static int node_log_level(int argc, char **argv)
{
	return do_generic_subcommand(node_log_level_cmd, argc, argv);
}

static struct subcommand node_log_cmd[] = {
	{"level", "<subcommand>", NULL, "manipulate loglevel",
	 node_log_level_cmd, CMD_NEED_ARG, node_log_level},
	{NULL},
};

static int node_log(int argc, char **argv)
{
	return do_generic_subcommand(node_log_cmd, argc, argv);
}

static struct subcommand node_cmd[] = {
	{"kill", "<node id>", "aprhlT", "kill node", NULL,
	 CMD_NEED_NODELIST, node_kill, node_options},
	{"list", NULL, "aprhT", "list nodes", NULL,
	 CMD_NEED_NODELIST, node_list},
	{"info", NULL, "aprhT", "show information about each node", NULL,
	 CMD_NEED_NODELIST, node_info},
	{"recovery", "<max> <interval>", "aphPrT",
	 "show recovery information or set/get recovery speed throttling of nodes",
	 node_recovery_cmd, 0, node_recovery, node_options},
	{"md", "[disks]", "aprAfhT", "See 'dog node md' for more information",
	 node_md_cmd, CMD_NEED_ARG, node_md, node_options},
	{"stat", NULL, "aprwhT", "show stat information about the node", NULL,
	 0, node_stat, node_options},
	{"log", NULL, "aphT", "show or set log level of the node", node_log_cmd,
	 CMD_NEED_ARG, node_log},
	{NULL,},
};

struct command node_command = {
	"node",
	node_cmd,
	node_parser
};
