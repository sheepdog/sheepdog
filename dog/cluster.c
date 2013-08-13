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
#include "farm/farm.h"

static struct sd_option cluster_options[] = {
	{'b', "store", true, "specify backend store"},
	{'c', "copies", true, "specify the default data redundancy (number of copies)"},
	{'f', "force", false, "do not prompt for confirmation"},

	{ 0, NULL, false, NULL },
};

static struct cluster_cmd_data {
	int copies;
	bool force;
	char name[STORE_LEN];
} cluster_cmd_data;

#define DEFAULT_STORE	"plain"

static int list_store(void)
{
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	char buf[512] = { 0 };

	sd_init_req(&hdr, SD_OP_GET_STORE_LIST);
	hdr.data_length = 512;

	ret = dog_exec_req(sdhost, sdport, &hdr, buf);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Restore failed: %s", sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	printf("Available stores:\n");
	printf("---------------------------------------\n");
	printf("%s\n", buf);
	return EXIT_SYSFAIL;
}

static bool no_vdi(const unsigned long *vdis)
{
	return find_next_bit(vdis, SD_NR_VDIS, 0) == SD_NR_VDIS;
}

#define FORMAT_PRINT				\
	"    __\n"				\
	"   ()'`;\n"				\
	"   /\\|`\n"				\
	"  /  |   Caution! The cluster is not empty.\n" \
	"(/_)_|_  Are you sure you want to continue? [yes/no]: "

static int cluster_format(int argc, char **argv)
{
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	struct timeval tv;
	char store_name[STORE_LEN];
	static DECLARE_BITMAP(vdi_inuse, SD_NR_VDIS);

	sd_init_req(&hdr, SD_OP_READ_VDIS);
	hdr.data_length = sizeof(vdi_inuse);

	ret = dog_exec_req(sdhost, sdport, &hdr, &vdi_inuse);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (!no_vdi(vdi_inuse))
		confirm(FORMAT_PRINT);

	gettimeofday(&tv, NULL);

	sd_init_req(&hdr, SD_OP_MAKE_FS);
	hdr.cluster.copies = cluster_cmd_data.copies;
	hdr.cluster.ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;

	if (strlen(cluster_cmd_data.name))
		pstrcpy(store_name, STORE_LEN, cluster_cmd_data.name);
	else
		pstrcpy(store_name, STORE_LEN, DEFAULT_STORE);
	hdr.data_length = strlen(store_name) + 1;
	hdr.flags |= SD_FLAG_CMD_WRITE;

	printf("using backend %s store\n", store_name);
	ret = dog_exec_req(sdhost, sdport, &hdr, store_name);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Format failed: %s", sd_strerror(rsp->result));
		if (rsp->result == SD_RES_NO_STORE)
			return list_store();
		else
			return EXIT_SYSFAIL;
	}

	return EXIT_SUCCESS;
}

static int cluster_info(int argc, char **argv)
{
	int i, ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	struct epoch_log *logs;
	int nr_logs, log_length;
	time_t ti, ct;
	struct tm tm;
	char time_str[128];

	log_length = sd_epoch * sizeof(struct epoch_log);
	logs = xmalloc(log_length);

	sd_init_req(&hdr, SD_OP_STAT_CLUSTER);
	hdr.data_length = log_length;

	ret = dog_exec_req(sdhost, sdport, &hdr, logs);
	if (ret < 0)
		goto error;

	if (!raw_output)
		printf("Cluster status: ");
	if (rsp->result == SD_RES_SUCCESS)
		printf("running, auto-recovery %s\n", logs->disable_recovery ?
		       "disabled" : "enabled");
	else
		printf("%s\n", sd_strerror(rsp->result));

	if (!raw_output && rsp->data_length > 0) {
		ct = logs[0].ctime >> 32;
		printf("\nCluster created at %s\n", ctime(&ct));
		printf("Epoch Time           Version\n");
	}

	nr_logs = rsp->data_length / sizeof(struct epoch_log);
	for (i = 0; i < nr_logs; i++) {
		int j;
		const struct sd_node *entry;

		ti = logs[i].time;
		if (raw_output) {
			snprintf(time_str, sizeof(time_str), "%" PRIu64, (uint64_t) ti);
		} else {
			localtime_r(&ti, &tm);
			strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm);
		}

		printf(raw_output ? "%s %d" : "%s %6d", time_str, logs[i].epoch);
		printf(" [");
		for (j = 0; j < logs[i].nr_nodes; j++) {
			entry = logs[i].nodes + j;
			printf("%s%s",
			       (j == 0) ? "" : ", ",
			       addr_to_str(entry->nid.addr, entry->nid.port));
		}
		printf("]\n");
	}

	free(logs);
	return EXIT_SUCCESS;
error:
	free(logs);
	return EXIT_SYSFAIL;
}

static int cluster_shutdown(int argc, char **argv)
{
	int ret;
	struct sd_req hdr;

	sd_init_req(&hdr, SD_OP_SHUTDOWN);

	ret = send_light_req(&hdr, sdhost, sdport);
	if (ret) {
		sd_err("failed to execute request");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static void print_list(void *buf, unsigned len)
{
	struct snap_log *log_buf = (struct snap_log *)buf;
	unsigned nr = len / sizeof(struct snap_log);

	printf("Index\t\tTag\t\tSnapshot Time\n");
	for (unsigned i = 0; i < nr; i++, log_buf++) {
		time_t *t = (time_t *)&log_buf->time;
		printf("%d\t\t", log_buf->idx);
		printf("%s\t\t", log_buf->tag);
		printf("%s", ctime(t));
	}
}

static int list_snapshot(int argc, char **argv)
{
	char *path = argv[optind++];
	void *buf = NULL;
	int log_nr;
	int ret = EXIT_SYSFAIL;

	if (farm_init(path) != SD_RES_SUCCESS)
		goto out;

	buf = snap_log_read(&log_nr);
	if (!buf)
		goto out;

	print_list(buf, log_nr * sizeof(struct snap_log));
	ret = EXIT_SUCCESS;
out:
	if (ret)
		sd_err("Fail to list snapshot.");
	free(buf);
	return ret;
}

static void fill_object_tree(uint32_t vid, const char *name, const char *tag,
			  uint32_t snapid, uint32_t flags,
			  const struct sd_inode *i, void *data)
{
	uint64_t vdi_oid = vid_to_vdi_oid(vid), vmstate_oid;
	int nr_vmstate_object;

	/* ignore active vdi */
	if (!vdi_is_snapshot(i))
		return;

	/* fill vdi object id */
	object_tree_insert(vdi_oid, i->nr_copies);

	/* fill data object id */
	for (uint64_t idx = 0; idx < MAX_DATA_OBJS; idx++) {
		if (i->data_vdi_id[idx]) {
			uint64_t oid = vid_to_data_oid(i->data_vdi_id[idx],
						       idx);
			object_tree_insert(oid, i->nr_copies);
		}
	}

	/* fill vmstate object id */
	nr_vmstate_object = DIV_ROUND_UP(i->vm_state_size, SD_DATA_OBJ_SIZE);
	for (int idx = 0; idx < nr_vmstate_object; idx++) {
		vmstate_oid = vid_to_vmstate_oid(vid, idx);
		object_tree_insert(vmstate_oid, i->nr_copies);
	}
}

static int save_snapshot(int argc, char **argv)
{
	char *tag = argv[optind++];
	char *path, *p;
	int ret = EXIT_SYSFAIL, uninitialized_var(unused);

	unused = strtol(tag, &p, 10);
	if (tag != p) {
		sd_err("Tag should not start with number.");
		return EXIT_USAGE;
	}

	if (!argv[optind]) {
		sd_err("Please specify the path to save snapshot.");
		return EXIT_USAGE;
	}
	path = argv[optind];

	if (farm_init(path) != SD_RES_SUCCESS)
		goto out;

	if (farm_contain_snapshot(0, tag)) {
		sd_err("Snapshot tag has already been used for another"
		       " snapshot, please, use another one.");
		goto out;
	}

	if (parse_vdi(fill_object_tree, SD_INODE_SIZE, NULL) != SD_RES_SUCCESS)
		goto out;

	if (farm_save_snapshot(tag) != SD_RES_SUCCESS)
		goto out;

	ret = EXIT_SUCCESS;
out:
	if (ret)
		sd_err("Fail to save snapshot to path: %s.", path);
	object_tree_free();
	return ret;
}

static int load_snapshot(int argc, char **argv)
{
	char *tag = argv[optind++];
	char *path, *p;
	uint32_t idx;
	int ret = EXIT_SYSFAIL;

	idx = strtol(tag, &p, 10);
	if (tag == p)
		idx = 0;

	if (!argv[optind]) {
		sd_err("Please specify the path to save snapshot.");
		return EXIT_USAGE;
	}
	path = argv[optind];

	if (farm_init(path) != SD_RES_SUCCESS)
		goto out;

	if (!farm_contain_snapshot(idx, tag)) {
		sd_err("Snapshot index or tag does not exist.");
		goto out;
	}

	if (cluster_format(0, NULL) != SD_RES_SUCCESS)
		goto out;

	if (farm_load_snapshot(idx, tag) != SD_RES_SUCCESS)
		goto out;

	ret = EXIT_SUCCESS;
out:
	if (ret)
		sd_err("Fail to load snapshot");
	return ret;
}

#define RECOVER_PRINT \
	"Caution! Please try starting all the cluster nodes normally before\n" \
	"running this command.\n\n" \
	"The cluster may need to be force recovered if:\n" \
	"  - the master node fails to start because of epoch mismatch; or\n" \
	"  - some nodes fail to start after a cluster shutdown.\n\n" \
	"Are you sure you want to continue? [yes/no]: "

static int cluster_force_recover(int argc, char **argv)
{
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	char str[123] = {'\0'};
	struct sd_node nodes[SD_MAX_NODES];

	if (!cluster_cmd_data.force) {
		int i, l;
		printf(RECOVER_PRINT);
		ret = scanf("%s", str);
		if (ret < 0)
			return EXIT_SYSFAIL;
		l = strlen(str);
		for (i = 0; i < l; i++)
			str[i] = tolower(str[i]);
		if (strncmp(str, "yes", 3) != 0)
			return EXIT_SUCCESS;
	}

	sd_init_req(&hdr, SD_OP_FORCE_RECOVER);
	hdr.data_length = sizeof(nodes);

	ret = dog_exec_req(sdhost, sdport, &hdr, nodes);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("failed to execute request, %s",
		       sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int cluster_disable_recover(int argc, char **argv)
{
	int ret;
	struct sd_req hdr;

	sd_init_req(&hdr, SD_OP_DISABLE_RECOVER);

	ret = send_light_req(&hdr, sdhost, sdport);
	if (ret)
		return EXIT_FAILURE;

	printf("Cluster recovery: disable\n");
	return EXIT_SUCCESS;
}

static int cluster_enable_recover(int argc, char **argv)
{
	int ret;
	struct sd_req hdr;

	sd_init_req(&hdr, SD_OP_ENABLE_RECOVER);

	ret = send_light_req(&hdr, sdhost, sdport);
	if (ret)
		return EXIT_FAILURE;

	printf("Cluster recovery: enable\n");
	return EXIT_SUCCESS;
}

/* Subcommand list of recover */
static struct subcommand cluster_recover_cmd[] = {
	{"force", NULL, NULL, "force recover cluster immediately",
	 NULL, 0, cluster_force_recover},
	{"enable", NULL, NULL, "enable automatic recovery and "
				"run once recover if necessary",
	 NULL, 0, cluster_enable_recover},
	{"disable", NULL, NULL, "disable automatic recovery",
	 NULL, 0, cluster_disable_recover},
	{NULL},
};

static int cluster_recover(int argc, char **argv)
{
	return do_generic_subcommand(cluster_recover_cmd, argc, argv);
}

/* Subcommand list of snapshot */
static struct subcommand cluster_snapshot_cmd[] = {
	{"save", NULL, "h", "save snapshot to localpath",
	 NULL, CMD_NEED_ARG|CMD_NEED_NODELIST,
	 save_snapshot, NULL},
	{"list", NULL, "h", "list snapshot of localpath",
	 NULL, CMD_NEED_ARG, list_snapshot, NULL},
	{"load", NULL, "h", "load snapshot from localpath",
	 NULL, CMD_NEED_ARG, load_snapshot, NULL},
	{NULL},
};

static int cluster_snapshot(int argc, char **argv)
{
	return do_generic_subcommand(cluster_snapshot_cmd, argc, argv);
}

static int cluster_reweight(int argc, char **argv)
{
	int ret;
	struct sd_req hdr;

	sd_init_req(&hdr, SD_OP_REWEIGHT);
	ret = send_light_req(&hdr, sdhost, sdport);
	if (ret)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}

static struct subcommand cluster_cmd[] = {
	{"info", NULL, "aprh", "show cluster information",
	 NULL, CMD_NEED_NODELIST, cluster_info, cluster_options},
	{"format", NULL, "bcaph", "create a Sheepdog store",
	 NULL, 0, cluster_format, cluster_options},
	{"shutdown", NULL, "aph", "stop Sheepdog",
	 NULL, 0, cluster_shutdown, cluster_options},
	{"snapshot", "<tag|idx> <path>", "aph", "snapshot/restore the cluster",
	 cluster_snapshot_cmd, CMD_NEED_ARG,
	 cluster_snapshot, cluster_options},
	{"recover", NULL, "afph",
	 "See 'dog cluster recover' for more information",
	 cluster_recover_cmd, CMD_NEED_ARG,
	 cluster_recover, cluster_options},
	{"reweight", NULL, "aph", "reweight the cluster", NULL, 0,
	 cluster_reweight, cluster_options},
	{NULL,},
};

static int cluster_parser(int ch, char *opt)
{
	int copies;
	char *p;

	switch (ch) {
	case 'b':
		pstrcpy(cluster_cmd_data.name, sizeof(cluster_cmd_data.name),
			opt);
		break;
	case 'c':
		copies = strtol(opt, &p, 10);
		if (opt == p || copies < 1) {
			sd_err("There must be at least one copy of data");
			exit(EXIT_FAILURE);
		} else if (copies > SD_MAX_COPIES) {
			sd_err("Redundancy may not exceed %d copies",
			       SD_MAX_COPIES);
			exit(EXIT_FAILURE);
		}
		cluster_cmd_data.copies = copies;
		break;
	case 'f':
		cluster_cmd_data.force = true;
		break;
	}

	return 0;
}

struct command cluster_command = {
	"cluster",
	cluster_cmd,
	cluster_parser
};
