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

#include "collie.h"

static struct sd_option cluster_options[] = {
	{'b', "store", true, "specify backend store"},
	{'c', "copies", true, "specify the default data redundancy (number of copies)"},
	{'m', "mode", true, "mode (safe, quorum, unsafe)"},
	{'f', "force", false, "do not prompt for confirmation"},
	{'R', "restore", true, "restore the cluster"},
	{'l', "list", false, "list the user epoch information"},

	{ 0, NULL, false, NULL },
};

static struct cluster_cmd_data {
	uint32_t epoch;
	bool list;
	int copies;
	bool nohalt;
	bool quorum;
	bool force;
	char name[STORE_LEN];
} cluster_cmd_data;

#define DEFAULT_STORE	"farm"

static int list_store(void)
{
	int fd, ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	char buf[512] = { 0 };

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return EXIT_SYSFAIL;

	sd_init_req(&hdr, SD_OP_GET_STORE_LIST);
	hdr.data_length = 512;

	ret = collie_exec_req(fd, &hdr, buf);
	close(fd);

	if (ret) {
		fprintf(stderr, "Failed to connect\n");
		return EXIT_SYSFAIL;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "Restore failed: %s\n",
				sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	printf("Available stores:\n");
	printf("---------------------------------------\n");
	printf("%s\n", buf);
	return EXIT_SYSFAIL;
}

#define FORMAT_PRINT				\
	"    __\n"				\
	"   ()'`;\n"				\
	"   /\\|`\n"				\
	"  /  |   Caution! The cluster is not empty.\n" \
	"(/_)_|_  Are you sure you want to continue? [yes/no]: "

static int cluster_format(int argc, char **argv)
{
	int fd, ret;
	struct sd_so_req hdr;
	struct sd_so_rsp *rsp = (struct sd_so_rsp *)&hdr;
	struct timeval tv;
	char store_name[STORE_LEN];
	static DECLARE_BITMAP(vdi_inuse, SD_NR_VDIS);
	unsigned long nr;

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return EXIT_SYSFAIL;

	sd_init_req((struct sd_req *)&hdr, SD_OP_READ_VDIS);
	hdr.data_length = sizeof(vdi_inuse);

	ret = collie_exec_req(fd, (struct sd_req *)&hdr, &vdi_inuse);
	if (ret < 0) {
		fprintf(stderr, "Failed to read VDIs from %s:%d\n",
			sdhost, sdport);
		close(fd);
		return EXIT_SYSFAIL;
	}

	for (nr = 0; nr < SD_NR_VDIS; nr++)
		if (test_bit(nr, vdi_inuse))
			break;

	if (nr != SD_NR_VDIS) {
		int i, l;
		char str[123] = {'\0'};

		printf(FORMAT_PRINT);
		ret = scanf("%s", str);
		if (ret < 0)
			return EXIT_SYSFAIL;
		l = strlen(str);
		for (i = 0; i < l; i++)
			str[i] = tolower(str[i]);
		if (strncmp(str, "yes", 3) != 0)
			return EXIT_SUCCESS;
	}

	gettimeofday(&tv, NULL);

	sd_init_req((struct sd_req *)&hdr, SD_OP_MAKE_FS);
	hdr.copies = cluster_cmd_data.copies;
	if (cluster_cmd_data.nohalt)
		hdr.flags |= SD_FLAG_NOHALT;
	if (cluster_cmd_data.quorum)
		hdr.flags |= SD_FLAG_QUORUM;

	hdr.ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;

	if (strlen(cluster_cmd_data.name))
		pstrcpy(store_name, STORE_LEN, cluster_cmd_data.name);
	else
		pstrcpy(store_name, STORE_LEN, DEFAULT_STORE);
	hdr.data_length = strlen(store_name) + 1;
	hdr.flags |= SD_FLAG_CMD_WRITE;

	printf("using backend %s store\n", store_name);
	ret = collie_exec_req(fd, (struct sd_req *)&hdr, store_name);
	close(fd);

	if (ret) {
		fprintf(stderr, "Failed to connect\n");
		return EXIT_SYSFAIL;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "Format failed: %s\n",
				sd_strerror(rsp->result));
		if (rsp->result == SD_RES_NO_STORE)
			return list_store();
		else
			return EXIT_SYSFAIL;
	}

	return EXIT_SUCCESS;
}

static int cluster_info(int argc, char **argv)
{
	int i, fd, ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	struct epoch_log *logs;
	int nr_logs, log_length;
	time_t ti, ct;
	struct tm tm;
	char time_str[128];

	log_length = sd_epoch * sizeof(struct epoch_log);
again:
	logs = malloc(log_length);
	if (!logs) {
		if (log_length < 10) {
			fprintf(stderr, "No memory to allocate.\n");
			return EXIT_SYSFAIL;
		}
		log_length /= 2;
		goto again;
	}

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		goto error;

	sd_init_req(&hdr, SD_OP_STAT_CLUSTER);
	hdr.data_length = log_length;

	ret = collie_exec_req(fd, &hdr, logs);
	close(fd);

	if (ret != 0)
		goto error;

	if (!raw_output)
		printf("Cluster status: ");
	if (rsp->result == SD_RES_SUCCESS)
		printf("running\n");
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
		char name[128];
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
			       addr_to_str(name, sizeof(name),
					   entry->nid.addr, entry->nid.port));
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
		fprintf(stderr, "failed to execute request\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int restore_snap(uint32_t epoch)
{
	int ret;
	struct sd_req hdr;

	sd_init_req(&hdr, SD_OP_RESTORE);
	hdr.obj.tgt_epoch = epoch;

	ret = send_light_req(&hdr, sdhost, sdport);
	if (ret) {
		fprintf(stderr, "failed to execute request\n");
		return EXIT_FAILURE;
	}

	printf("Cluster restore to the snapshot %d\n", epoch);
	return EXIT_SUCCESS;
}

static void print_list(void *buf, unsigned len)
{
	struct snap_log *log_buf = (struct snap_log *)buf;
	unsigned nr = len / sizeof(struct snap_log), i;

	printf("Index\t\tSnapshot Time\n");
	for (i = 0; i < nr; i++, log_buf++) {
		time_t *t = (time_t *)&log_buf->time;
		printf("%d\t\t", log_buf->epoch);
		printf("%s", ctime(t));
	}
}

static int list_snap(void)
{
	int fd, ret = EXIT_SYSFAIL;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	void *buf;

	buf = xmalloc(SD_DATA_OBJ_SIZE);

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		goto out;

	sd_init_req(&hdr, SD_OP_GET_SNAP_FILE);
	hdr.data_length = SD_DATA_OBJ_SIZE;

	ret = collie_exec_req(fd, &hdr, buf);
	close(fd);

	if (ret) {
		fprintf(stderr, "Failed to connect\n");
		goto out;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "Listing snapshots failed: %s\n",
				sd_strerror(rsp->result));
		ret = EXIT_FAILURE;
		goto out;
	}

	print_list(buf, rsp->data_length);
out:
	free(buf);
	return EXIT_SUCCESS;
}

static int do_snapshot(void)
{
	int ret;
	struct sd_req hdr;

	sd_init_req(&hdr, SD_OP_SNAPSHOT);

	ret = send_light_req(&hdr, sdhost, sdport);
	if (ret) {
		fprintf(stderr, "failed to execute request\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int cluster_snapshot(int argc, char **argv)
{
	int ret, epoch = cluster_cmd_data.epoch;
	if (epoch)
		ret = restore_snap(epoch);
	else if (cluster_cmd_data.list)
		ret = list_snap();
	else
		ret = do_snapshot();
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
	char str[123] = {'\0'};

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

	ret = send_light_req(&hdr, sdhost, sdport);
	if (ret) {
		fprintf(stderr, "failed to execute request\n");
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

static struct subcommand cluster_cmd[] = {
	{"info", NULL, "aprh", "show cluster information",
	 NULL, SUBCMD_FLAG_NEED_NODELIST, cluster_info, cluster_options},
	{"format", NULL, "bcmaph", "create a Sheepdog store",
	 NULL, 0, cluster_format, cluster_options},
	{"shutdown", NULL, "aph", "stop Sheepdog",
	 NULL, 0, cluster_shutdown, cluster_options},
	{"snapshot", NULL, "aRlph", "snapshot/restore the cluster",
	 NULL, 0, cluster_snapshot, cluster_options},
	{"recover", NULL, "afph",
	 "See 'collie cluster recover' for more information\n",
	 cluster_recover_cmd, SUBCMD_FLAG_NEED_ARG,
	 cluster_recover, cluster_options},
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
			fprintf(stderr, "There must be at least one copy of data\n");
			exit(EXIT_FAILURE);
		} else if (copies > SD_MAX_COPIES) {
			fprintf(stderr, "Redundancy may not exceed %d copies\n",
				SD_MAX_COPIES);
			exit(EXIT_FAILURE);
		}
		cluster_cmd_data.copies = copies;
		break;
	case 'm':
		if (strcmp(opt, "safe") == 0) {
			cluster_cmd_data.nohalt = false;
			cluster_cmd_data.quorum = false;
		} else if (strcmp(opt, "quorum") == 0) {
			cluster_cmd_data.nohalt = false;
			cluster_cmd_data.quorum = true;
		} else if (strcmp(opt, "unsafe") == 0) {
			cluster_cmd_data.nohalt = true;
			cluster_cmd_data.quorum = false;
		} else {
			fprintf(stderr, "Unknown mode '%s'\n", opt);
			exit(EXIT_FAILURE);
		}
		break;
	case 'f':
		cluster_cmd_data.force = true;
		break;
	case 'R':
		cluster_cmd_data.epoch = strtol(opt, &p, 10);
		if (opt == p) {
			fprintf(stderr, "The epoch must be an integer\n");
			exit(EXIT_FAILURE);
		}
		if (cluster_cmd_data.epoch < 1) {
			fprintf(stderr, "The epoch must be greater than 0\n");
			exit(EXIT_FAILURE);
		}
		break;
	case 'l':
		cluster_cmd_data.list = true;
		break;
	}

	return 0;
}

struct command cluster_command = {
	"cluster",
	cluster_cmd,
	cluster_parser
};
