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
#include <sys/time.h>

#include "collie.h"

struct cluster_cmd_data {
	int copies;
} cluster_cmd_data;

static int cluster_format(int argc, char **argv)
{
	int fd, ret;
	struct sd_so_req hdr;
	struct sd_so_rsp *rsp = (struct sd_so_rsp *)&hdr;
	unsigned rlen, wlen;
	struct timeval tv;

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return EXIT_SYSFAIL;

	gettimeofday(&tv, NULL);

	memset(&hdr, 0, sizeof(hdr));

	hdr.opcode = SD_OP_MAKE_FS;
	hdr.copies = cluster_cmd_data.copies;
	hdr.epoch = node_list_version;
	hdr.ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;

	rlen = 0;
	wlen = 0;
	ret = exec_req(fd, (struct sd_req *)&hdr, NULL, &wlen, &rlen);
	close(fd);

	if (ret) {
		fprintf(stderr, "failed to connect\n");
		return EXIT_SYSFAIL;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "%s\n", sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int cluster_info(int argc, char **argv)
{
	int i, fd, ret;
	struct sd_vdi_req hdr;
	struct sd_vdi_rsp *rsp = (struct sd_vdi_rsp *)&hdr;
	unsigned rlen, wlen;
	struct epoch_log logs[8];
	int nr_logs;
	time_t ti;
	struct tm tm;
	char time_str[128];

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return EXIT_SYSFAIL;

	memset(&hdr, 0, sizeof(hdr));

	hdr.opcode = SD_OP_STAT_CLUSTER;
	hdr.epoch = node_list_version;
	hdr.data_length = sizeof(logs);

	rlen = hdr.data_length;
	wlen = 0;
	ret = exec_req(fd, (struct sd_req *)&hdr, logs, &wlen, &rlen);
	close(fd);

	if (ret != 0)
		return EXIT_SYSFAIL;

	if (!raw_output)
		printf("Cluster status: ");
	if (rsp->result == SD_RES_SUCCESS)
		printf("running\n");
	else
		printf("%s\n", sd_strerror(rsp->result));

	if (!raw_output)
		printf("\nCreation time        Epoch Nodes\n");

	nr_logs = rsp->data_length / sizeof(struct epoch_log);
	for (i = 0; i < nr_logs; i++) {
		int j;
		char name[128];
		struct sheepdog_node_list_entry *entry;

		ti = logs[i].ctime >> 32;
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
					   entry->addr, entry->port));
		}
		printf("]\n");
	}

	return EXIT_SUCCESS;
}

static int cluster_shutdown(int argc, char **argv)
{
	int fd, ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	unsigned rlen, wlen;

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return EXIT_SYSFAIL;

	memset(&hdr, 0, sizeof(hdr));

	hdr.opcode = SD_OP_SHUTDOWN;
	hdr.epoch = node_list_version;

	rlen = 0;
	wlen = 0;
	ret = exec_req(fd, &hdr, NULL, &wlen, &rlen);
	close(fd);

	if (ret) {
		fprintf(stderr, "failed to connect\n");
		return EXIT_SYSFAIL;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "%s\n", sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static struct subcommand cluster_cmd[] = {
	{"info", NULL, "aprh", "show cluster information",
	 0, cluster_info},
	{"format", NULL, "caph", "create a Sheepdog storage",
	 0, cluster_format},
	{"shutdown", NULL, "aph", "stop Sheepdog",
	 SUBCMD_FLAG_NEED_NODELIST, cluster_shutdown},
	{NULL,},
};

static int cluster_parser(int ch, char *opt)
{
	switch (ch) {
	case 'c':
		cluster_cmd_data.copies = atoi(opt);
		break;
	}

	return 0;
}

struct command cluster_command = {
	"cluster",
	cluster_cmd,
	cluster_parser
};
