/*
 * Copyright (C) 2011 Taobao Inc.
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

#include "collie.h"

static inline void print_thread_name(struct trace_graph_item *item)
{
	printf("%-20s|", item->tname);
}

static inline void print_time(struct trace_graph_item *item)
{
	if (item->type == TRACE_GRAPH_RETURN) {
		unsigned duration = item->return_time - item->entry_time;
		unsigned quot = duration / 1000, rem = duration % 1000;

		printf("%8u.%-3u|", quot, rem);
	} else if (item->type == TRACE_GRAPH_ENTRY) {
		printf("            |");
	}
}

static inline void print_finale(struct trace_graph_item *item)
{
	int i;

	for (i = 0; i < item->depth; i++)
		printf("   ");
	if (item->type == TRACE_GRAPH_ENTRY)
		printf("%s() {\n", item->fname);
	else
		printf("}\n");
}

static void print_trace_item(struct trace_graph_item *item)
{
	print_thread_name(item);
	print_time(item);
	print_finale(item);
}

static void parse_trace_buffer(char *buf, int size)
{
	struct trace_graph_item *item = (struct trace_graph_item *)buf;
	int sz = size / sizeof(struct trace_graph_item), i;

	printf("   Thread Name      |  Time(us)  |  Function Graph\n");
	printf("--------------------------------------------------\n");
	for (i = 0; i < sz; i++)
		print_trace_item(item++);
	return;
}

static const char *tracefile = "/tmp/tracefile";

static int trace_read_buffer(void)
{
	int fd, ret, tfd;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
#define TRACE_BUF_LEN      (1024 * 1024 * 20)
	char *buf = xzalloc(TRACE_BUF_LEN);

	tfd = open(tracefile, O_CREAT | O_RDWR | O_APPEND | O_TRUNC, 0644);
	if (tfd < 0) {
		fprintf(stderr, "can't create tracefile\n");
		return EXIT_SYSFAIL;
	}

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return EXIT_SYSFAIL;

read_buffer:
	sd_init_req(&hdr, SD_OP_TRACE_READ_BUF);
	hdr.data_length = TRACE_BUF_LEN;

	ret = collie_exec_req(fd, &hdr, buf);

	if (ret) {
		fprintf(stderr, "Failed to connect\n");
		close(fd);
		return EXIT_SYSFAIL;
	}

	if (rsp->result == SD_RES_AGAIN)
		goto read_buffer;

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "Trace failed: %s\n",
				sd_strerror(rsp->result));
		close(fd);
		return EXIT_FAILURE;
	}

	xwrite(tfd, buf, rsp->data_length);
	if (rsp->data_length == TRACE_BUF_LEN) {
		memset(buf, 0, TRACE_BUF_LEN);
		goto read_buffer;
	}

	close(fd);
	free(buf);
	return EXIT_SUCCESS;
}

static int trace_start(int argc, char **argv)
{
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

	sd_init_req(&hdr, SD_OP_TRACE);
	hdr.data_length = 1;

	ret = send_light_req(&hdr, sdhost, sdport);
	if (ret) {
		fprintf(stderr, "Trace start failed: %s\n",
				sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int trace_stop(int argc, char **argv)
{
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

	sd_init_req(&hdr, SD_OP_TRACE);
	hdr.data_length = 0;

	ret = send_light_req(&hdr, sdhost, sdport);
	if (ret) {
		fprintf(stderr, "Trace stop failed: %s\n",
				sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	return trace_read_buffer();
}

static int trace_cat(int argc, char **argv)
{
	int fd = open(tracefile, O_RDONLY);
	struct stat st;
	void *map;

	if (fd < 0) {
		fprintf(stderr, "%m\n");
		return EXIT_SYSFAIL;
	}

	if (fstat(fd, &st) < 0) {
		fprintf(stderr, "%m\n");
		close(fd);
		return EXIT_SYSFAIL;
	}

	map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (map == MAP_FAILED) {
		fprintf(stderr, "%m\n");
		return EXIT_SYSFAIL;
	}
	parse_trace_buffer(map, st.st_size);
	munmap(map, st.st_size);

	return EXIT_SUCCESS;
}

static int debug_parser(int ch, char *opt)
{
	return 0;
}

/* Subcommand list of trace */
static struct subcommand trace_cmd[] = {
	{"start", NULL, NULL, "start the trace",
	 NULL, 0, trace_start},
	{"stop", NULL, NULL, "stop the trace",
	 NULL, 0, trace_stop},
	{"cat", NULL, NULL, "cat the trace",
	 NULL, 0, trace_cat},
	{NULL},
};

static int debug_trace(int argc, char **argv)
{
	int i;

	for (i = 0; trace_cmd[i].name; i++) {
		if (!strcmp(trace_cmd[i].name, argv[optind]))
			return trace_cmd[i].fn(argc, argv);
	}

	subcommand_usage(argv[1], argv[2], EXIT_FAILURE);
	return EXIT_FAILURE;
}

static struct subcommand debug_cmd[] = {
	{"trace", NULL, "aph", "trace the node",
	 trace_cmd, SUBCMD_FLAG_NEED_ARG, debug_trace},
	{NULL,},
};

struct command debug_command = {
	"debug",
	debug_cmd,
	debug_parser
};
