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

#include "dog.h"
#include "rbtree.h"
#include "list.h"

static inline void print_thread_name(struct trace_graph_item *item)
{
	printf("%-*s|", TRACE_THREAD_LEN, item->tname);
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

static void cat_trace_file(void *buf, size_t size)
{
	struct trace_graph_item *item = (struct trace_graph_item *)buf;
	size_t sz = size / sizeof(struct trace_graph_item), i;

	printf("   Thread Name      |  Time(us)  |  Function Graph\n");
	printf("--------------------------------------------------\n");
	for (i = 0; i < sz; i++)
		print_trace_item(item++);
	return;
}

static const char *tracefile = "/tmp/tracefile";

static int trace_read_buffer(void)
{
	int ret, tfd;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
#define TRACE_BUF_LEN      (1024 * 1024 * 20)
	char *buf = xzalloc(TRACE_BUF_LEN);

	tfd = open(tracefile, O_CREAT | O_RDWR | O_APPEND | O_TRUNC, 0644);
	if (tfd < 0) {
		sd_err("can't create tracefile");
		return EXIT_SYSFAIL;
	}

read_buffer:
	sd_init_req(&hdr, SD_OP_TRACE_READ_BUF);
	hdr.data_length = TRACE_BUF_LEN;

	ret = dog_exec_req(sdhost, sdport, &hdr, buf);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (rsp->result == SD_RES_AGAIN)
		goto read_buffer;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Trace failed: %s", sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	xwrite(tfd, buf, rsp->data_length);
	if (rsp->data_length == TRACE_BUF_LEN) {
		memset(buf, 0, TRACE_BUF_LEN);
		goto read_buffer;
	}

	free(buf);
	return EXIT_SUCCESS;
}

static int trace_enable(int argc, char **argv)
{
	const char *tracer = argv[optind];
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

	sd_init_req(&hdr, SD_OP_TRACE_ENABLE);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = strlen(tracer) + 1;

	ret = dog_exec_req(sdhost, sdport, &hdr, (void *)tracer);
	if (ret < 0)
		return EXIT_SYSFAIL;

	switch (rsp->result) {
	case SD_RES_SUCCESS:
		break;
	case SD_RES_NO_SUPPORT:
		sd_err("no such tracer %s", tracer);
		return EXIT_FAILURE;
	case SD_RES_INVALID_PARMS:
		sd_err("tracer %s is already enabled", tracer);
		return EXIT_FAILURE;
	default:
		sd_err("unknown error (%s)", sd_strerror(rsp->result));
		return EXIT_SYSFAIL;
	}

	return EXIT_SUCCESS;
}

static int trace_disable(int argc, char **argv)
{
	const char *tracer = argv[optind];
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

	sd_init_req(&hdr, SD_OP_TRACE_DISABLE);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = strlen(tracer) + 1;

	ret = dog_exec_req(sdhost, sdport, &hdr, (void *)tracer);
	if (ret < 0)
		return EXIT_SYSFAIL;

	switch (rsp->result) {
	case SD_RES_SUCCESS:
		break;
	case SD_RES_NO_SUPPORT:
		sd_err("no such tracer %s", tracer);
		return EXIT_FAILURE;
	case SD_RES_INVALID_PARMS:
		sd_err("tracer %s is not enabled", tracer);
		return EXIT_FAILURE;
	default:
		sd_err("unknown error (%s)", sd_strerror(rsp->result));
		return EXIT_SYSFAIL;
	}

	return trace_read_buffer();
}

static int trace_status(int argc, char **argv)
{
	char buf[4096]; /* must have enough space to store tracer list */
	int ret;
	struct sd_req hdr;

	sd_init_req(&hdr, SD_OP_TRACE_STATUS);
	hdr.data_length = sizeof(buf);

	ret = dog_exec_req(sdhost, sdport, &hdr, buf);
	if (ret < 0)
		return EXIT_SYSFAIL;

	printf("%s", buf);

	return EXIT_SUCCESS;
}

static void *map_trace_file(struct stat *st)
{
	int fd = open(tracefile, O_RDONLY);
	void *map;

	if (fd < 0) {
		sd_err("%m");
		return NULL;
	}

	if (fstat(fd, st) < 0) {
		sd_err("%m");
		close(fd);
		return NULL;
	}

	if (st->st_size == 0) {
		sd_err("trace file is empty");
		return NULL;
	}

	map = mmap(NULL, st->st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (map == MAP_FAILED) {
		sd_err("%m");
		return NULL;
	}

	return map;
}

static int graph_cat(int argc, char **argv)
{
	struct stat st;
	void *map = map_trace_file(&st);

	if (!map)
		return EXIT_FAILURE;

	cat_trace_file(map, st.st_size);
	munmap(map, st.st_size);

	return EXIT_SUCCESS;
}

struct graph_stat_entry {
	struct rb_node rb;
	struct list_head list;
	char fname[TRACE_FNAME_LEN];
	uint64_t duration;
	uint16_t nr_calls;
};

static struct rb_root stat_tree_root;

static LIST_HEAD(stat_list);

static struct graph_stat_entry *
stat_tree_insert(struct graph_stat_entry *new)
{
	struct rb_node **p = &stat_tree_root.rb_node;
	struct rb_node *parent = NULL;
	struct graph_stat_entry *entry;

	while (*p) {
		int cmp;

		parent = *p;
		entry = rb_entry(parent, struct graph_stat_entry, rb);
		cmp = strcmp(new->fname, entry->fname);

		if (cmp < 0)
			p = &(*p)->rb_left;
		else if (cmp > 0)
			p = &(*p)->rb_right;
		else {
			entry->duration += new->duration;
			entry->nr_calls++;
			return entry;
		}
	}
	rb_link_node(&new->rb, parent, p);
	rb_insert_color(&new->rb, &stat_tree_root);

	return NULL; /* insert successfully */
}

static void prepare_stat_tree(struct trace_graph_item *item)
{
	struct graph_stat_entry *new;

	if (item->type != TRACE_GRAPH_RETURN)
		return;
	new = xmalloc(sizeof(*new));
	pstrcpy(new->fname, sizeof(new->fname), item->fname);
	new->duration = item->return_time - item->entry_time;
	new->nr_calls = 1;
	INIT_LIST_HEAD(&new->list);
	if (stat_tree_insert(new)) {
		free(new);
		return;
	}
	list_add(&new->list, &stat_list);
}

static void stat_list_print(void)
{
	struct graph_stat_entry *entry;

	list_for_each_entry(entry, &stat_list, list) {
		float total = (float)entry->duration / 1000000000;
		float per = (float)entry->duration / entry->nr_calls / 1000000;

		printf("%10.3f   %10.3f        %5"PRIu16"   %-*s\n", total, per,
		       entry->nr_calls, TRACE_FNAME_LEN, entry->fname);
	}
}

static int stat_list_cmp(void *priv, struct list_head *a, struct list_head *b)
{
	struct graph_stat_entry *ga = container_of(a, struct graph_stat_entry,
						   list);
	struct graph_stat_entry *gb = container_of(b, struct graph_stat_entry,
						   list);
	/* '-' is for reverse sort, largest first */
	return -intcmp(ga->duration, gb->duration);
}

static void stat_trace_file(void *buf, size_t size)
{
	struct trace_graph_item *item = (struct trace_graph_item *)buf;
	size_t sz = size / sizeof(struct trace_graph_item), i;

	printf("   Total (s)   Per Call (ms)   Calls   Name\n");
	for (i = 0; i < sz; i++)
		prepare_stat_tree(item++);
	list_sort(NULL, &stat_list, stat_list_cmp);
	stat_list_print();
}

static int graph_stat(int argc, char **argv)
{
	struct stat st;
	void *map = map_trace_file(&st);

	if (!map)
		return EXIT_FAILURE;

	stat_trace_file(map, st.st_size);
	munmap(map, st.st_size);
	return EXIT_SUCCESS;
}

static int trace_parser(int ch, char *opt)
{
	return 0;
}

static struct subcommand graph_cmd[] = {
	{"cat", NULL, NULL, "cat the output of graph tracer",
	 NULL, 0, graph_cat},
	{"stat", NULL, NULL, "get the stat of the graph calls",
	 NULL, 0, graph_stat},
	{NULL,},
};

static int trace_graph(int argc, char **argv)
{
	return do_generic_subcommand(graph_cmd, argc, argv);
}

/* Subcommand list of trace */
static struct subcommand trace_cmd[] = {
	{"enable", "<tracer>", "aph", "enable tracer", NULL,
	 CMD_NEED_ARG, trace_enable},
	{"disable", "<tracer>", "aph", "disable tracer", NULL,
	 CMD_NEED_ARG, trace_disable},
	{"status", NULL, "aph", "show tracer statuses", NULL,
	 0, trace_status},
	{"graph", NULL, "aph", "run dog trace graph for more information",
	 graph_cmd, CMD_NEED_ARG, trace_graph},
	{NULL},
};

struct command trace_command = {
	"trace",
	trace_cmd,
	trace_parser
};
