/*
 * Copyright (C) 2009 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "sheep.h"
#include "list.h"
#include "util.h"
#include "event.h"

#define EPOLL_SIZE 4096
#define DEFAULT_OBJECT_DIR "/tmp"

static char program_name[] = "sheep";

static struct option const long_options[] =
{
	{"dport", required_argument, 0, 'D'},
	{"sport", required_argument, 0, 's'},
	{"foreground", no_argument, 0, 'f'},
	{"debug", no_argument, 0, 'd'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

static char *short_options = "D:s:fdh";

int nr_nodes;
struct sheepdog_node_list_entry *node_list_entries;

static void usage(int status)
{
	if (status)
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	else {
		printf("Usage: %s [OPTION] [PATH]\n", program_name);
		printf("\
Virtual Machine Distributed File System Object Store Target\n\
  -D, --dport             specify the dog listen port number\n\
  -s, --sport             specify the sheep (our) listen port number\n\
  -f, --foreground        make the program run in the foreground\n\
  -d, --debug             print debug messages\n\
  -h, --help              display this help and exit\n\
");
	}
	exit(status);
}

uint32_t node_list_version;

#define NODE_LIST_UPDATE_INTERVAL 2

static struct timer node_list_timer;

static int node_idx;
int dogport = DOG_LISTEN_PORT;

int get_node_list(void *buf, unsigned int size, unsigned int *epoch, int *idx,
		  int set_timer)
{
	int fd, ret = 1;
	unsigned int wlen;
	struct sheepdog_node_list_entry *ent;
	struct sd_node_req hdr;
	struct sd_node_rsp *rsp = (struct sd_node_rsp *)&hdr;

	fd = connect_to("localhost", dogport);
	if (fd < 0) {
		eprintf("can't connect to dog!\n");
		goto out;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = SD_OP_GET_NODE_LIST;
	hdr.data_length = size;
	hdr.epoch = *epoch;

	wlen = 0;

	ret = exec_req(fd, (struct sd_req *)&hdr, buf, &wlen, &size);

	close(fd);

	if (ret) {
		eprintf("can't connect to dog!\n");
		ret = -1;
		goto out;
	}

	if (size <= 0)
		goto out;

	ret = size / sizeof(*ent);
	*epoch = rsp->epoch;
	*idx = rsp->local_idx;
out:
	if (set_timer)
		add_timer(&node_list_timer, NODE_LIST_UPDATE_INTERVAL);

	return ret;
}

static void update_node_list(void *data)
{
	int ret, size, idx = 0;
	unsigned epoch = 0;
	char *buf;

	size = SD_MAX_NODES * sizeof(struct sheepdog_node_list_entry);

	buf = zalloc(size);
	if (!buf)
		return;

	ret = get_node_list(buf, size, &epoch, &idx, 1);

	if (ret > 0 && epoch != node_list_version) {
		memcpy(node_list_entries, buf, size);
		node_list_version = epoch;
		nr_nodes = ret;
		node_idx = idx;
	}

	free(buf);
}

static int init_node_list(void)
{
	int ret, size, idx = 0;
	unsigned epoch = 0;

	size = SD_MAX_NODES * sizeof(struct sheepdog_node_list_entry);

	node_list_entries = zalloc(size);

	ret = get_node_list(node_list_entries, size, &epoch, &idx, 0);
	if (ret > 0) {
		node_list_version = epoch;
		node_idx = idx;
		nr_nodes = ret;
	}

	node_list_timer.callback = update_node_list;

	add_timer(&node_list_timer, NODE_LIST_UPDATE_INTERVAL);

	return 0;
}

int main(int argc, char **argv)
{
	int ch, longindex;
	int ret, port = SHEEP_LISTEN_PORT;
	char *dir = DEFAULT_OBJECT_DIR;
	int is_daemon = 1;
	int is_debug = 0;

	while ((ch = getopt_long(argc, argv, short_options, long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'D':
			dogport = atoi(optarg);
			break;
		case 's':
			port = atoi(optarg);
			break;
		case 'f':
			is_daemon = 0;
			break;
		case 'd':
			is_debug = 1;
			break;
		case 'h':
			usage(0);
			break;
		default:
			usage(1);
			break;
		}
	}

	if (optind != argc)
		dir = argv[optind];

	ret = log_init(program_name, LOG_SPACE_SIZE, is_daemon, is_debug);
	if (ret)
		exit(1);

	if (is_daemon && daemon(0, 0))
		exit(1);

	ret = init_event(EPOLL_SIZE);
	if (ret)
		exit(1);

	ret = init_node_list();

	ret = create_listen_port(port);
	if (ret)
		exit(1);

	ret = init_store(dir);
	if (ret)
		exit(1);

	init_worker();

	event_loop(-1);

	return 0;
}
