/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "sheepdog_proto.h"
#include "sheep.h"
#include "collie.h"

static char program_name[] = "collie";
const char *sdhost = "localhost";
int sdport = SD_LISTEN_PORT;
int highlight = 1;
int raw_output = 0;

static const struct sd_option collie_options[] = {

	/* common options */
	{'a', "address", 1, "specify the daemon address (default: localhost)"},
	{'p', "port", 1, "specify the daemon port"},
	{'r', "raw", 0, "raw output mode: omit headers, separate fields with\n\
                          single spaces and print all sizes in decimal bytes"},
	{'h', "help", 0, "display this help and exit"},

	/* VDI options */
	{'P', "prealloc", 0, "preallocate all the data objects"},
	{'i', "index", 1, "specify the index of data objects"},
	{'s', "snapshot", 1, "specify a snapshot id or tag name"},
	{'x', "exclusive", 0, "write in an exclusive mode"},
	{'d', "delete", 0, "delete a key"},

	/* cluster options */
	{'b', "store", 1, "specify backend store"},
	{'c', "copies", 1, "specify the data redundancy (number of copies)"},
	{'H', "nohalt", 0, "serve IO requests even if there are too few\n\
                          nodes for the configured redundancy"},
	{'f', "force", 0, "do not prompt for confirmation"},
	{'R', "restore", 1, "restore the cluster"},
	{'l', "list", 0, "list the user epoch information"},

	{ 0, NULL, 0, NULL },
};

static void usage(struct command *commands, int status);

uint32_t node_list_version;

struct sd_node node_list_entries[SD_MAX_NODES];
struct sd_vnode vnode_list_entries[SD_MAX_VNODES];
int nr_nodes, nr_vnodes;
unsigned master_idx;

static int update_node_list(int max_nodes, uint32_t epoch)
{
	int fd, ret;
	unsigned int size, wlen;
	char *buf = NULL;
	struct sd_node *ent;
	struct sd_node_req hdr;
	struct sd_node_rsp *rsp = (struct sd_node_rsp *)&hdr;

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return -1;

	size = sizeof(*ent) * max_nodes;
	buf = zalloc(size);
	if (!buf) {
		ret = -1;
		goto out;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = SD_OP_GET_NODE_LIST;
	hdr.request_ver = epoch;

	hdr.data_length = size;

	wlen = 0;

	ret = exec_req(fd, (struct sd_req *)&hdr, buf, &wlen, &size);
	if (ret) {
		ret = -1;
		goto out;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to update node list: %s\n",
				sd_strerror(rsp->result));
		ret = -1;
		goto out;
	}

	nr_nodes = size / sizeof(*ent);
	if (nr_nodes == 0) {
		fprintf(stderr, "There are no active sheep daemons\n");
		exit(EXIT_FAILURE);
	}

	/* FIXME */
	if (nr_nodes > max_nodes) {
		ret = -1;
		goto out;
	}

	memcpy(node_list_entries, buf, size);
	nr_vnodes = nodes_to_vnodes(node_list_entries, nr_nodes, vnode_list_entries);
	node_list_version = hdr.epoch;
	master_idx = rsp->master_idx;
out:
	if (buf)
		free(buf);
	if (fd >= 0)
		close(fd);

	return ret;
}

static int (*command_parser)(int, char *);
static int (*command_fn)(int, char **);
static const char *command_options;
static const char *command_arg;
static const char *command_desc;

static const struct sd_option *find_opt(int ch)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(collie_options); i++) {
		if (collie_options[i].val == ch)
			return collie_options + i;
	}
	fprintf(stderr, "Internal error\n");
	exit(EXIT_SYSFAIL);
}

static char *build_short_options(const char *opts)
{
	static char sopts[256], *p;
	const struct sd_option *sd_opt;
	int i, len = strlen(opts);

	p = sopts;
	for (i = 0; i < len; i++) {
		sd_opt = find_opt(opts[i]);
		*p++ = sd_opt->val;
		if (sd_opt->has_arg)
			*p++ = ':';
	}
	*p = '\0';

	return sopts;
}

static struct option *build_long_options(const char *opts)
{
	static struct option lopts[256], *p;
	const struct sd_option *sd_opt;
	int i, len = strlen(opts);

	p = lopts;
	for (i = 0; i < len; i++) {
		sd_opt = find_opt(opts[i]);
		p->name = sd_opt->name;
		p->has_arg = sd_opt->has_arg;
		p->flag = NULL;
		p->val = sd_opt->val;
		p++;
	}
	memset(p, 0, sizeof(struct option));

	return lopts;
}

static unsigned long setup_command(struct command *commands, char *cmd, char *subcmd)
{
	int i, found = 0;
	struct subcommand *s;
	unsigned long flags = 0;

	for (i = 0; commands[i].name; i++) {
		if (!strcmp(commands[i].name, cmd)) {
			found = 1;
			if (commands[i].parser)
				command_parser = commands[i].parser;
			break;
		}
	}

	if (!found) {
		fprintf(stderr, "Invalid command '%s'\n", cmd);
		usage(commands, EXIT_USAGE);
	}

	for (s = commands[i].sub; s->name; s++) {
		if (!strcmp(s->name, subcmd)) {
			command_fn = s->fn;
			command_options = s->opts;
			command_arg = s->arg;
			command_desc = s->desc;
			flags = s->flags;
			break;
		}
	}

	if (!command_fn) {
		if (strcmp(subcmd, "help") && strcmp(subcmd, "--help"))
			fprintf(stderr, "Invalid command '%s %s'\n", cmd, subcmd);
		fprintf(stderr, "Available %s commands:\n", cmd);
		for (s = commands[i].sub; s->name; s++)
			fprintf(stderr, "  %s %s\n", cmd, s->name);
		exit(EXIT_USAGE);
	}

	return flags;
}

static void usage(struct command *commands, int status)
{
	int i;
	struct subcommand *s;
	char name[64];

	if (status)
		fprintf(stderr, "Try '%s --help' for more information.\n", program_name);
	else {
		printf("Sheepdog administrator utility\n");
		printf("Usage: %s <command> <subcommand> [options]\n", program_name);
		printf("\nAvailable commands:\n");
		for (i = 0; commands[i].name; i++) {
			for (s = commands[i].sub; s->name; s++) {
				sprintf(name, "%s %s", commands[i].name, s->name);
				printf("  %-24s%s\n", name, s->desc);
			}
		}
		printf("\n");
		printf("For more information, run "
		       "'%s <command> <subcommand> --help'.\n", program_name);
	}
	exit(status);
}

static void subcommand_usage(char *cmd, char *subcmd, int status)
{
	int i, len = strlen(command_options);
	const struct sd_option *sd_opt;
	char name[64];

	printf("Usage: %s %s %s", program_name, cmd, subcmd);
	for (i = 0; i < len; i++) {
		sd_opt = find_opt(command_options[i]);
		if (sd_opt->has_arg)
			printf(" [-%c %s]", sd_opt->val, sd_opt->name);
		else
			printf(" [-%c]", sd_opt->val);
	}
	if (command_arg)
		printf(" %s", command_arg);
	printf("\nOptions:\n");
	for (i = 0; i < len; i++) {
		sd_opt = find_opt(command_options[i]);
		sprintf(name, "-%c, --%s", sd_opt->val, sd_opt->name);
		printf("  %-24s%s\n", name, sd_opt->desc);
	}

	exit(status);
}

int main(int argc, char **argv)
{
	int ch, longindex, ret;
	unsigned long flags;
	struct option *long_options;
	const char *short_options;
	char *p;
	struct command commands[] = {
		vdi_command,
		node_command,
		cluster_command,
		debug_command,
		{NULL,}
	};


	if (argc < 3)
		usage(commands, 0);

	flags = setup_command(commands, argv[1], argv[2]);

	optind = 3;

	long_options = build_long_options(command_options);
	short_options = build_short_options(command_options);

	while ((ch = getopt_long(argc, argv, short_options, long_options,
				&longindex)) >= 0) {

		switch (ch) {
		case 'a':
			sdhost = optarg;
			break;
		case 'p':
			sdport = strtol(optarg, &p, 10);
			if (optarg == p || sdport < 1 || sdport > UINT16_MAX) {
				fprintf(stderr, "Invalid port number '%s'\n", optarg);
				exit(EXIT_USAGE);
			}
			break;
		case 'r':
			raw_output = 1;
			break;
		case 'h':
			subcommand_usage(argv[1], argv[2], EXIT_SUCCESS);
			break;
		case '?':
			usage(commands, EXIT_USAGE);
			break;
		default:
			if (command_parser)
				command_parser(ch, optarg);
			else
				usage(commands, EXIT_USAGE);
			break;
		}
	}

	if (!isatty(STDOUT_FILENO) || raw_output)
		highlight = 0;

	if (flags & SUBCMD_FLAG_NEED_NODELIST) {
		ret = update_node_list(SD_MAX_NODES, 0);
		if (ret < 0) {
			fprintf(stderr, "Failed to get node list\n");
			exit(EXIT_SYSFAIL);
		}
	}

	if (flags & SUBCMD_FLAG_NEED_THIRD_ARG && argc == optind)
		subcommand_usage(argv[1], argv[2], EXIT_USAGE);

	return command_fn(argc, argv);
}
