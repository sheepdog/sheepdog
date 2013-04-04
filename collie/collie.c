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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "sheepdog_proto.h"
#include "sheep.h"
#include "collie.h"
#include "util.h"

static const char program_name[] = "collie";
const char *sdhost = "127.0.0.1";
int sdport = SD_LISTEN_PORT;
bool highlight = true;
bool raw_output;

static const struct sd_option collie_options[] = {

	/* common options for all collie commands */
	{'a', "address", true, "specify the daemon address (default: localhost)"},
	{'p', "port", true, "specify the daemon port"},
	{'r', "raw", false, "raw output mode: omit headers, separate fields with\n"
	 "                          single spaces and print all sizes in decimal bytes"},
	{'h', "help", false, "display this help and exit"},

	{ 0, NULL, false, NULL },
};

static void usage(const struct command *commands, int status);

uint32_t sd_epoch;

struct sd_node sd_nodes[SD_MAX_NODES];
struct sd_vnode sd_vnodes[SD_MAX_VNODES];
int sd_nodes_nr, sd_vnodes_nr;
unsigned master_idx;

static int update_node_list(int max_nodes, uint32_t epoch)
{
	int fd, ret;
	unsigned int size;
	char *buf = NULL;
	struct sd_node *ent;
	struct sd_node_req hdr;
	struct sd_node_rsp *rsp = (struct sd_node_rsp *)&hdr;

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return -1;

	size = sizeof(*ent) * max_nodes;
	buf = xzalloc(size);
	sd_init_req((struct sd_req *)&hdr, SD_OP_GET_NODE_LIST);
	hdr.request_ver = epoch;

	hdr.data_length = size;

	ret = collie_exec_req(fd, (struct sd_req *)&hdr, buf);
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

	size = rsp->data_length;
	sd_nodes_nr = size / sizeof(*ent);
	if (sd_nodes_nr == 0) {
		fprintf(stderr, "There are no active sheep daemons\n");
		exit(EXIT_FAILURE);
	}

	/* FIXME */
	if (sd_nodes_nr > max_nodes) {
		ret = -1;
		goto out;
	}

	memcpy(sd_nodes, buf, size);
	sd_vnodes_nr = nodes_to_vnodes(sd_nodes, sd_nodes_nr, sd_vnodes);
	sd_epoch = hdr.epoch;
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
static const char *command_opts;
static const char *command_arg;
static const char *command_desc;
static struct sd_option *command_options;

static const struct sd_option *find_opt(int ch)
{
	const struct sd_option *opt;

	/* search for common options */
	sd_for_each_option(opt, collie_options) {
		if (opt->ch == ch)
			return opt;
	}

	/* search for self options */
	if (command_options) {
		sd_for_each_option(opt, command_options) {
			if (opt->ch == ch)
				return opt;
		}
	}

	fprintf(stderr, "Internal error\n");
	exit(EXIT_SYSFAIL);
}

static void init_commands(const struct command **commands)
{
	static struct command *cmds;
	struct command command_list[] = {
		vdi_command,
		node_command,
		cluster_command,
		debug_command,
		{NULL,}
	};

	if (!cmds) {
		cmds = (struct command *)xmalloc(sizeof(command_list));
		memcpy(cmds, command_list, sizeof(command_list));
	}

	*commands = cmds;
	return;
}

static const struct subcommand *find_subcmd(const char *cmd, const char *subcmd)
{
	int i, j;
	const struct command *commands;
	const struct subcommand *sub;

	init_commands(&commands);

	for (i = 0; commands[i].name; i++) {
		if (!strcmp(commands[i].name, cmd)) {
			sub = commands[i].sub;
			for (j = 0; sub[j].name; j++) {
				if (!strcmp(sub[j].name, subcmd))
					return &sub[j];
			}
		}
	}

	return NULL;
}

static unsigned long setup_commands(const struct command *commands,
				    char *cmd, char *subcmd)
{
	int i;
	bool found = false;
	struct subcommand *s;
	unsigned long flags = 0;

	for (i = 0; commands[i].name; i++) {
		if (!strcmp(commands[i].name, cmd)) {
			found = true;
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
			command_opts = s->opts;
			command_arg = s->arg;
			command_desc = s->desc;
			command_options = s->options;
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

static void usage(const struct command *commands, int status)
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
				snprintf(name, sizeof(name), "%s %s",
					 commands[i].name, s->name);
				printf("  %-24s%s\n", name, s->desc);
			}
		}
		printf("\n");
		printf("For more information, run "
		       "'%s <command> <subcommand> --help'.\n", program_name);
	}
	exit(status);
}

void subcommand_usage(char *cmd, char *subcmd, int status)
{
	int i, n, len = strlen(command_opts);
	const struct sd_option *sd_opt;
	const struct subcommand *sub, *subsub;
	char name[64];

	printf("Usage: %s %s %s", program_name, cmd, subcmd);

	/* Show subcmd's subcommands if necessary */
	sub = find_subcmd(cmd, subcmd);
	subsub = sub->sub;
	if (subsub) {
		n = 0;
		while (subsub[n].name)
			n++;
		if (n == 1)
			printf(" %s", subsub[0].name);
		else if (n > 1) {
			printf(" {%s", subsub[0].name);
			for (i = 1; i < n; i++)
				printf("|%s", subsub[i].name);
			printf("}");
		}
	}

	for (i = 0; i < len; i++) {
		sd_opt = find_opt(command_opts[i]);
		if (sd_opt->has_arg)
			printf(" [-%c %s]", sd_opt->ch, sd_opt->name);
		else
			printf(" [-%c]", sd_opt->ch);
	}
	if (command_arg)
		printf(" %s", command_arg);

	printf("\n");
	if (subsub) {
		printf("Available subcommands:\n");
		for (i = 0; subsub[i].name; i++)
			printf("  %-24s%s\n", subsub[i].name, subsub[i].desc);

	}

	printf("Options:\n");
	for (i = 0; i < len; i++) {
		sd_opt = find_opt(command_opts[i]);
		snprintf(name, sizeof(name), "-%c, --%s",
			 sd_opt->ch, sd_opt->name);
		printf("  %-24s%s\n", name, sd_opt->desc);
	}

	exit(status);
}

static const struct sd_option *build_sd_options(const char *opts)
{
	static struct sd_option sd_opts[256], *p;
	int i, len = strlen(opts);

	p = sd_opts;
	for (i = 0; i < len; i++)
		*p++ = *find_opt(opts[i]);
	memset(p, 0, sizeof(struct sd_option));

	return sd_opts;
}

static void crash_handler(int signo)
{
	fprintf(stderr, "collie exits unexpectedly (%s).\n", strsignal(signo));

	sd_backtrace();

	exit(EXIT_SYSFAIL);
}

int main(int argc, char **argv)
{
	int ch, longindex, ret;
	unsigned long flags;
	struct option *long_options;
	const struct command *commands;
	const char *short_options;
	char *p;
	const struct sd_option *sd_opts;

	install_crash_handler(crash_handler);

	init_commands(&commands);

	if (argc < 3)
		usage(commands, 0);

	flags = setup_commands(commands, argv[1], argv[2]);

	optind = 3;

	sd_opts = build_sd_options(command_opts);
	long_options = build_long_options(sd_opts);
	short_options = build_short_options(sd_opts);

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
			raw_output = true;
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

	if (!is_stdout_console() || raw_output)
		highlight = false;

	if (flags & SUBCMD_FLAG_NEED_NODELIST) {
		ret = update_node_list(SD_MAX_NODES, 0);
		if (ret < 0) {
			fprintf(stderr, "Failed to get node list\n");
			exit(EXIT_SYSFAIL);
		}
	}

	if (flags & SUBCMD_FLAG_NEED_ARG && argc == optind)
		subcommand_usage(argv[1], argv[2], EXIT_USAGE);

	return command_fn(argc, argv);
}
