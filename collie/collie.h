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
#ifndef __COLLIE_H__
#define __COLLIE_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sheepdog_proto.h"
#include "sheep.h"
#include "exits.h"

#define SUBCMD_FLAG_NEED_NODELIST (1 << 0)
#define SUBCMD_FLAG_NEED_THIRD_ARG (1 << 1)

#define TEXT_NORMAL "\033[0m"
#define TEXT_BOLD   "\033[1m"

struct sd_option {
	int val;
	const char *name;
	int has_arg;
	const char *desc;
};

struct command {
	const char *name;
	struct subcommand *sub;
	int (*parser)(int, char *);
};

struct subcommand {
	const char *name;
	const char *arg;
	const char *opts;
	const char *desc;
	unsigned long flags;
	int (*fn)(int, char **);
};

extern const char *sdhost;
extern int sdport;
extern int highlight;
extern int raw_output;

extern uint64_t node_list_version;
extern struct sheepdog_node_list_entry node_list_entries[SD_MAX_NODES];
extern struct sheepdog_vnode_list_entry vnode_list_entries[SD_MAX_VNODES];
extern int nr_nodes, nr_vnodes;
extern unsigned master_idx;

int is_current(struct sheepdog_inode *i);
char *size_to_str(uint64_t _size, char *str, int str_size);
typedef void (*vdi_parser_func_t)(uint32_t vid, char *name, char *tag,
				  uint32_t snapid, uint32_t flags,
				  struct sheepdog_inode *i, void *data);
int parse_vdi(vdi_parser_func_t func, size_t size, void *data);
int sd_read_object(uint64_t oid, void *data, unsigned int datalen,
		   uint64_t offset);
int sd_write_object(uint64_t oid, uint64_t cow_oid, void *data, unsigned int datalen,
		    uint64_t offset, uint32_t flags, int copies, int create);

extern struct command vdi_command;
extern struct command node_command;
extern struct command cluster_command;

#endif
