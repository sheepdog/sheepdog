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
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "sheepdog_proto.h"
#include "sheep.h"
#include "exits.h"
#include "option.h"

#define SUBCMD_FLAG_NEED_NODELIST (1 << 0)
#define SUBCMD_FLAG_NEED_THIRD_ARG (1 << 1)

#define TEXT_NORMAL "\033[0m"
#define TEXT_BOLD   "\033[1m"

#define UINT64_DECIMAL_SIZE 21

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
	struct subcommand *sub;
	unsigned long flags;
	int (*fn)(int, char **);
	struct sd_option *options;
};
void subcommand_usage(char *cmd, char *subcmd, int status);

extern const char *sdhost;
extern int sdport;
extern bool highlight;
extern bool raw_output;

extern uint32_t sd_epoch;
extern struct sd_node sd_nodes[SD_MAX_NODES];
extern struct sd_vnode sd_vnodes[SD_MAX_VNODES];
extern int sd_nodes_nr, sd_vnodes_nr;
extern unsigned master_idx;

bool is_current(const struct sheepdog_inode *i);
char *size_to_str(uint64_t _size, char *str, int str_size);
typedef void (*vdi_parser_func_t)(uint32_t vid, const char *name,
				  const char *tag, uint32_t snapid,
				  uint32_t flags,
				  const struct sheepdog_inode *i, void *data);
int parse_vdi(vdi_parser_func_t func, size_t size, void *data);
int sd_read_object(uint64_t oid, void *data, unsigned int datalen,
		   uint64_t offset, bool direct);
int sd_write_object(uint64_t oid, uint64_t cow_oid, void *data,
		    unsigned int datalen, uint64_t offset, uint32_t flags,
		    int copies, bool create, bool direct);
int send_light_req(struct sd_req *hdr, const char *host, int port);
int send_light_req_get_response(struct sd_req *hdr, const char *host, int port);

extern struct command vdi_command;
extern struct command node_command;
extern struct command cluster_command;

#ifdef ENABLE_TRACE
  extern struct command debug_command;
#else
  #define debug_command {}
#endif /* ENABLE_TRACE */

#endif
