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
#ifndef __DOG_H__
#define __DOG_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "sheepdog_proto.h"
#include "sheep.h"
#include "exits.h"
#include "option.h"
#include "work.h"
#include "event.h"
#include "config.h"

#define CMD_NEED_NODELIST (1 << 0)
#define CMD_NEED_ARG (1 << 1)

#define UINT64_DECIMAL_SIZE 21

struct command {
	const char *name;
	const struct subcommand *sub;
	int (*parser)(int, const char *);
};

struct subcommand {
	const char *name;
	const char *arg;
	const char *opts;
	const char *desc;
	const struct subcommand *sub;
	unsigned long flags;
	int (*fn)(int, char **);
	const struct sd_option *options;
};
void subcommand_usage(char *cmd, char *subcmd, int status);

extern struct node_id sd_nid;
extern bool highlight;
extern bool raw_output;
extern bool verbose;

extern uint32_t sd_epoch;
extern struct rb_root sd_vroot;
extern struct rb_root sd_nroot;
extern int sd_nodes_nr;

bool is_current(const struct sd_inode *i);
char *strnumber(uint64_t _size);
typedef void (*vdi_parser_func_t)(uint32_t vid, const char *name,
				  const char *tag, uint32_t snapid,
				  uint32_t flags,
				  const struct sd_inode *i, void *data);
int parse_vdi(vdi_parser_func_t func, size_t size, void *data);
int sd_read_object(uint64_t oid, void *data, unsigned int datalen,
		   uint64_t offset, bool direct);
int sd_write_object(uint64_t oid, uint64_t cow_oid, void *data,
		    unsigned int datalen, uint64_t offset, uint32_t flags,
		    uint8_t copies, uint8_t, bool create, bool direct);
int dog_exec_req(const struct node_id *, struct sd_req *hdr, void *data);
int send_light_req(const struct node_id *, struct sd_req *hdr);
int do_generic_subcommand(struct subcommand *sub, int argc, char **argv);
int update_node_list(int max_nodes);
void confirm(const char *message);
void work_queue_wait(struct work_queue *q);
int do_vdi_create(const char *vdiname, int64_t vdi_size,
		  uint32_t base_vid, uint32_t *vdi_id, bool snapshot,
		  uint8_t nr_copies, uint8_t copy_policy);
int do_vdi_check(const struct sd_inode *inode);
void show_progress(uint64_t done, uint64_t total, bool raw);
size_t get_store_objsize(uint8_t copy_policy, uint64_t oid);

extern struct command vdi_command;
extern struct command node_command;
extern struct command cluster_command;

#ifdef HAVE_TRACE
  extern struct command trace_command;
#else
  #define trace_command {}
#endif /* HAVE_TRACE */

#endif
