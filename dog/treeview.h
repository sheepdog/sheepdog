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
#ifndef __TREEVIEW__
#define __TREEVIEW__

#include <stdbool.h>
#include "list.h"

struct vdi_tree {
	char name[1024];
	char label[256];
	uint32_t vid;
	uint32_t pvid;
	bool highlight;
	struct list_head children;
	struct list_node siblings;
};

void init_tree(void);
void add_vdi_tree(const char *label, const char *tag, uint32_t vid,
		  uint32_t pvid, bool highlight);
void dump_tree(void);
struct vdi_tree *find_vdi_from_root(uint32_t vid, const char *name);

#endif
