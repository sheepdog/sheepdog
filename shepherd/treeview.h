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
#ifndef __TREEVIEW__
#define __TREEVIEW__

void init_tree(void);
void add_proc(const char *label, const char *tag, uint64_t pid, uint64_t ppid, int highlight);
void dump_tree(void);

#endif
