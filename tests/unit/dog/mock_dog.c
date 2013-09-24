/*
 * Copyright (C) 2013 Zelin.io
 *
 * Kai Zhang <kyle@zelin.io>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "dog.h"
#include "mock.h"

/* dog mock */
struct node_id sd_nid = {
	/* default sdhost is "127.0.0.1" */
	.addr = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1 },
	.port = SD_LISTEN_PORT,
};
bool highlight = true;
bool raw_output;
struct rb_root sd_vroot = RB_ROOT;
struct rb_root sd_nroot = RB_ROOT;

MOCK_METHOD(update_node_list, int, 0, int max_nodes)
MOCK_VOID_METHOD(subcommand_usage, char *cmd, char *subcmd, int status)
