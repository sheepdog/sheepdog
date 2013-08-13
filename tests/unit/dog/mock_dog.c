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
uint8_t sdhost[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1 };
int sdport = 7000, sd_vnodes_nr = 100;
bool highlight = true;
bool raw_output;
struct sd_vnode sd_vnodes[SD_MAX_VNODES];

MOCK_METHOD(update_node_list, int, 0, int max_nodes)
MOCK_VOID_METHOD(subcommand_usage, char *cmd, char *subcmd, int status)
