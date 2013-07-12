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

#include "collie.h"

/* collie mock */
const char *sdhost = "127.0.0.1";
int sdport = 7000, sd_vnodes_nr = 100;
bool highlight = true;
bool raw_output;
struct sd_vnode sd_vnodes[SD_MAX_VNODES];

int update_node_list(int max_nodes)
{
	return 0;
}

void subcommand_usage(char *cmd, char *subcmd, int status)
{
	return;
}
