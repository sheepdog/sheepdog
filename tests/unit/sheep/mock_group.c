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

#include "mock.h"

#include "cluster.h"

MOCK_VOID_METHOD(sd_accept_handler, const struct sd_node *joined,
		 const struct sd_node *members, size_t nr_members,
		 const void *opaque)
MOCK_METHOD(sd_join_handler, bool, true, const struct sd_node *joining,
	    const struct sd_node *nodes, size_t nr_nodes,
	    void *opaque)
MOCK_VOID_METHOD(sd_leave_handler, const struct sd_node *left,
		 const struct sd_node *members, size_t nr_members)
MOCK_VOID_METHOD(sd_notify_handler, const struct sd_node *sender, void *msg,
		 size_t msg_len)
MOCK_METHOD(sd_block_handler, bool, true, const struct sd_node *sender)
MOCK_METHOD(sd_reconnect_handler, int, 0)
MOCK_VOID_METHOD(sd_update_node_handler, struct sd_node *node)
