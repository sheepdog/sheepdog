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
#include "sheep_priv.h"

MOCK_METHOD(exec_local_req, int, 0, struct sd_req *rq, void *data)
MOCK_METHOD(sheep_exec_req, int, 0,
	    const struct node_id *nid, struct sd_req *hdr, void *buf)
MOCK_METHOD(for_each_object_in_wd, int, 0,
	    int (*func)(uint64_t oid, const char *path,
			uint32_t epoch, uint8_t ec_index,
			struct vnode_info *vinfo, void *arg),
	    bool cleanup, void *arg)
MOCK_VOID_METHOD(put_request, struct request *req)
