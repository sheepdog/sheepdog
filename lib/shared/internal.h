/*
 * Copyright (C) 2015 China Mobile Inc.
 *
 * Liu Yuan <liuyuan@cmss.chinamobile.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef INTERNAL_H_
#define INTERNAL_H_

struct sd_request {
	struct list_node list;
	struct sd_vdi *vdi;
	void *data;
	size_t length;
	off_t offset;
	bool write;
	int efd;
	int ret;
};

#endif
