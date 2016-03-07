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

MOCK_METHOD(sd_read_object, int, 0,
	    uint64_t oid, char *data, unsigned int datalen, uint64_t offset)
MOCK_METHOD(sd_write_object, int, 0,
	    uint64_t oid, char *data, unsigned int datalen, uint64_t offset,
	    bool create)
MOCK_METHOD(sd_remove_object, int, 0,
	    uint64_t oid)
