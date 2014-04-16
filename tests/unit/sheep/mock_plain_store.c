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

MOCK_METHOD(get_store_objsize, size_t, SD_DATA_OBJ_SIZE, uint64_t oid)
MOCK_METHOD(get_store_path, int, 0, uint64_t oid, uint8_t ec_index, char *path)
