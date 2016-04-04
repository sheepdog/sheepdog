/*
 * Copyright (C) 2016 Nippon Telegraph and Telephone Corporation
 *
 * Takashi Menjo <menjo.takashi@lab.ntt.co.jp>
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

MOCK_METHOD(get_vdi_object_size, uint32_t, 0, uint32_t vid)
MOCK_METHOD(get_vdi_copy_policy, int, 0, uint32_t vid)
