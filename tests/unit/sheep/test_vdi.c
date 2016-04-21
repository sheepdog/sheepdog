/*
 * Copyright (C) 2013 Zelin.io
 * Copyright (C) 2016 Nippon Telegraph and Telephone Corporation
 *
 * Kai Zhang <kyle@zelin.io>
 * Takashi Menjo <menjo.takashi@lab.ntt.co.jp>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <unity.h>

#include "sheep_priv.h"

static void test_vdi(void)
{
	struct system_info mock_sys = {0}; sys = &mock_sys;
	add_vdi_state(1, 1, true, 0, 22, 0);
	add_vdi_state(2, 1, true, 0, 22, 0);
	add_vdi_state(3, 2, false, 0, 22, 0);
	TEST_ASSERT_EQUAL_INT(1, get_vdi_copy_number(1));
	TEST_ASSERT_EQUAL_INT(1, get_vdi_copy_number(2));
	TEST_ASSERT_EQUAL_INT(2, get_vdi_copy_number(3));
}

int main(void)
{
	UNITY_BEGIN();
	RUN_TEST(test_vdi);
	return UNITY_END();
}
