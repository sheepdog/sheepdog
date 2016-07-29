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

void setUp(void)
{
	clean_vdi_state();
}

void tearDown(void)
{
	/* add codes if needed */
}

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

static void test_fill_vdi_state_list_empty(void)
{
	const struct sd_req request = {0};
	struct sd_rsp response = {0};
	TEST_ASSERT_EQUAL_INT(SD_RES_SUCCESS, fill_vdi_state_list(&request, &response, NULL));
}

static void test_fill_vdi_state_list_one(void)
{
	const size_t SIZE_VDI_STATE = sizeof(struct vdi_state);
	const struct sd_req request = { .data_length = SIZE_VDI_STATE };
	struct sd_rsp response = {0};
	struct vdi_state state = {0};
	add_vdi_state(1, 3, false, 0, 22, 0);
	TEST_ASSERT_EQUAL_INT(SD_RES_SUCCESS, fill_vdi_state_list(&request, &response, &state));
	TEST_ASSERT_EQUAL_UINT32(SIZE_VDI_STATE, response.data_length);
	TEST_ASSERT_EQUAL_UINT32(1, state.vid);
	TEST_ASSERT_EQUAL_INT(3, state.nr_copies);
	TEST_ASSERT_FALSE(state.snapshot);
	TEST_ASSERT_EQUAL_UINT8(0, state.copy_policy);
	TEST_ASSERT_EQUAL_UINT8(22, state.block_size_shift);
	TEST_ASSERT_EQUAL_UINT32(0, state.parent_vid);
	TEST_ASSERT_FALSE(state.deleted);
}

static void test_fill_vdi_state_list_should_set_deleted(void)
{
	const size_t SIZE_VDI_STATE = sizeof(struct vdi_state);
	const struct sd_req request = { .data_length = SIZE_VDI_STATE };
	struct sd_rsp response = {0};
	struct vdi_state state = {0};
	add_vdi_state(1, 3, false, 0, 22, 0);
	vdi_mark_deleted(1);
	TEST_ASSERT_EQUAL_INT(SD_RES_SUCCESS, fill_vdi_state_list(&request, &response, &state));
	TEST_ASSERT_EQUAL_UINT32(SIZE_VDI_STATE, response.data_length);
	TEST_ASSERT_EQUAL_UINT32(1, state.vid);
	TEST_ASSERT_EQUAL_INT(3, state.nr_copies);
	TEST_ASSERT_FALSE(state.snapshot);
	TEST_ASSERT_EQUAL_UINT8(0, state.copy_policy);
	TEST_ASSERT_EQUAL_UINT8(22, state.block_size_shift);
	TEST_ASSERT_EQUAL_UINT32(0, state.parent_vid);
	TEST_ASSERT_TRUE(state.deleted);
}

int main(void)
{
	UNITY_BEGIN();
	RUN_TEST(test_vdi);
	RUN_TEST(test_fill_vdi_state_list_empty);
	RUN_TEST(test_fill_vdi_state_list_one);
	RUN_TEST(test_fill_vdi_state_list_should_set_deleted);
	return UNITY_END();
}
