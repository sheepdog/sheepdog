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

#include <check.h>

#include "sheep_priv.h"

START_TEST(test_vdi)
{
	add_vdi_state(1, 1, true);
	add_vdi_state(2, 1, true);
	add_vdi_state(3, 2, false);

	ck_assert_int_eq(get_vdi_copy_number(1), 1);
	ck_assert_int_eq(get_vdi_copy_number(2), 1);
	ck_assert_int_eq(get_vdi_copy_number(3), 2);
}
END_TEST

static Suite *test_suite(void)
{
	Suite *s = suite_create("test vdi");

	TCase *tc_vdi = tcase_create("vdi");
	tcase_add_test(tc_vdi, test_vdi);

	suite_add_tcase(s, tc_vdi);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s = test_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
