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
