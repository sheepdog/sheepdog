#include <check.h>

#include "collie.h"

/* test */
START_TEST(test_common)
{
	char str[100];

	raw_output = true;
	ck_assert_str_eq(size_to_str(10, str, 100), "10");
	ck_assert_str_eq(size_to_str(10000, str, 100), "10000");
	ck_assert_str_eq(size_to_str(100000000, str, 100), "100000000");

	raw_output = false;
	ck_assert_str_eq(size_to_str(10, str, 100), "0.0 MB");
	ck_assert_str_eq(size_to_str(10000, str, 100), "0.0 MB");
	ck_assert_str_eq(size_to_str(100000000, str, 100), "95 MB");
}
END_TEST

static Suite *test_suite(void)
{
	Suite *s = suite_create("test common");

	TCase *tc_common = tcase_create("common");
	tcase_add_test(tc_common, test_common);

	suite_add_tcase(s, tc_common);

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
