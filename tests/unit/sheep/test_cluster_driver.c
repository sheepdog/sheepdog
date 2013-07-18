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

#ifdef BUILD_ZOOKEEPER
#include <zookeeper/zookeeper.h>
#endif

#include "cluster.h"
#include "event.h"
#include "mock.h"

#define LOOP_WHEN(expr)				\
	while (expr)				\
		event_loop(-1)

#define assert_ret(call, expect)			\
	do {						\
		int __ret = call;			\
		ck_assert_int_eq(__ret, expect);	\
	} while (0)

static void teardown(void)
{
	method_reset_all();
}

static void do_test(const char *arg)
{
	struct cluster_driver *driver;
	struct sd_node node;
	const char *option;
	size_t len = 4;
	void *msg;

	driver = find_cdrv(arg);
	if (!driver)
		return;

	option = get_cdrv_option(driver, arg);
	msg = xmalloc(len);

	assert_ret(driver->init(option), 0);
	assert_ret(driver->join(&node, msg, len), 0);

	LOOP_WHEN(method_nr_call(sd_join_handler) == 0);
	LOOP_WHEN(method_nr_call(sd_accept_handler) == 0);
	ck_assert_int_eq(method_nr_call(sd_join_handler), 1);
	ck_assert_int_eq(method_nr_call(sd_accept_handler), 1);

	assert_ret(driver->block(), 0);
	assert_ret(driver->block(), 0);

	LOOP_WHEN(method_nr_call(sd_block_handler) == 0);
	ck_assert_int_eq(method_nr_call(sd_block_handler), 1);

	assert_ret(driver->unblock(msg, len), 0);
	LOOP_WHEN(method_nr_call(sd_block_handler) == 1);

	ck_assert_int_eq(method_nr_call(sd_block_handler), 2);
	ck_assert_int_eq(method_nr_call(sd_notify_handler), 1);

	assert_ret(driver->unblock(msg, len), 0);
	LOOP_WHEN(method_nr_call(sd_notify_handler) == 1);

	ck_assert_int_eq(method_nr_call(sd_notify_handler), 2);

	free(msg);
}

START_TEST(test_local)
{
	assert_ret(init_event(4096), 0);
	do_test("local");
}
END_TEST

START_TEST(test_zookeeper)
{
	assert_ret(init_event(4096), 0);
#ifdef BUILD_ZOOKEEPER
	zoo_set_debug_level(0);
#endif
	do_test("zookeeper:localhost:2181,timeout=1000");
}
END_TEST

static Suite *test_suite(void)
{
	Suite *s = suite_create("test cluster driver");

	/*
	 * If the program is configured with "--enable-zookeeper",
	 * tests succeed only when zookeeper is started externally.
	 * TODO: use JNI to call curator's TestingServer to remove this
	 * dependency
	 */
	TCase *tc_local = tcase_create("local");
	TCase *tc_zk = tcase_create("zookeeper");
	tcase_add_test(tc_local, test_local);
	tcase_add_test(tc_zk, test_zookeeper);

	suite_add_tcase(s, tc_local);
	suite_add_tcase(s, tc_zk);
	tcase_add_checked_fixture(tc_local, NULL, teardown);
	tcase_add_checked_fixture(tc_zk, NULL, teardown);

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
