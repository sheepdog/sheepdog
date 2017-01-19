#include <stdlib.h>
#include <unity.h>
#include <cmock.h>

#include "work.h"
#include "event.h"

/* define at sheep/sheep.c */
#define EPOLL_SIZE 4096

struct work_queue *wq;

static void test_init_work_queue(void)
{
	TEST_ASSERT_EQUAL_HEX8(-1, init_work_queue(NULL));
	init_event(EPOLL_SIZE);
	TEST_ASSERT_EQUAL_HEX8(0, init_work_queue(NULL));
}

static void test_create_work_queue(void)
{
	const char *name_o = "wq_ordered";
	const char *name_d = "wq_dynamic";
	enum wq_thread_control tc = WQ_ORDERED;

	wq = create_work_queue(name_o, tc);
	TEST_ASSERT_NOT_NULL(wq);

	tc = WQ_DYNAMIC;
	wq = create_work_queue(name_d, tc);
	TEST_ASSERT_NOT_NULL(wq);
}

static void test_queue_work(void)
{
	struct work w;

	queue_work(wq, &w);
	TEST_ASSERT_EQUAL_PTR(&w, wq->pending_list.n.next);
}

int main(int argc, char **argv)
{
	UNITY_BEGIN();

	RUN_TEST(test_init_work_queue);
	RUN_TEST(test_create_work_queue);
	/*
	 * Execute test_queue_work after test_create_work_queue.
	 * Because test_queue_work use work_queue
	 */
	RUN_TEST(test_queue_work);

	return UNITY_END();
}
