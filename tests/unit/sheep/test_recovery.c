#include <stdlib.h>
#include <unity.h>
#include <cmock.h>
#include <unistd.h>

#include "sheep_priv.h"
/* need for work_queue */
#include "work.h"
#include "event.h"
/* define at sheep/sheep.c */
#define EPOLL_SIZE 4096

int is_default_update_epoch_called = 0;

int default_update_epoch(uint32_t epoch)
{
	is_default_update_epoch_called = 1;
	return 0;
}

static void test_start_recovery()
{
	struct vnode_info cur_vinfo;
	struct vnode_info old_vinfo;
	bool epoch_lifted = false;
	bool wildcard = false;
	struct system_info __sys;
	struct sd_node new;

	/* parameter set */
	sys = &__sys;
	__sys.gateway_only = false;
	__sys.this_node.nr_vnodes = 1;
	__sys.cinfo.flags = SD_CLUSTER_FLAG_AVOID_DISKFULL;
	__sys.ninfo.store[0] = 'p';
	__sys.ninfo.store[1] = 'l';
	__sys.ninfo.store[2] = 'a';
	__sys.ninfo.store[3] = 'i';
	__sys.ninfo.store[4] = 'n';
	__sys.ninfo.store[5] = '\0';

	INIT_RB_ROOT(&cur_vinfo.vroot);
	INIT_RB_ROOT(&cur_vinfo.nroot);
	cur_vinfo.nr_nodes = 1;
	new.nid.addr[12]=127;
	new.nid.addr[13]=0;
	new.nid.addr[14]=0;
	new.nid.addr[15]=1;
	new.nid.port=7000;
	rb_insert(&cur_vinfo.nroot, &new, rb, node_cmp);

	/* create work queue */
	init_event(EPOLL_SIZE);
	init_work_queue(NULL);
	sys->recovery_wqueue = create_work_queue("rw", WQ_UNLIMITED);

	INIT_LIST_HEAD(&sys->req_wait_queue);

	/* create store_driver */
	static struct store_driver plain_store = {
		.id = PLAIN_STORE,
		.name = "plain",
		.update_epoch = default_update_epoch,
		/*
		.init = default_init,
		.exist = default_exist,
		.create_and_write = default_create_and_write,
		.write = default_write,
		.read = default_read,
		.link = default_link,
		.cleanup = default_cleanup,
		.format = default_format,
		.remove_object = default_remove_object,
		.get_hash = default_get_hash,
		.purge_obj = default_purge_obj,
		*/
	};
	list_add(&plain_store.list, &store_drivers);
	init_store_driver(true);

	/* test target */
	TEST_ASSERT_EQUAL_HEX8(0, start_recovery(&cur_vinfo, &old_vinfo, epoch_lifted, wildcard));
	TEST_ASSERT_EQUAL_HEX8(1, is_default_update_epoch_called);
	sleep(1);
}

int main(int argc, char **argv)
{
	UNITY_BEGIN();

	RUN_TEST(test_start_recovery);

	return UNITY_END();
}
