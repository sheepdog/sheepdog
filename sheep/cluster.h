/*
 * Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __CLUSTER_H__
#define __CLUSTER_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <memory.h>

#include "sheepdog_proto.h"
#include "sheep.h"
#include "logger.h"

struct sheepid {
	uint8_t addr[16];
	uint64_t pid;
};

struct cdrv_handlers {
	void (*join_handler)(struct sheepid *joined, struct sheepid *members,
			     size_t nr_members);
	void (*leave_handler)(struct sheepid *left, struct sheepid *members,
			      size_t nr_members);
	void (*notify_handler)(struct sheepid *sender, void *msg, size_t msg_len);
};

struct cluster_driver {
	const char *name;

	/*
	 * Initialize the cluster driver
	 *
	 * On success, this function returns the file descriptor that
	 * may be used with the poll(2) to monitor cluster events.  On
	 * error, returns -1.
	 */
	int (*init)(struct cdrv_handlers *handlers, struct sheepid *myid);

	/*
	 * Join the cluster
	 *
	 * This function is used to join the cluster, and notifies a
	 * join event to all the nodes.
	 *
	 * Returns zero on success, -1 on error
	 */
	int (*join)(void);

	/*
	 * Leave the cluster
	 *
	 * This function is used to leave the cluster, and notifies a
	 * leave event to all the nodes.
	 *
	 * Returns zero on success, -1 on error
	 */
	int (*leave)(void);

	/*
	 * Notify a message to all nodes in the cluster
	 *
	 * This function sends 'msg' to all the nodes.  The notified
	 * messages can be read through notify_handler() in
	 * cdrv_handlers.  If 'block_cb' is specified, block_cb() is
	 * called before 'msg' is notified to all the nodes.  All the
	 * cluster events including this notification are blocked
	 * until block_cb() returns or this blocking node leaves the
	 * cluster.  The sheep daemon can sleep in block_cb(), so this
	 * callback must be not called from the dispatch (main) thread.
	 *
	 * Returns zero on success, -1 on error
	 */
	int (*notify)(void *msg, size_t msg_len, void (*block_cb)(void *arg));

	/*
	 * Dispatch handlers
	 *
	 * This function dispatches handlers according to the
	 * delivered events (join/leave/notify) in the cluster.
	 *
	 * Note that the events sequence is totally ordered; all nodes
	 * call the handlers in the same sequence.
	 *
	 * Returns zero on success, -1 on error
	 */
	int (*dispatch)(void);

	struct list_head list;
};

extern struct list_head cluster_drivers;

#define cdrv_register(driver)						\
static void __attribute__((constructor)) regist_ ## driver(void) {	\
	if (!driver.init || !driver.join || !driver.leave ||		\
	    !driver.notify || !driver.dispatch)				\
		panic("the driver '%s' is incomplete\n", driver.name);	\
	list_add(&driver.list, &cluster_drivers);			\
}

#define FOR_EACH_CLUSTER_DRIVER(driver) \
	list_for_each_entry(driver, &cluster_drivers, list)


static inline int sheepid_find(struct sheepid *sheeps, size_t nr_sheeps,
			       struct sheepid *key)
{
	int i;

	for (i = 0; i < nr_sheeps; i++) {
		if (memcmp(sheeps + i, key, sizeof(*key)) == 0)
			return i;
	}
	return -1;
}

static inline void sheepid_add(struct sheepid *sheeps1, size_t nr_sheeps1,
			       struct sheepid *sheeps2, size_t nr_sheeps2)
{
	memcpy(sheeps1 + nr_sheeps1, sheeps2, sizeof(*sheeps2) * nr_sheeps2);
}

static inline void sheepid_del(struct sheepid *sheeps1, size_t nr_sheeps1,
			       struct sheepid *sheeps2, size_t nr_sheeps2)
{
	int i, idx;

	for (i = 0; i < nr_sheeps2; i++) {
		idx = sheepid_find(sheeps1, nr_sheeps1, sheeps2 + i);
		if (idx < 0)
			panic("internal error: cannot find sheepid\n");

		nr_sheeps1--;
		memmove(sheeps1 + idx, sheeps1 + idx + 1,
			sizeof(*sheeps1) * nr_sheeps1 - idx);
	}
}

static inline char *sheepid_to_str(struct sheepid *id)
{
	static char str[256];
	char name[256];

	snprintf(str, sizeof(str), "ip: %s, pid: %" PRIu64,
		 addr_to_str(name, sizeof(name), id->addr, 0), id->pid);

	return str;
}

static inline int sheepid_cmp(struct sheepid *id1, struct sheepid *id2)
{
	return memcmp(id1, id2, sizeof(*id1));
}

#endif
