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
#include <arpa/inet.h>
#include <memory.h>

#include "sheepdog_proto.h"
#include "sheep.h"
#include "logger.h"

enum cluster_join_result {
	CJ_RES_SUCCESS, /* Success */
	CJ_RES_FAIL, /* Fail to join.  The joining node has an invalidepoch. */
	CJ_RES_JOIN_LATER, /* Fail to join.  The joining node should
			    * be added after the cluster start working. */
	CJ_RES_MASTER_TRANSFER, /* Transfer mastership.  The joining
				 * node has a newer epoch, so this node
				 * will leave the cluster (restart later). */
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
	int (*init)(const char *option, uint8_t *myaddr);

	/*
	 * Join the cluster
	 *
	 * This function is used to join the cluster, and notifies a join
	 * event to all the nodes.  The copy of 'opaque' is passed to
	 * sd_check_join_cb() and sd_join_handler().
	 *
	 * sd_check_join_cb() is called on one of the nodes which already
	 * paticipate in the cluster.  If the content of 'opaque' is
	 * changed in sd_check_join_cb(), the updated 'opaque' must be
	 * passed to sd_join_handler().
	 *
	 * Returns zero on success, -1 on error
	 */
	int (*join)(struct sd_node *myself, void *opaque, size_t opaque_len);

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
	 * This function sends 'msg' to all the nodes.  The notified messages
	 * can be read through sd_notify_handler().
	 *
	 * If 'block_cb' is specified, block_cb() is called before 'msg' is
	 * notified to all the nodes.  All the cluster events including this
	 * notification are blocked until block_cb() returns or this blocking
	 * node leaves the cluster.  The sheep daemon can sleep in block_cb(),
	 * so this callback must be not called from the dispatch (main) thread.
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

static inline struct cluster_driver *find_cdrv(const char *name)
{
	struct cluster_driver *cdrv;
	int len;

	FOR_EACH_CLUSTER_DRIVER(cdrv) {
		len = strlen(cdrv->name);

		if (strncmp(cdrv->name, name, len) == 0 &&
		    (name[len] == ':' || name[len] == '\0'))
			return cdrv;
	}

	return NULL;
}

static inline const char *get_cdrv_option(struct cluster_driver *cdrv,
					  const char *arg)
{
	int len = strlen(cdrv->name);

	if (arg[len] == ':')
		return strdup(arg + len + 1);
	else
		return NULL;
}

static inline char *node_to_str(struct sd_node *id)
{
	static char str[256];
	char name[256];
	int af = AF_INET6;
	uint8_t *addr = id->addr;

	/* Find address family type */
	if (addr[12]) {
		int  oct_no = 0;
		while (!addr[oct_no] && oct_no++ < 12)
			;
		if (oct_no == 12)
			af = AF_INET;
	}

	snprintf(str, sizeof(str), "%s ip:%s port:%d",
		(af == AF_INET) ? "IPv4" : "IPv6",
		addr_to_str(name, sizeof(name), id->addr, 0), id->port);

	return str;
}

static inline struct sd_node *str_to_node(const char *str, struct sd_node *id)
{
	int port, af = AF_INET6;
	char v[8], ip[256];

	sscanf(str, "%s ip:%s port:%d", v, ip, &port);
	id->port = port;

	if (strcmp(v, "IPv4") == 0)
		af = AF_INET;

	if (!str_to_addr(af, ip, id->addr))
		return NULL;

	return id;
}

/* callbacks back into sheepdog from the cluster drivers */
void sd_join_handler(struct sd_node *joined, struct sd_node *members,
		size_t nr_members, enum cluster_join_result result,
		void *opaque);
void sd_leave_handler(struct sd_node *left, struct sd_node *members,
		size_t nr_members);
void sd_notify_handler(struct sd_node *sender, void *msg, size_t msg_len);
enum cluster_join_result sd_check_join_cb(struct sd_node *joining,
		void *opaque);

#endif
