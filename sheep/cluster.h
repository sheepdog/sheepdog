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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <memory.h>

#include "sheepdog_proto.h"
#include "sheep.h"
#include "logger.h"

/* maximum payload size sent in ->notify and ->unblock */
#define SD_MAX_EVENT_BUF_SIZE (128 * 1024) /* 128k */

struct cluster_driver {
	const char *name;

	/*
	 * Initialize the cluster driver
	 *
	 * Returns zero on success, -1 on error.
	 */
	int (*init)(const char *option);

	/*
	 * Get a node ID for this sheep.
	 *
	 * Gets and ID that is used in all communication with other sheep,
	 * which normally would be a string formatted IP address.
	 *
	 * Returns zero on success, -1 on error.
	 */
	int (*get_local_addr)(uint8_t *myaddr);

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
	int (*join)(const struct sd_node *myself, void *opaque,
		    size_t opaque_len);

	/*
	 * Leave the cluster
	 *
	 * This function is used to leave the cluster, and notifies a
	 * leave event to all the nodes.  The cluster driver calls event
	 * handlers even after this function is called, so the left node can
	 * work as a gateway.
	 *
	 * Returns zero on success, -1 on error
	 */
	int (*leave)(void);

	/*
	 * Notify a message to all nodes in the cluster
	 *
	 * This function sends 'msg' to all the nodes.  The notified messages
	 * can be read through sd_notify_handler() and totally ordered with
	 * node change events.
	 *
	 * Returns zero on success, -1 on error
	 */
	int (*notify)(void *msg, size_t msg_len);

	/*
	 * Send a message to all nodes to block further events.
	 *
	 * Once the cluster driver has ensured that events are blocked on all
	 * nodes it needs to call sd_block_handler() on the node where ->block
	 * was called.
	 */
	void (*block)(void);

	/*
	 * Unblock events on all nodes, and send a total order message
	 * to all nodes.
	 */
	void (*unblock)(void *msg, size_t msg_len);

	/* Update the specific node in the driver's private copy of nodes */
	void (*update_node)(struct sd_node *);

	struct list_head list;
};

extern struct list_head cluster_drivers;

#define cdrv_register(driver)						\
static void __attribute__((constructor)) regist_ ## driver(void)	\
{									\
	if (!driver.init || !driver.join || !driver.leave || !driver.notify) \
		panic("the driver '%s' is incomplete", driver.name);	\
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

static inline const char *get_cdrv_option(const struct cluster_driver *cdrv,
					  const char *arg)
{
	int len = strlen(cdrv->name);

	if (arg[len] == ':')
		return strdup(arg + len + 1);
	else
		return NULL;
}

/* callbacks back into sheepdog from the cluster drivers */
void sd_join_handler(const struct sd_node *joined,
		     const struct sd_node *members,
		     size_t nr_members, enum cluster_join_result result,
		     const void *opaque);
void sd_leave_handler(const struct sd_node *left, const struct sd_node *members,
		      size_t nr_members);
void sd_notify_handler(const struct sd_node *sender, void *msg, size_t msg_len);
bool sd_block_handler(const struct sd_node *sender);
int sd_reconnect_handler(void);
enum cluster_join_result sd_check_join_cb(const struct sd_node *joining,
					  const struct sd_node *nodes,
					  size_t nr_nodes, void *opaque);
void recalculate_vnodes(struct sd_node *nodes, int nr_nodes);

#endif
