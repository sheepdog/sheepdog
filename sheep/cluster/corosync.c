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
#include <stdio.h>
#include <unistd.h>
#include <corosync/cpg.h>
#include <corosync/cfg.h>

#include "cluster.h"

static cpg_handle_t cpg_handle;
static struct cpg_name cpg_group = { 9, "sheepdog" };

static corosync_cfg_handle_t cfg_handle;

static struct cdrv_handlers corosync_handlers;

static int nodeid_to_addr(uint32_t nodeid, uint8_t *addr)
{
	int ret, nr;
	corosync_cfg_node_address_t caddr;
	struct sockaddr_storage *ss = (struct sockaddr_storage *)caddr.address;
	struct sockaddr_in *sin = (struct sockaddr_in *)caddr.address;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)caddr.address;
	void *saddr;

	ret = corosync_cfg_get_node_addrs(cfg_handle, nodeid, 1, &nr, &caddr);
	if (ret != CS_OK) {
		vprintf(SDOG_ERR "failed to get addr %d\n", ret);
		return -1;
	}

	if (!nr) {
		vprintf(SDOG_ERR "we got no address\n");
		return -1;
	}

	if (ss->ss_family == AF_INET6) {
		saddr = &sin6->sin6_addr;
		memcpy(addr, saddr, 16);
	} else if (ss->ss_family == AF_INET) {
		saddr = &sin->sin_addr;
		memset(addr, 0, 16);
		memcpy(addr + 12, saddr, 4);
	} else {
		vprintf(SDOG_ERR "unknown protocol %d\n", ss->ss_family);
		return -1;
	}

	return 0;
}

static void cpg_addr_to_sheepid(const struct cpg_address *cpgs,
				struct sheepid *sheeps, size_t nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		nodeid_to_addr(cpgs[i].nodeid, sheeps[i].addr);
		sheeps[i].pid = cpgs[i].pid;
	}
}

static void cdrv_cpg_deliver(cpg_handle_t handle,
			     const struct cpg_name *group_name,
			     uint32_t nodeid, uint32_t pid,
			     void *msg, size_t msg_len)
{
	struct sheepid sender;

	nodeid_to_addr(nodeid, sender.addr);
	sender.pid = pid;

	corosync_handlers.notify_handler(&sender, msg, msg_len);
}

static void cdrv_cpg_confchg(cpg_handle_t handle,
			     const struct cpg_name *group_name,
			     const struct cpg_address *member_list,
			     size_t member_list_entries,
			     const struct cpg_address *left_list,
			     size_t left_list_entries,
			     const struct cpg_address *joined_list,
			     size_t joined_list_entries)
{
	int i;
	struct sheepid member_sheeps[SD_MAX_NODES];
	struct sheepid joined_sheeps[SD_MAX_NODES];
	struct sheepid left_sheeps[SD_MAX_NODES];

	/* convert cpg_address to sheepid*/
	cpg_addr_to_sheepid(member_list, member_sheeps, member_list_entries);
	cpg_addr_to_sheepid(left_list, left_sheeps, left_list_entries);
	cpg_addr_to_sheepid(joined_list, joined_sheeps, joined_list_entries);

	/* calculate a start member list */
	sheepid_del(member_sheeps, member_list_entries,
		    joined_sheeps, joined_list_entries);
	member_list_entries -= joined_list_entries;

	sheepid_add(member_sheeps, member_list_entries,
		    left_sheeps, left_list_entries);
	member_list_entries += left_list_entries;

	/* dispatch leave_handler */
	for (i = 0; i < left_list_entries; i++) {
		sheepid_del(member_sheeps, member_list_entries,
			    left_sheeps + i, 1);
		member_list_entries--;

		corosync_handlers.leave_handler(left_sheeps + i, member_sheeps,
						member_list_entries);
	}

	/* dispatch join_handler */
	for (i = 0; i < joined_list_entries; i++) {
		sheepid_add(member_sheeps, member_list_entries,
			    joined_sheeps, 1);
		member_list_entries++;

		corosync_handlers.join_handler(joined_sheeps + i, member_sheeps,
					       member_list_entries);
	}
}

static int corosync_init(struct cdrv_handlers *handlers, struct sheepid *myid)
{
	int ret, fd;
	uint32_t nodeid;
	cpg_callbacks_t cb = {
		.cpg_deliver_fn = cdrv_cpg_deliver,
		.cpg_confchg_fn = cdrv_cpg_confchg
	};

	corosync_handlers = *handlers;

	ret = cpg_initialize(&cpg_handle, &cb);
	if (ret != CPG_OK) {
		eprintf("Failed to initialize cpg, %d\n", ret);
		eprintf("Is corosync running?\n");
		return -1;
	}

	ret = corosync_cfg_initialize(&cfg_handle, NULL);
	if (ret != CS_OK) {
		vprintf(SDOG_ERR "failed to initiazize cfg %d\n", ret);
		return -1;
	}

	ret = corosync_cfg_local_get(cfg_handle, &nodeid);
	if (ret != CS_OK) {
		vprintf(SDOG_ERR "failed to get nodeid %d\n", ret);
		return -1;
	}

	ret = nodeid_to_addr(nodeid, myid->addr);
	if (ret < 0) {
		eprintf("failed to get local address\n");
		return -1;
	}

	myid->pid = getpid();

	ret = cpg_fd_get(cpg_handle, &fd);
	if (ret != CPG_OK) {
		eprintf("Failed to retrieve cpg file descriptor, %d\n", ret);
		return -1;
	}

	return fd;
}

static int corosync_join(void)
{
	int ret;
retry:
	ret = cpg_join(cpg_handle, &cpg_group);
	switch (ret) {
	case CPG_OK:
		break;
	case CPG_ERR_TRY_AGAIN:
		dprintf("Failed to join the sheepdog group, try again\n");
		sleep(1);
		goto retry;
	case CPG_ERR_SECURITY:
		eprintf("Permission error.\n");
		return -1;
	default:
		eprintf("Failed to join the sheepdog group, %d\n", ret);
		return -1;
	}

	return 0;
}

static int corosync_leave(void)
{
	int ret;

	ret = cpg_leave(cpg_handle, &cpg_group);
	if (ret != CPG_OK) {
		eprintf("failed to leave the sheepdog group\n, %d", ret);
		return -1;
	}

	return 0;
}

static int corosync_notify(void *msg, size_t msg_len)
{
	struct iovec iov;
	int ret;

	iov.iov_base = msg;
	iov.iov_len = msg_len;
retry:
	ret = cpg_mcast_joined(cpg_handle, CPG_TYPE_AGREED, &iov, 1);
	switch (ret) {
	case CPG_OK:
		break;
	case CPG_ERR_TRY_AGAIN:
		dprintf("failed to send message. try again\n");
		sleep(1);
		goto retry;
	default:
		eprintf("failed to send message, %d\n", ret);
		return -1;
	}
	return 0;
}

static int corosync_dispatch(void)
{
	int ret;

	ret = cpg_dispatch(cpg_handle, CPG_DISPATCH_ALL);
	if (ret != CPG_OK)
		return -1;

	return 0;
}

struct cluster_driver cdrv_corosync = {
	.name       = "corosync",

	.init       = corosync_init,
	.join       = corosync_join,
	.leave      = corosync_leave,
	.notify     = corosync_notify,
	.dispatch   = corosync_dispatch,
};

cdrv_register(cdrv_corosync);
