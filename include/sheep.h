/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __SHEEP_H__
#define __SHEEP_H__

#include <stdint.h>
#include "util.h"
#include "list.h"
#include "net.h"

#define SD_SHEEP_PROTO_VER 0x03

#define SD_DEFAULT_REDUNDANCY 3
#define SD_MAX_REDUNDANCY 8

#define SD_MAX_NODES 1024
#define SD_DEFAULT_VNODES 64
#define SD_MAX_VNODES 65536
#define SD_MAX_VMS   4096 /* FIXME: should be removed */

#define SD_OP_SHEEP         0x80
#define SD_OP_DEL_VDI        0x81
#define SD_OP_GET_NODE_LIST  0x82
#define SD_OP_GET_VM_LIST    0x83
#define SD_OP_MAKE_FS        0x84
#define SD_OP_SHUTDOWN       0x85
#define SD_OP_STAT_SHEEP     0x86
#define SD_OP_STAT_CLUSTER   0x87
#define SD_OP_KILL_NODE      0x88
#define SD_OP_GET_VDI_ATTR   0x89

#define SD_FLAG_CMD_DIRECT   0x10
#define SD_FLAG_CMD_RECOVERY 0x20
#define SD_FLAG_CMD_CREAT    0x40
#define SD_FLAG_CMD_EXCL     0x80

#define SD_RES_OLD_NODE_VER  0x41 /* Remote node has an old epoch */
#define SD_RES_NEW_NODE_VER  0x42 /* Remote node has a new epoch */
#define SD_RES_NOT_FORMATTED 0x43 /* Sheepdog is not formatted yet */
#define SD_RES_INVALID_CTIME 0x44 /* Creation time of sheepdog is different */
#define SD_RES_INVALID_EPOCH 0x45 /* Invalid epoch */

struct sd_so_req {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint64_t	oid;
	uint64_t	ctime;
	uint32_t	copies;
	uint32_t	tag;
	uint32_t	opcode_specific[2];
};

struct sd_so_rsp {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint32_t        result;
	uint32_t	copies;
	uint64_t	ctime;
	uint64_t	oid;
	uint32_t	opcode_specific[2];
};

struct sd_list_req {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint32_t        tgt_epoch;
	uint32_t        pad[7];
};

struct sd_list_rsp {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint32_t        result;
	uint32_t        pad[7];
};

struct sd_node_req {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint32_t	request_ver;
	uint32_t	pad[7];
};

struct sd_node_rsp {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint32_t        result;
	uint32_t	nr_nodes;
	uint32_t	local_idx;
	uint32_t	master_idx;
	uint64_t	store_size;
	uint64_t	store_free;
};

struct sheepdog_node_list_entry {
	uint8_t         addr[16];
	uint16_t        port;
	uint16_t	nr_vnodes;
	uint32_t	zone;
};

struct sheepdog_vnode_list_entry {
	uint64_t        id;
	uint8_t         addr[16];
	uint16_t        port;
	uint16_t	node_idx;
	uint32_t	zone;
};

struct epoch_log {
	uint64_t ctime;
	uint32_t epoch;
	uint32_t nr_nodes;
	struct sheepdog_node_list_entry nodes[SD_MAX_NODES];
};

static inline int same_node(struct sheepdog_vnode_list_entry *e, int n1, int n2)
{
	if (memcmp(e[n1].addr, e[n2].addr, sizeof(e->addr)) == 0 &&
	    e[n1].port == e[n2].port)
		return 1;

	return 0;
}

static inline int same_zone(struct sheepdog_vnode_list_entry *e, int n1, int n2)
{
	return e[n1].zone != 0 && e[n1].zone == e[n2].zone;
}

/* traverse the virtual node list and return the n'th one */
static inline int get_nth_node(struct sheepdog_vnode_list_entry *entries,
			       int nr_entries, int base, int n)
{
	int nodes[SD_MAX_REDUNDANCY];
	int nr = 0, idx = base, i;

	while (n--) {
		nodes[nr++] = idx;
next:
		idx = (idx + 1) % nr_entries;
		if (idx == base) {
			abort();
			return -1; /* not found */
		}
		for (i = 0; i < nr; i++) {
			if (same_node(entries, idx, nodes[i]))
				/* this node is already selected, so skip here */
				goto next;
			if (same_zone(entries, idx, nodes[i]))
				/* this node is in the same zone, so skip here */
				goto next;
		}
	}

	return idx;
}

static inline int hval_to_sheep(struct sheepdog_vnode_list_entry *entries,
				int nr_entries, uint64_t id, int idx)
{
	int i, ret;
	struct sheepdog_vnode_list_entry *e = entries, *n;

	for (i = 0; i < nr_entries - 1; i++, e++) {
		n = e + 1;
		if (id > e->id && id <= n->id)
			break;
	}
	ret = get_nth_node(entries, nr_entries, (i + 1) % nr_entries, idx);
	if (ret < 0) {
		printf("bug\n");
		abort();
	}

	return ret;
}

static inline int obj_to_sheep(struct sheepdog_vnode_list_entry *entries,
			       int nr_entries, uint64_t oid, int idx)
{
	uint64_t id = fnv_64a_buf(&oid, sizeof(oid), FNV1A_64_INIT);

	return hval_to_sheep(entries, nr_entries, id, idx);
}

static inline int is_sheep_op(uint8_t op)
{
	return op & SD_OP_SHEEP;
}

static inline const char *sd_strerror(int err)
{
	int i;

	static const struct {
		int err;
		const char *desc;
	} errors[] = {
		{SD_RES_SUCCESS, "Success"},
		{SD_RES_UNKNOWN, "Unknown error"},
		{SD_RES_NO_OBJ, "No object found"},
		{SD_RES_EIO, "I/O error"},
		{SD_RES_VDI_EXIST, "VDI exists already"},
		{SD_RES_INVALID_PARMS, "Invalid parameters"},
		{SD_RES_SYSTEM_ERROR, "System error"},
		{SD_RES_VDI_LOCKED, "VDI is already locked"},
		{SD_RES_NO_VDI, "No vdi found"},
		{SD_RES_NO_BASE_VDI, "No base VDI found"},
		{SD_RES_VDI_READ, "Failed read the requested VDI"},
		{SD_RES_VDI_WRITE, "Failed to write the requested VDI"},
		{SD_RES_BASE_VDI_READ, "Failed to read the base VDI"},
		{SD_RES_BASE_VDI_WRITE, "Failed to write the base VDI"},
		{SD_RES_NO_TAG, "Failed to find the requested tag"},
		{SD_RES_STARTUP, "The system is still booting"},
		{SD_RES_VDI_NOT_LOCKED, "VDI isn't locked"},
		{SD_RES_SHUTDOWN, "The system is shutting down"},
		{SD_RES_NO_MEM, "Out of memory on the server"},
		{SD_RES_FULL_VDI, "We already have the maximum vdis"},
		{SD_RES_VER_MISMATCH, "Protocol version mismatch"},
		{SD_RES_NO_SPACE, "Server has no space for new objects"},
		{SD_RES_WAIT_FOR_FORMAT, "Waiting for a format operation"},
		{SD_RES_WAIT_FOR_JOIN, "Waiting for other nodes joining"},
		{SD_RES_JOIN_FAILED, "The node had failed to join sheepdog"},

		{SD_RES_OLD_NODE_VER, "Remote node has an old epoch"},
		{SD_RES_NEW_NODE_VER, "Remote node has a new epoch"},
		{SD_RES_NOT_FORMATTED, "Not formatted yet"},
		{SD_RES_INVALID_CTIME, "Creation time is different"},
		{SD_RES_INVALID_EPOCH, "Invalid epoch"},
	};

	for (i = 0; i < ARRAY_SIZE(errors); ++i)
		if (errors[i].err == err)
			return errors[i].desc;

	return "Invalid error code";
}

static inline int node_cmp(const void *a, const void *b)
{
	const struct sheepdog_node_list_entry *node1 = a;
	const struct sheepdog_node_list_entry *node2 = b;
	int cmp;

	cmp = memcmp(node1->addr, node2->addr, sizeof(node1->addr));
	if (cmp != 0)
		return cmp;

	if (node1->port < node2->port)
		return -1;
	if (node1->port > node2->port)
		return 1;
	return 0;
}

static inline int vnode_cmp(const void *a, const void *b)
{
	const struct sheepdog_vnode_list_entry *node1 = a;
	const struct sheepdog_vnode_list_entry *node2 = b;

	if (node1->id < node2->id)
		return -1;
	if (node1->id > node2->id)
		return 1;
	return 0;
}

static inline int nodes_to_vnodes(struct sheepdog_node_list_entry *nodes, int nr,
				  struct sheepdog_vnode_list_entry *vnodes)
{
	struct sheepdog_node_list_entry *n = nodes;
	int i, j, nr_vnodes = 0;
	uint64_t hval;

	while (nr--) {
		hval = FNV1A_64_INIT;

		for (i = 0; i < n->nr_vnodes; i++) {
			if (vnodes) {
				hval = fnv_64a_buf(&n->port, sizeof(n->port), hval);
				for (j = ARRAY_SIZE(n->addr) - 1; j >= 0; j--)
					hval = fnv_64a_buf(&n->addr[j], 1, hval);

				vnodes[nr_vnodes].id = hval;
				memcpy(vnodes[nr_vnodes].addr, n->addr, sizeof(n->addr));
				vnodes[nr_vnodes].port = n->port;
				vnodes[nr_vnodes].node_idx = n - nodes;
				vnodes[nr_vnodes].zone = n->zone;
			}

			nr_vnodes++;
		}

		n++;
	}

	if (vnodes)
		qsort(vnodes, nr_vnodes, sizeof(*vnodes), vnode_cmp);

	return nr_vnodes;
}

#endif
