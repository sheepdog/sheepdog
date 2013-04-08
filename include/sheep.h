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
#include "internal_proto.h"
#include "util.h"
#include "list.h"
#include "net.h"
#include "logger.h"

struct sd_vnode {
	struct node_id  nid;
	uint16_t	node_idx;
	uint32_t	zone;
	uint64_t        id;
};

struct vnode_info {
	struct sd_vnode vnodes[SD_MAX_VNODES];
	int nr_vnodes;

	struct sd_node nodes[SD_MAX_NODES];
	int nr_nodes;

	int nr_zones;
	int refcnt;
};

struct vdi_copy {
	uint32_t vid;
	uint32_t nr_copies;
};

#define TRACE_GRAPH_ENTRY  0x01
#define TRACE_GRAPH_RETURN 0x02

#define TRACE_FNAME_LEN    36
#define TRACE_THREAD_LEN   MAX_THREAD_NAME_LEN

struct trace_graph_item {
	char tname[TRACE_THREAD_LEN];
	int type;
	char fname[TRACE_FNAME_LEN];
	int depth;
	unsigned long long entry_time;
	unsigned long long return_time;
};

static inline void sd_init_req(struct sd_req *req, uint8_t opcode)
{
	memset(req, 0, sizeof(*req));
	req->opcode = opcode;
	req->proto_ver = opcode < 0x80 ? SD_PROTO_VER : SD_SHEEP_PROTO_VER;
}

static inline int same_zone(const struct sd_vnode *e, int n1, int n2)
{
	return e[n1].zone == e[n2].zone;
}

/* Get the first vnode's index which is matching the OID */
static inline int get_vnode_first_idx(const struct sd_vnode *entries,
				      int nr_entries, uint64_t oid)
{
	uint64_t id = fnv_64a_buf(&oid, sizeof(oid), FNV1A_64_INIT);
	int start, end, pos;

	start = 0;
	end = nr_entries - 1;

	if (id > entries[end].id || id < entries[start].id)
		return (end + 1) % nr_entries;

	for (;;) {
		pos = (end - start) / 2 + start;
		if (entries[pos].id < id) {
			if (entries[pos + 1].id >= id)
				return (pos + 1) % nr_entries;
			start = pos;
		} else
			end = pos;
	}
}

/* Get next vnode's index according to the PREV_IDXS */
static inline int get_vnode_next_idx(const struct sd_vnode *entries,
				     int nr_entries, int *prev_idxs,
				     int nr_prev_idxs)
{
	int i, idx, first_idx;
	bool found;

	first_idx = prev_idxs[0];
	idx = prev_idxs[nr_prev_idxs - 1];
	for (;;) {
		idx = (idx + 1) % nr_entries;
		if (idx == first_idx)
			panic("can't find next new idx");

		for (found = false, i = 0; i < nr_prev_idxs; i++) {
			if (same_zone(entries, idx, prev_idxs[i])) {
				found = true;
				break;
			}
		}

		if (!found)
			return idx;
	}
}

/* Get the n'th vnode's index which is matching the OID */
static inline int get_vnode_nth_idx(const struct sd_vnode *entries,
			int nr_entries, uint64_t oid, int nth)
{
	int nr_idxs = 0, idxs[SD_MAX_COPIES];

	idxs[nr_idxs++] = get_vnode_first_idx(entries, nr_entries, oid);

	if (!nth)
		return idxs[nth];

	while (nr_idxs <= nth) {
		idxs[nr_idxs] = get_vnode_next_idx(entries, nr_entries,
						     idxs, nr_idxs);
		nr_idxs++;
	}

	return idxs[nth];
}

static inline const struct sd_vnode *oid_to_vnode(const struct sd_vnode *entries,
						  int nr_entries, uint64_t oid,
						  int copy_idx)
{
	int idx = get_vnode_nth_idx(entries, nr_entries, oid, copy_idx);

	return &entries[idx];
}

static inline void oid_to_vnodes(const struct sd_vnode *entries, int nr_entries,
				 uint64_t oid, int nr_copies,
				 const struct sd_vnode **vnodes)
{
	int idx, idxs[SD_MAX_COPIES], i;

	idx = get_vnode_first_idx(entries, nr_entries, oid);
	idxs[0] = idx;
	vnodes[0] = &entries[idx];

	for (i = 1; i < nr_copies; i++) {
		idx = get_vnode_next_idx(entries, nr_entries, idxs, i);
		idxs[i] = idx;
		vnodes[i] = &entries[idx];
	}
}

static inline void oid_to_nodes(const struct sd_vnode *entries, int nr_entries,
				uint64_t oid, int nr_copies,
				const struct sd_node *all_nodes,
				const struct sd_node **nodes)
{
	int i;
	const struct sd_vnode *vnodes[SD_MAX_COPIES];

	oid_to_vnodes(entries, nr_entries, oid, nr_copies, vnodes);
	for (i = 0; i < nr_copies; i++)
		nodes[i] = &all_nodes[vnodes[i]->node_idx];
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
		{SD_RES_NO_VDI, "No VDI found"},
		{SD_RES_NO_BASE_VDI, "No base VDI found"},
		{SD_RES_VDI_READ, "Failed to read from requested VDI"},
		{SD_RES_VDI_WRITE, "Failed to write to requested VDI"},
		{SD_RES_BASE_VDI_READ, "Failed to read from base VDI"},
		{SD_RES_BASE_VDI_WRITE, "Failed to write to base VDI"},
		{SD_RES_NO_TAG, "Failed to find requested tag"},
		{SD_RES_STARTUP, "System is still booting"},
		{SD_RES_VDI_NOT_LOCKED, "VDI is not locked"},
		{SD_RES_SHUTDOWN, "System is shutting down"},
		{SD_RES_NO_MEM, "Out of memory on server"},
		{SD_RES_FULL_VDI, "Maximum number of VDIs reached"},
		{SD_RES_VER_MISMATCH, "Protocol version mismatch"},
		{SD_RES_NO_SPACE, "Server has no space for new objects"},
		{SD_RES_WAIT_FOR_FORMAT, "Waiting for cluster to be formatted"},
		{SD_RES_WAIT_FOR_JOIN, "Waiting for other nodes to join cluster"},
		{SD_RES_JOIN_FAILED, "Node has failed to join cluster"},
		{SD_RES_HALT, "IO has halted as there are too few living nodes"},
		{SD_RES_FORCE_RECOVER, "Cluster is running/halted and cannot be force recovered"},
		{SD_RES_NO_STORE, "Targeted backend store is not found"},
		{SD_RES_NO_SUPPORT, "Operation is not supported"},
		{SD_RES_NODE_IN_RECOVERY, "Targeted node is in recovery"},

		{SD_RES_OLD_NODE_VER, "Remote node has an old epoch"},
		{SD_RES_NEW_NODE_VER, "Remote node has a new epoch"},
		{SD_RES_NOT_FORMATTED, "Cluster has not been formatted"},
		{SD_RES_INVALID_CTIME, "Creation times differ"},
		{SD_RES_INVALID_EPOCH, "Invalid epoch"},
	};

	for (i = 0; i < ARRAY_SIZE(errors); ++i)
		if (errors[i].err == err)
			return errors[i].desc;

	return "Invalid error code";
}

static inline int node_id_cmp(const void *a, const void *b)
{
	const struct node_id *node1 = a;
	const struct node_id *node2 = b;
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

static inline bool node_eq(const struct sd_node *a, const struct sd_node *b)
{
	return node_id_cmp(&a->nid, &b->nid) == 0;
}

static inline int vnode_cmp(const void *a, const void *b)
{
	const struct sd_vnode *node1 = a;
	const struct sd_vnode *node2 = b;

	if (node1->id < node2->id)
		return -1;
	if (node1->id > node2->id)
		return 1;
	return 0;
}

static inline int nodes_to_vnodes(struct sd_node *nodes, int nr,
				  struct sd_vnode *vnodes)
{
	struct sd_node *n = nodes;
	int i, j, nr_vnodes = 0;
	uint64_t hval;

	while (nr--) {
		hval = FNV1A_64_INIT;

		for (i = 0; i < n->nr_vnodes; i++) {
			if (vnodes) {
				hval = fnv_64a_buf(&n->nid.port, sizeof(n->nid.port), hval);
				for (j = ARRAY_SIZE(n->nid.addr) - 1; j >= 0; j--)
					hval = fnv_64a_buf(&n->nid.addr[j], 1, hval);

				vnodes[nr_vnodes].id = hval;
				memcpy(vnodes[nr_vnodes].nid.addr, n->nid.addr, sizeof(n->nid.addr));
				vnodes[nr_vnodes].nid.port = n->nid.port;
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

#define MAX_NODE_STR_LEN 256

static inline char *node_to_str(const struct sd_node *id)
{
	static char str[MAX_NODE_STR_LEN];
	char name[MAX_NODE_STR_LEN];
	int af = AF_INET6;
	const uint8_t *addr = id->nid.addr;

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
		addr_to_str(name, sizeof(name), id->nid.addr, 0), id->nid.port);

	return str;
}

static inline struct sd_node *str_to_node(const char *str, struct sd_node *id)
{
	int port;
	char v[8], ip[MAX_NODE_STR_LEN];

	sscanf(str, "%s ip:%s port:%d", v, ip, &port);
	id->nid.port = port;
	if (!str_to_addr(ip, id->nid.addr))
		return NULL;

	return id;
}

#endif
