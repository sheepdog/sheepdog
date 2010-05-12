/*
 * Copyright (C) 2009-2010 Nippon Telegraph and Telephone Corporation.
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

#define SD_SHEEP_PROTO_VER 0x01

#define SD_MAX_NODES 1024
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

#define SD_FLAG_CMD_DIRECT   0x10
#define SD_FLAG_CMD_RECOVERY 0x20

#define SD_RES_OLD_NODE_VER  0x41 /* Remote node has an old epoch */
#define SD_RES_NEW_NODE_VER  0x42 /* Remote node has a new epoch */
#define SD_RES_WAIT_FOR_FORMAT      0x43 /* Sheepdog is waiting for a format operation */
#define SD_RES_WAIT_FOR_JOIN        0x44 /* Sheepdog is waiting for other nodes joining */
#define SD_RES_NOT_FORMATTED 0x45 /* Sheepdog is not formatted yet */
#define SD_RES_INVALID_CTIME 0x46 /* Creation time of sheepdog is different */
#define SD_RES_INVALID_EPOCH 0x47 /* Invalid epoch */
#define SD_RES_JOIN_FAILED   0x48 /* Target node was failed to join sheepdog */

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
	uint64_t        start;
	uint64_t        end;
	uint32_t        tgt_epoch;
	uint32_t        pad[3];
};

struct sd_list_rsp {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint32_t        result;
	uint32_t        rsvd;
	uint64_t        next;
	uint32_t        pad[4];
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

struct sheepdog_vm_list_entry {
	uint8_t         name[SD_MAX_VDI_LEN];
	uint8_t         host_addr[16];
	uint16_t        host_port;
	uint8_t	        pad[6];
};

struct sheepdog_node_list_entry {
	uint64_t        id;
	uint8_t         addr[16];
	uint16_t        port;
	uint16_t	pad[3];
};

struct epoch_log {
	uint64_t ctime;
	uint32_t epoch;
	uint32_t nr_nodes;
	struct sheepdog_node_list_entry nodes[SD_MAX_NODES];
};

static inline int hval_to_sheep(struct sheepdog_node_list_entry *entries,
				int nr_entries, uint64_t id, int idx)
{
	int i;
	struct sheepdog_node_list_entry *e = entries, *n;

	for (i = 0; i < nr_entries - 1; i++, e++) {
		n = e + 1;
		if (id > e->id && id <= n->id)
			break;
	}

	return (i + 1 + idx) % nr_entries;
}

static inline int obj_to_sheep(struct sheepdog_node_list_entry *entries,
			       int nr_entries, uint64_t oid, int idx)
{
	uint64_t id = fnv_64a_buf(&oid, sizeof(oid), FNV1A_64_INIT);

	return hval_to_sheep(entries, nr_entries, id, idx);
}

static inline void print_node_list_entry(struct sheepdog_node_list_entry *e,
					 char *str, size_t size)
{
	snprintf(str, size, "%016" PRIx64 " - %d.%d.%d.%d:%d",
		 e->id, e->addr[12], e->addr[13],
		 e->addr[14], e->addr[15], e->port);
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

		{SD_RES_OLD_NODE_VER, "Remote node has an old epoch"},
		{SD_RES_NEW_NODE_VER, "Remote node has a new epoch"},
		{SD_RES_WAIT_FOR_FORMAT, "Waiting for a format operation"},
		{SD_RES_WAIT_FOR_JOIN, "Waiting for other nodes joining"},
		{SD_RES_NOT_FORMATTED, "Not formatted yet"},
		{SD_RES_INVALID_CTIME, "Creation time is different"},
		{SD_RES_INVALID_EPOCH, "Invalid epoch"},
		{SD_RES_JOIN_FAILED, "The node was failed to join sheepdog"},
	};

	for (i = 0; i < ARRAY_SIZE(errors); ++i)
		if (errors[i].err == err)
			return errors[i].desc;

	return "Invalid error code";
}

#endif
