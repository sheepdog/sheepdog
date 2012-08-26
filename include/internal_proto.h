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
#ifndef __INTERNAL_PROTO_H__
#define __INTERNAL_PROTO_H__

/*
 * This file specified the sheepdog-internal protocol, which is spoken between
 * sheepdog daemons, as well as between collie and sheepdog daemon for internal
 * operations.
 */

#include <stdint.h>

#define SD_SHEEP_PROTO_VER 0x06

#define SD_DEFAULT_COPIES 3
#define SD_MAX_COPIES 8

#define SD_MAX_NODES 1024
#define SD_DEFAULT_VNODES 64
#define SD_MAX_VNODES 65536

/*
 * Operations with opcodes above 0x80 are considered part of the inter-sheep
 * protocol and are versioned using SD_SHEEP_PROTO_VER instead of SD_PROTO_VER.
 *
 * These same applies for the above 0x80 flags and error values below.
 */
#define SD_OP_DEL_VDI        0x81
#define SD_OP_GET_NODE_LIST  0x82
#define SD_OP_MAKE_FS        0x84
#define SD_OP_SHUTDOWN       0x85
#define SD_OP_STAT_SHEEP     0x86
#define SD_OP_STAT_CLUSTER   0x87
#define SD_OP_GET_VDI_ATTR   0x89
#define SD_OP_FORCE_RECOVER  0x8a
#define SD_OP_GET_STORE_LIST 0x90
#define SD_OP_SNAPSHOT       0x91
#define SD_OP_RESTORE        0x92
#define SD_OP_GET_SNAP_FILE  0x93
#define SD_OP_CLEANUP        0x94
#define SD_OP_TRACE          0x95
#define SD_OP_TRACE_CAT      0x96
#define SD_OP_STAT_RECOVERY  0x97
#define SD_OP_FLUSH_DEL_CACHE  0x98
#define SD_OP_NOTIFY_VDI_DEL 0x99
#define SD_OP_KILL_NODE      0x9A
#define SD_OP_GET_OBJ_LIST   0xA1
#define SD_OP_GET_EPOCH      0xA2
#define SD_OP_CREATE_AND_WRITE_PEER 0xA3
#define SD_OP_READ_PEER      0xA4
#define SD_OP_WRITE_PEER     0xA5
#define SD_OP_REMOVE_PEER    0xA6
#define SD_OP_SET_CACHE_SIZE 0xA7
#define SD_OP_ENABLE_RECOVER 0xA8
#define SD_OP_DISABLE_RECOVER 0xA9
#define SD_OP_INFO_RECOVER 0xAA
#define SD_OP_GET_VDI_COPIES 0xAB
#define SD_OP_COMPLETE_RECOVERY 0xAC

/* internal flags for hdr.flags, must be above 0x80 */
#define SD_FLAG_CMD_RECOVERY 0x0080

/* flags for VDI attribute operations */
#define SD_FLAG_CMD_CREAT    0x0100
#define SD_FLAG_CMD_EXCL     0x0200
#define SD_FLAG_CMD_DEL      0x0400

/* internal error return values, must be above 0x80 */
#define SD_RES_OLD_NODE_VER  0x81 /* Remote node has an old epoch */
#define SD_RES_NEW_NODE_VER  0x82 /* Remote node has a new epoch */
#define SD_RES_NOT_FORMATTED 0x83 /* Sheepdog is not formatted yet */
#define SD_RES_INVALID_CTIME 0x84 /* Creation time of sheepdog is different */
#define SD_RES_INVALID_EPOCH 0x85 /* Invalid epoch */
#define SD_RES_NETWORK_ERROR 0x86 /* Network error between sheep */
#define SD_RES_NO_CACHE      0x87 /* No cache object found */

#define SD_FLAG_NOHALT       0x0004 /* Serve the IO rquest even lack of nodes */
#define SD_FLAG_QUORUM       0x0008 /* Serve the IO rquest as long we are quorate */

#define SD_STATUS_OK                0x00000001
#define SD_STATUS_WAIT_FOR_FORMAT   0x00000002
#define SD_STATUS_WAIT_FOR_JOIN     0x00000004
#define SD_STATUS_SHUTDOWN          0x00000008
#define SD_STATUS_HALT              0x00000020
#define SD_STATUS_KILLED            0x00000040

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

struct node_id {
	uint8_t addr[16];
	uint16_t port;
};

struct sd_node {
	struct node_id  nid;
	uint16_t	nr_vnodes;
	uint32_t	zone;
	uint64_t        space;
};

struct epoch_log {
	uint64_t ctime;
	uint64_t time;
	uint32_t epoch;
	uint32_t nr_nodes;
	uint32_t nr_copies;
	struct sd_node nodes[SD_MAX_NODES];
};

struct join_message {
	uint8_t proto_ver;
	uint8_t nr_copies;
	uint16_t nr_nodes;
	uint16_t nr_failed_nodes;
	uint16_t nr_delayed_nodes;
	uint16_t cluster_flags;
	uint32_t cluster_status;
	uint32_t epoch;
	uint64_t ctime;
	uint8_t inc_epoch; /* set non-zero when we increment epoch of all nodes */
	uint8_t disable_recovery;
	uint8_t store[STORE_LEN];

	/*
	 * A joining sheep puts the local node list here, which is nr_nodes
	 * entries long.  After the master replies it will contain the list of
	 * nodes that attempted to join but failed the join process.  The
	 * number of entries in that case is nr_failed_nodes, which by
	 * defintion must be smaller than nr_nodes.
	 */
	struct sd_node nodes[];
};

struct vdi_op_message {
	struct sd_req req;
	struct sd_rsp rsp;
	uint8_t data[0];
};

#endif /* __INTERNAL_PROTO_H__ */
