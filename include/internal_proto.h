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
#include <netinet/in.h>

#define SD_SHEEP_PROTO_VER 0x07

#define SD_DEFAULT_COPIES 3
#define SD_MAX_COPIES 8

#define SD_MAX_NODES 1024
#define SD_DEFAULT_VNODES 64
#define SD_MAX_VNODES 65536

/*
 * Operations with opcodes above 0x80 are considered part of the inter-sheep
 * include sheep-collie protocol and are versioned using SD_SHEEP_PROTO_VER
 * instead of SD_PROTO_VER.
 *
 * These same applies for the above 0x80 flags and error values below.
 */
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
#define SD_OP_TRACE_READ_BUF 0x96
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
#define SD_OP_GET_VDI_COPIES 0xAB
#define SD_OP_COMPLETE_RECOVERY 0xAC
#define SD_OP_FLUSH_NODES 0xAD
#define SD_OP_FLUSH_PEER 0xAE
#define SD_OP_NOTIFY_VDI_ADD  0xAF
#define SD_OP_DELETE_CACHE    0xB0
#define SD_OP_MD_INFO   0xB1
#define SD_OP_MD_PLUG   0xB2
#define SD_OP_MD_UNPLUG 0xB3
#define SD_OP_GET_HASH       0xB4

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
#define SD_RES_BUFFER_SMALL  0x88 /* The buffer is too small */
#define SD_RES_FORCE_RECOVER    0x89 /* Users should not force recover this cluster */
#define SD_RES_NO_STORE         0x8A /* No targeted backend store */
#define SD_RES_NO_SUPPORT       0x8B /* Operation is not supported by backend store */
#define SD_RES_NODE_IN_RECOVERY 0x8C /*	Targeted node is in recovery */
#define SD_RES_KILLED           0x8D /* Node is killed */
#define SD_RES_OID_EXIST        0x8E /* Object ID exists already */
#define SD_RES_AGAIN            0x8F /* Ask to try again */
#define SD_RES_STALE_OBJ        0x90 /* Object may be stale */

#define SD_FLAG_NOHALT       0x0004 /* Serve the IO rquest even lack of nodes */
#define SD_FLAG_QUORUM       0x0008 /* Serve the IO rquest as long we are quorate */

#define SD_STATUS_OK                0x00000001
#define SD_STATUS_WAIT_FOR_FORMAT   0x00000002
#define SD_STATUS_WAIT_FOR_JOIN     0x00000004
#define SD_STATUS_SHUTDOWN          0x00000008
#define SD_STATUS_HALT              0x00000020
#define SD_STATUS_KILLED            0x00000040

struct node_id {
	uint8_t addr[16];
	uint16_t port;
	uint8_t io_addr[16];
	uint16_t io_port;
	uint8_t pad[4];
};

struct sd_node {
	struct node_id  nid;
	uint16_t	nr_vnodes;
	uint32_t	zone;
	uint64_t        space;
};

struct epoch_log {
	uint64_t ctime;
	uint64_t time;		/* treated as time_t */
	uint32_t epoch;
	uint32_t nr_nodes;
	uint32_t nr_copies;
	struct sd_node nodes[SD_MAX_NODES];
};

struct join_message {
	uint8_t proto_ver;
	uint8_t nr_copies;
	int16_t nr_nodes;
	uint16_t nr_failed_nodes;
	uint16_t nr_delayed_nodes;
	uint32_t cluster_status;
	uint32_t epoch;
	uint64_t ctime;
	uint8_t inc_epoch; /* set non-zero when we increment epoch of all nodes */
	uint8_t disable_recovery;
	uint16_t cluster_flags;
	uint32_t __pad;
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

struct md_info {
	int idx;
	uint64_t size;
	uint64_t used;
	char path[PATH_MAX];
};

#define MD_MAX_DISK 64 /* FIXME remove roof and make it dynamic */
struct sd_md_info {
	struct md_info disk[MD_MAX_DISK];
	int nr;
};

enum cluster_join_result {
	/* Success */
	CJ_RES_SUCCESS,

	/* Fail to join. The joining node has an invalid epoch. */
	CJ_RES_FAIL,

	/*
	 * Fail to join. The joining node should be added after the cluster
	 * start working.
	 */
	CJ_RES_JOIN_LATER,

	/*
	 * Transfer mastership.  The joining node has a newer epoch, so this
	 * node will leave the cluster (restart later).
	 */
	CJ_RES_MASTER_TRANSFER,
};

#endif /* __INTERNAL_PROTO_H__ */
