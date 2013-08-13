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
 * sheepdog daemons, as well as between dog and sheepdog daemon for internal
 * operations.
 */

#include <stdint.h>
#include <netinet/in.h>

#include "sheepdog_proto.h"

#define SD_SHEEP_PROTO_VER 0x08

#define SD_DEFAULT_COPIES 3
#define SD_MAX_COPIES 8

#define SD_MAX_NODES 1024
#define SD_DEFAULT_VNODES 64
#define SD_MAX_VNODES 65536

/*
 * Operations with opcodes above 0x80 are considered part of the inter-sheep
 * include sheep-dog protocol and are versioned using SD_SHEEP_PROTO_VER
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
#define SD_OP_TRACE_STATUS   0x95
#define SD_OP_TRACE_READ_BUF 0x96
#define SD_OP_STAT_RECOVERY  0x97
#define SD_OP_FLUSH_DEL_CACHE  0x98
#define SD_OP_NOTIFY_VDI_DEL 0x99
#define SD_OP_KILL_NODE      0x9A
#define SD_OP_TRACE_ENABLE   0x9B
#define SD_OP_TRACE_DISABLE  0x9C
#define SD_OP_GET_OBJ_LIST   0xA1
#define SD_OP_GET_EPOCH      0xA2
#define SD_OP_CREATE_AND_WRITE_PEER 0xA3
#define SD_OP_READ_PEER      0xA4
#define SD_OP_WRITE_PEER     0xA5
#define SD_OP_REMOVE_PEER    0xA6
/* #define SD_OP_SET_CACHE_SIZE 0xA7 deleted */
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
#define SD_OP_REWEIGHT       0xB5
#define SD_OP_GET_CACHE_INFO 0xB6

/* internal flags for hdr.flags, must be above 0x80 */
#define SD_FLAG_CMD_RECOVERY 0x0080

/* flags for VDI attribute operations */
#define SD_FLAG_CMD_CREAT    0x0100
#define SD_FLAG_CMD_EXCL     0x0200
#define SD_FLAG_CMD_DEL      0x0400

/* internal error return values, must be above 0x80 */
#define SD_RES_OLD_NODE_VER  0x81 /* Request has an old epoch */
#define SD_RES_NEW_NODE_VER  0x82 /* Request has a new epoch */
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
#define SD_RES_CLUSTER_ERROR    0x91 /* Cluster driver error */

enum sd_status {
	SD_STATUS_OK = 1,
	SD_STATUS_WAIT,
	SD_STATUS_SHUTDOWN,
	SD_STATUS_KILLED,
};

struct node_id {
	uint8_t addr[16];
	uint16_t port;
	uint8_t io_addr[16];
	uint16_t io_port;
	uint8_t pad[4];
};

#define SD_NODE_SIZE 56

struct sd_node {
	struct node_id  nid;
	uint16_t	nr_vnodes;
	uint32_t	zone;
	uint64_t        space;
};

/*
 * A joining sheep multicasts the local cluster info.  Then, the existing nodes
 * reply the latest cluster info which is unique among all of the nodes.
 */
struct cluster_info {
	uint8_t proto_ver; /* the version number of the internal protocol */
	uint8_t disable_recovery;
	int16_t nr_nodes;
	uint32_t epoch;
	uint64_t ctime;
	uint16_t flags;
	uint8_t nr_copies;
	enum sd_status status : 8;
	uint32_t __pad;
	uint8_t store[STORE_LEN];

	/* node list at cluster_info->epoch */
	struct sd_node nodes[SD_MAX_NODES];
};

struct epoch_log {
	uint64_t ctime;
	uint64_t time;		/* treated as time_t */
	uint32_t epoch;
	uint32_t nr_nodes;
	uint8_t  disable_recovery;
	uint8_t  __pad[3];
	struct sd_node nodes[SD_MAX_NODES];
};

struct vdi_op_message {
	struct sd_req req;
	struct sd_rsp rsp;
	uint8_t data[0];
};

struct md_info {
	int idx;
	uint64_t free;
	uint64_t used;
	char path[PATH_MAX];
};

#define MD_MAX_DISK 64 /* FIXME remove roof and make it dynamic */
struct sd_md_info {
	struct md_info disk[MD_MAX_DISK];
	int nr;
};

static inline __attribute__((used)) void __sd_epoch_format_build_bug_ons(void)
{
	/* never called, only for checking BUILD_BUG_ON()s */
	BUILD_BUG_ON(sizeof(struct sd_node) != SD_NODE_SIZE);
}

enum rw_state {
	RW_PREPARE_LIST, /* the recovery thread is preparing object list */
	RW_RECOVER_OBJ, /* the thread is recoering objects */
	RW_NOTIFY_COMPLETION, /* the thread is notifying recovery completion */
};

struct recovery_state {
	uint8_t in_recovery;
	enum rw_state state;
	uint64_t nr_finished;
	uint64_t nr_total;
};

#define CACHE_MAX	1024
struct cache_info {
	uint32_t vid;
	uint32_t dirty;
	uint32_t total;
};

struct object_cache_info {
	uint64_t size;
	uint64_t used;
	struct cache_info caches[CACHE_MAX];
	int count;
};

#endif /* __INTERNAL_PROTO_H__ */
