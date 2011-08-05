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
#ifndef __SHEEPDOG_PROTO_H__
#define __SHEEPDOG_PROTO_H__

#include <inttypes.h>
#include <stdint.h>
#include "util.h"

#define SD_PROTO_VER 0x01

#define SD_LISTEN_PORT 7000

#define SD_OP_CREATE_AND_WRITE_OBJ  0x01
#define SD_OP_READ_OBJ       0x02
#define SD_OP_WRITE_OBJ      0x03

#define SD_OP_NEW_VDI        0x11
#define SD_OP_LOCK_VDI       0x12
#define SD_OP_RELEASE_VDI    0x13
#define SD_OP_GET_VDI_INFO   0x14
#define SD_OP_READ_VDIS      0x15

#define SD_FLAG_CMD_WRITE    0x01
#define SD_FLAG_CMD_COW      0x02
#define SD_FLAG_CMD_TRUNCATE 0x04

#define SD_RES_SUCCESS       0x00 /* Success */
#define SD_RES_UNKNOWN       0x01 /* Unknown error */
#define SD_RES_NO_OBJ        0x02 /* No object found */
#define SD_RES_EIO           0x03 /* I/O error */
#define SD_RES_VDI_EXIST     0x04 /* Vdi exists already */
#define SD_RES_INVALID_PARMS 0x05 /* Invalid parameters */
#define SD_RES_SYSTEM_ERROR  0x06 /* System error */
#define SD_RES_VDI_LOCKED    0x07 /* Vdi is locked */
#define SD_RES_NO_VDI        0x08 /* No vdi found */
#define SD_RES_NO_BASE_VDI   0x09 /* No base vdi found */
#define SD_RES_VDI_READ      0x0A /* Cannot read requested vdi */
#define SD_RES_VDI_WRITE     0x0B /* Cannot write requested vdi */
#define SD_RES_BASE_VDI_READ 0x0C /* Cannot read base vdi */
#define SD_RES_BASE_VDI_WRITE   0x0D /* Cannot write base vdi */
#define SD_RES_NO_TAG        0x0E /* Requested tag is not found */
#define SD_RES_STARTUP       0x0F /* Sheepdog is on starting up */
#define SD_RES_VDI_NOT_LOCKED   0x10 /* Vdi is not locked */
#define SD_RES_SHUTDOWN      0x11 /* Sheepdog is shutting down */
#define SD_RES_NO_MEM        0x12 /* Cannot allocate memory */
#define SD_RES_FULL_VDI      0x13 /* we already have the maximum vdis */
#define SD_RES_VER_MISMATCH  0x14 /* Protocol version mismatch */
#define SD_RES_NO_SPACE      0x15 /* Server has no room for new objects */
#define SD_RES_WAIT_FOR_FORMAT  0x16 /* Sheepdog is waiting for a format operation */
#define SD_RES_WAIT_FOR_JOIN    0x17 /* Sheepdog is waiting for other nodes joining */
#define SD_RES_JOIN_FAILED   0x18 /* Target node had failed to join sheepdog */

/*
 * Object ID rules
 *
 *  0 - 19 (20 bits): data object space
 * 20 - 31 (12 bits): reserved data object space
 * 32 - 55 (24 bits): vdi object space
 * 56 - 59 ( 4 bits): reserved vdi object space
 * 60 - 63 ( 4 bits): object type indentifier space
 */

#define VDI_SPACE_SHIFT   32
#define VDI_BIT (UINT64_C(1) << 63)
#define VMSTATE_BIT (UINT64_C(1) << 62)
#define VDI_ATTR_BIT (UINT64_C(1) << 61)
#define MAX_DATA_OBJS (1ULL << 20)
#define MAX_CHILDREN 1024U
#define SD_MAX_VDI_LEN 256U
#define SD_MAX_VDI_TAG_LEN 256U
#define SD_MAX_VDI_ATTR_KEY_LEN 256U
#define SD_MAX_VDI_ATTR_VALUE_LEN (UINT64_C(1) << 22)
#define SD_NR_VDIS   (1U << 24)
#define SD_DATA_OBJ_SIZE (UINT64_C(1) << 22)
#define SD_MAX_VDI_SIZE (SD_DATA_OBJ_SIZE * MAX_DATA_OBJS)
#define SECTOR_SIZE (1U << 9)

#define SD_INODE_SIZE (sizeof(struct sheepdog_inode))
#define SD_INODE_HEADER_SIZE (sizeof(struct sheepdog_inode) - \
			      sizeof(uint32_t) * MAX_DATA_OBJS)
#define SD_ATTR_HEADER_SIZE (SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN + \
			     sizeof(uint32_t) + SD_MAX_VDI_ATTR_KEY_LEN)
#define CURRENT_VDI_ID 0

struct sd_req {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint32_t	opcode_specific[8];
};

struct sd_rsp {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint32_t        result;
	uint32_t	opcode_specific[7];
};

struct sd_obj_req {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint64_t        oid;
	uint64_t        cow_oid;
	uint32_t        copies;
	uint32_t        tgt_epoch;
	uint64_t        offset;
};

struct sd_obj_rsp {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint32_t        result;
	uint32_t        copies;
	uint32_t        pad[6];
};

struct sd_vdi_req {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint64_t	vdi_size;
	uint32_t        base_vdi_id;
	uint32_t	copies;
	uint32_t        snapid;
	uint32_t        pad[3];
};

struct sd_vdi_rsp {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	uint32_t        result;
	uint32_t        rsvd;
	uint32_t        vdi_id;
	uint32_t        attr_id;
	uint32_t        copies;
	uint32_t        pad[3];
};

struct sheepdog_inode {
	char name[SD_MAX_VDI_LEN];
	char tag[SD_MAX_VDI_TAG_LEN];
	uint64_t ctime;
	uint64_t snap_ctime;
	uint64_t vm_clock_nsec;
	uint64_t vdi_size;
	uint64_t vm_state_size;
	uint16_t copy_policy;
	uint8_t  nr_copies;
	uint8_t  block_size_shift;
	uint32_t snap_id;
	uint32_t vdi_id;
	uint32_t parent_vdi_id;
	uint32_t child_vdi_id[MAX_CHILDREN];
	uint32_t data_vdi_id[MAX_DATA_OBJS];
};

/*
 * 64 bit FNV-1a non-zero initial basis
 */
#define FNV1A_64_INIT ((uint64_t) 0xcbf29ce484222325ULL)

/*
 * 64 bit Fowler/Noll/Vo FNV-1a hash code
 */
static inline uint64_t fnv_64a_buf(void *buf, size_t len, uint64_t hval)
{
	unsigned char *bp = (unsigned char *) buf;
	unsigned char *be = bp + len;
	while (bp < be) {
		hval ^= (uint64_t) *bp++;
		hval += (hval << 1) + (hval << 4) + (hval << 5) +
			(hval << 7) + (hval << 8) + (hval << 40);
	}
	return hval;
}

static inline int is_data_obj_writeable(struct sheepdog_inode *inode, int idx)
{
	return inode->vdi_id == inode->data_vdi_id[idx];
}

static inline int is_vdi_obj(uint64_t oid)
{
	return !!(oid & VDI_BIT);
}

static inline int is_vmstate_obj(uint64_t oid)
{
	return !!(oid & VMSTATE_BIT);
}

static inline int is_vdi_attr_obj(uint64_t oid)
{
	return !!(oid & VDI_ATTR_BIT);
}

static inline int is_data_obj(uint64_t oid)
{
	return !is_vdi_obj(oid) && !is_vmstate_obj(oid) &&
		!is_vdi_attr_obj(oid);
}

static inline uint64_t data_oid_to_idx(uint64_t oid)
{
	return oid & (MAX_DATA_OBJS - 1);
}

static inline uint64_t vid_to_vdi_oid(uint32_t vid)
{
	return VDI_BIT | ((uint64_t)vid << VDI_SPACE_SHIFT);
}

static inline uint64_t vid_to_data_oid(uint32_t vid, uint32_t idx)
{
	return ((uint64_t)vid << VDI_SPACE_SHIFT) | idx;
}

static inline uint32_t oid_to_vid(uint64_t oid)
{
	return (~VDI_BIT & oid) >> VDI_SPACE_SHIFT;
}

static inline uint64_t vid_to_attr_oid(uint32_t vid, uint32_t attrid)
{
	return ((uint64_t)vid << VDI_SPACE_SHIFT) | VDI_ATTR_BIT | attrid;
}

#endif
