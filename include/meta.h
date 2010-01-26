/*
 * Copyright (C) 2009 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __META_H__
#define __META_H__

#include <stdint.h>
#include "util.h"
#include "list.h"

#define SD_DIR_OID 0
#define SD_DATA_OBJ_SIZE (UINT64_C(1) << 22)

/*
 * Object ID rules
 *
 *  0 - 17 (18 bits): data object
 * 17 - 55 (37 bits): inode object
 * 56 - 63 ( 8 bits): PGID
 *
 * each VDI can use 2^18 data objects.
 */

#define DATA_SPACE_SHIFT 18

#define DEAFAULT_NR_COPIES 1

static inline uint64_t oid_to_ino(uint64_t inode_oid)
{
	return (inode_oid >> DATA_SPACE_SHIFT) & ((UINT64_C(1) << 37) - 1);
}

static inline int is_data_obj_writeable(uint64_t inode_oid, uint64_t data_oid)
{
	return oid_to_ino(inode_oid) == oid_to_ino(data_oid);
}

static inline int is_data_obj(uint64_t oid)
{
	return oid & ((UINT64_C(1) << DATA_SPACE_SHIFT) - 1);
}

#define SHEEPDOG_SUPER_OBJ_SIZE (UINT64_C(1) << 12)

#define FLAG_CURRENT 1

struct sheepdog_vdi_info {
	uint64_t oid;
	uint16_t id;
	uint16_t name_len;
	uint16_t tag_len;
	uint8_t type;
	uint8_t flags;
	uint32_t epoch;
	char name[SD_MAX_VDI_LEN];
	char tag[SD_MAX_VDI_LEN];
};

#define MAX_DATA_OBJS (1 << 18)
#define MAX_CHILDREN 1024

struct sheepdog_inode {
	uint64_t oid;
	uint64_t ctime;
	uint64_t vdi_size;
	uint64_t block_size;
	uint32_t copy_policy;
	uint32_t nr_copies;
	uint64_t parent_oid;
	uint64_t child_oid[MAX_CHILDREN];
	uint64_t data_oid[MAX_DATA_OBJS];
};

#endif
