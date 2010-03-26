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
 *  0 - 19 (20 bits): data object space
 * 20 - 31 (12 bits): reserved data object space
 * 32 - 55 (24 bits): vdi object space
 * 56 - 62 (17 bits): reserved vdi object space
 * 63 - 63 ( 1 bit ): set if vdi
 */

#define VDI_SPACE   24
#define VDI_SPACE_SHIFT   32
#define VDI_BIT (UINT64_C(1) << 63)
#define DEAFAULT_NR_COPIES 1
#define SD_MAX_VDI_LEN 256
#define MAX_DATA_OBJS (1ULL << 20)
#define MAX_CHILDREN 1024

#define SD_NR_VDIS   (1U << 24)

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

struct sheepdog_inode {
	char name[SD_MAX_VDI_LEN];
	uint64_t oid;
	uint64_t ctime;
	uint64_t snap_ctime;
	uint64_t vdi_size;
	uint16_t copy_policy;
	uint8_t  nr_copies;
	uint8_t  block_size_shift;
	uint32_t snap_id;
	uint64_t parent_oid;
	uint64_t child_oid[MAX_CHILDREN];
	uint64_t data_oid[MAX_DATA_OBJS];
};

static inline int is_data_obj_writeable(struct sheepdog_inode *inode, int idx)
{
	return (inode->oid >> VDI_SPACE_SHIFT) ==
		(inode->data_oid[idx] >> VDI_SPACE_SHIFT);
}

static inline int is_data_obj(uint64_t oid)
{
	return !(VDI_BIT & oid);
}

#define NR_VDIS (1U << DATA_SPECE_SHIFT)

static inline uint64_t bit_to_oid(unsigned long nr)
{
	return ((unsigned long long)nr << VDI_SPACE_SHIFT) | VDI_BIT;
}

#endif
