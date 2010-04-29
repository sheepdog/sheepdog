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
#ifndef __META_H__
#define __META_H__

#include <stdint.h>
#include "util.h"
#include "list.h"

#define SD_DATA_OBJ_SIZE (UINT64_C(1) << 22)

/*
 * Object ID rules
 *
 *  0 - 19 (20 bits): data object space
 * 20 - 31 (12 bits): reserved data object space
 * 32 - 55 (24 bits): vdi object space
 * 56 - 59 ( 4 bits): reserved vdi object space
 * 60 - 63 ( 4 bit ): object type indentifier space
 */

#define VDI_SPACE   24
#define VDI_SPACE_SHIFT   32
#define VDI_BIT (UINT64_C(1) << 63)
#define VMSTATE_BIT (UINT64_C(1) << 62)
#define DEAFAULT_NR_COPIES 1
#define MAX_DATA_OBJS (1ULL << 20)
#define MAX_CHILDREN 1024

#define SD_NR_VDIS   (1U << 24)

struct sheepdog_inode {
	char name[SD_MAX_VDI_LEN];
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

static inline int is_data_obj_writeable(struct sheepdog_inode *inode, int idx)
{
	return inode->vdi_id == inode->data_vdi_id[idx];
}

static inline int is_data_obj(uint64_t oid)
{
	return !(VDI_BIT & oid);
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

#define NR_VDIS (1U << DATA_SPECE_SHIFT)

#endif
