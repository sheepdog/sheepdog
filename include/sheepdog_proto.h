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

#ifdef __KERNEL__
# define UINT64_MAX (18446744073709551615ULL)
# define UINT64_C(x) ((x) + (UINT64_MAX - UINT64_MAX))
#else
# include <inttypes.h>
# include <stdint.h>
# include <string.h>
#endif

#include <stdbool.h>
#include <linux/limits.h>
#include <stddef.h>

#define SD_PROTO_VER 0x02

/* This or later version supports trimming zero sectors from read response */
#define SD_PROTO_VER_TRIM_ZERO_SECTORS 0x02

#define SD_LISTEN_PORT 7000

#define SD_OP_CREATE_AND_WRITE_OBJ  0x01
#define SD_OP_READ_OBJ       0x02
#define SD_OP_WRITE_OBJ      0x03
#define SD_OP_REMOVE_OBJ     0x04
#define SD_OP_DISCARD_OBJ    0x05

#define SD_OP_NEW_VDI        0x11
#define SD_OP_LOCK_VDI       0x12
#define SD_OP_RELEASE_VDI    0x13
#define SD_OP_GET_VDI_INFO   0x14
#define SD_OP_READ_VDIS      0x15
#define SD_OP_FLUSH_VDI      0x16 /* obsolete */
#define SD_OP_DEL_VDI        0x17
#define SD_OP_GET_CLUSTER_DEFAULT   0x18

/* macros in the SD_FLAG_CMD_XXX group are mutually exclusive */
#define SD_FLAG_CMD_WRITE    0x01
#define SD_FLAG_CMD_COW      0x02
#define SD_FLAG_CMD_CACHE    0x04
#define SD_FLAG_CMD_DIRECT   0x08 /* don't use object cache */
/* return something back while sending something to sheep */
#define SD_FLAG_CMD_PIGGYBACK   0x10
#define SD_FLAG_CMD_TGT   0x20
#define SD_FLAG_CMD_FWD   0x40
/* flags above 0x80 are sheepdog-internal */

#define SD_RES_SUCCESS       0x00 /* Success */
#define SD_RES_UNKNOWN       0x01 /* Unknown error */
#define SD_RES_NO_OBJ        0x02 /* No object found */
#define SD_RES_EIO           0x03 /* I/O error */
#define SD_RES_VDI_EXIST     0x04 /* VDI exists already */
#define SD_RES_INVALID_PARMS 0x05 /* Invalid parameters */
#define SD_RES_SYSTEM_ERROR  0x06 /* System error */
#define SD_RES_VDI_LOCKED    0x07 /* VDI is locked */
#define SD_RES_NO_VDI        0x08 /* No VDI found */
#define SD_RES_NO_BASE_VDI   0x09 /* No base VDI found */
#define SD_RES_VDI_READ      0x0A /* Cannot read requested VDI */
#define SD_RES_VDI_WRITE     0x0B /* Cannot write requested VDI */
#define SD_RES_BASE_VDI_READ 0x0C /* Cannot read base VDI */
#define SD_RES_BASE_VDI_WRITE   0x0D /* Cannot write base VDI */
#define SD_RES_NO_TAG        0x0E /* Requested tag is not found */
#define SD_RES_STARTUP       0x0F /* Sheepdog is on starting up */
#define SD_RES_VDI_NOT_LOCKED   0x10 /* VDI is not locked */
#define SD_RES_SHUTDOWN      0x11 /* Sheepdog is shutting down */
#define SD_RES_NO_MEM        0x12 /* Cannot allocate memory */
#define SD_RES_FULL_VDI      0x13 /* we already have the maximum VDIs */
#define SD_RES_VER_MISMATCH  0x14 /* Protocol version mismatch */
#define SD_RES_NO_SPACE      0x15 /* Server has no room for new objects */
#define SD_RES_WAIT_FOR_FORMAT  0x16 /* Sheepdog is waiting for a format operation */
#define SD_RES_WAIT_FOR_JOIN 0x17 /* Sheepdog is waiting for other nodes joining */
#define SD_RES_JOIN_FAILED   0x18 /* Target node had failed to join sheepdog */
#define SD_RES_HALT          0x19 /* Sheepdog is stopped doing IO */
#define SD_RES_READONLY      0x1A /* Object is read-only */
/* inode object in client is invalidated, refreshing is required */
#define SD_RES_INODE_INVALIDATED 0x1D

/* errors above 0x80 are sheepdog-internal */

/*
 * Object ID rules
 *
 *  0 - 31 (32 bits): data object space
 * 32 - 55 (24 bits): VDI object space
 * 56 - 59 ( 4 bits): reserved VDI object space
 * 60 - 63 ( 4 bits): object type identifier space
 */

#define VDI_SPACE_SHIFT   32
#define SD_VDI_MASK 0x00FFFFFF00000000
#define VDI_BIT (UINT64_C(1) << 63)
#define VMSTATE_BIT (UINT64_C(1) << 62)
#define VDI_ATTR_BIT (UINT64_C(1) << 61)
#define VDI_BTREE_BIT (UINT64_C(1) << 60)
#define LEDGER_BIT (UINT64_C(1) << 59)
#define OLD_MAX_DATA_OBJS (1ULL << 20)
#define MAX_DATA_OBJS (1ULL << 32)
#define SD_MAX_VDI_LEN 256U
#define SD_MAX_VDI_TAG_LEN 256U
#define SD_MAX_VDI_ATTR_KEY_LEN 256U
#define SD_MAX_VDI_ATTR_VALUE_LEN 65536U
#define SD_MAX_SNAPSHOT_TAG_LEN 256U
#define SD_NR_VDIS   (1U << 24)
#define SD_DATA_OBJ_SIZE (UINT64_C(1) << 22)
#define SD_OLD_MAX_VDI_SIZE (SD_DATA_OBJ_SIZE * OLD_MAX_DATA_OBJS)
#define SD_MAX_VDI_SIZE (SD_DATA_OBJ_SIZE * MAX_DATA_OBJS)
#define SD_DEFAULT_BLOCK_SIZE_SHIFT 22

#define SD_INODE_SIZE (sizeof(struct sd_inode))
#define SD_INODE_INDEX_SIZE (sizeof(uint32_t) * MAX_DATA_OBJS)
#define SD_INODE_DATA_INDEX (1ULL << 20)
#define SD_INODE_DATA_INDEX_SIZE (sizeof(uint32_t) * SD_INODE_DATA_INDEX)
#define SD_INODE_HEADER_SIZE offsetof(struct sd_inode, data_vdi_id)
#define SD_ATTR_OBJ_SIZE (sizeof(struct sheepdog_vdi_attr))
#define SD_LEDGER_OBJ_SIZE (UINT64_C(1) << 22)
#define CURRENT_VDI_ID 0

#define STORE_LEN 16

#define SD_REQ_SIZE 48
#define SD_RSP_SIZE 48

#define LOCK_TYPE_NORMAL 0
#define LOCK_TYPE_SHARED 1	/* for iSCSI multipath */

struct sd_req {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	union {
		struct {
			uint64_t	oid;
			uint64_t	cow_oid;
			uint8_t		copies;
			uint8_t		copy_policy;
			uint8_t		ec_index;
			uint8_t		reserved;
			uint32_t	tgt_epoch;
			uint32_t	offset;
			uint32_t	__pad;
		} obj;
		struct {
			uint64_t	vdi_size;
			uint32_t	base_vdi_id;
			uint8_t		copies;
			uint8_t		copy_policy;
			uint8_t		store_policy;
			uint8_t		block_size_shift;
			uint32_t	snapid;
			uint32_t        type;
		} vdi;

		/* sheepdog-internal */
		struct {
			uint64_t	oid;
			uint64_t	ctime;
			uint8_t		copies;
			uint8_t		copy_policy;
			uint16_t	flags;
			uint32_t	tag;
			uint32_t	nodes_nr;
			uint8_t		block_size_shift;
			uint8_t		reserved[3];
		} cluster;
		struct {
			uint32_t	old_vid;
			uint32_t	new_vid;
			uint8_t		copies;
			uint8_t		set_bitmap; /* 0 means false */
						    /* others mean true */
			uint8_t		copy_policy;
			uint8_t		block_size_shift;
		} vdi_state;
		struct {
			uint64_t	oid;
			uint32_t	generation;
			uint32_t	count;
		} ref;
		struct {
			uint64_t	oid;
			uint8_t		addr[16];
			uint16_t	port;
		} forw;
		struct {
			uint32_t        get; /* 0 means free, 1 means get */
			uint32_t        tgt_epoch;

			uint32_t        vid; /* only used for get */
		} vdi_state_checkpoint;
		struct {
			/* 1 means validate, 0 means invalidate */
			uint32_t        vid;
			uint32_t        validate;
		} inode_coherence;


		uint32_t		__pad[8];
	};
};

struct sd_rsp {
	uint8_t		proto_ver;
	uint8_t		opcode;
	uint16_t	flags;
	uint32_t	epoch;
	uint32_t        id;
	uint32_t        data_length;
	union {
		uint32_t        result;
		struct {
			uint32_t	__pad;
			uint8_t		copies;
			uint8_t		reserved[3];
			uint64_t	offset;
		} obj;
		struct {
			uint32_t	__pad;
			uint32_t	rsvd;
			uint32_t	vdi_id;
			uint32_t	attr_id;
			uint8_t		copies;
			uint8_t		block_size_shift;
			uint8_t		reserved[2];
		} vdi;

		/* sheepdog-internal */
		struct {
			uint32_t	__pad;
			uint32_t	nr_nodes;
			uint32_t	__reserved[2];
			uint64_t	store_size;
			uint64_t	store_free;
		} node;
		struct {
			uint32_t	__pad1;
			uint32_t	__pad2;
			uint8_t		digest[20];
		} hash;
		struct {
			uint32_t	__pad1;
			uint8_t		nr_copies;
			uint8_t		copy_policy;
			uint8_t		block_size_shift;
			uint8_t		__pad2;
		} cluster_default;

		uint32_t		__pad[8];
	};
};

#define MAX_CHILDREN 1024U

/*
 * struct sd_inode_0_7: old inode format used in v0.7.x
 * Just used by upgrade tools.
 */
struct sd_inode_0_7 {
	char name[SD_MAX_VDI_LEN];
	char tag[SD_MAX_VDI_TAG_LEN];
	uint64_t create_time;
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
	uint32_t data_vdi_id[SD_INODE_DATA_INDEX];
};

/*
 * struct sd_inode_0_8: old inode format used in v0.8.x
 * Just used by upgrade tools.
 */
struct sd_inode_0_8 {
	char name[SD_MAX_VDI_LEN];
	char tag[SD_MAX_VDI_TAG_LEN];
	uint64_t create_time;
	uint64_t snap_ctime;
	uint64_t vm_clock_nsec;
	uint64_t vdi_size;
	uint64_t vm_state_size;
	uint8_t  copy_policy;
	uint8_t  store_policy;
	uint8_t  nr_copies;
	uint8_t  block_size_shift;
	uint32_t snap_id;
	uint32_t vdi_id;
	uint32_t parent_vdi_id;
	uint32_t child_vdi_id[MAX_CHILDREN];
	uint32_t data_vdi_id[SD_INODE_DATA_INDEX];
	uint32_t btree_counter;
};

/*
 * Historical notes: previous version of sheepdog (< v0.9.0) has a limit of
 * maximum number of children which can be created from single VDI. So the inode
 * object has an array for storing the IDs of the child VDIs. The constant
 * OLD_MAX_CHILDREN represents it. Current sheepdog doesn't have the limitation,
 * so we are recycling the area (4 * OLD_MAX_CHILDREN = 4KB) for storing new
 * metadata.
 *
 * users of the released area:
 * - uint32_t btree_counter
 */
#define OLD_MAX_CHILDREN 1024U

struct generation_reference {
	int32_t generation;
	int32_t count;
};

struct recovery_throttling {
	uint32_t max_exec_count;
	uint64_t queue_work_interval;
	bool throttling;
};

struct sd_inode {
	char name[SD_MAX_VDI_LEN];
	char tag[SD_MAX_VDI_TAG_LEN];
	uint64_t create_time;
	uint64_t snap_ctime;
	uint64_t vm_clock_nsec;
	uint64_t vdi_size;
	uint64_t vm_state_size;
	uint8_t  copy_policy;
	uint8_t  store_policy;
	uint8_t  nr_copies;
	uint8_t  block_size_shift;
	uint32_t snap_id;
	uint32_t vdi_id;
	uint32_t parent_vdi_id;

	uint32_t btree_counter;
	uint32_t __unused[OLD_MAX_CHILDREN - 1];

	uint32_t data_vdi_id[SD_INODE_DATA_INDEX];
	struct generation_reference gref[SD_INODE_DATA_INDEX];
};

struct sd_index {
	uint32_t idx; /* Index of data object */
	uint32_t vdi_id;
};

struct sd_indirect_idx {
	uint32_t idx; /* Max index of data object within this indirect node */
	uint64_t oid;
};

#define INODE_BTREE_MAGIC	0x6274

struct sd_index_header {
	uint16_t magic;
	uint16_t depth;	/* 2: root node; 1: indirect node */
	uint32_t entries;
};

#define	BTREE_HEAD         1
#define	BTREE_INDEX        2
#define BTREE_INDIRECT_IDX 4

typedef int (*write_node_fn)(uint64_t id, void *mem, unsigned int len,
				uint64_t offset, uint32_t flags, int copies,
				int copy_policy, bool create, bool direct);
typedef int (*read_node_fn)(uint64_t id, void **mem, unsigned int len,
				uint64_t offset);

struct sheepdog_vdi_attr {
	char name[SD_MAX_VDI_LEN];
	char tag[SD_MAX_VDI_TAG_LEN];
	uint64_t ctime;
	uint32_t snap_id;
	uint32_t value_len;
	char key[SD_MAX_VDI_ATTR_KEY_LEN];
	char value[SD_MAX_VDI_ATTR_VALUE_LEN];
};

extern void sd_inode_init(void *data, int depth);
extern int sd_inode_actor_init(write_node_fn writer, read_node_fn reader);
extern uint32_t sd_inode_get_vid(const struct sd_inode *inode, uint32_t idx);
extern int sd_inode_set_vid(struct sd_inode *inode, uint32_t idx, uint32_t);
extern int sd_inode_set_vid_range(struct sd_inode *inode, uint32_t idx_start,
				  uint32_t idx_end, uint32_t vdi_id);
extern int sd_inode_write(struct sd_inode *inode, int flags, bool create, bool);
extern int sd_inode_write_vid(struct sd_inode *inode,
			      uint32_t idx, uint32_t vid, uint32_t value,
			      int flags, bool create, bool direct);
extern uint32_t sd_inode_get_meta_size(struct sd_inode *inode, size_t size);
extern void sd_inode_copy_vdis(write_node_fn writer, read_node_fn reader,
			       uint32_t *data_vdi_id, uint8_t store_policy,
			       uint8_t nr_copies, uint8_t copy_policy,
			       struct sd_inode *newi);

typedef void (*index_cb_fn)(struct sd_index *, void *arg, int type);
void sd_inode_index_walk(const struct sd_inode *inode, index_cb_fn, void *);

/* 64 bit FNV-1a non-zero initial basis */
#define FNV1A_64_INIT ((uint64_t) 0xcbf29ce484222325ULL)
#define FNV_64_PRIME ((uint64_t) 0x100000001b3ULL)

/* 64 bit Fowler/Noll/Vo FNV-1a hash code */
static inline uint64_t fnv_64a_buf(const void *buf, size_t len, uint64_t hval)
{
	const unsigned char *p = (const unsigned char *) buf;
	int i;

	for (i = 0; i < len; i++) {
		hval ^= (uint64_t) p[i];
		hval *= FNV_64_PRIME;
	}

	return hval;
}

/*
 * The result is same as fnv_64a_buf(&oid, sizeof(oid), hval) but this function
 * is a bit faster.
 */
static inline uint64_t fnv_64a_64(uint64_t oid, uint64_t hval)
{
	hval ^= oid & 0xff;
	hval *= FNV_64_PRIME;
	hval ^= oid >> 8 & 0xff;
	hval *= FNV_64_PRIME;
	hval ^= oid >> 16 & 0xff;
	hval *= FNV_64_PRIME;
	hval ^= oid >> 24 & 0xff;
	hval *= FNV_64_PRIME;
	hval ^= oid >> 32 & 0xff;
	hval *= FNV_64_PRIME;
	hval ^= oid >> 40 & 0xff;
	hval *= FNV_64_PRIME;
	hval ^= oid >> 48 & 0xff;
	hval *= FNV_64_PRIME;
	hval ^= oid >> 56 & 0xff;
	hval *= FNV_64_PRIME;

	return hval;
}

static inline uint64_t sd_hash(const void *buf, size_t len)
{
	uint64_t hval = fnv_64a_buf(buf, len, FNV1A_64_INIT);

	return fnv_64a_64(hval, hval);
}

static inline uint64_t sd_hash_64(uint64_t oid)
{
	uint64_t hval = fnv_64a_64(oid, FNV1A_64_INIT);

	return fnv_64a_64(hval, hval);
}

static inline uint64_t sd_hash_next(uint64_t hval)
{
	return fnv_64a_64(hval, hval);
}

/*
 * Create a hash value from an object id.  The result is same as sd_hash(&oid,
 * sizeof(oid)) but this function is a bit faster.
 */
static inline uint64_t sd_hash_oid(uint64_t oid)
{
	return sd_hash_64(oid);
}

/*
 * Create a hash value from a vdi name.  We cannot use sd_hash_buf for this
 * purpose because of backward compatibility.
 */
static inline uint32_t sd_hash_vdi(const char *name)
{
	uint64_t hval = fnv_64a_buf(name, strlen(name), FNV1A_64_INIT);

	return (uint32_t)(hval & (SD_NR_VDIS - 1));
}

#ifndef __KERNEL__
static inline uint64_t hash_64(uint64_t val, unsigned int bits)
{
	return sd_hash_64(val) >> (64 - bits);
}
#endif

static inline bool is_vdi_obj(uint64_t oid)
{
	return !!(oid & VDI_BIT);
}

static inline bool is_vmstate_obj(uint64_t oid)
{
	return !!(oid & VMSTATE_BIT);
}

static inline bool is_vdi_attr_obj(uint64_t oid)
{
	return !!(oid & VDI_ATTR_BIT);
}

static inline bool is_vdi_btree_obj(uint64_t oid)
{
	return !!(oid & VDI_BTREE_BIT);
}

static inline bool is_ledger_object(uint64_t oid)
{
	return !!(oid & LEDGER_BIT);
}

static inline bool is_data_obj(uint64_t oid)
{
	return !is_vdi_obj(oid) && !is_vmstate_obj(oid) &&
		!is_vdi_attr_obj(oid) && !is_vdi_btree_obj(oid) &&
		!is_ledger_object(oid);
}

static inline size_t get_objsize(uint64_t oid, uint32_t object_size)
{
	if (is_vdi_obj(oid))
		return SD_INODE_SIZE;

	if (is_vdi_attr_obj(oid))
		return SD_ATTR_OBJ_SIZE;

	if (is_vdi_btree_obj(oid))
		return SD_INODE_DATA_INDEX_SIZE;

	if (is_ledger_object(oid))
		return SD_LEDGER_OBJ_SIZE;

	return object_size;
}

static inline uint64_t data_oid_to_idx(uint64_t oid)
{
	return oid & (MAX_DATA_OBJS - 1);
}

static inline uint64_t vid_to_vdi_oid(uint32_t vid)
{
	return VDI_BIT | ((uint64_t)vid << VDI_SPACE_SHIFT);
}

static inline uint64_t vid_to_data_oid(uint32_t vid, uint64_t idx)
{
	return ((uint64_t)vid << VDI_SPACE_SHIFT) | idx;
}

static inline uint32_t oid_to_vid(uint64_t oid)
{
	return (oid & SD_VDI_MASK) >> VDI_SPACE_SHIFT;
}

static inline uint64_t vid_to_attr_oid(uint32_t vid, uint32_t attrid)
{
	return ((uint64_t)vid << VDI_SPACE_SHIFT) | VDI_ATTR_BIT | attrid;
}

static inline uint64_t vid_to_btree_oid(uint32_t vid, uint32_t btreeid)
{
	return ((uint64_t)vid << VDI_SPACE_SHIFT) | VDI_BTREE_BIT | btreeid;
}

static inline uint64_t vid_to_vmstate_oid(uint32_t vid, uint32_t idx)
{
	return VMSTATE_BIT | ((uint64_t)vid << VDI_SPACE_SHIFT) | idx;
}

static inline bool vdi_is_snapshot(const struct sd_inode *inode)
{
	return !!inode->snap_ctime;
}

static inline uint64_t ledger_oid_to_data_oid(uint64_t oid)
{
	return ~LEDGER_BIT & oid;
}

static inline uint64_t data_oid_to_ledger_oid(uint64_t oid)
{
	return LEDGER_BIT | oid;
}

static inline uint64_t data_vid_offset(int idx)
{
	return offsetof(struct sd_inode, data_vdi_id[idx]);
}

#endif
