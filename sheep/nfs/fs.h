/*
 * Copyright (C) 2014 Taobao Inc.
 *
 * Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <nfs://www.gnu.org/licenses/>.
 */
#ifndef _FS_H_
#define _FS_H_

#include "sheep_priv.h"

struct extent {
	uint64_t start;
	uint64_t count;
};

#define INODE_HDR_SIZE    SECTOR_SIZE
#define INODE_EXTENT_SIZE (BLOCK_SIZE * 2)
#define INODE_META_SIZE (INODE_HDR_SIZE + INODE_EXTENT_SIZE)
#define INODE_DATA_SIZE (SD_DATA_OBJ_SIZE - INODE_META_SIZE)

struct inode {
	union {
		struct {
			uint32_t mode;	/* File mode */
			uint32_t nlink;	/* Links count */
			uint32_t uid;	/* Owner Uid */
			uint32_t gid;	/* Group Id */
			uint64_t size;	/* Size in bytes */
			uint64_t used;	/* Used in bytes */
			uint64_t atime;	/* Access time */
			uint64_t ctime;	/* Creation time */
			uint64_t mtime;	/* Modification time */
			uint64_t ino;   /* Inode number */
			uint16_t extent_count; /* Number of extents */
		};
		uint8_t __pad1[INODE_HDR_SIZE];
	};
	union {
		struct extent extent[0];
		uint8_t __pad2[INODE_EXTENT_SIZE];
	};
	uint8_t data[INODE_DATA_SIZE];
};

struct dentry {
	uint64_t ino;             /* Inode number */
	uint16_t nlen;            /* Name length */
	char name[NFS_MAXNAMLEN]; /* File name */
};

int fs_make_root(uint32_t vid);
uint64_t fs_root_ino(uint32_t vid);
struct inode *fs_read_inode_hdr(uint64_t ino);
struct inode *fs_read_inode_full(uint64_t ino);
int fs_write_inode_hdr(struct inode *inode);
int fs_write_inode_full(struct inode *inode);
int fs_read_dir(struct inode *inode, uint64_t offset,
		int (*dentry_reader)(struct inode *, struct dentry *, void *),
		void *data);
struct dentry *fs_lookup_dir(struct inode *inode, const char *name);
int fs_create_file(uint64_t pino, struct inode *new, const char *name);

#endif
