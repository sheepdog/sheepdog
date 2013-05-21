#ifndef FARM_H
#define FARM_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <memory.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <linux/limits.h>

#include "collie.h"
#include "sheepdog_proto.h"
#include "sheep.h"
#include "logger.h"
#include "strbuf.h"
#include "sha1.h"

#define TAG_LEN         6
#define TAG_DATA        "data\0\0"
#define TAG_TRUNK       "trunk\0"
#define TAG_SNAP        "snap\0\0"

struct trunk_entry {
	uint64_t oid;
	int nr_copies;
	unsigned char sha1[SHA1_LEN];
};

struct sha1_file_hdr {
	char tag[TAG_LEN];
	uint64_t size;
	uint64_t priv;
	uint64_t reserved;
};

static char farm_obj_dir[PATH_MAX];
static char farm_dir[PATH_MAX];

static inline char *get_object_directory(void)
{
	return farm_obj_dir;
}

typedef int (*object_handler_func_t)(uint64_t oid, int nr_copies, void *buf,
				     size_t size, void *data);

/* trunk.c */
int trunk_init(void);
int trunk_file_write(unsigned char *trunk_sha1, struct strbuf *trunk_entries);
void *trunk_file_read(unsigned char *sha1, struct sha1_file_hdr *);
int for_each_object_in_trunk(unsigned char *trunk_sha1,
			     object_handler_func_t func, void *data);

/* snap.c */
int snap_init(const char *path);
void *snap_file_read(unsigned char *sha1, struct sha1_file_hdr *outhdr);
int snap_file_write(uint32_t idx, unsigned char *trunksha1,
		    unsigned char *outsha1);
void *snap_log_read(int *out_nr);
int snap_log_write(uint32_t idx, const char *tag, unsigned char *sha1);

/* sha1_file.c */
int sha1_file_write(unsigned char *buf, unsigned len, unsigned char *);
void *sha1_file_read(const unsigned char *sha1, struct sha1_file_hdr *);
int get_sha1_hex(const char *hex, unsigned char *sha1);
int sha1_file_try_delete(const unsigned char *sha1);

/* object_tree.c */
int object_tree_size(void);
void object_tree_insert(uint64_t oid, int nr_copies);
void object_tree_free(void);
void object_tree_print(void);
int for_each_object_in_tree(object_handler_func_t func, void *data);

#endif
