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

#include "dog.h"
#include "sheep.h"
#include "strbuf.h"
#include "sha1.h"

struct trunk_entry {
	uint64_t oid;
	int nr_copies;
	unsigned char sha1[SHA1_DIGEST_SIZE];
};

struct trunk_file {
	uint64_t nr_entries;
	struct trunk_entry *entries;
};

struct snap_file {
	int idx;
	unsigned char trunk_sha1[SHA1_DIGEST_SIZE];
};

struct snap_log {
	uint32_t idx;
	char tag[SD_MAX_SNAPSHOT_TAG_LEN];
	uint64_t time;
	unsigned char sha1[SHA1_DIGEST_SIZE];
};

/* farm.c */
int farm_init(const char *path);
bool farm_contain_snapshot(uint32_t idx, const char *tag);
int farm_save_snapshot(const char *tag);
int farm_load_snapshot(uint32_t idx, const char *tag);
char *get_object_directory(void);

/* trunk.c */
int trunk_init(void);
int trunk_file_write(uint64_t nr_entries, struct trunk_entry *entries,
		     unsigned char *trunk_sha1);
int for_each_entry_in_trunk(unsigned char *trunk_sha1,
			    int (*func)(struct trunk_entry *entry, void *data),
			    void *data);
uint64_t trunk_get_count(void);

/* snap.c */
int snap_init(const char *path);
struct snap_file *snap_file_read(unsigned char *sha1);
int snap_file_write(uint32_t idx, unsigned char *trunk_sha1,
		    unsigned char *outsha1);
void *snap_log_read(int *out_nr);
int snap_log_write(uint32_t idx, const char *tag, unsigned char *sha1);

/* sha1_file.c */
int sha1_file_write(void *buf, size_t len, unsigned char *sha1);
void *sha1_file_read(const unsigned char *sha1, size_t *size);

/* object_tree.c */
int object_tree_size(void);
void object_tree_insert(uint64_t oid, int nr_copies);
void object_tree_free(void);
void object_tree_print(void);
int for_each_object_in_tree(int (*func)(uint64_t oid, int nr_copies,
					void *data), void *data);
/* slice.c */
int slice_write(void *buf, size_t len, unsigned char *outsha1);
void *slice_read(const unsigned char *sha1, size_t *outsize);

#endif
