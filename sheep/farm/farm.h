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

#include "sheepdog_proto.h"
#include "sheep.h"
#include "logger.h"
#include "strbuf.h"
#include "sha1.h"

#define HEX_LEN         40
#define NAME_LEN        HEX_LEN

#define TAG_LEN         6
#define TAG_DATA        "data\0\0"
#define TAG_TRUNK       "trunk\0"
#define TAG_SNAP        "snap\0\0"

struct sha1_file_hdr {
	char tag[TAG_LEN];
	uint64_t size;
	uint64_t priv;
	uint64_t reserved;
};

struct trunk_entry {
	uint64_t oid;
	unsigned char sha1[SHA1_LEN];
};

/* farm.c */
extern char farm_dir[PATH_MAX];
extern char farm_obj_dir[PATH_MAX];

/* sha1_file.c */
char *sha1_to_path(const unsigned char *sha1);
int sha1_file_write(unsigned char *buf, unsigned len, unsigned char *);
void *sha1_file_read(const unsigned char *sha1, struct sha1_file_hdr *);
int get_sha1_hex(const char *hex, unsigned char *sha1);
int sha1_file_try_delete(const unsigned char *sha1);

/* trunk.c */
int trunk_init(void);
int trunk_file_write(unsigned char *outsha1);
void *trunk_file_read(unsigned char *sha1, struct sha1_file_hdr *);

/* snap.c */
int snap_init(void);
void *snap_file_read(unsigned char *sha1, struct sha1_file_hdr *outhdr);
int snap_file_write(uint32_t epoch, struct sd_node *nodes, int nr_nodes,
		unsigned char *trunksha1, unsigned char *outsha1);
int snap_log_truncate(void);
void *snap_log_read(int *);
int snap_log_write(uint32_t epoch, unsigned char *sha1);

#endif
