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
#include <openssl/sha.h>
#include <zlib.h>

#include "sheepdog_proto.h"
#include "sheep.h"
#include "logger.h"

#define SHA1_LEN        20
#define HEX_LEN         40
#define NAME_LEN        HEX_LEN

struct sha1_file_hdr {
	char tag[TAG_LEN];
	uint64_t size;
	uint64_t priv;
	uint64_t reserved;
};

/* sha1_file.c */
extern char *sha1_to_path(const unsigned char *sha1);
extern int sha1_file_write(unsigned char *buf, unsigned len, unsigned char *outsha1);
extern void *sha1_file_read(const unsigned char *sha1, struct sha1_file_hdr *hdr);
extern char *sha1_to_hex(const unsigned char *sha1);
extern int get_sha1_hex(const char *hex, unsigned char *sha1);
extern int sha1_file_try_delete(const unsigned char *sha1);

#endif
