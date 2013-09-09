/*
 * sha1.h - SHA1 Secure Hash Algorithm used for CHAP authentication.
 * copied from the Linux kernel's Cryptographic API and slightly adjusted to
 * fit IET's needs
 *
 * This file is (c) 2004 Xiranet Communications GmbH <arne.redlich@xiranet.com>
 * and licensed under the GPL.
 */

#ifndef SHA1_H
#define SHA1_H

#include <sys/types.h>
#include <string.h>
#include <inttypes.h>

#define SHA1_DIGEST_SIZE        20
#define SHA1_BLOCK_SIZE         64

struct sha1_ctx {
	uint64_t count;
	uint32_t state[SHA1_DIGEST_SIZE / 4];
	uint8_t buffer[SHA1_BLOCK_SIZE];
};

typedef void (*sha1_init_func_t)(void *);
typedef void (*sha1_update_func_t)(void *, const uint8_t *, unsigned int);
typedef void (*sha1_final_func_t)(void *, uint8_t *);

sha1_init_func_t sha1_init;
sha1_update_func_t sha1_update;
sha1_final_func_t sha1_final;

const char *sha1_to_hex(const unsigned char *sha1);
void sha1_from_buffer(const void *buf, size_t size, unsigned char *sha1);

#endif
