/*
 * Cryptographic API.
 *
 * SHA1 Secure Hash Algorithm.
 *
 * Derived from cryptoapi implementation, adapted for in-place
 * scatterlist interface.  Originally based on the public domain
 * implementation written by Steve Reid.
 *
 * Copyright (c) Alan Smithee.
 * Copyright (c) Andrew McDonald <andrew@mcdonald.org.uk>
 * Copyright (c) Jean-Francois Dive <jef@linuxbe.org>
 *
 * Add x86 hardware acceleration by Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */
#include <arpa/inet.h>
#include "sha1.h"
#include "util.h"

#define SHA1_H0		0x67452301UL
#define SHA1_H1		0xefcdab89UL
#define SHA1_H2		0x98badcfeUL
#define SHA1_H3		0x10325476UL
#define SHA1_H4		0xc3d2e1f0UL

sha1_init_func_t sha1_init;
sha1_update_func_t sha1_update;
sha1_final_func_t sha1_final;

static __always_inline uint32_t rol(uint32_t value, uint32_t bits)
{
	return (value << bits) | (value >> (32 - bits));
}

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
# define blk0(i) block32[i]

#define blk(i) \
	(block32[i & 15] = rol(block32[(i + 13) & 15] ^ block32[(i + 8) & 15] \
			       ^ block32[(i + 2) & 15] ^ block32[i & 15], 1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v, w, x, y, z, i) \
	z += ((w & (x ^ y)) ^ y) + blk0(i) + 0x5A827999 + rol(v, 5);	\
	w = rol(w, 30);
#define R1(v, w, x, y, z, i) \
	z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rol(v, 5);	\
	w = rol(w, 30);
#define R2(v, w, x, y, z, i) \
	z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rol(v, 5); \
	w = rol(w, 30);
#define R3(v, w, x, y, z, i) \
	z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + rol(v, 5); \
	w = rol(w, 30);
#define R4(v, w, x, y, z, i) \
	z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rol(v, 5); \
	w = rol(w, 30);

/* Hash a single 512-bit block. This is the core of the algorithm. */
static void sha1_transform(uint32_t *state, const uint8_t *in)
{
	uint32_t a, b, c, d, e;
	uint32_t block32[16];

	/* convert/copy data to workspace */
	for (a = 0; a < sizeof(block32)/sizeof(uint32_t); a++)
		block32[a] = ntohl(((const uint32_t *)in)[a]);

	/* Copy context->state[] to working vars */
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];

	/* 4 rounds of 20 operations each. Loop unrolled. */
	R0(a, b, c, d, e, 0); R0(e, a, b, c, d, 1);
	R0(d, e, a, b, c, 2); R0(c, d, e, a, b, 3);
	R0(b, c, d, e, a, 4); R0(a, b, c, d, e, 5);
	R0(e, a, b, c, d, 6); R0(d, e, a, b, c, 7);
	R0(c, d, e, a, b, 8); R0(b, c, d, e, a, 9);
	R0(a, b, c, d, e, 10); R0(e, a, b, c, d, 11);
	R0(d, e, a, b, c, 12); R0(c, d, e, a, b, 13);
	R0(b, c, d, e, a, 14); R0(a, b, c, d, e, 15);
	R1(e, a, b, c, d, 16); R1(d, e, a, b, c, 17);
	R1(c, d, e, a, b, 18); R1(b, c, d, e, a, 19);

	R2(a, b, c, d, e, 20); R2(e, a, b, c, d, 21);
	R2(d, e, a, b, c, 22); R2(c, d, e, a, b, 23);
	R2(b, c, d, e, a, 24); R2(a, b, c, d, e, 25);
	R2(e, a, b, c, d, 26); R2(d, e, a, b, c, 27);
	R2(c, d, e, a, b, 28); R2(b, c, d, e, a, 29);
	R2(a, b, c, d, e, 30); R2(e, a, b, c, d, 31);
	R2(d, e, a, b, c, 32); R2(c, d, e, a, b, 33);
	R2(b, c, d, e, a, 34); R2(a, b, c, d, e, 35);
	R2(e, a, b, c, d, 36); R2(d, e, a, b, c, 37);
	R2(c, d, e, a, b, 38); R2(b, c, d, e, a, 39);

	R3(a, b, c, d, e, 40); R3(e, a, b, c, d, 41);
	R3(d, e, a, b, c, 42); R3(c, d, e, a, b, 43);
	R3(b, c, d, e, a, 44); R3(a, b, c, d, e, 45);
	R3(e, a, b, c, d, 46); R3(d, e, a, b, c, 47);
	R3(c, d, e, a, b, 48); R3(b, c, d, e, a, 49);
	R3(a, b, c, d, e, 50); R3(e, a, b, c, d, 51);
	R3(d, e, a, b, c, 52); R3(c, d, e, a, b, 53);
	R3(b, c, d, e, a, 54); R3(a, b, c, d, e, 55);
	R3(e, a, b, c, d, 56); R3(d, e, a, b, c, 57);
	R3(c, d, e, a, b, 58); R3(b, c, d, e, a, 59);

	R4(a, b, c, d, e, 60); R4(e, a, b, c, d, 61);
	R4(d, e, a, b, c, 62); R4(c, d, e, a, b, 63);
	R4(b, c, d, e, a, 64); R4(a, b, c, d, e, 65);
	R4(e, a, b, c, d, 66); R4(d, e, a, b, c, 67);
	R4(c, d, e, a, b, 68); R4(b, c, d, e, a, 69);
	R4(a, b, c, d, e, 70); R4(e, a, b, c, d, 71);
	R4(d, e, a, b, c, 72); R4(c, d, e, a, b, 73);
	R4(b, c, d, e, a, 74); R4(a, b, c, d, e, 75);
	R4(e, a, b, c, d, 76); R4(d, e, a, b, c, 77);
	R4(c, d, e, a, b, 78); R4(b, c, d, e, a, 79);

	/* Add the working vars back into context.state[] */
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	/* Wipe variables */
	a = b = c = d = e = 0;
	memset(block32, 0x00, sizeof block32);
}

static void generic_sha1_init(void *ctx)
{
	struct sha1_ctx *sctx = ctx;

	*sctx = (struct sha1_ctx){
		.state = { SHA1_H0, SHA1_H1, SHA1_H2, SHA1_H3, SHA1_H4 },
	};
}

static void generic_sha1_update(void *ctx, const uint8_t *data,
				unsigned int len)
{
	struct sha1_ctx *sctx = ctx;
	unsigned int i, j;

	j = (sctx->count >> 3) & 0x3f;
	sctx->count += len << 3;

	if ((j + len) > 63) {
		memcpy(&sctx->buffer[j], data, (i = 64-j));
		sha1_transform(sctx->state, sctx->buffer);
		for ( ; i + 63 < len; i += 64)
			sha1_transform(sctx->state, &data[i]);
		j = 0;
	} else
		i = 0;
	memcpy(&sctx->buffer[j], &data[i], len - i);
}


/* Add padding and return the message digest. */
static void generic_sha1_final(void *ctx, uint8_t *out)
{
	struct sha1_ctx *sctx = ctx;
	uint32_t i, j, idx, padlen;
	uint64_t t;
	uint8_t bits[8] = { 0, };
	static const uint8_t padding[64] = { 0x80, };

	t = sctx->count;
	bits[7] = 0xff & t; t >>= 8;
	bits[6] = 0xff & t; t >>= 8;
	bits[5] = 0xff & t; t >>= 8;
	bits[4] = 0xff & t; t >>= 8;
	bits[3] = 0xff & t; t >>= 8;
	bits[2] = 0xff & t; t >>= 8;
	bits[1] = 0xff & t; t >>= 8;
	bits[0] = 0xff & t;

	/* Pad out to 56 mod 64 */
	idx = (sctx->count >> 3) & 0x3f;
	padlen = (idx < 56) ? (56 - idx) : ((64+56) - idx);
	generic_sha1_update(sctx, padding, padlen);

	/* Append length */
	generic_sha1_update(sctx, bits, sizeof bits);

	/* Store state in digest */
	for (i = j = 0; i < 5; i++, j += 4) {
		uint32_t t2 = sctx->state[i];
		out[j+3] = t2 & 0xff; t2 >>= 8;
		out[j+2] = t2 & 0xff; t2 >>= 8;
		out[j+1] = t2 & 0xff; t2 >>= 8;
		out[j] = t2 & 0xff;
	}

	/* Wipe context */
	memset(sctx, 0, sizeof *sctx);
}

#ifdef __x86_64__

static asmlinkage void
(*sha1_transform_asm)(uint32_t *, const uint8_t *, unsigned int);

asmlinkage void sha1_transform_ssse3(uint32_t *, const uint8_t *, unsigned int);
asmlinkage void sha1_transform_avx(uint32_t *, const uint8_t *, unsigned int);

static void do_ssse3_sha1_update(struct sha1_ctx *ctx, const uint8_t *data,
				unsigned int len, unsigned int partial)
{
	struct sha1_ctx *sctx = ctx;
	unsigned int done = 0;

	sctx->count += len;

	if (partial) {
		done = SHA1_BLOCK_SIZE - partial;
		memcpy(sctx->buffer + partial, data, done);
		sha1_transform_asm(sctx->state, sctx->buffer, 1);
	}

	if (len - done >= SHA1_BLOCK_SIZE) {
		const unsigned int rounds = (len - done) / SHA1_BLOCK_SIZE;

		sha1_transform_asm(sctx->state, data + done, rounds);
		done += rounds * SHA1_BLOCK_SIZE;
	}

	memcpy(sctx->buffer, data + done, len - done);

	return;
}

static void ssse3_sha1_update(void *ctx, const uint8_t *data,
			     unsigned int len)
{
	struct sha1_ctx *sctx = ctx;
	unsigned int partial = sctx->count % SHA1_BLOCK_SIZE;

	/* Handle the fast case right here */
	if (partial + len < SHA1_BLOCK_SIZE) {
		sctx->count += len;
		memcpy(sctx->buffer + partial, data, len);

		return;
	}

	do_ssse3_sha1_update(ctx, data, len, partial);
}

/* Add padding and return the message digest. */
static void ssse3_sha1_final(void *ctx, uint8_t *out)
{
	struct sha1_ctx *sctx = ctx;
	unsigned int i, j, idx, padlen;
	uint64_t t;
	uint8_t bits[8] = { 0, };
	static const uint8_t padding[SHA1_BLOCK_SIZE] = { 0x80, };

	t = sctx->count << 3;
	bits[7] = 0xff & t; t >>= 8;
	bits[6] = 0xff & t; t >>= 8;
	bits[5] = 0xff & t; t >>= 8;
	bits[4] = 0xff & t; t >>= 8;
	bits[3] = 0xff & t; t >>= 8;
	bits[2] = 0xff & t; t >>= 8;
	bits[1] = 0xff & t; t >>= 8;
	bits[0] = 0xff & t;

	/* Pad out to 56 mod 64 and append length */
	idx = sctx->count % SHA1_BLOCK_SIZE;
	padlen = (idx < 56) ? (56 - idx) : ((SHA1_BLOCK_SIZE+56) - idx);
	/* We need to fill a whole block for do_ssse3_sha1_update() */
	if (padlen <= 56) {
		sctx->count += padlen;
		memcpy(sctx->buffer + idx, padding, padlen);
	} else {
		do_ssse3_sha1_update(ctx, padding, padlen, idx);
	}
	do_ssse3_sha1_update(ctx, (const uint8_t *)&bits, sizeof(bits), 56);

	/* Store state in digest */
	for (i = j = 0; i < 5; i++, j += 4) {
		uint32_t t2 = sctx->state[i];
		out[j+3] = t2 & 0xff; t2 >>= 8;
		out[j+2] = t2 & 0xff; t2 >>= 8;
		out[j+1] = t2 & 0xff; t2 >>= 8;
		out[j] = t2 & 0xff;
	}

	/* Wipe context */
	memset(sctx, 0, sizeof(*sctx));

	return;
}

static bool avx_usable(void)
{
	uint64_t xcr0;

	if (!cpu_has_avx || !cpu_has_osxsave)
		return false;

	xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);
	if ((xcr0 & (XSTATE_SSE | XSTATE_YMM)) != (XSTATE_SSE | XSTATE_YMM))
		return false;

	return true;
}

#endif

const char *sha1_to_hex(const unsigned char *sha1)
{
	static __thread char buffer[50];
	static const char hex[] = "0123456789abcdef";
	char *buf = buffer;
	int i;

	for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
		unsigned int val = *sha1++;
		*buf++ = hex[val >> 4];
		*buf++ = hex[val & 0xf];
	}
	return buffer;
}

/*
 * Calculate a sha1 message digest based on the content of 'buf'
 *
 * We can uniquely generate the original buffer from
 * - the trimmed buffer
 * - the orignal buffer length
 * - the trimmed buffer length
 * - the trimmed buffer offset
 *
 * This calculates a unique sha1 digest faster than the naive calculation when
 * the content of 'buf' is sparse.  The result will be set in 'sha1'.
 */
void sha1_from_buffer(const void *buf, size_t size, unsigned char *sha1)
{
	struct sha1_ctx c;
	uint64_t offset = 0;
	uint32_t length = size;

	sha1_init(&c);
	sha1_update(&c, (uint8_t *)&length, sizeof(length));

	find_zero_blocks(buf, &offset, &length);

	sha1_update(&c, (uint8_t *)&length, sizeof(length));
	sha1_update(&c, (uint8_t *)&offset, sizeof(offset));
	sha1_update(&c, buf, length);
	sha1_final(&c, sha1);
}

static void __attribute__((constructor)) __sha1_init(void)
{
	sha1_init = generic_sha1_init;
	sha1_update = generic_sha1_update;
	sha1_final = generic_sha1_final;

#ifdef __x86_64__
	if (cpu_has_ssse3)
		sha1_transform_asm = sha1_transform_ssse3;
	else
		return;

	if (avx_usable())
		sha1_transform_asm = sha1_transform_avx;

	sha1_update = ssse3_sha1_update;
	sha1_final = ssse3_sha1_final;
#endif
}
