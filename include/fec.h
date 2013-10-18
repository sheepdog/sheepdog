/*
 * zfec -- fast forward error correction library
 *
 * Copyright (C) 2007-2008 Allmyds, Inc.
 * Author: Zooko Wilcox-O'Hearn
 *
 * This file is part of zfec.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Much of this work is derived from the "fec" software by Luigi Rizzo, et
 * al., the copyright notice and licence terms of which are included below
 * for reference.
 *
 * fec.h -- forward error correction based on Vandermonde matrices
 * 980614
 * (C) 1997-98 Luigi Rizzo (luigi@iet.unipi.it)
 *
 * Portions derived from code by Phil Karn (karn@ka9q.ampr.org),
 * Robert Morelos-Zaragoza (robert@spectra.eng.hawaii.edu) and Hari
 * Thirumoorthy (harit@spectra.eng.hawaii.edu), Aug 1995
 *
 * Modifications by Dan Rubenstein (see Modifications.txt for
 * their description.
 * Modifications (C) 1998 Dan Rubenstein (drubenst@cs.umass.edu)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:

 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#include <stddef.h>
#include <stdint.h>

struct fec {
	unsigned long magic;
	unsigned short d, dp;                     /* parameters of the code */
	uint8_t *enc_matrix;
};

void init_fec(void);
/*
 * param d the number of blocks required to reconstruct
 * param dp the total number of blocks created
 */
struct fec *fec_new(unsigned short d, unsigned short dp);
void fec_free(struct fec *p);

/*
 * @param inpkts the "primary blocks" i.e. the chunks of the input data
 * @param fecs buffers into which the secondary blocks will be written
 * @param block_nums the numbers of the desired check blocks (the id >= k) which
 * fec_encode() will produce and store into the buffers of the fecs parameter
 * @param num_block_nums the length of the block_nums array
 * @param sz size of a packet in bytes
 */
void fec_encode(const struct fec *code,
		const uint8_t *const *const src,
		uint8_t *const *const fecs,
		const int *const block_nums,
		size_t num_block_nums, size_t sz);

/*
 * @param inpkts an array of packets (size k); If a primary block, i, is present
 * then it must be at index i. Secondary blocks can appear anywhere.
 * @param outpkts an array of buffers into which the reconstructed output
 * packets will be written (only packets which are not present in the inpkts
 * input will be reconstructed and written to outpkts)
 * @param index an array of the blocknums of the packets in inpkts
 * @param sz size of a packet in bytes
 */
void fec_decode(const struct fec *code,
		const uint8_t *const *const inpkts,
		uint8_t *const *const outpkts,
		const int *const index, size_t sz);

#define SD_EC_D	4 /* No. of data strips */
#define SD_EC_P 2 /* No. of parity strips */
#define SD_EC_DP (SD_EC_D + SD_EC_P)

/*
 * SD_EC_D_SIZE <= 1K is the safe value to run VM after some experimentations.
 *
 * Though most OS's file system will operate on 4K block, some softwares like
 * grub will operate on 512 bytes and Linux kernel itself will sometimes
 * operate on 1K blocks. I have tried 4K alignement and centos6 installation
 * failed (grub got screwed) and 1K is probably the biggest value if we want
 * VM to run on erasure coded volume.
 */
#define SD_EC_DATA_STRIPE_SIZE (1024) /* 1K */
#define SD_EC_OBJECT_SIZE (SD_DATA_OBJ_SIZE / SD_EC_D)
#define SD_EC_NR_STRIPE_PER_OBJECT (SD_DATA_OBJ_SIZE / SD_EC_DATA_STRIPE_SIZE)

/*
 * Stripe: data strips + parity strips, spread on all replica
 * DS: data strip
 * PS: parity strip
 * R: Replica
 *
 *  +--------------------stripe ----------------------+
 *  v   data stripe                   parity stripe   v
 * +----+----+----+----+----+-----+----+----+-----+----+
 * | ds | ds | ds | ds | ds | ... | ps | ps | ... | ps |
 * +----+----+----+----+----+-----+----+----+-----+----+
 * | .. | .. | .. | .. | .. | ... | .. | .. | ... | .. |
 * +----+----+----+----+----+ ... +----+----+-----+----+
 *  R1    R2   R3   R4   R5   ...   Rn  Rn+1  Rn+2  Rn+3
 */

/* Return the erasure code context to encode|decode */
static inline struct fec *ec_init(int d, int dp)
{
	return fec_new(d, dp);
}

/*
 * This function decodes the data strips and return the parity strips
 *
 * @ds: data strips to generate parity strips
 * @ps: parity strips to return
 */
static inline void ec_encode(struct fec *ctx, const uint8_t *ds[],
			     uint8_t *ps[])
{
	int p = ctx->dp - ctx->d;
	int pidx[p];

	for (int i = 0; i < p; i++)
		pidx[i] = ctx->d + i;

	fec_encode(ctx, ds, ps, pidx, p, SD_EC_DATA_STRIPE_SIZE / ctx->d);
}

/*
 * This function takes input strips and return the lost strip
 *
 * @input: strips (either ds or ps) that are used to generate lost strips
 * @inidx: indexes of each input strip in the whole stripe, must be in numeric
 *         order such as { 0, 2, 4, 5 }
 * @output: the lost ds or ps to return
 * @idx: index of output which is lost
 */
void ec_decode(struct fec *ctx, const uint8_t *input[],
	       const int inidx[],
	       uint8_t output[], int idx);

/* Destroy the erasure code context */
static inline void ec_destroy(struct fec *ctx)
{
	fec_free(ctx);
}
