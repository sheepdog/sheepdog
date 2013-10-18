/*
 * zfec -- fast forward error correction
 *
 * Copyright (C) 2007-2010 Zooko Wilcox-O'Hearn
 * Author: Zooko Wilcox-O'Hearn
 *
 * This file is part of zfec.
 *
 * Imported by Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This work is derived from the "fec" software by Luigi Rizzo, et al., the
 * copyright notice and licence terms of which are included below for reference.
 * fec.c -- forward error correction based on Vandermonde matrices 980624 (C)
 * 1997-98 Luigi Rizzo (luigi@iet.unipi.it)
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
 *
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fec.h"
#include "util.h"

/*
 * Primitive polynomials - see Lin & Costello, Appendix A,
 * and  Lee & Messerschmitt, p. 453.
 */
static const char *const Pp = "101110001";

/*
 * To speed up computations, we have tables for logarithm, exponent and
 * inverse of a number.  We use a table for multiplication as well (it takes
 * 64K, no big deal even on a PDA, especially because it can be
 * pre-initialized an put into a ROM!), otherwhise we use a table of
 * logarithms. In any case the macro gf_mul(x,y) takes care of
 * multiplications.
 */

static uint8_t gf_exp[510];  /* idx->poly form conversion table    */
static int gf_log[256]; /* Poly->idx form conversion table    */
static uint8_t inverse[256]; /* inverse of field elem.               */
/* inv[\alpha**i]=\alpha**(GF_SIZE-i-1) */

/*
 * modnn(x) computes x % GF_SIZE, where GF_SIZE is 2**GF_BITS - 1,
 * without a slow divide.
 */
static uint8_t modnn(int x)
{
	while (x >= 255) {
		x -= 255;
		x = (x >> 8) + (x & 255);
	}
	return x;
}

/*
 * gf_mul(x,y) multiplies two numbers.  It is much faster to use a
 * multiplication table.
 *
 * USE_GF_MULC, GF_MULC0(c) and GF_ADDMULC(x) can be used when multiplying
 * many numbers by the same constant. In this case the first call sets the
 * constant, and others perform the multiplications.  A value related to the
 * multiplication is held in a local variable declared with USE_GF_MULC . See
 * usage in _addmul1().
 */
static uint8_t gf_mul_table[256][256];

#define gf_mul(x, y) gf_mul_table[x][y]

#define USE_GF_MULC register uint8_t *__gf_mulc_

#define GF_MULC0(c) __gf_mulc_ = gf_mul_table[c]
#define GF_ADDMULC(dst, x) dst ^= __gf_mulc_[x]

/*
 * Generate GF(2**m) from the irreducible polynomial p(X) in p[0]..p[m]
 * Lookup tables:
 *     idx->polynomial form		gf_exp[] contains j= \alpha^i;
 *     polynomial form -> idx form	gf_log[ j = \alpha^i ] = i
 * \alpha=x is the primitive element of GF(2^m)
 *
 * For efficiency, gf_exp[] has size 2*GF_SIZE, so that a simple
 * multiplication of two numbers can be resolved without calling modnn
 */
static void _init_mul_table(void)
{
	int i, j;
	for (i = 0; i < 256; i++)
		for (j = 0; j < 256; j++)
			gf_mul_table[i][j] = gf_exp[modnn(gf_log[i] +
							  gf_log[j])];

	for (j = 0; j < 256; j++)
		gf_mul_table[0][j] = gf_mul_table[j][0] = 0;
}

#define NEW_GF_MATRIX(rows, cols) \
	(uint8_t *)xmalloc(rows * cols)

/* initialize the data structures used for computations in GF. */
static void generate_gf(void)
{
	int i;
	uint8_t mask;

	mask = 1;                     /* x ** 0 = 1 */
	gf_exp[8] = 0;          /* will be updated at the end of the 1st loop */
	/*
	 * first, generate the (polynomial representation of) powers of \alpha,
	 * which are stored in gf_exp[i] = \alpha ** i .
	 * At the same time build gf_log[gf_exp[i]] = i .
	 * The first 8 powers are simply bits shifted to the left.
	 */
	for (i = 0; i < 8; i++, mask <<= 1) {
		gf_exp[i] = mask;
		gf_log[gf_exp[i]] = i;
		/*
		 * If Pp[i] == 1 then \alpha ** i occurs in poly-repr
		 * gf_exp[8] = \alpha ** 8
		 */
		if (Pp[i] == '1')
			gf_exp[8] ^= mask;
	}
	/*
	 * now gf_exp[8] = \alpha ** 8 is complete, so can also
	 * compute its inverse.
	 */
	gf_log[gf_exp[8]] = 8;
	/*
	 * Poly-repr of \alpha ** (i+1) is given by poly-repr of
	 * \alpha ** i shifted left one-bit and accounting for any
	 * \alpha ** 8 term that may occur when poly-repr of
	 * \alpha ** i is shifted.
	 */
	mask = 1 << 7;
	for (i = 9; i < 255; i++) {
		if (gf_exp[i - 1] >= mask)
			gf_exp[i] = gf_exp[8] ^ ((gf_exp[i - 1] ^ mask) << 1);
		else
			gf_exp[i] = gf_exp[i - 1] << 1;
		gf_log[gf_exp[i]] = i;
	}
	/* log(0) is not defined, so use a special value */
	gf_log[0] = 255;
	/* set the extended gf_exp values for fast multiply */
	for (i = 0; i < 255; i++)
		gf_exp[i + 255] = gf_exp[i];

	/*
	 * again special cases. 0 has no inverse. This used to
	 * be initialized to 255, but it should make no difference
	 * since noone is supposed to read from here.
	 */
	inverse[0] = 0;
	inverse[1] = 1;
	for (i = 2; i <= 255; i++)
		inverse[i] = gf_exp[255 - gf_log[i]];
}

/* Various linear algebra operations that i use often. */

/*
 * addmul() computes dst[] = dst[] + c * src[]
 * This is used often, so better optimize it! Currently the loop is
 * unrolled 16 times, a good value for 486 and pentium-class machines.
 * The case c=0 is also optimized, whereas c=1 is not. These
 * calls are unfrequent in my typical apps so I did not bother.
 */
#define addmul(dst, src, c, sz)                 \
	if (c != 0)				\
		_addmul1(dst, src, c, sz)

#define UNROLL 16               /* 1, 4, 8, 16 */
static void _addmul1(register uint8_t *dst,
		     const register uint8_t *src,
		     uint8_t c, size_t sz)
{
	USE_GF_MULC;
	const uint8_t *lim = &dst[sz - UNROLL + 1];

	GF_MULC0(c);

#if (UNROLL > 1) /* unrolling by 8/16 is quite effective on the pentium */
	for (; dst < lim; dst += UNROLL, src += UNROLL) {
		GF_ADDMULC(dst[0], src[0]);
		GF_ADDMULC(dst[1], src[1]);
		GF_ADDMULC(dst[2], src[2]);
		GF_ADDMULC(dst[3], src[3]);
#if (UNROLL > 4)
		GF_ADDMULC(dst[4], src[4]);
		GF_ADDMULC(dst[5], src[5]);
		GF_ADDMULC(dst[6], src[6]);
		GF_ADDMULC(dst[7], src[7]);
#endif
#if (UNROLL > 8)
		GF_ADDMULC(dst[8], src[8]);
		GF_ADDMULC(dst[9], src[9]);
		GF_ADDMULC(dst[10], src[10]);
		GF_ADDMULC(dst[11], src[11]);
		GF_ADDMULC(dst[12], src[12]);
		GF_ADDMULC(dst[13], src[13]);
		GF_ADDMULC(dst[14], src[14]);
		GF_ADDMULC(dst[15], src[15]);
#endif
	}
#endif
	lim += UNROLL - 1;
	for (; dst < lim; dst++, src++)       /* final components */
		GF_ADDMULC(*dst, *src);
}

/* computes C = AB where A is dp*d, B is d*m, C is dp*m */
static void _matmul(uint8_t *a, uint8_t *b, uint8_t *c, unsigned dp, unsigned d,
		    unsigned m)
{
	unsigned row, col, i;

	for (row = 0; row < dp; row++) {
		for (col = 0; col < m; col++) {
			uint8_t *pa = &a[row * d];
			uint8_t *pb = &b[col];
			uint8_t acc = 0;
			for (i = 0; i < d; i++, pa++, pb += m)
				acc ^= gf_mul(*pa, *pb);
			c[row * m + col] = acc;
		}
	}
}

/*
 * _invert_mat() takes a matrix and produces its inverse
 * d is the size of the matrix.
 * (Gauss-Jordan, adapted from Numerical Recipes in C)
 * Return non-zero if singular.
 */
static void _invert_mat(uint8_t *src, unsigned d)
{
	uint8_t c, *p;
	unsigned irow = 0;
	unsigned icol = 0;
	unsigned row, col, i, ix;

	unsigned *indxc = (unsigned *)xmalloc(d * sizeof(unsigned));
	unsigned *indxr = (unsigned *)xmalloc(d * sizeof(unsigned));
	unsigned *ipiv = (unsigned *)xmalloc(d * sizeof(unsigned));
	uint8_t *id_row = NEW_GF_MATRIX(1, d);

	memset(id_row, '\0', d * sizeof(uint8_t));
	/* ipiv marks elements already used as pivots. */
	for (i = 0; i < d; i++)
		ipiv[i] = 0;

	for (col = 0; col < d; col++) {
		uint8_t *pivot_row;
		/*
		 * Zeroing column 'col', look for a non-zero element.
		 * First try on the diagonal, if it fails, look elsewhere.
		 */
		if (ipiv[col] != 1 && src[col * d + col] != 0) {
			irow = col;
			icol = col;
			goto found_piv;
		}
		for (row = 0; row < d; row++) {
			if (ipiv[row] != 1) {
				for (ix = 0; ix < d; ix++) {
					if (ipiv[ix] == 0) {
						if (src[row * d + ix] != 0) {
							irow = row;
							icol = ix;
							goto found_piv;
						}
					} else
						assert(ipiv[ix] <= 1);
				}
			}
		}
found_piv:
		++(ipiv[icol]);
		/*
		 * swap rows irow and icol, so afterwards the diagonal
		 * element will be correct. Rarely done, not worth
		 * optimizing.
		 */
		if (irow != icol)
			for (ix = 0; ix < d; ix++)
				SWAP(src[irow*d + ix], src[icol*d + ix]);
		indxr[col] = irow;
		indxc[col] = icol;
		pivot_row = &src[icol * d];
		c = pivot_row[icol];
		assert(c != 0);
		if (c != 1) {   /* otherwhise this is a NOP */
			/*
			 * this is done often , but optimizing is not so
			 * fruitful, at least in the obvious ways (unrolling)
			 */
			c = inverse[c];
			pivot_row[icol] = 1;
			for (ix = 0; ix < d; ix++)
				pivot_row[ix] = gf_mul(c, pivot_row[ix]);
		}
		/*
		 * from all rows, remove multiples of the selected row
		 * to zero the relevant entry (in fact, the entry is not zero
		 * because we know it must be zero).
		 * (Here, if we know that the pivot_row is the identity,
		 * we can optimize the addmul).
		 */
		id_row[icol] = 1;
		if (memcmp(pivot_row, id_row, d * sizeof(uint8_t)) != 0) {
			for (p = src, ix = 0; ix < d; ix++, p += d) {
				if (ix != icol) {
					c = p[icol];
					p[icol] = 0;
					addmul(p, pivot_row, c, d);
				}
			}
		}
		id_row[icol] = 0;
	}                           /* done all columns */
	for (col = d; col > 0; col--)
		if (indxr[col-1] != indxc[col-1])
			for (row = 0; row < d; row++)
				SWAP(src[row * d + indxr[col-1]],
				     src[row * d + indxc[col-1]]);
}

/*
 * fast code for inverting a vandermonde matrix.
 *
 * NOTE: It assumes that the matrix is not singular and _IS_ a vandermonde
 * matrix. Only uses the second column of the matrix, containing the p_i's.
 *
 * Algorithm borrowed from "Numerical recipes in C" -- sec.2.8, but largely
 * revised for my purposes.
 * p = coefficients of the matrix (p_i)
 * q = values of the polynomial (known)
 */
static void _invert_vdm(uint8_t *src, unsigned d)
{
	unsigned i, j, row, col;
	uint8_t *b, *c, *p;
	uint8_t t, xx;

	if (d == 1)     /* degenerate case, matrix must be p^0 = 1 */
		return;
	/*
	 * c holds the coefficient of P(x) = Prod (x - p_i), i=0..d-1
	 * b holds the coefficient for the matrix inversion
	 */
	c = NEW_GF_MATRIX(1, d);
	b = NEW_GF_MATRIX(1, d);
	p = NEW_GF_MATRIX(1, d);

	for (j = 1, i = 0; i < d; i++, j += d) {
		c[i] = 0;
		p[i] = src[j];            /* p[i] */
	}
	/*
	 * construct coeffs. recursively. We know c[d] = 1 (implicit)
	 * and start P_0 = x - p_0, then at each stage multiply by
	 * x - p_i generating P_i = x P_{i-1} - p_i P_{i-1}
	 * After d steps we are done.
	 */
	c[d - 1] = p[0];              /* really -p(0), but x = -x in GF(2^m) */
	for (i = 1; i < d; i++) {
		uint8_t p_i = p[i];            /* see above comment */
		for (j = d - 1 - (i - 1); j < d - 1; j++)
			c[j] ^= gf_mul(p_i, c[j + 1]);
		c[d - 1] ^= p_i;
	}

	for (row = 0; row < d; row++) {
		/* synthetic division etc. */
		xx = p[row];
		t = 1;
		b[d - 1] = 1;             /* this is in fact c[d] */
		for (i = d - 1; i > 0; i--) {
			b[i-1] = c[i] ^ gf_mul(xx, b[i]);
			t = gf_mul(xx, t) ^ b[i-1];
		}
		for (col = 0; col < d; col++)
			src[col * d + row] = gf_mul(inverse[t], b[col]);
	}
	free(c);
	free(b);
	free(p);
	return;
}

void init_fec(void)
{
	generate_gf();
	_init_mul_table();
}

/*
 * This section contains the proper FEC encoding/decoding routines.
 * The encoding matrix is computed starting with a Vandermonde matrix,
 * and then transforming it into a systematic matrix.
 */

#define FEC_MAGIC	0xFECC0DEC

void fec_free(struct fec *p)
{
	assert(p != NULL && p->magic == (((FEC_MAGIC ^ p->d) ^ p->dp) ^
					 (unsigned long) (p->enc_matrix)));
	free(p->enc_matrix);
	free(p);
}

struct fec *fec_new(unsigned short d, unsigned short dp)
{
	unsigned row, col;
	uint8_t *p, *tmp_m;

	struct fec *retval;

	retval = (struct fec *)xmalloc(sizeof(struct fec));
	retval->d = d;
	retval->dp = dp;
	retval->enc_matrix = NEW_GF_MATRIX(dp, d);
	retval->magic = ((FEC_MAGIC^d)^dp)^(unsigned long)(retval->enc_matrix);
	tmp_m = NEW_GF_MATRIX(dp, d);
	/*
	 * fill the matrix with powers of field elements, starting from 0.
	 * The first row is special, cannot be computed with exp. table.
	 */
	tmp_m[0] = 1;
	for (col = 1; col < d; col++)
		tmp_m[col] = 0;
	for (p = tmp_m + d, row = 0; row < dp - 1; row++, p += d)
		for (col = 0; col < d; col++)
			p[col] = gf_exp[modnn(row * col)];

	/*
	 * quick code to build systematic matrix: invert the top
	 * d*d vandermonde matrix, multiply right the bottom dp-d rows
	 * by the inverse, and construct the identity matrix at the top.
	 */
	_invert_vdm(tmp_m, d);        /* much faster than _invert_mat */
	_matmul(tmp_m + d * d, tmp_m, retval->enc_matrix + d * d, dp - d, d, d);
	/* the upper matrix is I so do not bother with a slow multiply */
	memset(retval->enc_matrix, '\0', d * d * sizeof(uint8_t));
	for (p = retval->enc_matrix, col = 0; col < d; col++, p += d + 1)
		*p = 1;
	free(tmp_m);

	return retval;
}

/*
 * To make sure that we stay within cache in the inner loops of fec_encode().
 * (It would probably help to also do this for fec_decode().
 */
#ifndef STRIDE
#define STRIDE 8192
#endif

void fec_encode(const struct fec *code,
		const uint8_t *const *const src,
		uint8_t *const *const fecs,
		const int *const block_nums,
		size_t num_block_nums, size_t sz)
{
	unsigned char i, j;
	size_t d;
	unsigned fecnum;
	const uint8_t *p;

	for (d = 0; d < sz; d += STRIDE) {
		size_t stride = ((sz-d) < STRIDE) ? (sz-d) : STRIDE;
		for (i = 0; i < num_block_nums; i++) {
			fecnum = block_nums[i];
			assert(fecnum >= code->d);
			memset(fecs[i]+d, 0, stride);
			p = &(code->enc_matrix[fecnum * code->d]);
			for (j = 0; j < code->d; j++)
				addmul(fecs[i]+d, src[j]+d, p[j], stride);
		}
	}
}

/*
 * Build decode matrix into some memory space.
 *
 * @param matrix a space allocated for a d by d matrix
 */
static void
build_decode_matrix_into_space(const struct fec *const code,
			       const int *const idx,
			       const unsigned d, uint8_t *const matrix)
{
	unsigned char i;
	uint8_t *p;
	for (i = 0, p = matrix; i < d; i++, p += d) {
		if (idx[i] < d) {
			memset(p, 0, d);
			p[i] = 1;
		} else {
			memcpy(p, &(code->enc_matrix[idx[i] * code->d]), d);
		}
	}
	_invert_mat(matrix, d);
}

void fec_decode(const struct fec *code,
		const uint8_t *const *const inpkts,
		uint8_t *const *const outpkts,
		const int *const idx, size_t sz)
{
	uint8_t m_dec[code->d * code->d];
	unsigned char outix = 0;
	unsigned char row = 0;
	unsigned char col = 0;

	assert(code->d * code->d < 8 * 1024 * 1024);
	build_decode_matrix_into_space(code, idx, code->d, m_dec);

	for (row = 0; row < code->d; row++) {
		/*
		 * If the block whose number is i is present, then it is
		 * required to be in the i'th element.
		 */
		assert((idx[row] >= code->d) || (idx[row] == row));
		if (idx[row] >= code->d) {
			memset(outpkts[outix], 0, sz);
			for (col = 0; col < code->d; col++)
				addmul(outpkts[outix], inpkts[col],
				       m_dec[row * code->d + col], sz);
			outix++;
		}
	}
}

/*
 * fec_decode need primary(data) strips in the numeric place, e,g, we have
 * indexes passed as { 0, 2, 4, 5 } and 4, 5 are parity strip, we need to pass
 * { 0, 4, 2, 5 } (we choose this form) or { 0, 5, 2, 4} to it.
 *
 * Return out and outidx as fec_decode requested.
 */
static inline void decode_prepare(struct fec *ctx, const uint8_t *dp[],
				  const uint8_t *out[],
				  int outidx[])
{
	int i, p = 0;

	for (i = ctx->d; i < ctx->dp; i++) {
		if (dp[i]) {
			p = i;
			break;
		}
	}

	for (i = 0; i < ctx->d; i++) {
		if (dp[i]) {
			out[i] = dp[i];
			outidx[i] = i;
		} else {
			out[i] = dp[p];
			outidx[i] = p;
			p++;
		}
	}
}

static inline bool data_is_missing(const uint8_t *dp[], int d)
{
	for (int i = 0; i < d; i++)
		if (!dp[i])
			return true;
	return false;
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
void ec_decode(struct fec *ctx, const uint8_t *input[], const int inidx[],
	       uint8_t output[], int idx)
{
	int edp = ctx->dp, ep = ctx->dp - ctx->d, ed = ctx->d;
	const uint8_t *dp[edp];
	const uint8_t *oin[ed];
	int oidx[ed], i;
	int strip_size = SD_EC_DATA_STRIPE_SIZE / ed;
	uint8_t m0[strip_size], m1[strip_size], m2[strip_size], m3[strip_size],
		m4[strip_size], m5[strip_size], m6[strip_size], m7[strip_size],
		p0[strip_size], p1[strip_size], p2[strip_size], p3[strip_size],
		p4[strip_size], p5[strip_size], p6[strip_size], p7[strip_size];
#define SD_EC_MAX_PARITY 8
	uint8_t *missing[SD_EC_MAX_PARITY] = { m0, m1, m2, m3, m4, m5, m6, m7 };
	uint8_t *p[SD_EC_MAX_PARITY] = { p0, p1, p2, p3, p4, p5, p6, p7 };

	for (i = 0; i < edp; i++)
		dp[i] = NULL;
	for (i = 0; i < ed; i++)
		oin[i] = NULL;
	for (i = 0; i < ed; i++)
		oidx[i] = 0;

	for (i = 0; i < ed; i++)
		dp[inidx[i]] = input[i];

	decode_prepare(ctx, dp, oin, oidx);

	/* Fill the data strip if missing */
	if (data_is_missing(dp, ed)) {
		int m = 0;
		fec_decode(ctx, oin, missing, oidx, strip_size);
		for (i = 0; i < ed; i++)
			if (!dp[i])
				dp[i] = missing[m++];
	}

	if (idx < ed)
		goto out;

	/* Fill the parity strip */
	ec_encode(ctx, dp, p);
	for (i = 0; i < ep; i++)
		dp[ed + i] = p[i];
out:
	memcpy(output, dp[idx], strip_size);
}
