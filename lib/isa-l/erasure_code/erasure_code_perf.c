/**********************************************************************
  Copyright(c) 2011-2013 Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions 
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>  // for memset, memcmp
#include "erasure_code.h"
#include "test.h"

//#define CACHED_TEST
#ifdef CACHED_TEST
// Cached test, loop many times over small dataset
# define TEST_SOURCES 250
# define TEST_LEN(m)  ((256*1024 / m) & ~(64-1))
# define TEST_LOOPS(m)   (4000*m)
# define TEST_TYPE_STR "_warm"
#else
# ifndef TEST_CUSTOM
// Uncached test.  Pull from large mem base.
#  define TEST_SOURCES 250
#  define GT_L3_CACHE  32*1024*1024  /* some number > last level cache */
#  define TEST_LEN(m)  ((GT_L3_CACHE / m) & ~(64-1))
#  define TEST_LOOPS(m)   (10*m)
#  define TEST_TYPE_STR "_cold"
# else
#  define TEST_TYPE_STR "_cus"
#  ifndef TEST_LOOPS
#    define TEST_LOOPS(m) 1000
#  endif
# endif
#endif

#define MMAX TEST_SOURCES
#define KMAX TEST_SOURCES

typedef unsigned char u8;


void dump(unsigned char* buf, int len)
{
	int i;
	for (i=0; i<len; ) {
		printf(" %2x", 0xff & buf[i++]);
		if (i % 32 == 0)
			printf("\n");
	}
	printf("\n");
}

void dump_matrix(unsigned char **s, int k, int m)
{
	int i, j;
	for (i=0; i<k; i++) {
		for (j=0; j<m; j++){
			printf(" %2x", s[i][j]);
		}
		printf("\n");
	}
	printf("\n");
}

void dump_u8xu8(unsigned char *s, int k, int m)
{
	int i, j;
	for (i=0; i<k; i++) {
		for (j=0; j<m; j++){
			printf(" %2x", 0xff & s[j+(i*m)]);
		}
		printf("\n");
	}
	printf("\n");
}


int main(int argc, char *argv[])
{
	int i, j, rtest, m, k, nerrs, r, err;
	void *buf;
	u8 *temp_buffs[TEST_SOURCES], *buffs[TEST_SOURCES];
	u8 a[MMAX*KMAX], b[MMAX*KMAX], c[MMAX*KMAX], d[MMAX*KMAX];
	u8 g_tbls[KMAX*TEST_SOURCES*32], src_in_err[TEST_SOURCES];
	u8 src_err_list[TEST_SOURCES], *recov[TEST_SOURCES];
	struct perf start, stop;
	m = 32;
	k = 28;
	printf("erasure_code_perf: %dx%d ",
			m, (TEST_LEN(m)));


	// Allocate the arrays
	for(i=0; i<TEST_SOURCES; i++){
		if (posix_memalign(&buf, 64, TEST_LEN(m))) {
			printf("alloc error: Fail");
			return -1;
		}
		buffs[i] = buf;
	}

	for (i=0; i<TEST_SOURCES; i++){
		if (posix_memalign(&buf, 64, TEST_LEN(m))) {
			printf("alloc error: Fail");
			return -1;
		}
		temp_buffs[i] = buf;
	}

	// Test erasure code by encode and recovery

	// Pick a first test
	if (m > MMAX || k > KMAX)
		return -1;

	// Make random data
	for(i=0; i<k; i++)
		for(j=0; j<(TEST_LEN(m)); j++)
			buffs[i][j] = rand();


	memset(src_in_err, 0, TEST_SOURCES);

	srand(1);
	for (i=0, nerrs=0; i<k && nerrs<m-k; i++){
		err = 1 & rand();
		src_in_err[i] = err;
		if (err)
			src_err_list[nerrs++] = i;
	}
	if (nerrs == 0){  // should have at least one error
		while ((err = (rand() % KMAX)) >= k) ;
		src_err_list[nerrs++] = err;
		src_in_err[err] = 1;
	}
	printf("Test erase list = ");
	for (i=0; i<nerrs; i++)
		printf(" %d", src_err_list[i]);
	printf("\n");

	perf_start(&start);

	for (rtest = 0; rtest < TEST_LOOPS(m); rtest++){
		gf_gen_rs_matrix(a, m, k);

		// Make parity vects
		ec_init_tables(k, m-k, &a[k*k], g_tbls);
		ec_encode_data((TEST_LEN(m)),
				k, m-k, g_tbls, buffs, &buffs[k]);
	}

	perf_stop(&stop);
	printf("erasure_code_encode" TEST_TYPE_STR ": ");
	perf_print(stop,start,
			(long long)(TEST_LEN(m))*(m)*rtest);

	perf_start(&start);

	for (rtest = 0; rtest < TEST_LOOPS(m); rtest++){
		// Construct b by removing error rows
		for(i=0, r=0; i<k; i++, r++){
			while (src_in_err[r]) 
				r++;
			for(j=0; j<k; j++)
				b[k*i+j] = a[k*r+j];
		}

		if (gf_invert_matrix(b, d, k) < 0){
			printf("BAD MATRIX\n");
			return -1;
		}

		for(i=0, r=0; i<k; i++, r++){
			while (src_in_err[r]) 
				r++;
			recov[i] = buffs[r];
		}

		for(i=0; i<nerrs; i++){
			for(j=0; j<k; j++){
				c[k*i+j]=d[k*src_err_list[i]+j];
			}
		}

		// Recover data
		ec_init_tables(k, nerrs, c, g_tbls);
		ec_encode_data((TEST_LEN(m)),
				k, nerrs, g_tbls, recov, &temp_buffs[k]);

	}
	
	perf_stop(&stop);
	for(i=0; i<nerrs; i++){
		if (0 != memcmp(temp_buffs[k+i], buffs[src_err_list[i]],
				(TEST_LEN(m)))){
			printf("Fail error recovery (%d, %d, %d) - ", 
				m, k, nerrs);
			printf(" - erase list = ");
			for (j=0; j<nerrs; j++)
				printf(" %d", src_err_list[j]);
			printf("\na:\n"); 
			dump_u8xu8((u8*)a, m, k);
			printf("inv b:\n");
			dump_u8xu8((u8*)d, k, k);
			printf("orig data:\n"); 
			dump_matrix(buffs, m, 25);
			printf("orig   :");
			dump(buffs[src_err_list[i]],25);
			printf("recov %d:",src_err_list[i]);
			dump(temp_buffs[k+i], 25);
			return -1;
		}
	}

	printf("erasure_code_decode" TEST_TYPE_STR ": ");
	perf_print(stop,start,
			(long long)(TEST_LEN(m))*(k+nerrs)*rtest);

	printf("done all: Pass\n");
	return 0;
}

