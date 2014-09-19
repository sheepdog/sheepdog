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
#include "types.h"

#define TEST_LEN 8192
#define TEST_SIZE (TEST_LEN/2)

#ifndef TEST_SOURCES
# define TEST_SOURCES  127
#endif
#ifndef RANDOMS
# define RANDOMS 50
#endif

#define MMAX TEST_SOURCES
#define KMAX TEST_SOURCES

#define EFENCE_TEST_MIN_SIZE 16

#ifdef EC_ALIGNED_ADDR
// Define power of 2 range to check ptr, len alignment
# define PTR_ALIGN_CHK_B 0
# define LEN_ALIGN_CHK_B 0 // 0 for aligned only
#else
// Define power of 2 range to check ptr, len alignment
# define PTR_ALIGN_CHK_B 32
# define LEN_ALIGN_CHK_B 32 // 0 for aligned only
#endif

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
	int i, j, rtest, err, m, k, nerrs, r;
	void *buf;
	unsigned char *temp_buffs[TEST_SOURCES], *buffs[TEST_SOURCES], *a, *b, *c, *d, *g_tbls;
	unsigned char  src_in_err[TEST_SOURCES], src_err_list[TEST_SOURCES];
	unsigned char *recov[TEST_SOURCES];

	int rows, align, size;
	unsigned char *efence_buffs[TEST_SOURCES];
	unsigned int offset;
	u8 *ubuffs[TEST_SOURCES];
	u8 *temp_ubuffs[TEST_SOURCES];

	printf("erasure_code_base_test: %dx%d ", TEST_SOURCES, TEST_LEN);


	// Allocate the arrays
	for(i=0; i<TEST_SOURCES; i++){
		if (posix_memalign(&buf, 64, TEST_LEN)) {
			printf("alloc error: Fail");
			return -1;
		}
		buffs[i] = buf;
	}

	for(i=0; i<TEST_SOURCES; i++){
		if (posix_memalign(&buf, 64, TEST_LEN)) {
			printf("alloc error: Fail");
			return -1;
		}
		temp_buffs[i] = buf;
	}

	// Test erasure code by encode and recovery

	a = malloc(MMAX*KMAX);
	b = malloc(MMAX*KMAX);
	c = malloc(MMAX*KMAX);
	d = malloc(MMAX*KMAX);
	g_tbls = malloc(KMAX*TEST_SOURCES*32);

	if (a == NULL || b == NULL || c == NULL || d == NULL || g_tbls == NULL) {
		printf("Test failure! Error with malloc\n");
		return -1;
	}

	// Pick a first test
	m = 9;
	k = 5;
	if (m > MMAX || k > KMAX)
		return -1;

	// Make random data
	for(i=0; i<k; i++)
		for(j=0; j<TEST_LEN; j++)
			buffs[i][j] = rand();


	gf_gen_rs_matrix(a, m, k);
	ec_init_tables(k, m-k, &a[k*k], g_tbls);
	ec_encode_data_base(TEST_LEN, k, m-k, g_tbls, buffs, &buffs[k]);

	// Choose random buffers to be in erasure
	memset(src_in_err, 0, TEST_SOURCES);
	for (i=0, nerrs=0; i<k && nerrs<m-k; i++){
		err = 1 & rand();
		src_in_err[i] = err;
		if (err)
			src_err_list[nerrs++] = i;
	}


	// Construct matrix b by removing error rows
	for(i=0, r=0; i<k; i++, r++){
		while (src_in_err[r]) 
			r++; 
		for(j=0; j<k; j++)
			b[k*i+j] = a[k*r+j];
	}


	// Generate decode matrix d as matrix inverse of b
	if (gf_invert_matrix(b, d, k) < 0){
		printf("BAD MATRIX\n");
		return -1;
	}
	
	// Pack recovery array as list of valid sources
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
	ec_encode_data(TEST_LEN, k, nerrs, g_tbls, recov, &temp_buffs[k]);

	for(i=0; i<nerrs; i++){

		if (0 != memcmp(temp_buffs[k+i], buffs[src_err_list[i]], TEST_LEN)){
			printf("Fail error recovery (%d, %d, %d)\n", m, k, nerrs);
			printf("recov %d:",src_err_list[i]); 
			dump(temp_buffs[k+i], 25);
			printf("orig   :");     
			dump(buffs[src_err_list[i]],25);
			return -1;
		}
	}


	// Do more random tests

	for (rtest = 0; rtest < RANDOMS; rtest++){
		while ((m = (rand() % MMAX)) < 2);
		while ((k = (rand() % KMAX)) >= m || k < 1);

		if (m>MMAX || k>KMAX) 
			continue;


		// Make random data
		for(i=0; i<k; i++)
			for(j=0; j<TEST_LEN; j++)
				buffs[i][j] = rand();


		gf_gen_rs_matrix(a, m, k);

		// Make parity vects
		ec_init_tables(k, m-k, &a[k*k], g_tbls);
		ec_encode_data_base(TEST_LEN, k, m-k, g_tbls, buffs, &buffs[k]);



		// Random errors
		memset(src_in_err, 0, TEST_SOURCES);
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
		ec_encode_data(TEST_LEN, k, nerrs, g_tbls, recov, &temp_buffs[k]);

		for(i=0; i<nerrs; i++){

			if (0 != memcmp(temp_buffs[k+i], buffs[src_err_list[i]], TEST_LEN)){
				printf("Fail error recovery (%d, %d, %d) - ", m, k, nerrs);
				printf(" - erase list = ");
				for (i=0; i<nerrs; i++)
					printf(" %d", src_err_list[i]);
				printf("\na:\n"); 
				dump_u8xu8((unsigned char*)a, m, k);
				printf("inv b:\n");   
				dump_u8xu8((unsigned char*)d, k, k);
				printf("orig data:\n"); 
				dump_matrix(buffs, m, 25);
				printf("orig   :");     
				dump(buffs[src_err_list[i]],25);
				printf("recov %d:",src_err_list[i]); 
				dump(temp_buffs[k+i], 25);
				return -1;
			}
		}

		putchar('.');

	}

	// Run tests at end of buffer for Electric Fence
	k = 16;
	align = (LEN_ALIGN_CHK_B != 0) ? 1 : 16;
	if (k > KMAX)
		return -1;

	for(rows=1; rows<=16; rows++){
		m = k+rows;
		if (m > MMAX)
			return -1;

		// Make random data
		for(i=0; i<k; i++)
			for(j=0; j<TEST_LEN; j++)
				buffs[i][j] = rand();


		for(size=EFENCE_TEST_MIN_SIZE; size<=TEST_SIZE; size+=align){
			for(i=0; i<m; i++){ // Line up TEST_SIZE from end
				efence_buffs[i] = buffs[i] + TEST_LEN - size;
			}

			gf_gen_rs_matrix(a, m, k);
			ec_init_tables(k, m-k, &a[k*k], g_tbls);
			ec_encode_data_base(size, k, m-k, g_tbls, efence_buffs, &efence_buffs[k]);

			// Random errors
			memset(src_in_err, 0, TEST_SOURCES);
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

			// Construct b by removing error rows
			for(i=0, r=0; i<k; i++, r++){
				while (src_in_err[r])
					r++;
				for(j=0; j<k; j++)
					b[k*i+j] = a[k*r+j];
			}

			// Generate decode matrix d as matrix inverse of b
			if (gf_invert_matrix(b, d, k) < 0){
				printf("BAD MATRIX\n");
				return -1;
			}

			// Pack recovery array as list of valid sources
			for(i=0, r=0; i<k; i++, r++){
				while (src_in_err[r])
					r++;
				recov[i] = efence_buffs[r];
			}
			for(i=0; i<nerrs; i++){
				for(j=0; j<k; j++){
					c[k*i+j]=d[k*src_err_list[i]+j];
				}
			}

			// Recover data
			ec_init_tables(k, nerrs, c, g_tbls);
			ec_encode_data(size, k, nerrs, g_tbls, recov, &temp_buffs[k]);

			for(i=0; i<nerrs; i++){

				if (0 != memcmp(temp_buffs[k+i], efence_buffs[src_err_list[i]], size)){
					printf("Efence: Fail error recovery (%d, %d, %d)\n", m, k, nerrs);

					printf("Test erase list = ");
					for (i=0; i<nerrs; i++)
						printf(" %d", src_err_list[i]);
					printf("\n");

					printf("recov %d:",src_err_list[i]);
					dump(temp_buffs[k+i], align);
					printf("orig   :");
					dump(efence_buffs[src_err_list[i]],align);
					return -1;
				}
			}
		}

	}

	// Test rand ptr alignment if available

	for(rtest=0; rtest<RANDOMS; rtest++){
		while ((m = (rand() % MMAX)) < 2);
		while ((k = (rand() % KMAX)) >= m || k < 1);

		if (m>MMAX || k>KMAX)
			continue;

		size = (TEST_LEN - PTR_ALIGN_CHK_B) & ~15;

		offset = (PTR_ALIGN_CHK_B != 0) ? 1 : PTR_ALIGN_CHK_B;
		// Add random offsets
		for(i=0; i<m; i++) {
			memset(buffs[i], 0, TEST_LEN);  // zero pad to check write-over
			memset(temp_buffs[i], 0, TEST_LEN);  // zero pad to check write-over
			ubuffs[i] = buffs[i] + (rand() & (PTR_ALIGN_CHK_B - offset));
			temp_ubuffs[i] = temp_buffs[i] + (rand() & (PTR_ALIGN_CHK_B - offset));
		}

		for(i=0; i<k; i++)
			for(j=0; j<size; j++)
				ubuffs[i][j] = rand();

		gf_gen_rs_matrix(a, m, k);

		// Make parity vects
		ec_init_tables(k, m-k, &a[k*k], g_tbls);
		ec_encode_data_base(size, k, m-k, g_tbls, ubuffs, &ubuffs[k]);

		// Random errors
		memset(src_in_err, 0, TEST_SOURCES);
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
			recov[i] = ubuffs[r];
		}
		for(i=0; i<nerrs; i++){
			for(j=0; j<k; j++){
				c[k*i+j]=d[k*src_err_list[i]+j];
			}
		}

		// Recover data
		ec_init_tables(k, nerrs, c, g_tbls);
		ec_encode_data(size, k, nerrs, g_tbls, recov, &temp_ubuffs[k]);

		for(i=0; i<nerrs; i++){

			if (0 != memcmp(temp_ubuffs[k+i], ubuffs[src_err_list[i]], size)){
				printf("Fail error recovery (%d, %d, %d) - ", m, k, nerrs);
				printf(" - erase list = ");
				for (i=0; i<nerrs; i++)
					printf(" %d", src_err_list[i]);
				printf("\na:\n"); 
				dump_u8xu8((unsigned char*)a, m, k);
				printf("inv b:\n");   
				dump_u8xu8((unsigned char*)d, k, k);
				printf("orig data:\n"); 
				dump_matrix(ubuffs, m, 25);
				printf("orig   :");     
				dump(ubuffs[src_err_list[i]],25);
				printf("recov %d:",src_err_list[i]); 
				dump(temp_ubuffs[k+i], 25);
				return -1;
			}
		}

		// Confirm that padding around dests is unchanged
		memset(temp_buffs[0], 0, PTR_ALIGN_CHK_B);  // Make reference zero buff

		for(i=0; i<m; i++){

			offset = ubuffs[i] - buffs[i];

			if (memcmp(buffs[i], temp_buffs[0], offset)){
				printf("Fail rand ualign encode pad start\n");
				return -1;
			}
			if (memcmp(buffs[i] + offset + size, temp_buffs[0], PTR_ALIGN_CHK_B - offset)){
				printf("Fail rand ualign encode pad end\n");
				return -1;
			}
		}

		for(i=0; i<nerrs; i++){

			offset = temp_ubuffs[k+i] - temp_buffs[k+i];
			if (memcmp(temp_buffs[k+i], temp_buffs[0], offset)){
				printf("Fail rand ualign decode pad start\n");
				return -1;
			}
			if (memcmp(temp_buffs[k+i] + offset + size, temp_buffs[0], PTR_ALIGN_CHK_B - offset)){
				printf("Fail rand ualign decode pad end\n");
				return -1;
			}
		}

		putchar('.');
	}

	// Test size alignment
	align = (LEN_ALIGN_CHK_B != 0) ? 13 : 16;

	for(size=TEST_LEN; size>0; size-=align){
		while ((m = (rand() % MMAX)) < 2);
		while ((k = (rand() % KMAX)) >= m || k < 1);

		if (m>MMAX || k>KMAX)
			continue;

		for(i=0; i<k; i++)
			for(j=0; j<size; j++)
				buffs[i][j] = rand();

		gf_gen_rs_matrix(a, m, k);

		// Make parity vects
		ec_init_tables(k, m-k, &a[k*k], g_tbls);
		ec_encode_data_base(size, k, m-k, g_tbls, buffs, &buffs[k]);

		// Random errors
		memset(src_in_err, 0, TEST_SOURCES);
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
		ec_encode_data(size, k, nerrs, g_tbls, recov, &temp_buffs[k]);

		for(i=0; i<nerrs; i++){

			if (0 != memcmp(temp_buffs[k+i], buffs[src_err_list[i]], size)){
				printf("Fail error recovery (%d, %d, %d) - ", m, k, nerrs);
				printf(" - erase list = ");
				for (i=0; i<nerrs; i++)
					printf(" %d", src_err_list[i]);
				printf("\na:\n"); 
				dump_u8xu8((unsigned char*)a, m, k);
				printf("inv b:\n");   
				dump_u8xu8((unsigned char*)d, k, k);
				printf("orig data:\n"); 
				dump_matrix(buffs, m, 25);
				printf("orig   :");     
				dump(buffs[src_err_list[i]],25);
				printf("recov %d:",src_err_list[i]); 
				dump(temp_buffs[k+i], 25);
				return -1;
			}
		}
	}

	printf("done EC tests: Pass\n");
	return 0;
}



