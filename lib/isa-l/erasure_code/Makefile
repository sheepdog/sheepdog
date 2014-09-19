########################################################################
#  Copyright(c) 2011-2013 Intel Corporation All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions 
#  are met:
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in
#      the documentation and/or other materials provided with the
#      distribution.
#    * Neither the name of Intel Corporation nor the names of its
#      contributors may be used to endorse or promote products derived
#      from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
########################################################################


lib_name    := 	erasure_code.a

lsrc        += 	ec_highlevel_func.c ec_base.c \
		gf_vect_mul_sse.asm gf_vect_mul_avx.asm \
		gf_vect_dot_prod_sse.asm  \
		gf_2vect_dot_prod_sse.asm gf_3vect_dot_prod_sse.asm \
		gf_4vect_dot_prod_sse.asm gf_5vect_dot_prod_sse.asm \
		gf_6vect_dot_prod_sse.asm ec_multibinary.asm 

lsrc32      	+=  ec_highlevel_func.c ec_multibinary.asm ec_base.c

unit_tests32  	+=  erasure_code_base_test erasure_code_test \
			gf_vect_mul_test gf_vect_mul_base_test \
			gf_vect_dot_prod_base_test gf_vect_dot_prod_test

perf_tests32	+=  gf_vect_mul_perf gf_vect_dot_prod_perf erasure_code_perf \
			erasure_code_base_perf gf_vect_dot_prod_1tbl 

extern_hdrs +=	erasure_code.h gf_vect_mul.h test.h types.h

unit_tests  += 	gf_vect_mul_test gf_vect_mul_sse_test gf_vect_mul_avx_test \
		gf_vect_mul_base_test \
		gf_vect_dot_prod_sse_test gf_2vect_dot_prod_sse_test \
		gf_3vect_dot_prod_sse_test gf_4vect_dot_prod_sse_test \
		gf_5vect_dot_prod_sse_test gf_6vect_dot_prod_sse_test \
		gf_inverse_test gf_vect_dot_prod_base_test \
		gf_vect_dot_prod_test \
		erasure_code_test erasure_code_base_test erasure_code_sse_test

perf_tests  += 	gf_vect_mul_perf gf_vect_mul_sse_perf gf_vect_mul_avx_perf \
		gf_vect_dot_prod_sse_perf gf_2vect_dot_prod_sse_perf \
		gf_3vect_dot_prod_sse_perf gf_4vect_dot_prod_sse_perf \
		gf_5vect_dot_prod_sse_perf gf_6vect_dot_prod_sse_perf \
		gf_vect_dot_prod_perf gf_vect_dot_prod_1tbl\
		erasure_code_perf erasure_code_base_perf erasure_code_sse_perf

other_src   += ec_base.h reg_sizes.asm


VPATH = .. ../include

-include ../make.inc
