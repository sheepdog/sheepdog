#define __ASSEMBLY__
#include "trace.h"

#define _ALIGN_TEXT .align 16, 0x90

#define ENTRY(x) \
        .text; _ALIGN_TEXT; .globl x; .type x,@function; x:

ENTRY(mcount)
	subq $0x38, %rsp
	movq %rax, (%rsp)
	movq %rcx, 8(%rsp)
	movq %rdx, 16(%rsp)
	movq %rsi, 24(%rsp)
	movq %rdi, 32(%rsp)
	movq %r8, 40(%rsp)
	movq %r9, 48(%rsp)

	movq 0x38(%rsp), %rdi
	subq $INSN_SIZE, %rdi

.globl mcount_call
mcount_call:
	call trace_stub

	movq 48(%rsp), %r9
	movq 40(%rsp), %r8
	movq 32(%rsp), %rdi
	movq 24(%rsp), %rsi
	movq 16(%rsp), %rdx
	movq 8(%rsp), %rcx
	movq (%rsp), %rax
	addq $0x38, %rsp

	retq

ENTRY(trace_caller)
	subq $0x38, %rsp
	movq %rax, (%rsp)
	movq %rcx, 8(%rsp)
	movq %rdx, 16(%rsp)
	movq %rsi, 24(%rsp)
	movq %rdi, 32(%rsp)
	movq %r8, 40(%rsp)
	movq %r9, 48(%rsp)

	movq 0x38(%rsp), %rdi
	leaq 8(%rbp), %rsi
	subq $INSN_SIZE, %rdi

.globl trace_call
trace_call:
	call trace_stub

	movq 48(%rsp), %r9
	movq 40(%rsp), %r8
	movq 32(%rsp), %rdi
	movq 24(%rsp), %rsi
	movq 16(%rsp), %rdx
	movq 8(%rsp), %rcx
	movq (%rsp), %rax
	addq $0x38, %rsp

.globl trace_stub
trace_stub:
	retq

ENTRY(trace_return_caller)
	subq  $24, %rsp

	movq %rax, (%rsp)
	movq %rdx, 8(%rsp)

	call trace_return_call

	movq %rax, %rdi
	movq 8(%rsp), %rdx
	movq (%rsp), %rax
	addq $24, %rsp
	jmp *%rdi

.globl NOP5
NOP5:
	.byte 0x0f,0x1f,0x44,0x00,0x00 # Intel recommended one for 5 bytes nops
