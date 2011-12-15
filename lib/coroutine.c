/*
 * Copyright (C) 2011 MORITA Kazutaka <morita.kazutaka@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 * This code is based on coroutine-ucontext.c and qemu-coroutine.c from QEMU:
 *   Copyright (C) 2006 Anthony Liguori <anthony@codemonkey.ws>
 *   Copyright (C) 2011 Stefan Hajnoczi <stefanha@linux.vnet.ibm.com>
 *   Copyright (C) 2011 Kevin Wolf <kwolf@redhat.com>
 */

/* disable glibc's stack check for longjmp which doesn't work well
 * with our code */
#ifdef _FORTIFY_SOURCE
#undef _FORTIFY_SOURCE
#endif

#include <stdlib.h>
#include <setjmp.h>
#include <stdint.h>
#include <ucontext.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include "util.h"
#include "coroutine.h"

enum co_action {
	COROUTINE_YIELD = 1,
	COROUTINE_TERMINATE = 2,
};

/* Maximum free pool size prevents holding too many freed coroutines */
#ifdef COROUTINE_DEBUG
#define POOL_MAX_SIZE   1
#else
#define POOL_MAX_SIZE   64
#endif

#define STACK_MAX_SIZE (1 << 20)  /* 1 MB */

struct coroutine {
	coroutine_entry_func_t *entry;
	void *entry_arg;
	struct coroutine *caller;
	struct list_head pool_next;
	struct list_head co_queue_next;
};

struct co_ucontext {
	struct coroutine base;
	void *stack;
	jmp_buf env;
};

/**
 * Per-thread coroutine bookkeeping
 */
__thread struct co_thread_state{
	/** Currently executing coroutine */
	struct coroutine *current;

	/** Free list to speed up creation */
	struct list_head pool;
	unsigned int pool_size;

	/** The default coroutine */
	struct co_ucontext leader;
} co_ts;

static enum co_action coroutine_switch(struct coroutine *from,
				       struct coroutine *to,
				       enum co_action action);

/*
 * va_args to makecontext() must be type 'int', so passing
 * the pointer we need may require several int args. This
 * union is a quick hack to let us do that
 */
union cc_arg {
	void *p;
	int i[2];
};

static struct co_thread_state *coroutine_get_thread_state(void)
{
	struct co_thread_state *s = &co_ts;

	if (!s->current) {
		s->current = &s->leader.base;
		INIT_LIST_HEAD(&s->pool);
	}
	return s;
}

static void coroutine_trampoline(int i0, int i1)
{
	union cc_arg arg;
	struct co_ucontext *self;
	struct coroutine *co;

	arg.i[0] = i0;
	arg.i[1] = i1;
	self = arg.p;
	co = &self->base;

	/* Initialize longjmp environment and switch back the caller */
	if (!setjmp(self->env))
		longjmp(*(jmp_buf *)co->entry_arg, 1);

	for (;;) {
		co->entry(co->entry_arg);
		coroutine_switch(co, co->caller, COROUTINE_TERMINATE);
	}
}

#ifdef COROUTINE_DEBUG

#define MAGIC_NUMBER 0x1234567890123456

static void init_stack(struct co_ucontext *co)
{
	uint64_t *stack = co->stack;
	int i;

	for (i = 0; i < STACK_MAX_SIZE / sizeof(stack[0]); i++)
		stack[i] = MAGIC_NUMBER;
}

static int get_stack_size(struct co_ucontext *co)
{
	uint64_t *stack = co->stack;
	int i;

	for (i = 0; i < STACK_MAX_SIZE / sizeof(stack[0]); i++)
		if (stack[i] != MAGIC_NUMBER)
			break;

	if (i == 0) {
		fprintf(stderr, "stack overflow\n");
		fflush(stderr);
		abort();
	}

	return STACK_MAX_SIZE - i * sizeof(stack[0]);
}

#endif

static struct coroutine *__coroutine_new(void)
{
	const size_t stack_size = STACK_MAX_SIZE;
	struct co_ucontext *co;
	ucontext_t old_uc, uc;
	jmp_buf old_env;
	union cc_arg arg = {0};

	/* The ucontext functions preserve signal masks which incurs a
	 * system call overhead.  setjmp()/longjmp() does not preserve
	 * signal masks but only works on the current stack.  Since we
	 * need a way to create and switch to a new stack, use the
	 * ucontext functions for that but setjmp()/longjmp() for
	 * everything else.
	 */

	if (getcontext(&uc) == -1)
		abort();

	co = zalloc(sizeof(*co));
	if (!co)
		abort();
	co->stack = zalloc(stack_size);
	if (!co->stack)
		abort();
#ifdef COROUTINE_DEBUG
	init_stack(co);
#endif
	co->base.entry_arg = &old_env; /* stash away our jmp_buf */

	uc.uc_link = &old_uc;
	uc.uc_stack.ss_sp = co->stack;
	uc.uc_stack.ss_size = stack_size;
	uc.uc_stack.ss_flags = 0;

	arg.p = co;

	makecontext(&uc, (void (*)(void))coroutine_trampoline,
		    2, arg.i[0], arg.i[1]);

	/* swapcontext() in, longjmp() back out */
	if (!setjmp(old_env))
		swapcontext(&old_uc, &uc);

	return &co->base;
}

static struct coroutine *coroutine_new(void)
{
	struct co_thread_state *s = coroutine_get_thread_state();
	struct coroutine *co;

	if (!list_empty(&s->pool)) {
		co = list_first_entry(&s->pool, struct coroutine, pool_next);
		list_del(&co->pool_next);
		s->pool_size--;
	} else
		co = __coroutine_new();

	return co;
}

static void coroutine_delete(struct coroutine *co_)
{
	struct co_thread_state *s = coroutine_get_thread_state();
	struct co_ucontext *co = container_of(co_, struct co_ucontext, base);

#ifdef COROUTINE_DEBUG
	fprintf(stdout, "%d bytes are consumed\n", get_stack_size(co));
#endif

	if (s->pool_size < POOL_MAX_SIZE) {
		list_add(&co->base.pool_next, &s->pool);
		co->base.caller = NULL;
		s->pool_size++;
		return;
	}

	free(co->stack);
	free(co);
}

static enum co_action coroutine_switch(struct coroutine *from_,
				       struct coroutine *to_,
				       enum co_action action)
{
	struct co_ucontext *from = container_of(from_, struct co_ucontext, base);
	struct co_ucontext *to = container_of(to_, struct co_ucontext, base);
	struct co_thread_state *s = coroutine_get_thread_state();
	int ret;

	s->current = to_;

	ret = setjmp(from->env);
	if (ret == 0)
		longjmp(to->env, action);

	return ret;
}

struct coroutine *coroutine_self(void)
{
	struct co_thread_state *s = coroutine_get_thread_state();

	return s->current;
}

int in_coroutine(void)
{
	struct co_thread_state *s = &co_ts;

	return s->current && s->current->caller;
}


struct coroutine *coroutine_create(coroutine_entry_func_t *entry)
{
	struct coroutine *co = coroutine_new();
	co->entry = entry;
	return co;
}

static void coroutine_swap(struct coroutine *from, struct coroutine *to)
{
	enum co_action ret;

	ret = coroutine_switch(from, to, COROUTINE_YIELD);

	switch (ret) {
	case COROUTINE_YIELD:
		return;
	case COROUTINE_TERMINATE:
		coroutine_delete(to);
		return;
	default:
		abort();
	}
}

void coroutine_enter(struct coroutine *co, void *opaque)
{
	struct coroutine *self = coroutine_self();

	if (co->caller) {
		fprintf(stderr, "Co-routine re-entered recursively\n");
		abort();
	}

	co->caller = self;
	co->entry_arg = opaque;
	coroutine_swap(self, co);
}

void coroutine_yield(void)
{
	struct coroutine *self = coroutine_self();
	struct coroutine *to = self->caller;

	if (!to) {
		fprintf(stderr, "Co-routine is yielding to no one\n");
		abort();
	}

	self->caller = NULL;
	coroutine_swap(self, to);
}
