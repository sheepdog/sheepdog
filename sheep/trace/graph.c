/*
 * Copyright (C) 2012 Taobao Inc.
 *
 * Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <time.h>
#include <assert.h>

#include "trace.h"
#include "logger.h"
#include "util.h"

static __thread unsigned ret_stack_index;
static __thread struct trace_ret_stack {
	unsigned long ret;
	unsigned long func;
	unsigned long long entry_time;
} trace_ret_stack[100]; /* FIXME: consider stack overrun */

static __thread struct rbuffer rbuf;

static void push_return_trace(unsigned long ret, unsigned long long etime,
		unsigned long func, int *depth)
{
	trace_ret_stack[ret_stack_index].ret = ret;
	trace_ret_stack[ret_stack_index].func = func;
	trace_ret_stack[ret_stack_index].entry_time = etime;
	*depth = ret_stack_index;
	ret_stack_index++;
}

static void pop_return_trace(struct trace_graph_item *trace, unsigned long *ret_func)
{
	ret_stack_index--;
	trace->entry_time = trace_ret_stack[ret_stack_index].entry_time;
	*ret_func = trace_ret_stack[ret_stack_index].ret;
	trace->depth = ret_stack_index;
}

static notrace uint64_t clock_get_time(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000000000LL + (uint64_t)ts.tv_nsec;
}

static notrace void default_trace_graph_entry(struct trace_graph_item *item)
{
	rbuffer_push(&rbuf, item);
}

static notrace void default_trace_graph_return(struct trace_graph_item *item)
{
	rbuffer_push(&rbuf, item);
}

static trace_func_graph_ent_t trace_graph_entry = default_trace_graph_entry;
static trace_func_graph_ret_t trace_graph_return = default_trace_graph_return;

notrace unsigned long trace_return_call(void)
{
	struct trace_graph_item trace;
	unsigned long ret;

	trace.return_time = clock_get_time();
	pop_return_trace(&trace, &ret);
	trace.type = TRACE_GRAPH_RETURN;
	trace_graph_return(&trace);

	return ret;
}

notrace void trace_init_buffer(struct list_head *list)
{
	int sz = sizeof(struct trace_graph_item);
	rbuffer_create(&rbuf, TRACE_BUF_LEN / sz, sz);
	list_add(&rbuf.list, list);
}

/* Hook the return address and push it in the trace_ret_stack.
 *
 * ip: the address of the call instruction in the code.
 * ret_addr: the address of return address in the stack frame.
 */
static notrace void graph_tracer(unsigned long ip, unsigned long *ret_addr)
{
	unsigned long old_addr = *ret_addr;
	uint64_t entry_time;
	struct trace_graph_item trace;
	struct caller *cr;

	cr = trace_lookup_ip(ip, 0);
	assert(cr->namelen + 1 < TRACE_FNAME_LEN);
	memcpy(trace.fname, cr->name, cr->namelen);
	memset(trace.fname + cr->namelen, '\0', 1);

	*ret_addr = (unsigned long)trace_return_caller;
	entry_time = clock_get_time();
	push_return_trace(old_addr, entry_time, ip, &trace.depth);
	trace.type = TRACE_GRAPH_ENTRY;

	trace_graph_entry(&trace);
}

register_tracer(graph_tracer);
