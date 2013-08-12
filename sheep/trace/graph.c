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

#include "trace.h"

static __thread unsigned long long entry_time[SD_MAX_STACK_DEPTH];

static void graph_tracer_exit(const struct caller *this_fn, int depth)
{
	struct trace_graph_item trace = {
		.depth = depth,
		.type = TRACE_GRAPH_RETURN,
		.entry_time = entry_time[depth],
		.return_time = clock_get_time(),
	};

	pstrcpy(trace.fname, sizeof(trace.fname), this_fn->name);
	get_thread_name(trace.tname);

	trace_buffer_push(sched_getcpu(), &trace);
}

static void graph_tracer_enter(const struct caller *this_fn, int depth)
{
	struct trace_graph_item trace = {
		.type = TRACE_GRAPH_ENTRY,
		.depth = depth,
	};

	pstrcpy(trace.fname, sizeof(trace.fname), this_fn->name);
	get_thread_name(trace.tname);

	entry_time[depth] = clock_get_time();

	trace_buffer_push(sched_getcpu(), &trace);
}

static struct tracer graph_tracer = {
	.name = "graph",

	.enter = graph_tracer_enter,
	.exit = graph_tracer_exit,
};

tracer_register(graph_tracer);
