/*
 * Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef ENABLE_LTTNG_UST

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER work

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./work_tp.h"

#if !defined(WORK_TRACEPOINT_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define WORK_TRACEPOINT_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
	work,
	queue_work,
	TP_ARGS(void *, wi, void *, work),
	TP_FIELDS(
		ctf_integer_hex(void *, worker_info_ptr, wi)
		ctf_integer_hex(void *, work_ptr, work)
		)
	)

TRACEPOINT_EVENT(
	work,
	do_work,
	TP_ARGS(void *, wi, void *, work),
	TP_FIELDS(
		ctf_integer_hex(void *, worker_info_ptr, wi)
		ctf_integer_hex(void *, work_ptr, work)
		)
	)

TRACEPOINT_EVENT(
	work,
	request_done,
	TP_ARGS(void *, wi, void *, work),
	TP_FIELDS(
		ctf_integer_hex(void *, worker_info_ptr, wi)
		ctf_integer_hex(void *, work_ptr, work)
		)
	)

TRACEPOINT_EVENT(
	work,
	create_queue,
	TP_ARGS(const char *, name, void *, wi, int, control),
	TP_FIELDS(
		ctf_string(queue_name, name)
		ctf_integer_hex(void *, worker_info_ptr, wi)
		ctf_integer(int, thread_control_policy, control)
		)
	)

TRACEPOINT_EVENT(
	work,
	exit_for_shrink,
	TP_ARGS(void *, wi),
	TP_FIELDS(
		ctf_integer_hex(void *, worker_info_ptr, wi)
		)
	)

TRACEPOINT_EVENT(
	work,
	grow_queue,
	TP_ARGS(void *, wi, int, nr_threads),
	TP_FIELDS(
		ctf_integer_hex(void *, worker_info_ptr, wi)
		ctf_integer(int, next_nr_threads, nr_threads)
		)
	)

#endif /* WORK_TRACEPOINT_H */

#include <lttng/tracepoint-event.h>

#else /* ENABLE_LTTNG_UST */

#include "lttng_disable.h"

#endif
