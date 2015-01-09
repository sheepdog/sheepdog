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
#define TRACEPOINT_PROVIDER event

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./event_tp.h"

#if !defined(EVENT_TRACEPOINT_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define EVENT_TRACEPOINT_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
	event,
	loop_start,
	TP_ARGS(int, nr_events),
	TP_FIELDS(
		ctf_integer(int, nr, nr_events)
		)
	)

TRACEPOINT_EVENT(
	event,
	_register,
	TP_ARGS(int, _fd, void *, _handler, void *, _data, int, _prio),
	TP_FIELDS(
		ctf_integer(int, fd, _fd)
		ctf_integer(void *, handler, _handler)
		ctf_integer(void *, data, _data)
		ctf_integer(int, prio, _prio)
		)
	)

TRACEPOINT_EVENT(
	event,
	unregister,
	TP_ARGS(int, _fd),
	TP_FIELDS(
		ctf_integer(int, fd, _fd)
		)
	)

#endif /* EVENT_TRACEPOINT_H */

#include <lttng/tracepoint-event.h>

#else /* ENABLE_LTTNG_UST */

#include "lttng_disable.h"

#endif
