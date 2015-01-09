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
#define TRACEPOINT_PROVIDER sockfd_cache

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./sockfd_cache_tp.h"

#if !defined(SOCKFD_CACHE_TRACEPOINT_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define SOCKFD_CACHE_TRACEPOINT_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
	sockfd_cache,
	new_sockfd_entry,
	TP_ARGS(void *, _new_entry, int, _fd_count),
	TP_FIELDS(
		ctf_integer_hex(void *, new_entry, _new_entry)
		ctf_integer(void *, fd_count, _fd_count)
		)
	)

TRACEPOINT_EVENT(
	sockfd_cache,
	grow_fd_count,
	TP_ARGS(int, _new_fd_count),
	TP_FIELDS(
		ctf_integer(int, new_fd_count, _new_fd_count)
		)
	)

TRACEPOINT_EVENT(
	sockfd_cache,
	cache_get,
	TP_ARGS(int, _is_long_cache),
	TP_FIELDS(
		ctf_integer(int, is_long_cache, _is_long_cache)
		)
	)

TRACEPOINT_EVENT(
	sockfd_cache,
	cache_put,
	TP_ARGS(int, _is_long_cache),
	TP_FIELDS(
		ctf_integer(int, is_long_cache, _is_long_cache)
		)
	)

#endif /* WORK_TRACEPOINT_H */

#include <lttng/tracepoint-event.h>

#else /* ENABLE_LTTNG_UST */

#include "lttng_disable.h"

#endif
