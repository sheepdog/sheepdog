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
#define TRACEPOINT_PROVIDER request

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./request_tp.h"

#if !defined(EVENT_TRACEPOINT_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define EVENT_TRACEPOINT_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
	request,
	create_client,
	TP_ARGS(int, _fd),
	TP_FIELDS(
		ctf_integer(int, fd, _fd)
		)
	)

TRACEPOINT_EVENT(
	request,
	clear_client,
	TP_ARGS(int, _fd),
	TP_FIELDS(
		ctf_integer(int, fd, _fd)
		)
	)

TRACEPOINT_EVENT(
	request,
	queue_request,
	TP_ARGS(int, _fd, void *, _work, int, _is_read),
	TP_FIELDS(
		ctf_integer(int, fd, _fd)
		ctf_integer_hex(void *, work, _work)
		ctf_integer(int, is_read, _is_read)
		)
	)

TRACEPOINT_EVENT(
	request,
	rx_work,
	TP_ARGS(int, _fd, void *, _work, int, _id, int, _op),
	TP_FIELDS(
		ctf_integer(int, fd, _fd)
		ctf_integer_hex(void *, work, _work)
		ctf_integer_hex(int, id, _id)
		ctf_integer_hex(int, opcode, _op)
		)
	)

TRACEPOINT_EVENT(
	request,
	rx_main,
	TP_ARGS(int, _fd, void *, _work, int, _id, int, _op),
	TP_FIELDS(
		ctf_integer(int, fd, _fd)
		ctf_integer_hex(void *, work, _work)
		ctf_integer_hex(int, id, _id)
		ctf_integer_hex(int, opcode, _op)
		)
	)

TRACEPOINT_EVENT(
	request,
	tx_work,
	TP_ARGS(int, _fd, void *, _work, int, _id, int, _op),
	TP_FIELDS(
		ctf_integer(int, fd, _fd)
		ctf_integer_hex(void *, work, _work)
		ctf_integer_hex(int, id, _id)
		ctf_integer_hex(int, opcode, _op)
		)
	)

TRACEPOINT_EVENT(
	request,
	tx_main,
	TP_ARGS(int, _fd, void *, _work, int, _id, int, _op, int, _res),
	TP_FIELDS(
		ctf_integer(int, fd, _fd)
		ctf_integer_hex(void *, work, _work)
		ctf_integer_hex(int, id, _id)
		ctf_integer_hex(int, opcode, _op)
		ctf_integer(int, result, _res)
		)
	)

TRACEPOINT_EVENT(
	request,
	client_handler,
	TP_ARGS(int, _events, int, _conn_dead),
	TP_FIELDS(
		ctf_integer(int, events, _events)
		ctf_integer(int, conn_dead, _conn_dead)
		)
	)

#endif /* EVENT_TRACEPOINT_H */

#include <lttng/tracepoint-event.h>

#else /* ENABLE_LTTNG_UST */

#include "lttng_disable.h"

#endif
