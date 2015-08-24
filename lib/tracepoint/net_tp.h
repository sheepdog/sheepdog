#ifdef ENABLE_LTTNG_UST

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER net

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./net_tp.h"

#if !defined(NET_TRACEPOINT_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define NET_TRACEPOINT_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
	net,
	connect,
	TP_ARGS(int, _fd, const char *, _name, int, _port),
	TP_FIELDS(
		ctf_integer(int, fd, _fd)
		ctf_string(name, _name)
		ctf_integer(int, port, _port)
		)
	)

TRACEPOINT_EVENT(
	net,
	do_read,
	TP_ARGS(int, _fd, void *, _buf, int, _len),
	TP_FIELDS(
		ctf_integer(int, fd, _fd)
		ctf_integer_hex(void *, buf, _buf)
		ctf_integer(int, len, _len)
		)
	)

TRACEPOINT_EVENT(
	net,
	do_read_start,
	TP_ARGS(int, _fd, void *, _buf, int, _len),
	TP_FIELDS(
		ctf_integer(int, fd, _fd)
		ctf_integer_hex(void *, buf, _buf)
		ctf_integer(int, len, _len)
		)
	)

TRACEPOINT_EVENT(
	net,
	do_read_done,
	TP_ARGS(int, _fd, void *, _buf),
	TP_FIELDS(
		ctf_integer(int, fd, _fd)
		ctf_integer_hex(void *, buf, _buf)
		)
	)

TRACEPOINT_EVENT(
	net,
	do_write,
	TP_ARGS(int, _fd, void *, _buf, int, _len),
	TP_FIELDS(
		ctf_integer(int, fd, _fd)
		ctf_integer_hex(void *, buf, _buf)
		ctf_integer(int, len, _len)
		)
	)

TRACEPOINT_EVENT(
	net,
	do_write_start,
	TP_ARGS(int, _fd, void *, _buf, int, _len),
	TP_FIELDS(
		ctf_integer(int, fd, _fd)
		ctf_integer_hex(void *, buf, _buf)
		ctf_integer(int, len, _len)
		)
	)

TRACEPOINT_EVENT(
	net,
	do_write_done,
	TP_ARGS(int, _fd, void *, _buf),
	TP_FIELDS(
		ctf_integer(int, fd, _fd)
		ctf_integer_hex(void *, buf, _buf)
		)
	)

TRACEPOINT_EVENT(
	net,
	send_req,
	TP_ARGS(int, _fd, int, _id, int, _opcode, int, _data_length),
	TP_FIELDS(
		ctf_integer(int, fd, _fd)
		ctf_integer_hex(int, id, _id)
		ctf_integer_hex(int, opcode, _opcode)
		ctf_integer(int, data_length, _data_length)
		)
	)

TRACEPOINT_EVENT(
	net,
	exec_req,
	TP_ARGS(int, _fd, void *, _buf),
	TP_FIELDS(
		ctf_integer(int, fd, _fd)
		ctf_integer_hex(void *, buf, _buf)
		)
	)


#endif /* NET_TRACEPOINT_H */

#include <lttng/tracepoint-event.h>

#else /* ENABLE_LTTNG_UST */

#include "lttng_disable.h"

#endif
