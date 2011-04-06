/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sheepdog_proto.h"
#include "util.h"
#include "event.h"
#include "net.h"
#include "logger.h"

int conn_tx_off(struct connection *conn)
{
	return modify_event(conn->fd, EPOLLIN);
}

int conn_tx_on(struct connection *conn)
{
	return modify_event(conn->fd, EPOLLIN|EPOLLOUT);
}

int is_conn_dead(struct connection *conn)
{
	if (conn->c_rx_state == C_IO_CLOSED || conn->c_tx_state == C_IO_CLOSED)
		return 1;
	else
		return 0;
}

int rx(struct connection *conn, enum conn_state next_state)
{
	int ret;

	ret = read(conn->fd, conn->rx_buf, conn->rx_length);
	if (!ret || ret < 0) {
		if (errno != EAGAIN)
			conn->c_rx_state = C_IO_CLOSED;
		return 0;
	}

	conn->rx_length -= ret;
	conn->rx_buf = (char *)conn->rx_buf + ret;

	if (!conn->rx_length)
		conn->c_rx_state = next_state;

	return ret;
}

int tx(struct connection *conn, enum conn_state next_state, int flags)
{
	int ret;

	ret = send(conn->fd, conn->tx_buf, conn->tx_length, flags);
	if (ret < 0) {
		if (errno != EAGAIN)
			conn->c_tx_state = C_IO_CLOSED;
		return 0;
	}

	conn->tx_length -= ret;
	conn->tx_buf = (char *)conn->tx_buf + ret;

	if (!conn->tx_length)
		conn->c_tx_state = next_state;

	return ret;
}

int create_listen_ports(int port, int (*callback)(int fd, void *), void *data)
{
	char servname[64];
	int fd, ret, opt;
	int success = 0;
	struct addrinfo hints, *res, *res0;

	memset(servname, 0, sizeof(servname));
	snprintf(servname, sizeof(servname), "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	ret = getaddrinfo(NULL, servname, &hints, &res0);
	if (ret) {
		eprintf("unable to get address info, %m\n");
		return 1;
	}

	for (res = res0; res; res = res->ai_next) {
		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd < 0)
			continue;

		opt = 1;
		ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt,
				 sizeof(opt));
		if (ret)
			eprintf("can't set SO_REUSEADDR, %m\n");

		opt = 1;
		if (res->ai_family == AF_INET6) {
			ret = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt,
					 sizeof(opt));
			if (ret) {
				close(fd);
				continue;
			}
		}

		ret = bind(fd, res->ai_addr, res->ai_addrlen);
		if (ret) {
			fprintf(stderr, "can't bind server socket, %m\n");
			close(fd);
			continue;
		}

		ret = listen(fd, SOMAXCONN);
		if (ret) {
			eprintf("can't listen to server socket, %m\n");
			close(fd);
			continue;
		}

		ret = set_nonblocking(fd);
		if (ret < 0) {
			close(fd);
			continue;
		}

		ret = callback(fd, data);
		if (ret) {
			close(fd);
			continue;
		}

		success++;
	}

	freeaddrinfo(res0);

	if (!success)
		eprintf("can't create a listen fd\n");

	return !success;
}

int connect_to(const char *name, int port)
{
	char buf[64];
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	int fd, ret;
	struct addrinfo hints, *res, *res0;
	struct linger linger_opt = {1, 0};

	memset(&hints, 0, sizeof(hints));
	snprintf(buf, sizeof(buf), "%d", port);

	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(name, buf, &hints, &res0);
	if (ret) {
		fprintf(stderr, "unable to get address info, %m\n");
		return -1;
	}

	for (res = res0; res; res = res->ai_next) {
		ret = getnameinfo(res->ai_addr, res->ai_addrlen,
				  hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
				  NI_NUMERICHOST | NI_NUMERICSERV);
		if (ret)
			continue;

		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd < 0)
			continue;

		ret = setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger_opt,
				 sizeof(linger_opt));
		if (ret) {
			eprintf("can't set SO_LINGER, %m\n");
			close(fd);
			continue;
		}

		ret = connect(fd, res->ai_addr, res->ai_addrlen);
		if (ret)
			fprintf(stderr, "failed to connect to %s:%d, %s\n",
				name, port, strerror(errno));
		else
			goto success;

		close(fd);
	}
	fd = -1;
success:
	freeaddrinfo(res0);
	return fd;
}

int do_read(int sockfd, void *buf, int len)
{
	int ret;
reread:
	ret = read(sockfd, buf, len);
	if (ret < 0 || !ret) {
		if (errno == EINTR || errno == EAGAIN)
			goto reread;
		fprintf(stderr, "failed to send a req, %m\n");
		return 1;
	}

	len -= ret;
	buf = (char *)buf + ret;
	if (len)
		goto reread;

	return 0;
}

static void forward_iov(struct msghdr *msg, int len)
{
	while (msg->msg_iov->iov_len <= len) {
		len -= msg->msg_iov->iov_len;
		msg->msg_iov++;
		msg->msg_iovlen--;
	}

	msg->msg_iov->iov_base = (char *) msg->msg_iov->iov_base + len;
	msg->msg_iov->iov_len -= len;
}


static int do_write(int sockfd, struct msghdr *msg, int len)
{
	int ret;
rewrite:
	ret = sendmsg(sockfd, msg, 0);
	if (ret < 0) {
		if (errno == EINTR || errno == EAGAIN)
			goto rewrite;
		fprintf(stderr, "failed to send a req, %m\n");
		return 1;
	}

	len -= ret;
	if (len) {
		forward_iov(msg, ret);
		goto rewrite;
	}

	return 0;
}

int send_req(int sockfd, struct sd_req *hdr, void *data, unsigned int *wlen)
{
	int ret;
	struct msghdr msg;
	struct iovec iov[2];

	memset(&msg, 0, sizeof(msg));

	msg.msg_iov = iov;

	msg.msg_iovlen = 1;
	iov[0].iov_base = hdr;
	iov[0].iov_len = sizeof(*hdr);

	if (*wlen) {
		msg.msg_iovlen++;
		iov[1].iov_base = data;
		iov[1].iov_len = *wlen;
	}

	ret = do_write(sockfd, &msg, sizeof(*hdr) + *wlen);
	if (ret) {
		eprintf("failed to send a req, %x %d, %m\n", hdr->opcode,
			*wlen);
		ret = -1;
	}

	return ret;
}

int exec_req(int sockfd, struct sd_req *hdr, void *data,
	     unsigned int *wlen, unsigned int *rlen)
{
	int ret;
	struct sd_rsp *rsp = (struct sd_rsp *)hdr;

	ret = send_req(sockfd, hdr, data, wlen);
	if (ret) {
		fprintf(stderr, "failed to send a req, %m\n");
		return 1;
	}

	ret = do_read(sockfd, rsp, sizeof(*rsp));
	if (ret) {
		fprintf(stderr, "failed to get a rsp, %m\n");
		return 1;
	}

	if (*rlen > rsp->data_length)
		*rlen = rsp->data_length;

	if (*rlen) {
		ret = do_read(sockfd, data, *rlen);
		if (ret) {
			fprintf(stderr, "failed to get the data, %m\n");
			return 1;
		}
	}

	return 0;
}

char *addr_to_str(char *str, int size, uint8_t *addr, uint16_t port)
{
	int  af = AF_INET6;
	int  addr_start_idx = 0;

	/* Find address family type */
	if (addr[12]) {
		int  oct_no = 0;
		while (!addr[oct_no] && oct_no++ < 12 );
		if (oct_no == 12) {
			af = AF_INET;
			addr_start_idx = 12;
		}
	}
	inet_ntop(af, addr + addr_start_idx, str, size);
	if (port) {
		int  len = strlen(str);
		snprintf(str + len, size - len, ":%d", port);
	}

	return str;
}

int set_nonblocking(int fd)
{
	int ret;

	ret = fcntl(fd, F_GETFL);
	if (ret < 0) {
		eprintf("can't fcntl (F_GETFL), %m\n");
		close(fd);
	} else {
		ret = fcntl(fd, F_SETFL, ret | O_NONBLOCK);
		if (ret < 0)
			eprintf("can't fcntl (O_NONBLOCK), %m\n");
	}

	return ret;
}

int set_nodelay(int fd)
{
	int ret, opt;

	opt = 1;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
	return ret;
}
