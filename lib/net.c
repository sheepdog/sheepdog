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
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "sheepdog_proto.h"
#include "sheep.h"
#include "util.h"
#include "event.h"
#include "net.h"

int conn_tx_off(struct connection *conn)
{
	conn->events &= ~EPOLLOUT;

	return modify_event(conn->fd, conn->events);
}

int conn_tx_on(struct connection *conn)
{
	conn->events |= EPOLLOUT;

	return modify_event(conn->fd, conn->events);
}

int conn_rx_off(struct connection *conn)
{
	conn->events &= ~EPOLLIN;

	return modify_event(conn->fd, conn->events);
}

int conn_rx_on(struct connection *conn)
{
	conn->events |= EPOLLIN;

	return modify_event(conn->fd, conn->events);
}

bool is_conn_dead(const struct connection *conn)
{
	if (conn->c_rx_state == C_IO_CLOSED || conn->c_tx_state == C_IO_CLOSED)
		return true;
	else
		return false;
}

int rx(struct connection *conn, enum conn_state next_state)
{
	int ret;

	ret = read(conn->fd, conn->rx_buf, conn->rx_length);
	if (!ret) {
		conn->c_rx_state = C_IO_CLOSED;
		return 0;
	}

	if (ret < 0) {
		if (errno != EAGAIN && errno != EINTR)
			conn->c_rx_state = C_IO_CLOSED;
		return 0;
	}

	conn->rx_length -= ret;
	conn->rx_buf = (char *)conn->rx_buf + ret;

	if (!conn->rx_length)
		conn->c_rx_state = next_state;

	return ret;
}

int tx(struct connection *conn, enum conn_state next_state)
{
	int ret;

	ret = write(conn->fd, conn->tx_buf, conn->tx_length);
	if (ret < 0) {
		if (errno != EAGAIN && errno != EINTR)
			conn->c_tx_state = C_IO_CLOSED;
		return 0;
	}

	conn->tx_length -= ret;
	conn->tx_buf = (char *)conn->tx_buf + ret;

	if (!conn->tx_length)
		conn->c_tx_state = next_state;

	return ret;
}

int create_listen_ports(const char *bindaddr, int port,
		int (*callback)(int fd, void *), void *data)
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

	ret = getaddrinfo(bindaddr, servname, &hints, &res0);
	if (ret) {
		sd_err("failed to get address info: %m");
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
			sd_err("failed to set SO_REUSEADDR: %m");

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
			sd_err("failed to bind server socket: %m");
			close(fd);
			continue;
		}

		ret = listen(fd, SOMAXCONN);
		if (ret) {
			sd_err("failed to listen on server socket: %m");
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
		sd_err("failed to create a listening port");

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
		sd_err("failed to get address info: %m");
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
			sd_err("failed to set SO_LINGER: %m");
			close(fd);
			continue;
		}

		ret = set_snd_timeout(fd);
		if (ret) {
			sd_err("failed to set send timeout: %m");
			close(fd);
			break;
		}

		ret = set_rcv_timeout(fd);
		if (ret) {
			sd_err("failed to set recv timeout: %m");
			close(fd);
			break;
		}
reconnect:
		ret = connect(fd, res->ai_addr, res->ai_addrlen);
		if (ret) {
			if (errno == EINTR)
				goto reconnect;
			sd_err("failed to connect to %s:%d: %m", name, port);
			close(fd);
			continue;
		}

		ret = set_nodelay(fd);
		if (ret) {
			sd_err("%m");
			close(fd);
			break;
		} else
			goto success;
	}
	fd = -1;
success:
	freeaddrinfo(res0);
	sd_debug("%d, %s:%d", fd, name, port);
	return fd;
}

int do_read(int sockfd, void *buf, int len, bool (*need_retry)(uint32_t epoch),
	    uint32_t epoch, uint32_t max_count)
{
	int ret, repeat = max_count;
reread:
	ret = read(sockfd, buf, len);
	if (ret == 0) {
		sd_err("connection is closed (%d bytes left)", len);
		return 1;
	}
	if (ret < 0) {
		if (errno == EINTR)
			goto reread;
		/*
		 * Since we set timeout for read, we'll get EAGAIN even for
		 * blocking sockfd.
		 */
		if (errno == EAGAIN && repeat &&
		    (need_retry == NULL || need_retry(epoch))) {
			repeat--;
			goto reread;
		}

		sd_err("failed to read from socket: %d, %m", ret);
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


static int do_write(int sockfd, struct msghdr *msg, int len,
		    bool (*need_retry)(uint32_t), uint32_t epoch,
		    uint32_t max_count)
{
	int ret, repeat = max_count;
rewrite:
	ret = sendmsg(sockfd, msg, 0);
	if (ret < 0) {
		if (errno == EINTR)
			goto rewrite;
		/*
		 * Since we set timeout for write, we'll get EAGAIN even for
		 * blocking sockfd.
		 */
		if (errno == EAGAIN && repeat &&
		    (need_retry == NULL || need_retry(epoch))) {
			repeat--;
			goto rewrite;
		}

		sd_err("failed to write to socket: %m");
		return 1;
	}

	len -= ret;
	if (len) {
		forward_iov(msg, ret);
		goto rewrite;
	}

	return 0;
}

int send_req(int sockfd, struct sd_req *hdr, void *data, unsigned int wlen,
	     bool (*need_retry)(uint32_t epoch), uint32_t epoch,
	     uint32_t max_count)
{
	int ret;
	struct msghdr msg;
	struct iovec iov[2];

	memset(&msg, 0, sizeof(msg));

	msg.msg_iov = iov;

	msg.msg_iovlen = 1;
	iov[0].iov_base = hdr;
	iov[0].iov_len = sizeof(*hdr);

	if (wlen) {
		msg.msg_iovlen++;
		iov[1].iov_base = data;
		iov[1].iov_len = wlen;
	}

	ret = do_write(sockfd, &msg, sizeof(*hdr) + wlen, need_retry, epoch,
		       max_count);
	if (ret) {
		sd_err("failed to send request %x, %d: %m", hdr->opcode, wlen);
		ret = -1;
	}

	return ret;
}

int exec_req(int sockfd, struct sd_req *hdr, void *data,
	     bool (*need_retry)(uint32_t epoch), uint32_t epoch,
	     uint32_t max_count)
{
	int ret;
	struct sd_rsp *rsp = (struct sd_rsp *)hdr;
	unsigned int wlen, rlen;

	if (hdr->flags & SD_FLAG_CMD_WRITE) {
		wlen = hdr->data_length;
		rlen = 0;
	} else {
		wlen = 0;
		rlen = hdr->data_length;
	}

	if (send_req(sockfd, hdr, data, wlen, need_retry, epoch, max_count))
		return 1;

	ret = do_read(sockfd, rsp, sizeof(*rsp), need_retry, epoch, max_count);
	if (ret) {
		sd_err("failed to read a response");
		return 1;
	}

	if (rlen > rsp->data_length)
		rlen = rsp->data_length;

	if (rlen) {
		ret = do_read(sockfd, data, rlen, need_retry, epoch, max_count);
		if (ret) {
			sd_err("failed to read the response data");
			return 1;
		}
	}

	return 0;
}

const char *addr_to_str(const uint8_t *addr, uint16_t port)
{
	static __thread char str[HOST_NAME_MAX + 8];
	int af = AF_INET6;
	int addr_start_idx = 0;
	const char *ret;

	/* Find address family type */
	if (addr[12]) {
		int  oct_no = 0;
		while (!addr[oct_no] && oct_no++ < 12)
			;
		if (oct_no == 12) {
			af = AF_INET;
			addr_start_idx = 12;
		}
	}
	ret = inet_ntop(af, addr + addr_start_idx, str, sizeof(str));
	if (unlikely(ret == NULL))
		panic("failed to convert addr to string, %m");

	if (port) {
		int  len = strlen(str);
		snprintf(str + len, sizeof(str) - len, ":%d", port);
	}

	return str;
}

char *sockaddr_in_to_str(struct sockaddr_in *sockaddr)
{
	int i, si;
	static char str[32];
	uint8_t *addr;

	si = 0;
	memset(str, 0, 32);

	addr = (uint8_t *)&sockaddr->sin_addr.s_addr;
	for (i = 0; i < 4; i++) {
		si += snprintf(str + si, 32 - si,
			i != 3 ? "%d." : "%d", addr[i]);
	}
	snprintf(str + si, 32 - si, ":%u", sockaddr->sin_port);

	return str;
}

uint8_t *str_to_addr(const char *ipstr, uint8_t *addr)
{
	int addr_start_idx = 0, af = strstr(ipstr, ":") ? AF_INET6 : AF_INET;

	if (af == AF_INET) {
		addr_start_idx = 12;
		memset(addr, 0, addr_start_idx);
	}
	if (!inet_pton(af, ipstr, addr + addr_start_idx))
		return NULL;

	return addr;
}

int set_nonblocking(int fd)
{
	int ret;

	ret = fcntl(fd, F_GETFL);
	if (ret < 0) {
		sd_err("fcntl F_GETFL failed: %m");
		close(fd);
	} else {
		ret = fcntl(fd, F_SETFL, ret | O_NONBLOCK);
		if (ret < 0)
			sd_err("fcntl O_NONBLOCK failed: %m");
	}

	return ret;
}

int set_snd_timeout(int fd)
{
	struct timeval timeout;

	timeout.tv_sec = POLL_TIMEOUT;
	timeout.tv_usec = 0;

	return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
			  sizeof(timeout));
}

int set_rcv_timeout(int fd)
{
	struct timeval timeout;
/*
 * We should wait longer for read than write because the target node might be
 * busy doing IO
 */
	timeout.tv_sec = MAX_POLLTIME;
	timeout.tv_usec = 0;

	return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
			  sizeof(timeout));
}

int set_nodelay(int fd)
{
	int ret, opt;

	opt = 1;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
	return ret;
}

/*
 * Timeout after request is issued after 5s.
 *
 * Heart-beat message will be sent periodically with 1s interval.
 * If the node of the other end of fd fails, we'll detect it in 3s
 */
int set_keepalive(int fd)
{
	int val = 1;

	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) < 0) {
		sd_debug("%m");
		return -1;
	}
	val = 5;
	if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &val, sizeof(val)) < 0) {
		sd_debug("%m");
		return -1;
	}
	val = 1;
	if (setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &val, sizeof(val)) < 0) {
		sd_debug("%m");
		return -1;
	}
	val = 3;
	if (setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &val, sizeof(val)) < 0) {
		sd_debug("%m");
		return -1;
	}
	return 0;
}

int get_local_addr(uint8_t *bytes)
{
	struct ifaddrs *ifaddr, *ifa;
	int ret = 0;

	if (getifaddrs(&ifaddr) == -1) {
		sd_err("getifaddrs failed: %m");
		return -1;
	}


	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
		struct sockaddr_in *sin;
		struct sockaddr_in6 *sin6;

		if (ifa->ifa_flags & IFF_LOOPBACK)
			continue;
		if (!ifa->ifa_addr)
			continue;

		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)ifa->ifa_addr;
			memset(bytes, 0, 12);
			memcpy(bytes + 12, &sin->sin_addr, 4);
			memcpy(bytes + 12, &sin->sin_addr, 4);
			sd_err("found IPv4 address");
			goto out;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			memcpy(bytes, &sin6->sin6_addr, 16);
			sd_err("found IPv6 address");
			goto out;
		}
	}

	sd_err("no valid interface found");
	ret = -1;
out:
	freeifaddrs(ifaddr);
	return ret;
}

int create_unix_domain_socket(const char *unix_path,
			      int (*callback)(int, void *), void *data)
{
	int fd, ret;
	struct sockaddr_un addr;

	addr.sun_family = AF_UNIX;
	pstrcpy(addr.sun_path, sizeof(addr.sun_path), unix_path);

	fd = socket(addr.sun_family, SOCK_STREAM, 0);
	if (fd < 0) {
		sd_err("failed to create socket, %m");
		return -1;
	}

	ret = bind(fd, &addr, sizeof(addr));
	if (ret) {
		sd_err("failed to bind socket: %m");
		goto err;
	}

	ret = listen(fd, SOMAXCONN);
	if (ret) {
		sd_err("failed to listen on socket: %m");
		goto err;
	}

	ret = set_nonblocking(fd);
	if (ret < 0)
		goto err;

	ret = callback(fd, data);
	if (ret)
		goto err;

	return 0;
err:
	close(fd);

	return -1;
}

bool inetaddr_is_valid(char *addr)
{
	unsigned char buf[INET6_ADDRSTRLEN];
	int af;

	af = strstr(addr, ":") ? AF_INET6 : AF_INET;
	if (!inet_pton(af, addr, buf)) {
		sd_err("Bad address '%s'", addr);
		return false;
	}
	return true;
}

int do_writev2(int fd, void *hdr, size_t hdr_len, void *body, size_t body_len)
{
	struct iovec iov[2];

	iov[0].iov_base = hdr;
	iov[0].iov_len = hdr_len;

	iov[1].iov_base = body;
	iov[1].iov_len = body_len;

	return writev(fd, iov, 2);
}
