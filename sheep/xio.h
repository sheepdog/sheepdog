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

#ifndef __XIO_H__
#define __XIO_H__

#include "sheep.h"

#include <libxio.h>

void sd_xio_init(void);
void sd_xio_shutdown(void);

int xio_exec_req(const struct node_id *nid, struct sd_req *hdr, void *data,
		 bool (*need_retry)(uint32_t epoch), uint32_t epoch,
		 uint32_t max_count);
int xio_send_req(struct node_id *nid, struct sd_req *hdr, void *data,
		 unsigned int wlen,
		 bool (*need_retry)(uint32_t), uint32_t, uint32_t);
int xio_do_read(struct node_id *nid, void *buf, uint32_t len,
	    bool (*need_retry)(uint32_t), uint32_t, uint32_t);
int xio_create_listen_ports(const char *bindaddr, int port,
			    int (*callback)(int fd, void *), bool rdma);

void xio_init_main_ctx(void);

struct xio_context *xio_get_main_ctx(void);

struct xio_session *sd_xio_gw_create_session(struct xio_context *ctx,
					     const struct node_id *nid,
					     void *user_ctx);
struct xio_connection *sd_xio_gw_create_connection(struct xio_context *ctx,
						   struct xio_session *session,
						   void *user_ctx);
void xio_gw_send_req(struct xio_connection *conn, struct sd_req *hdr,
		     void *data, bool (*need_retry)(uint32_t epoch),
		     uint32_t epoch, uint32_t max_count);

struct xio_forward_info;

struct xio_forward_info_entry {
	const struct node_id *nid;
	void *buf;
	int wlen;

	struct xio_connection *conn;
	struct xio_session *session;

	struct xio_forward_info *fi;
};

struct xio_forward_info {
	struct xio_forward_info_entry ent[SD_MAX_NODES];
	int nr_send, nr_done;

	struct xio_context *ctx;
};

#endif	/* __XIO_H__ */
