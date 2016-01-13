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

#include <string.h>

#include "sheep.h"
#include "internal_proto.h"
#include "rbtree.h"
#include "event.h"
#include "work.h"
#include "xio.h"

#include <libxio.h>

static struct xio_context *main_ctx;

struct xio_context *xio_get_main_ctx(void)
{
	return main_ctx;
}

struct client_data {
	struct xio_context	*ctx;
	struct xio_msg *rsp;
};

static int client_on_response(struct xio_session *session,
			      struct xio_msg *rsp,
			      int last_in_rxq,
			      void *cb_user_context)
{
	struct client_data *client_data =
			(struct client_data *)cb_user_context;

	sd_debug("response on session %p", client_data);
	xio_context_stop_loop(client_data->ctx);
	client_data->rsp = rsp;

	return 0;
}

static int on_msg_error(struct xio_session *session,
			enum xio_status error,
			enum xio_msg_direction direction,
			struct xio_msg *msg,
			void *cb_user_context)
{
	/* struct server_data *sdata = (struct server_data *)cb_user_context; */

	if (direction == XIO_MSG_DIRECTION_OUT) {
		sd_debug("**** [%p] message %lu failed. reason: %s",
		       session, msg->sn, xio_strerror(error));
	} else {
		xio_release_response(msg);
		sd_debug("**** [%p] message %lu failed. reason: %s",
		       session, msg->request->sn, xio_strerror(error));
	}

	switch (error) {
	case XIO_E_MSG_FLUSHED:
		break;
	default:
		/* xio_disconnect(sdata->connection); */
		break;
	};

	return 0;
}

static int on_session_event(struct xio_session *session,
			    struct xio_session_event_data *event_data,
			    void *cb_user_context)
{
	struct client_data *client_data =
			(struct client_data *)cb_user_context;

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		xio_connection_destroy(event_data->conn);
		xio_context_stop_loop(client_data->ctx);  /* exit */
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		xio_session_destroy(session);
		xio_context_stop_loop(client_data->ctx);  /* exit */
		break;
	default:
		sd_debug("other event: %d", event_data->event);
		break;
	};

	return 0;
}

static int client_assign_data_in_buf(struct xio_msg *msg, void *cb_user_context)
{
	struct xio_iovec_ex	*sglist = vmsg_sglist(&msg->in);
	struct xio_reg_mem	in_xbuf;

	sd_debug("assign buffer, msg vec len: %lu", sglist[0].iov_len);
	if (!sglist[0].iov_len)
		return 0;

	xio_mem_alloc(sglist[0].iov_len, &in_xbuf);

	sglist[0].iov_base = in_xbuf.addr;
	sglist[0].mr = in_xbuf.mr;

	return 0;
}

static struct xio_session_ops client_ses_ops = {
	.on_session_event = on_session_event,
	.on_session_established = NULL,
	.on_msg = client_on_response,
	.on_msg_error = on_msg_error,
	.assign_data_in_buf = client_assign_data_in_buf,
};

static struct xio_connection *sd_xio_create_connection(struct xio_context *ctx,
					       const struct node_id *nid,
					       void *user_ctx)
{
	struct xio_connection *conn;
	struct xio_session *session;
	char url[256];
	struct xio_session_params params;
	struct xio_connection_params cparams;

	if (nid->io_transport_type == IO_TRANSPORT_TYPE_RDMA)
		snprintf(url, 256, "rdma://%s",
			 addr_to_str(nid->io_addr, nid->io_port));
	else
		snprintf(url, 256, "tcp://%s",
			 addr_to_str(nid->io_addr, nid->io_port));

	memset(&params, 0, sizeof(params));
	params.type = XIO_SESSION_CLIENT;
	params.ses_ops = &client_ses_ops;
	params.uri = url;
	params.user_context = user_ctx;

	session = xio_session_create(&params);

	memset(&cparams, 0, sizeof(cparams));
	cparams.session = session;
	cparams.ctx = ctx;
	cparams.conn_user_context = user_ctx;

	conn = xio_connect(&cparams);

	return conn;
}

static int client_msg_vec_init(struct xio_msg *msg)
{
	msg->in.sgl_type		= XIO_SGL_TYPE_IOV_PTR;
	msg->in.pdata_iov.max_nents	= 2;
	msg->in.pdata_iov.sglist	=
		(struct xio_iovec_ex *)calloc(2, sizeof(struct xio_iovec_ex));

	msg->out.sgl_type		= XIO_SGL_TYPE_IOV_PTR;
	msg->out.pdata_iov.max_nents	= 1;
	msg->out.pdata_iov.sglist	=
		(struct xio_iovec_ex *)calloc(1, sizeof(struct xio_iovec_ex));

	return 0;
}

static void msg_prep_for_send(struct sd_req *hdr, struct sd_rsp *rsp,
			      void *data, struct xio_msg *msg)
{
	struct xio_vmsg *pomsg = &msg->out;
	struct xio_iovec_ex *osglist = vmsg_sglist(pomsg);
	struct xio_vmsg *pimsg = &msg->in;
	struct xio_iovec_ex *isglist = vmsg_sglist(pimsg);

	vmsg_sglist_set_nents(pomsg, 0);
	pomsg->header.iov_len = sizeof(*hdr);
	pomsg->header.iov_base = hdr;

	if (hdr->flags & SD_FLAG_CMD_WRITE) {
		vmsg_sglist_set_nents(pomsg, 1);

		osglist[0].iov_base = data;
		osglist[0].iov_len = hdr->data_length;
		osglist[0].mr = NULL;
	}

	vmsg_sglist_set_nents(pimsg, 1);
	isglist[0].iov_base = rsp;
	isglist[0].iov_len = sizeof(*rsp);
	isglist[0].mr = NULL;

	if (hdr->data_length) {
		vmsg_sglist_set_nents(pimsg, 2);
		isglist[1].iov_base = xzalloc(hdr->data_length);
		isglist[1].iov_len = hdr->data_length;
		isglist[1].mr = NULL;
	}
}

static void msg_finalize(struct sd_req *hdr, void *data, struct xio_msg *xrsp)
{
	struct xio_vmsg *pimsg = &xrsp->in;
	struct xio_iovec_ex *isglist = vmsg_sglist(pimsg);
	int nents = vmsg_sglist_nents(pimsg);

	sd_assert(xrsp->in.header.iov_len == sizeof(struct sd_rsp));
	memcpy(hdr, xrsp->in.header.iov_base, sizeof(*hdr));
	if (data) {
		int total = 0;

		for (int i = 0; i < nents; i++) {
			memcpy((char *)data + total, isglist[i].iov_base,
			       isglist[i].iov_len);
			total += isglist[i].iov_len;
		}
	}

	xio_release_response(xrsp);
}

int xio_exec_req(const struct node_id *nid, struct sd_req *hdr, void *data,
		 bool (*need_retry)(uint32_t epoch), uint32_t epoch,
		 uint32_t max_count)
{
	struct xio_context *ctx = xio_context_create(NULL, 0, -1);
	struct client_data cli = { .ctx = ctx };
	struct xio_connection *conn = sd_xio_create_connection(ctx, nid, &cli);
	struct xio_msg xreq;
	struct sd_rsp rsp;

	sd_assert(!is_main_thread());

	memset(&rsp, 0, sizeof(rsp));
	memset(&xreq, 0, sizeof(xreq));
	client_msg_vec_init(&xreq);
	memset(&rsp, 0, sizeof(rsp));
	msg_prep_for_send(hdr, &rsp, data, &xreq);

	xio_send_request(conn, &xreq);
	xio_context_run_loop(ctx, XIO_INFINITE);

	msg_finalize(hdr, data, cli.rsp);

	xio_connection_destroy(conn);
	xio_context_destroy(ctx);

	return 0;
}

static int gw_client_on_response(struct xio_session *session,
				 struct xio_msg *rsp,
				 int last_in_rxq,
				 void *cb_user_context)
{
	struct xio_forward_info_entry *fi_entry =
		(struct xio_forward_info_entry *)cb_user_context;
	struct xio_forward_info *fi = fi_entry->fi;

	struct xio_vmsg *pimsg = &rsp->in;
	struct xio_iovec_ex *isglist = vmsg_sglist(pimsg);

	int nents = vmsg_sglist_nents(pimsg), total = 0;

	sd_debug("response on fi_entry %p", fi_entry);

	for (int i = 0; i < nents; i++) {
		memcpy((char *)fi_entry->buf + total,
		       isglist[i].iov_base, isglist[i].iov_len);

		total += isglist[i].iov_len;
	}

	fi->nr_done++;
	if (fi->nr_done == fi->nr_send)
		xio_context_stop_loop(fi->ctx);

	return 0;
}

static struct xio_session_ops gw_client_ses_ops = {
	.on_session_event = on_session_event,
	.on_session_established = NULL,
	.on_msg = gw_client_on_response,
	.on_msg_error = on_msg_error,
	.assign_data_in_buf		= client_assign_data_in_buf,
};

struct xio_session *sd_xio_gw_create_session(struct xio_context *ctx,
					     const struct node_id *nid,
					     void *user_ctx)
{
	struct xio_session *session;
	char url[256];
	struct xio_session_params params;

	if (nid->io_transport_type == IO_TRANSPORT_TYPE_RDMA)
		snprintf(url, 256, "rdma://%s",
			 addr_to_str(nid->io_addr, nid->io_port));
	else
		snprintf(url, 256, "tcp://%s",
			 addr_to_str(nid->io_addr, nid->io_port));

	memset(&params, 0, sizeof(params));
	params.type = XIO_SESSION_CLIENT;
	params.ses_ops = &gw_client_ses_ops;
	params.uri = url;
	params.user_context = user_ctx;

	session = xio_session_create(&params);

	return session;
}

struct xio_connection *sd_xio_gw_create_connection(struct xio_context *ctx,
						   struct xio_session *session,
						   void *user_ctx)
{
	struct xio_connection *conn;
	struct xio_connection_params cparams;

	memset(&cparams, 0, sizeof(cparams));
	cparams.session = session;
	cparams.ctx = ctx;
	cparams.conn_user_context = user_ctx;

	conn = xio_connect(&cparams);

	return conn;
}

void xio_gw_send_req(struct xio_connection *conn, struct sd_req *hdr,
		     void *data, bool (*need_retry)(uint32_t epoch),
		     uint32_t epoch, uint32_t max_count)
{
	struct xio_msg *xreq = xzalloc(sizeof(*xreq));
	struct sd_rsp *rsp = xzalloc(sizeof(*rsp));

	client_msg_vec_init(xreq);
	msg_prep_for_send(hdr, rsp, data, xreq);

	xio_send_request(conn, xreq);
}

void xio_init_main_ctx(void)
{
	/*
	 * Why do we need this main_ctx?
	 *
	 * xio_context_create() changes signal handlers of a calling thread
	 * internally, so SIGUSR1 fd of local cluster driver cannot work
	 * if we call xio_context_create() after initializing the driver.
	 */
	main_ctx = xio_context_create(NULL, 0, -1);
}

void sd_xio_init(void)
{
	int xopt = 2;		/* hdr + body */

	xio_init();

	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_MAX_IN_IOVLEN,
		    &xopt, sizeof(int));
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_MAX_OUT_IOVLEN,
		    &xopt, sizeof(int));
}

void sd_xio_shutdown(void)
{
	xio_shutdown();
}
