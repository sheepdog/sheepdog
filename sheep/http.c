/*
 * Copyright (C) 2013 Taobao Inc.
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

/* This files implement RESTful interface to sheepdog storage via fastcgi */

#include <fcgiapp.h>

#include "sheep_priv.h"

struct http_request {
	FCGX_Request fcgx;
	int opcode;
	char *data;
	size_t data_length;
};

enum http_opcode {
	HTTP_GET = 1,
	HTTP_PUT,
	HTTP_POST,
	HTTP_DELETE,
	HTTP_HEAD,
};

enum http_status {
	OK = 1,                         /* 200 */
	CREATED,                        /* 201 */
	PARTIAL_CONTENT,                /* 206 */
	BAD_REQUEST,                    /* 400 */
	NOT_FOUND,                      /* 404 */
	REQUEST_RANGE_NOT_SATISFIABLE,  /* 416 */
	INTERNAL_SERVER_ERROR,          /* 500 */
	NOT_IMPLEMENTED,                /* 501 */
};

static inline const char *strstatus(int status)
{
	static const char *const descs[] = {
		[OK] = "200 OK",
		[CREATED] = "201 CREATED",
		[PARTIAL_CONTENT] = "206 Partial Content",
		[BAD_REQUEST] = "400 Bad Request",
		[NOT_FOUND] = "404 Not Found",
		[REQUEST_RANGE_NOT_SATISFIABLE] =
			"416 Requested Range Not Satisfiable",
		[INTERNAL_SERVER_ERROR] = "500 Internal Server Error",
		[NOT_IMPLEMENTED] = "501 Not Implemented",
	};

	if (descs[status] == NULL) {
		static __thread char msg[32];
		snprintf(msg, sizeof(msg), "Invalid Status %d", status);
		return msg;
	}

	return descs[status];
}

struct http_work {
	struct work work;
	struct http_request *request;
};

static inline int http_request_error(struct http_request *req)
{
	int ret = FCGX_GetError(req->fcgx.out);

	if (ret == 0) {
		return OK;
	} else if (ret < 0) {
		sd_err("failed, FCGI error %d", ret);
		return INTERNAL_SERVER_ERROR;
	} else {
		sd_err("failed, %s", strerror(ret));
		return INTERNAL_SERVER_ERROR;
	}
}

static inline int http_request_write(struct http_request *req,
				     const char *buf, int len)
{
	int ret = FCGX_PutStr(buf, len, req->fcgx.out);
	if (ret < 0)
		return http_request_error(req);
	return OK;
}

static inline int http_request_read(struct http_request *req,
				    char *buf, int len)
{
	int ret = FCGX_GetStr(buf, len, req->fcgx.in);
	if (ret < 0)
		return http_request_error(req);
	return OK;
}

static inline int http_request_writes(struct http_request *req, const char *str)
{
	int ret = FCGX_PutS(str, req->fcgx.out);
	if (ret < 0)
		return http_request_error(req);
	return OK;
}

__printf(2, 3)
static int http_request_writef(struct http_request *req, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = FCGX_VFPrintF(req->fcgx.out, fmt, ap);
	va_end(ap);
	if (ret < 0)
		return http_request_error(req);
	return OK;
}

static int request_init_operation(struct http_request *req)
{
	char **env = req->fcgx.envp;
	char *p;

	p = FCGX_GetParam("REQUEST_METHOD", env);
	if (!strcmp(p, "PUT")) {
		req->opcode = HTTP_PUT;
		p = FCGX_GetParam("CONTENT_LENGTH", env);
		req->data_length = strtoll(p, NULL, 10);
		req->data = xmalloc(req->data_length);
		http_request_read(req, req->data, req->data_length);
	} else if (!strcmp(p, "GET")) {
		req->opcode = HTTP_GET;
	} else if (!strcmp(p, "POST")) {
		req->opcode = HTTP_POST;
	} else if (!strcmp(p, "DELETE")) {
		req->opcode = HTTP_DELETE;
	} else if (!strcmp(p, "HEAD")) {
		req->opcode = HTTP_HEAD;
	} else {
		return BAD_REQUEST;
	}
	return OK;
}

static int http_init_request(struct http_request *req)
{
	char *p;
	int ret;

	for (int i = 0; (p = req->fcgx.envp[i]); ++i)
		sd_debug("%s", p);

	ret = request_init_operation(req);
	if (ret != OK)
		return ret;
	return OK;
}

static void http_response_header(struct http_request *req, int status)
{
	http_request_writef(req, "Status: %s\n", strstatus(status));
	http_request_writes(req, "Content-type: text/plain;\r\n\r\n");
}

static void http_handle_get(struct http_request *req)
{
	http_response_header(req, NOT_IMPLEMENTED);
	http_request_writes(req, "not implemented\n");
}

static void http_handle_put(struct http_request *req)
{
	http_response_header(req, NOT_IMPLEMENTED);
	http_request_writes(req, "not implemented\n");
}

static void http_handle_post(struct http_request *req)
{
	http_response_header(req, NOT_IMPLEMENTED);
	http_request_writes(req, "not implemented\n");
}

static void http_handle_delete(struct http_request *req)
{
	http_response_header(req, NOT_IMPLEMENTED);
	http_request_writes(req, "not implemented\n");
}

static void http_handle_head(struct http_request *req)
{
	http_response_header(req, NOT_IMPLEMENTED);
	http_request_writes(req, "not implemented\n");
}

static void (*const http_request_handlers[])(struct http_request *req) = {
	[HTTP_GET] = http_handle_get,
	[HTTP_PUT] = http_handle_put,
	[HTTP_POST] = http_handle_post,
	[HTTP_DELETE] = http_handle_delete,
	[HTTP_HEAD] = http_handle_head,
};

static const int http_max_request_handlers = ARRAY_SIZE(http_request_handlers);

static void http_end_request(struct http_request *req)
{
	FCGX_Finish_r(&req->fcgx);
	free(req->data);
	free(req);
}

static void http_run_request(struct work *work)
{
	struct http_work *hw = container_of(work, struct http_work, work);
	struct http_request *req = hw->request;
	int op = req->opcode;

	if (op < http_max_request_handlers && http_request_handlers[op])
		http_request_handlers[op](req);
	else
		panic("unhandled opcode %d", op);
	http_end_request(req);
}

static void http_request_done(struct work *work)
{
	struct http_work *hw = container_of(work, struct http_work, work);
	free(hw);
}

static void http_queue_request(struct http_request *req)
{
	struct http_work *hw = xmalloc(sizeof(*hw));

	hw->work.fn = http_run_request;
	hw->work.done = http_request_done;
	hw->request = req;
	queue_work(sys->http_wqueue, &hw->work);
}

static inline struct http_request *http_new_request(int sockfd)
{
	struct http_request *req = xzalloc(sizeof(*req));

	FCGX_InitRequest(&req->fcgx, sockfd, 0);
	return req;
}

static int http_sockfd;

static void *http_main_loop(void *ignored)
{
	int err;

	for (;;) {
		struct http_request *req = http_new_request(http_sockfd);
		int ret;

		ret = FCGX_Accept_r(&req->fcgx);
		if (ret < 0) {
			sd_err("accept failed, %d, %d", http_sockfd, ret);
			goto out;
		}
		ret = http_init_request(req);
		if (ret != OK) {
			http_response_header(req, ret);
			http_end_request(req);
			continue;
		}
		http_queue_request(req);
	}
out:
	err = pthread_detach(pthread_self());
	if (err)
		sd_err("%s", strerror(err));
	pthread_exit(NULL);
}

int http_init(const char *address)
{
	pthread_t t;
	int err;

	sys->http_wqueue = create_work_queue("http", WQ_DYNAMIC);
	if (!sys->http_wqueue)
		return -1;

	FCGX_Init();

#define LISTEN_QUEUE_DEPTH 1024 /* No rationale */
	http_sockfd = FCGX_OpenSocket(address, LISTEN_QUEUE_DEPTH);
	if (http_sockfd < 0) {
		sd_err("open socket failed, address %s", address);
		return -1;
	}
	sd_info("http service listen at %s", address);
	err = pthread_create(&t, NULL, http_main_loop, NULL);
	if (err) {
		sd_err("%s", strerror(err));
		return -1;
	}
	return 0;
}
