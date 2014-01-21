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

#include "http.h"
#include "sheep_priv.h"
#include "option.h"

static const char *http_host = "localhost";
static const char *http_port = "8000";

LIST_HEAD(http_drivers);
static LIST_HEAD(http_enabled_drivers);

static inline const char *stropcode(enum http_opcode opcode)
{
	static const char *const descs[] = {
		[HTTP_GET] = "GET",
		[HTTP_PUT] = "PUT",
		[HTTP_POST] = "POST",
		[HTTP_DELETE] = "DELETE",
		[HTTP_HEAD] = "HEAD",
	};

	if (descs[opcode] == NULL) {
		static __thread char msg[32];
		snprintf(msg, sizeof(msg), "Invalid opcode %d", opcode);
		return msg;
	}

	return descs[opcode];
}

static inline const char *strstatus(enum http_status status)
{
	static const char *const descs[] = {
		[UNKNOWN] = "Unknown",
		[OK] = "200 OK",
		[CREATED] = "201 Created",
		[ACCEPTED] = "202 Accepted",
		[NO_CONTENT] = "204 No Content",
		[PARTIAL_CONTENT] = "206 Partial Content",
		[BAD_REQUEST] = "400 Bad Request",
		[UNAUTHORIZED] = "401 Unauthorized",
		[NOT_FOUND] = "404 Not Found",
		[METHOD_NOT_ALLOWED] = "405 Method Not Allowed",
		[CONFLICT] = "409 Conflict",
		[REQUEST_RANGE_NOT_SATISFIABLE] =
			"416 Requested Range Not Satisfiable",
		[INTERNAL_SERVER_ERROR] = "500 Internal Server Error",
		[NOT_IMPLEMENTED] = "501 Not Implemented",
		[SERVICE_UNAVAILABLE] = "503 Service_Unavailable",
	};

	if (descs[status] == NULL) {
		static __thread char msg[32];
		snprintf(msg, sizeof(msg), "Invalid Status %d", status);
		return msg;
	}

	return descs[status];
}

const char *str_http_req(const struct http_request *req)
{
	static __thread char msg[1024];

	snprintf(msg, sizeof(msg), "%s %s, status = %s, data_length = %"PRIu64,
		 req->uri, stropcode(req->opcode), strstatus(req->status),
		 req->data_length);

	return msg;
}

struct http_work {
	struct work work;
	struct http_request *request;
};

static inline void http_request_error(struct http_request *req)
{
	int ret = FCGX_GetError(req->fcgx.out);

	if (ret == 0)
		return;
	else if (ret < 0)
		sd_err("failed, FCGI error %d", ret);
	else
		sd_err("failed, %s", strerror(ret));
}

int http_request_write(struct http_request *req, const void *buf, int len)
{
	int ret = FCGX_PutStr(buf, len, req->fcgx.out);
	if (ret < 0)
		http_request_error(req);
	return ret;
}

int http_request_read(struct http_request *req, void *buf, int len)
{
	int ret = FCGX_GetStr(buf, len, req->fcgx.in);
	if (ret < 0)
		http_request_error(req);
	return ret;
}

int http_request_writes(struct http_request *req, const char *str)
{
	int ret = FCGX_PutS(str, req->fcgx.out);
	if (ret < 0)
		http_request_error(req);
	return ret;
}

__printf(2, 3)
int http_request_writef(struct http_request *req, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = FCGX_VFPrintF(req->fcgx.out, fmt, ap);
	va_end(ap);
	if (ret < 0)
		http_request_error(req);
	return ret;
}

static int request_init_operation(struct http_request *req)
{
	char **env = req->fcgx.envp;
	char *p, *endp;

	p = FCGX_GetParam("REQUEST_METHOD", env);
	if (!strcmp(p, "PUT")) {
		req->opcode = HTTP_PUT;
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

	p = FCGX_GetParam("CONTENT_LENGTH", env);
	if (p[0] != '\0') {
		req->data_length = strtoll(p, &endp, 10);
		if (p == endp) {
			sd_err("invalid content_length %s", p);
			return BAD_REQUEST;
		}
	}
	req->uri = FCGX_GetParam("DOCUMENT_URI", env);
	if (!req->uri)
		return BAD_REQUEST;
	p = FCGX_GetParam("HTTP_RANGE", env);
	if (p && p[0] != '\0') {
		const char prefix[] = "bytes=";
		char *left, *right, num[64];
		uint64_t max;
		left = strstr(p, prefix);
		if (!p)
			goto invalid_range;
		right = strchr(left, '-');
		strncpy(num, left + sizeof(prefix) - 1, right - left);
		req->offset = strtoll(num, &endp, 10);
		if (num == endp)
			goto invalid_range;
		strcpy(num, right + 1);
		/*
		 * In swift spec, the second number of RANGE should be included
		 * which means [num1, num2], but our common means for read and
		 * write data by 'offset' and 'len' is [num1, num2), so we
		 * should add 1 to num2.
		 */
		max = strtoll(num, &endp, 10) + 1;
		if (num == endp)
			goto invalid_range;
		if (max <= req->offset)
			goto invalid_range;
		req->data_length = max - req->offset;
		sd_debug("HTTP_RANGE: %"PRIu64" %"PRIu64, req->offset, max);
	}

	req->status = UNKNOWN;

	return OK;

invalid_range:
	sd_err("invalid range %s", p);
	return REQUEST_RANGE_NOT_SATISFIABLE;
}

static int http_init_request(struct http_request *req)
{
	char *p;

	for (int i = 0; (p = req->fcgx.envp[i]); ++i)
		sd_debug("%s", p);

	return request_init_operation(req);
}

/* This function does nothing if we have already printed a status code. */
void http_response_header(struct http_request *req, enum http_status status)
{
	if (req->status != UNKNOWN)
		return;

	req->status = status;
	http_request_writef(req, "Status: %s\r\n", strstatus(status));
	if (req->opcode == HTTP_GET || req->opcode == HTTP_HEAD)
		http_request_writef(req, "Content-Length: %"PRIu64"\r\n",
				    req->data_length);
	http_request_writes(req, "Content-type: text/plain;\r\n\r\n");
}

static void http_end_request(struct http_request *req)
{
	FCGX_Finish_r(&req->fcgx);
	free(req);
}

static void http_run_request(struct work *work)
{
	struct http_work *hw = container_of(work, struct http_work, work);
	struct http_request *req = hw->request;
	int op = req->opcode;
	struct http_driver *hdrv;

	list_for_each_entry(hdrv, &http_enabled_drivers, list) {
		void (*method)(struct http_request *req) = NULL;

		switch (op) {
		case HTTP_HEAD:
			method = hdrv->head;
			break;
		case HTTP_GET:
			method = hdrv->get;
			break;
		case HTTP_PUT:
			method = hdrv->put;
			break;
		case HTTP_POST:
			method = hdrv->post;
			break;
		case HTTP_DELETE:
			method = hdrv->delete;
			break;
		default:
			break;
		}

		if (method != NULL) {
			method(req);
			sd_debug("req->status %d", req->status);
			if (req->status != UNKNOWN)
				goto out;
		}
	}

	http_response_header(req, METHOD_NOT_ALLOWED);
out:
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

static int http_opt_host_parser(const char *s)
{
	http_host = s;
	return 0;
}

static int http_opt_port_parser(const char *s)
{
	http_port = s;
	return 0;
}

static int http_opt_default_parser(const char *s)
{
	struct http_driver *hdrv;

	hdrv = find_hdrv(&http_enabled_drivers, s);
	if (hdrv != NULL) {
		sd_err("%s driver is already enabled", hdrv->name);
		return -1;
	}

	hdrv = find_hdrv(&http_drivers, s);
	if (hdrv == NULL) {
		sd_err("'%s' is not a valid driver name", s);
		return -1;
	}

	if (hdrv->init(get_hdrv_option(hdrv, s)) < 0) {
		sd_err("failed to initialize %s driver", hdrv->name);
		return -1;
	}

	list_move_tail(&hdrv->list, &http_enabled_drivers);

	return 0;
}

static struct option_parser http_opt_parsers[] = {
	{ "host=", http_opt_host_parser },
	{ "port=", http_opt_port_parser },
	{ "", http_opt_default_parser },
	{ NULL, NULL },
};

int http_init(const char *options)
{
	pthread_t t;
	int err;
	char *s, address[HOST_NAME_MAX + 8];

	s = strdup(options);
	if (s == NULL) {
		sd_emerg("OOM");
		return -1;
	}

	if (option_parse(s, ",", http_opt_parsers) < 0)
		return -1;

	sys->http_wqueue = create_work_queue("http", WQ_DYNAMIC);
	if (!sys->http_wqueue)
		return -1;

	FCGX_Init();

#define LISTEN_QUEUE_DEPTH 1024 /* No rationale */
	snprintf(address, sizeof(address), "%s:%s", http_host, http_port);
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
