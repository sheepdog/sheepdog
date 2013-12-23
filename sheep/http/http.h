/*
 * Copyright (C) 2013 MORITA Kazutaka <morita.kazutaka@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __SHEEP_HTTP_H__
#define __SHEEP_HTTP_H__

#include <fcgiapp.h>

#include "sheepdog_proto.h"
#include "sheep.h"

enum http_opcode {
	HTTP_GET = 1,
	HTTP_PUT,
	HTTP_POST,
	HTTP_DELETE,
	HTTP_HEAD,
};

enum http_status {
	UNKNOWN = 0,
	OK,                             /* 200 */
	CREATED,                        /* 201 */
	ACCEPTED,                       /* 202 */
	NO_CONTENT,                     /* 204 */
	PARTIAL_CONTENT,                /* 206 */
	BAD_REQUEST,                    /* 400 */
	UNAUTHORIZED,			/* 401 */
	NOT_FOUND,                      /* 404 */
	METHOD_NOT_ALLOWED,             /* 405 */
	CONFLICT,                       /* 409 */
	REQUEST_RANGE_NOT_SATISFIABLE,  /* 416 */
	INTERNAL_SERVER_ERROR,          /* 500 */
	NOT_IMPLEMENTED,                /* 501 */
	SERVICE_UNAVAILABLE,            /* 503 */
};

struct http_request {
	FCGX_Request fcgx;
	char *uri;
	enum http_opcode opcode;
	enum http_status status;
	size_t data_length;
};

struct http_driver {
	const char *name;

	/* Returns zero on success, -1 on error. */
	int (*init)(const char *option);

	void (*head)(struct http_request *req);
	void (*get)(struct http_request *req);
	void (*put)(struct http_request *req);
	void (*post)(struct http_request *req);
	void (*delete)(struct http_request *req);

	struct list_node list;
};

extern struct list_head http_drivers;

#define hdrv_register(driver)						\
static void __attribute__((constructor)) register_ ## driver(void)	\
{									\
	list_add(&driver.list, &http_drivers);				\
}

static inline struct http_driver *find_hdrv(struct list_head *drivers,
					    const char *name)
{
	struct http_driver *hdrv;
	int len;

	list_for_each_entry(hdrv, drivers, list) {
		len = strlen(hdrv->name);

		if (strncmp(hdrv->name, name, len) == 0 &&
		    (name[len] == ':' || name[len] == '\0'))
			return hdrv;
	}

	return NULL;
}

static inline const char *get_hdrv_option(const struct http_driver *hdrv,
					  const char *arg)
{
	int len = strlen(hdrv->name);

	if (arg[len] == ':')
		return strdup(arg + len + 1);
	else
		return NULL;
}

const char *str_http_req(const struct http_request *req);
void http_response_header(struct http_request *req, enum http_status status);
int http_request_read(struct http_request *req, void *buf, int len);
int http_request_write(struct http_request *req, const void *buf, int len);
int http_request_writes(struct http_request *req, const char *str);
__printf(2, 3)
int http_request_writef(struct http_request *req, const char *fmt, ...);

/* For kv.c */

#define SD_MAX_BUCKET_NAME 256
#define SD_MAX_OBJECT_NAME 1024

/* Account operations */
int kv_create_account(const char *account);
int kv_read_account(const char *account, uint32_t *nr_buckets);
int kv_update_account(const char *account);
int kv_delete_account(const char *account);
int kv_list_accounts(struct http_request *req,
		    void (*cb)(struct http_request *req, const char *account,
			       void *opaque),
		    void *opaque);

/* Bucket operations */
int kv_create_bucket(const char *account, const char *bucket);
int kv_read_bucket(const char *account, const char *bucket);
int kv_update_bucket(const char *account, const char *bucket);
int kv_delete_bucket(const char *account, const char *bucket);
int kv_list_buckets(struct http_request *req, const char *account,
		    void (*cb)(struct http_request *req, const char *bucket,
			       void *opaque),
		    void *opaque);

/* Object operations */
int kv_create_object(struct http_request *req, const char *account,
		     const char *bucket, const char *object);
int kv_read_object(struct http_request *req, const char *account,
		   const char *bucket, const char *object);
int kv_delete_object(struct http_request *req, const char *account,
		     const char *bucket, const char *object);
int kv_list_objects(struct http_request *req, const char *account,
		    const char *bucket,
		    void (*cb)(struct http_request *req, const char *bucket,
			       const char *object, void *opaque),
		    void *opaque);

/* object_allocator.c */
int oalloc_new_prepare(uint32_t vid, uint64_t *start, uint64_t count);
int oalloc_new_finish(uint32_t vid, uint64_t start, uint64_t count);
int oalloc_free(uint32_t vid, uint64_t start, uint64_t count);
int oalloc_init(uint32_t vid);

#endif /* __SHEEP_HTTP_H__ */
