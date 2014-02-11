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

#include "strbuf.h"
#include "http.h"

/* Operations on Accounts */

static void swift_head_account(struct http_request *req, const char *account)
{
	int ret;

	ret = kv_read_account_meta(req, account);
	if (ret == SD_RES_SUCCESS)
		http_response_header(req, NO_CONTENT);
	else
		http_response_header(req, UNAUTHORIZED);
}

static void swift_get_account_cb(const char *bucket, void *opaque)
{
	struct strbuf *buf = (struct strbuf *)opaque;

	strbuf_addf(buf, "%s\n", bucket);
}

static void swift_get_account(struct http_request *req, const char *account)
{
	struct strbuf buf = STRBUF_INIT;
	int ret;

	ret = kv_iterate_bucket(account, swift_get_account_cb, &buf);
	switch (ret) {
	case SD_RES_SUCCESS:
		req->data_length = buf.len;
		http_response_header(req, OK);
		http_request_write(req, buf.buf, buf.len);
		break;
	case SD_RES_NO_VDI:
		http_response_header(req, NOT_FOUND);
		break;
	default:
		http_response_header(req, INTERNAL_SERVER_ERROR);
		break;
	}
	strbuf_release(&buf);
}

static void swift_put_account(struct http_request *req, const char *account)
{
	int ret;

	ret = kv_create_account(account);
	if (ret == SD_RES_SUCCESS)
		http_response_header(req, CREATED);
	else if (ret == SD_RES_VDI_EXIST)
		http_response_header(req, ACCEPTED);
	else
		http_response_header(req, INTERNAL_SERVER_ERROR);
}

static void swift_post_account(struct http_request *req, const char *account)
{
	http_response_header(req, NOT_IMPLEMENTED);
}

static void swift_delete_account(struct http_request *req, const char *account)
{
	int ret;

	ret = kv_delete_account(req, account);
	switch (ret) {
	case SD_RES_SUCCESS:
		http_response_header(req, NO_CONTENT);
		break;
	case SD_RES_NO_VDI:
	case SD_RES_NO_OBJ:
		http_response_header(req, NOT_FOUND);
		break;
	case SD_RES_VDI_NOT_EMPTY:
		http_response_header(req, CONFLICT);
		break;
	default:
		http_response_header(req, INTERNAL_SERVER_ERROR);
		break;
	}
}

/* Operations on Containers */

static void swift_head_container(struct http_request *req, const char *account,
				 const char *container)
{
	int ret;

	ret = kv_read_bucket(req, account, container);
	switch (ret) {
	case SD_RES_SUCCESS:
		http_response_header(req, NO_CONTENT);
		break;
	case SD_RES_NO_VDI:
	case SD_RES_NO_OBJ:
		http_response_header(req, NOT_FOUND);
		break;
	default:
		http_response_header(req, INTERNAL_SERVER_ERROR);
		break;
	}
}

static void swift_get_container_cb(const char *object, void *opaque)
{
	struct strbuf *buf = (struct strbuf *)opaque;

	strbuf_addf(buf, "%s\n", object);
}

static void swift_get_container(struct http_request *req, const char *account,
				const char *container)
{
	struct strbuf buf = STRBUF_INIT;
	int ret;

	ret = kv_iterate_object(account, container, swift_get_container_cb,
				&buf);
	switch (ret) {
	case SD_RES_SUCCESS:
		req->data_length = buf.len;
		http_response_header(req, OK);
		http_request_write(req, buf.buf, buf.len);
		break;
	case SD_RES_NO_VDI:
		http_response_header(req, NOT_FOUND);
		break;
	default:
		http_response_header(req, INTERNAL_SERVER_ERROR);
		break;
	}
	strbuf_release(&buf);
}

static void swift_put_container(struct http_request *req, const char *account,
				const char *container)
{
	int ret;
	ret = kv_create_bucket(account, container);
	switch (ret) {
	case SD_RES_SUCCESS:
		http_response_header(req, CREATED);
		break;
	case SD_RES_VDI_EXIST:
		http_response_header(req, ACCEPTED);
		break;
	default:
		http_response_header(req, INTERNAL_SERVER_ERROR);
		break;
	}
}

static void swift_post_container(struct http_request *req, const char *account,
				 const char *container)
{
	http_response_header(req, NOT_IMPLEMENTED);
}

static void swift_delete_container(struct http_request *req,
				   const char *account, const char *container)
{
	int ret;

	ret = kv_delete_bucket(account, container);
	switch (ret) {
	case SD_RES_SUCCESS:
		http_response_header(req, NO_CONTENT);
		break;
	case SD_RES_NO_VDI:
	case SD_RES_NO_OBJ:
		http_response_header(req, NOT_FOUND);
		break;
	case SD_RES_VDI_NOT_EMPTY:
		http_response_header(req, CONFLICT);
		break;
	default:
		http_response_header(req, INTERNAL_SERVER_ERROR);
		break;
	}
}

/* Operations on Objects */

static void swift_head_object(struct http_request *req, const char *account,
			      const char *container, const char *object)
{
	int ret;

	ret = kv_read_object_meta(req, account, container, object);
	switch (ret) {
	case SD_RES_SUCCESS:
		http_response_header(req, OK);
		break;
	case SD_RES_NO_VDI:
	case SD_RES_NO_OBJ:
		http_response_header(req, NOT_FOUND);
		break;
	default:
		http_response_header(req, INTERNAL_SERVER_ERROR);
		break;
	}
}

static void swift_get_object(struct http_request *req, const char *account,
			     const char *container, const char *object)
{
	int ret;

	ret = kv_read_object(req, account, container, object);
	switch (ret) {
	case SD_RES_SUCCESS:
		break;
	case SD_RES_NO_VDI:
	case SD_RES_NO_OBJ:
		http_response_header(req, NOT_FOUND);
		break;
	case SD_RES_INVALID_PARMS:
		http_response_header(req, REQUEST_RANGE_NOT_SATISFIABLE);
		break;
	case SD_RES_EIO:
		http_response_header(req, PARTIAL_CONTENT);
		break;
	default:
		http_response_header(req, INTERNAL_SERVER_ERROR);
		break;
	}
}

static void swift_put_object(struct http_request *req, const char *account,
			     const char *container, const char *object)
{
	int ret;

	ret = kv_create_object(req, account, container, object);
	switch (ret) {
	case SD_RES_SUCCESS:
		http_response_header(req, CREATED);
		break;
	case SD_RES_NO_VDI:
		http_response_header(req, NOT_FOUND);
		break;
	case SD_RES_NO_SPACE:
		http_response_header(req, SERVICE_UNAVAILABLE);
	default:
		http_response_header(req, INTERNAL_SERVER_ERROR);
		break;
	}
}

static void swift_post_object(struct http_request *req, const char *account,
			      const char *container, const char *object)
{
	http_response_header(req, NOT_IMPLEMENTED);
}

static void swift_delete_object(struct http_request *req, const char *account,
				const char *container, const char *object)
{
	int ret;

	ret = kv_delete_object(account, container, object);
	switch (ret) {
	case SD_RES_SUCCESS:
		http_response_header(req, NO_CONTENT);
		break;
	case SD_RES_NO_VDI:
	case SD_RES_NO_OBJ:
		http_response_header(req, NOT_FOUND);
		break;
	default:
		http_response_header(req, INTERNAL_SERVER_ERROR);
		break;
	}
}

/* Swift driver interfaces */

static int swift_init(const char *option)
{
	return 0;
}

static void swift_handle_request(struct http_request *req,
				 void (*a_handler)(struct http_request *req,
						   const char *account),
				 void (*c_handler)(struct http_request *req,
						   const char *account,
						   const char *container),
				 void (*o_handler)(struct http_request *req,
						   const char *account,
						   const char *container,
						   const char *object))
{
	char *args[4] = {};
	char *version, *account, *container, *object;

	split_path(req->uri, ARRAY_SIZE(args), args);

	version = args[0];
	account = args[1];
	container = args[2];
	object = args[3];

	sd_info("%s", str_http_req(req));

	if (account == NULL) {
		sd_info("invalid uri: %s", req->uri);
		http_response_header(req, NOT_FOUND);
	} else if (container == NULL) {
		sd_info("account operation, %s", account);
		a_handler(req, account);
	} else if (object == NULL) {
		sd_info("container operation, %s, %s", account, container);
		c_handler(req, account, container);
	} else {
		sd_info("object operation, %s, %s, %s", account, container,
			object);
		o_handler(req, account, container, object);
	}

	sd_info("%s", str_http_req(req));

	free(version);
	free(account);
	free(container);
	free(object);
}

static void swift_head(struct http_request *req)
{
	swift_handle_request(req, swift_head_account, swift_head_container,
			     swift_head_object);
}

static void swift_get(struct http_request *req)
{
	swift_handle_request(req, swift_get_account, swift_get_container,
			     swift_get_object);
}

static void swift_put(struct http_request *req)
{
	swift_handle_request(req, swift_put_account, swift_put_container,
			     swift_put_object);
}

static void swift_post(struct http_request *req)
{
	swift_handle_request(req, swift_post_account, swift_post_container,
			     swift_post_object);
}

static void swift_delete(struct http_request *req)
{
	swift_handle_request(req, swift_delete_account, swift_delete_container,
			     swift_delete_object);
}

static struct http_driver hdrv_swift = {
	.name	= "swift",

	.init	= swift_init,
	.head	= swift_head,
	.get	= swift_get,
	.put	= swift_put,
	.post	= swift_post,
	.delete	= swift_delete,
};

hdrv_register(hdrv_swift);
