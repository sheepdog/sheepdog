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

#include "http.h"
#include "kv.h"

static void make_bucket_path(char *bucket, size_t size, const char *account,
			     const char *container)
{
	const char *args[] = { account, container };

	make_path(bucket, size, ARRAY_SIZE(args), args);
}

/* Operations on Accounts */

static void swift_head_account(struct http_request *req, const char *account)
{
	http_response_header(req, NOT_IMPLEMENTED);
}

static void swift_get_account_cb(struct http_request *req, const char *bucket,
				 void *opaque)
{
	const char *account = opaque;
	char *args[2] = {};

	split_path(bucket, ARRAY_SIZE(args), args);

	if (args[1] != NULL && strcmp(args[0], account) == 0) {
		http_request_writes(req, args[1]);
		http_request_writes(req, "\n");
	}
}

static void swift_get_account(struct http_request *req, const char *account)
{
	kv_list_buckets(req, swift_get_account_cb, (void *)account);
}

static void swift_put_account(struct http_request *req, const char *account)
{
	http_response_header(req, NOT_IMPLEMENTED);
}

static void swift_post_account(struct http_request *req, const char *account)
{
	http_response_header(req, NOT_IMPLEMENTED);
}

static void swift_delete_account_cb(struct http_request *req,
				    const char *bucket, void *opaque)
{
	const char *account = opaque;
	char *args[2] = {};

	split_path(bucket, ARRAY_SIZE(args), args);

	if (args[1] != NULL && strcmp(args[0], account) == 0)
		kv_delete_bucket(req, bucket);
}

static void swift_delete_account(struct http_request *req, const char *account)
{
	kv_list_buckets(req, swift_delete_account_cb, (void *)account);
}

/* Operations on Containers */

static void swift_head_container(struct http_request *req, const char *account,
				 const char *container)
{
	http_response_header(req, NOT_IMPLEMENTED);
}

static void swift_get_container_cb(struct http_request *req, const char *bucket,
				   const char *object, void *opaque)
{
	http_request_writes(req, object);
	http_request_writes(req, "\n");
}

static void swift_get_container(struct http_request *req, const char *account,
				const char *container)
{
	char bucket[SD_MAX_BUCKET_NAME];

	make_bucket_path(bucket, sizeof(bucket), account, container);
	kv_list_objects(req, bucket, swift_get_container_cb, NULL);
}

static void swift_put_container(struct http_request *req, const char *account,
				const char *container)
{
	char bucket[SD_MAX_BUCKET_NAME];

	make_bucket_path(bucket, sizeof(bucket), account, container);
	kv_create_bucket(req, bucket);
}

static void swift_post_container(struct http_request *req, const char *account,
				 const char *container)
{
	http_response_header(req, NOT_IMPLEMENTED);
}

static void swift_delete_container(struct http_request *req,
				   const char *account, const char *container)
{
	char bucket[SD_MAX_BUCKET_NAME];

	make_bucket_path(bucket, sizeof(bucket), account, container);
	kv_delete_bucket(req, bucket);
}

/* Operations on Objects */

static void swift_head_object(struct http_request *req, const char *account,
			      const char *container, const char *object)
{
	http_response_header(req, NOT_IMPLEMENTED);
}

static void swift_get_object(struct http_request *req, const char *account,
			     const char *container, const char *object)
{
	char bucket[SD_MAX_BUCKET_NAME];

	make_bucket_path(bucket, sizeof(bucket), account, container);
	kv_read_object(req, bucket, object);
}

static void swift_put_object(struct http_request *req, const char *account,
			     const char *container, const char *object)
{
	char bucket[SD_MAX_BUCKET_NAME];

	make_bucket_path(bucket, sizeof(bucket), account, container);
	kv_create_object(req, bucket, object);
}

static void swift_post_object(struct http_request *req, const char *account,
			      const char *container, const char *object)
{
	http_response_header(req, NOT_IMPLEMENTED);
}

static void swift_delete_object(struct http_request *req, const char *account,
				const char *container, const char *object)
{
	char bucket[SD_MAX_BUCKET_NAME];

	make_bucket_path(bucket, sizeof(bucket), account, container);
	kv_delete_object(req, bucket, object);
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
