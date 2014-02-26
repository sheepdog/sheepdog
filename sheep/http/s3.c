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

#define MAX_BUCKET_LISTING 1000

static void s3_write_err_response(struct http_request *req, const char *code,
				  const char *desc)
{
	http_request_writef(req,
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
		"<Error>\r\n"
		"<Code>%s</Code>\r\n<Message>%s</Message>\r\n"
		"</Error>\r\n", code, desc);
}

/* Operations on the Service */

static void s3_get_service_cb(const char *bucket, void *opaque)
{
}

static void s3_get_service(struct http_request *req)
{
	bool print_header = true;

	kv_iterate_bucket("s3", s3_get_service_cb, &print_header);

	http_request_writes(req, "</Buckets></ListAllMyBucketsResult>\r\n");
}

/* Operations on Buckets */

static void s3_head_bucket(struct http_request *req, const char *bucket)
{
	http_response_header(req, NOT_IMPLEMENTED);
}

static void s3_get_bucket_cb(const char *object, void *opaque)
{
}

static void s3_get_bucket(struct http_request *req, const char *bucket)
{
	bool print_header = true;

	kv_iterate_object("s3", bucket, s3_get_bucket_cb, &print_header);

	switch (req->status) {
	case OK:
		http_request_writes(req, "</ListBucketResult>\r\n");
		break;
	case NOT_FOUND:
		s3_write_err_response(req, "NoSuchBucket",
			"The specified bucket does not exist");
		break;
	default:
		break;
	}
}

static void s3_put_bucket(struct http_request *req, const char *bucket)
{
	kv_create_bucket("s3", bucket);

	if (req->status == ACCEPTED)
		s3_write_err_response(req, "BucketAlreadyExists",
			"The requested bucket name is not available");
}

static void s3_post_bucket(struct http_request *req, const char *bucket)
{
	http_response_header(req, NOT_IMPLEMENTED);
}

static void s3_delete_bucket(struct http_request *req, const char *bucket)
{
	kv_delete_bucket("s3", bucket);

	switch (req->status) {
	case NOT_FOUND:
		s3_write_err_response(req, "NoSuchBucket",
			"The specified bucket does not exist");
		break;
	case CONFLICT:
		s3_write_err_response(req, "BucketNotEmpty",
			"The bucket you tried to delete is not empty");
		break;
	default:
		break;
	}
}

/* Operations on Objects */

static void s3_head_object(struct http_request *req, const char *bucket,
			   const char *object)
{
	http_response_header(req, NOT_IMPLEMENTED);
}

static void s3_get_object(struct http_request *req, const char *bucket,
			  const char *object)
{
	kv_read_object(req, "s3", bucket, object);

	if (req->status == NOT_FOUND)
		s3_write_err_response(req, "NoSuchKey",
			"The resource you requested does not exist");
}

static void s3_put_object(struct http_request *req, const char *bucket,
			  const char *object)
{
	kv_create_object(req, "s3", bucket, object);

	if (req->status == NOT_FOUND)
		s3_write_err_response(req, "NoSuchBucket",
			"The specified bucket does not exist");
}

static void s3_post_object(struct http_request *req, const char *bucket,
			   const char *object)
{
	http_response_header(req, NOT_IMPLEMENTED);
}

static void s3_delete_object(struct http_request *req, const char *bucket,
			     const char *object)
{
	kv_delete_object("s3", bucket, object, 0);

	if (req->status == NOT_FOUND)
		s3_write_err_response(req, "NoSuchKey",
			"The resource you requested does not exist");
}

/* S3 driver interfaces */

static int s3_init(const char *option)
{
	return 0;
}

static void s3_handle_request(struct http_request *req,
			      void (*s_handler)(struct http_request *req),
			      void (*b_handler)(struct http_request *req,
						const char *bucket),
			      void (*o_handler)(struct http_request *req,
						const char *bucket,
						const char *object))
{
	char *args[2] = {};
	char *bucket, *object;

	split_path(req->uri, ARRAY_SIZE(args), args);

	bucket = args[0];
	object = args[1];

	sd_info("%s", str_http_req(req));

	if (bucket == NULL) {
		if (s_handler) {
			sd_info("service operation");
			s_handler(req);
		}
	} else if (object == NULL) {
		sd_info("bucket operation, %s", bucket);
		b_handler(req, bucket);
	} else {
		sd_info("object operation, %s, %s", bucket, object);
		o_handler(req, bucket, object);
	}

	sd_info("%s", str_http_req(req));

	free(bucket);
	free(object);
}

static void s3_head(struct http_request *req)
{
	s3_handle_request(req, NULL, s3_head_bucket, s3_head_object);
}

static void s3_get(struct http_request *req)
{
	s3_handle_request(req, s3_get_service, s3_get_bucket, s3_get_object);
}

static void s3_put(struct http_request *req)
{
	s3_handle_request(req, NULL, s3_put_bucket, s3_put_object);
}

static void s3_post(struct http_request *req)
{
	s3_handle_request(req, NULL, s3_post_bucket, s3_post_object);
}

static void s3_delete(struct http_request *req)
{
	s3_handle_request(req, NULL, s3_delete_bucket, s3_delete_object);
}

static struct http_driver hdrv_s3 = {
	.name	= "s3",

	.init	= s3_init,
	.head	= s3_head,
	.get	= s3_get,
	.put	= s3_put,
	.post	= s3_post,
	.delete	= s3_delete,
};

hdrv_register(hdrv_s3);
