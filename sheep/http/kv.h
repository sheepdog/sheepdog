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

#ifndef __SD_KV_H__
#define __SD_KV_H__

#include "http.h"

#define SD_MAX_BUCKET_NAME 64
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
int kv_update_object(struct http_request *req, const char *bucket,
		     const char *object);
int kv_delete_object(struct http_request *req, const char *account,
		     const char *bucket, const char *object);
int kv_list_objects(struct http_request *req, const char *account,
		    const char *bucket,
		    void (*cb)(struct http_request *req, const char *bucket,
			       const char *object, void *opaque),
		    void *opaque);

#endif /* __SD_KV_H__ */
