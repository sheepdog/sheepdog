/*
 * Copyright (C) 2014 Taobao Inc.
 *
 * Robin Dong <sanbai@taobao.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <curl/curl.h>

#include "strbuf.h"
#include "sheepfs.h"
#include "net.h"

#define PATH_HTTP		"/http"
#define PATH_HTTP_ADDRESS	"/http/address"
#define PATH_HTTP_OBJECT	"/http/object"

#define HTTP_SIZE_NAME		"user.object.size"
#define HTTP_SIZE_SIZE		sizeof(uint64_t)

int create_http_layout(void)
{
	if (shadow_dir_create(PATH_HTTP) < 0)
		return -1;

	if (shadow_file_create(PATH_HTTP_ADDRESS) < 0)
		return -1;
	if (sheepfs_set_op(PATH_HTTP_ADDRESS, OP_HTTP_ADDRESS) < 0)
		return -1;

	if (shadow_file_create(PATH_HTTP_OBJECT) < 0)
		return -1;
	if (sheepfs_set_op(PATH_HTTP_OBJECT, OP_HTTP_OBJECT) < 0)
		return -1;

	return 0;
}

int http_address_read(const char *path, char *buf, size_t size, off_t ignore)
{
	return shadow_file_read(path, buf, size, 0);
}

int http_address_write(const char *path, const char *buf, size_t size,
		       off_t ignore)
{
	return shadow_file_write(path, buf, size);
}

size_t http_address_get_size(const char *path)
{
	struct stat st;
	if (shadow_file_stat(path, &st))
		return st.st_size;
	return 0;
}

static uint64_t curl_get_object_size(const char *url)
{
	CURL *curl;
	CURLcode res;
	double content_length;

	curl = curl_easy_init();
	if (!curl) {
		sheepfs_pr("Failed to init curl");
		goto out;
	}

	curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
	curl_easy_setopt(curl, CURLOPT_NOBODY, true);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "HEAD");
	curl_easy_setopt(curl, CURLOPT_URL, url);
	res = curl_easy_perform(curl);
	if (res == CURLE_OK) {
		res = curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD,
					&content_length);
		if (res != CURLE_OK) {
			sheepfs_pr("Failed to get size of object %s",
			       curl_easy_strerror(res));
			content_length = 0;
		}
	}
out:
	curl_easy_cleanup(curl);
	return (uint64_t)content_length;
}

struct buffer_s {
	char *mem;
	size_t current_size;
	size_t total_size;
};

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t real_size = size * nmemb;
	struct buffer_s *buff = (struct buffer_s *)userp;

	if ((buff->current_size + real_size) > buff->total_size)
		real_size = buff->total_size - buff->current_size;
	memcpy(buff->mem + buff->current_size, contents, real_size);
	buff->current_size += real_size;
	return real_size;
}

static size_t curl_read_object(const char *url, char *buf, size_t size,
			       off_t offset)
{
	CURL *curl;
	CURLcode res;
	char header[PATH_MAX];
	double content_length;
	struct buffer_s buffer = { 0 };
	struct curl_slist *headers = NULL;

	curl = curl_easy_init();
	if (!curl) {
		sheepfs_pr("Failed to init curl");
		goto out;
	}

	snprintf(header, sizeof(header), "Range: bytes=%"PRIu64"-%"PRIu64,
		 offset, offset + size - 1);
	headers = curl_slist_append(headers, header);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	buffer.mem = buf;
	buffer.total_size = size;
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
	res = curl_easy_perform(curl);
	if (res == CURLE_OK) {
		res = curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD,
					&content_length);
		if (res != CURLE_OK) {
			sheepfs_pr("Failed to getinfo res: %s",
			       curl_easy_strerror(res));
			size = 0;
			goto out;
		}
		if ((size_t)content_length > size) {
			sheepfs_pr("Failed to get correct CONTENT_LENGTH, "
			       "content_length: %"PRIu64", get_size: %"PRIu64,
			       (size_t)content_length, size);
			size = 0;
		} else
			sd_debug("Read out %"PRIu64" data from %s", size, url);
	} else {
		sheepfs_pr("Failed to call libcurl res: %s, url: %s",
		       curl_easy_strerror(res), url);
		size = 0;
	}
out:
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	return size;
}

static bool curl_object_exists(const char *url)
{
	CURL *curl;
	CURLcode res;
	bool ret = false;

	curl = curl_easy_init();
	if (!curl) {
		sheepfs_pr("Failed to init curl");
		goto out;
	}

	curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
	curl_easy_setopt(curl, CURLOPT_NOBODY, true);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "HEAD");
	curl_easy_setopt(curl, CURLOPT_URL, url);
	res = curl_easy_perform(curl);
	if (res == CURLE_OK)
		ret = true;
	else
		sheepfs_pr("Failed to call libcurl res: %s, url: %s",
		       curl_easy_strerror(res), url);

out:
	curl_easy_cleanup(curl);
	return ret;
}

struct object_cache {
	uint64_t offset;
	uint64_t length;
	unsigned char *buffer;
};

static int generate_url(const char *buff, int size, char *url, int url_len)
{
	char address[PATH_MAX], *ch;
	int len, ret = 0;

	len = shadow_file_read(PATH_HTTP_ADDRESS, address, sizeof(address), 0);
	if (len <= 0) {
		sheepfs_pr("Can't get address of http");
		ret = -EINVAL;
		goto out;
	}

	/* remove last '\n' of address */
	ch = strchr(address, '\n');
	if (ch != NULL)
		*ch = '\0';

	snprintf(url, url_len, "http://%s/v1%.*s", address, size, buff);
out:
	return ret;
}

int object_read(const char *path, char *buf, size_t size, off_t offset)
{
	char url[PATH_MAX];
	char *pos;
	int ret;

	pos = strstr(path, PATH_HTTP);
	if (!pos) {
		sheepfs_pr("Invalid Path %s", path);
		ret = -EINVAL;
		goto out;
	}

	pos += strlen(PATH_HTTP);
	/* don't need '\n' at the end of 'path' */
	ret = generate_url(pos, strlen(path) - strlen(PATH_HTTP),
			   url, PATH_MAX);
	if (ret)
		goto out;

	ret = curl_read_object(url, buf, size, offset);
out:
	return ret;
}

size_t object_get_size(const char *path)
{
	uint64_t object_size;
	if (shadow_file_getxattr(path, HTTP_SIZE_NAME, &object_size,
				 HTTP_SIZE_SIZE) < 0)
		return 0;

	return object_size;
}

int object_unlink(const char *path)
{
	return shadow_file_delete(path);
}

int container_rmdir(const char *path)
{
	return shadow_dir_delete(path);
}

static int object_create_entry(const char *entry, const char *url)
{
	struct strbuf buf = STRBUF_INIT;
	char *args[3], path[PATH_MAX];
	int nr, ret = -EINVAL;
	uint64_t size;

	nr = split_path(entry, ARRAY_SIZE(args), args);
	if (nr != ARRAY_SIZE(args)) {
		sheepfs_pr("Invalid argument %d, %s", nr, entry);
		goto out;
	}

	strbuf_addf(&buf, "%s", PATH_HTTP);
	for (int i = 0; i < nr; i++) {
		strbuf_addf(&buf, "/%s", args[i]);
		snprintf(path, sizeof(path), "%.*s", (int)buf.len, buf.buf);
		if (i == (nr - 1)) {
			if (shadow_file_create(path) < 0) {
				sheepfs_pr("Create file %s fail", path);
				goto out;
			}
			size = curl_get_object_size(url);
			if (size <= 0) {
				sheepfs_pr("Failed to get size of object");
				shadow_file_delete(path);
				goto out;
			}
			if (shadow_file_setxattr(path, HTTP_SIZE_NAME, &size,
						 HTTP_SIZE_SIZE) < 0) {
				sheepfs_pr("Failed to setxattr for %s",
				       HTTP_SIZE_NAME);
				shadow_file_delete(path);
				goto out;
			}
			if (sheepfs_set_op(path, OP_OBJECT) < 0) {
				sheepfs_pr("Set_op %s fail", path);
				shadow_file_delete(path);
				goto out;
			}
		} else {
			if (shadow_dir_create(path) < 0) {
				sheepfs_pr("Create dir %s fail", path);
				goto out;
			}
			if (sheepfs_set_op(path, OP_CONTAINER) < 0) {
				sheepfs_pr("Set_op %s fail", path);
				shadow_dir_delete(path);
				goto out;
			}
		}
	}
	ret = 0;
out:
	strbuf_release(&buf);
	return ret;
}

int http_object_write(const char *path, const char *buf, size_t size,
		      off_t ignore)
{
	char entry[PATH_MAX], url[PATH_MAX];
	int ret = -EINVAL;

	/* don't need '\n' at the end of 'buf' */
	ret = generate_url(buf, size - 1, url, PATH_MAX);
	if (ret)
		goto out;

	if (curl_object_exists(url)) {
		snprintf(entry, size, "%s", buf);
		ret = object_create_entry(entry, url);
		if (ret >= 0)
			ret = size;
	}
out:
	return ret;
}
