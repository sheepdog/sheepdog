/*
 * copyright (c) 2013 taobao inc.
 *
 * liu yuan <namei.unix@gmail.com>
 *
 * this program is free software; you can redistribute it and/or
 * modify it under the terms of the gnu general public license version
 * 2 as published by the free software foundation.
 *
 * you should have received a copy of the gnu general public license
 * along with this program. if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Slice is a fixed chunk of one object to be stored in farm. We slice
 * the object into smaller chunks to get better deduplication.
 */

#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>

#include "farm.h"
#include "strbuf.h"
#include "util.h"
#include "sheepdog_proto.h"

struct slice {
	unsigned char sha1[SHA1_DIGEST_SIZE];
};

struct slice_file {
	uint32_t nr_slices;
	struct slice *slices;
};

/* 128k, best empirical value from some tests, but no rationale */
#define SLICE_SIZE (1024*128)

int slice_write(void *buf, size_t len, unsigned char *outsha1)
{
	int count = DIV_ROUND_UP(len, SLICE_SIZE);
	size_t slen = count * SHA1_DIGEST_SIZE;
	char *sbuf = xmalloc(slen);
	char *p = buf;

	for (int i = 0; i < count; i++, p += SLICE_SIZE) {
		unsigned char sha1[SHA1_DIGEST_SIZE];
		size_t wlen = (ssize_t)len - SLICE_SIZE > 0 ? SLICE_SIZE : len;
		len -= SLICE_SIZE;

		if (sha1_file_write(p, wlen, sha1) < 0)
			goto err;
		memcpy(sbuf + i * SHA1_DIGEST_SIZE, sha1, SHA1_DIGEST_SIZE);
	}

	if (sha1_file_write(sbuf, slen, outsha1) < 0)
		goto err;
	free(sbuf);
	return 0;
err:
	free(sbuf);
	return -1;
}

static struct slice_file *slice_file_read(const unsigned char *sha1)
{
	size_t size;
	struct slice_file *slice_file = NULL;
	void *buf = sha1_file_read(sha1, &size);

	if (!buf)
		return NULL;
	slice_file = xmalloc(sizeof(struct slice_file));
	slice_file->nr_slices = size / SHA1_DIGEST_SIZE;
	slice_file->slices = buf;

	return slice_file;
}

void *slice_read(const unsigned char *sha1, size_t *outsize)
{
	struct slice_file *file = slice_file_read(sha1);
	struct strbuf buf = STRBUF_INIT;
	void *object;

	if (!file)
		goto err;

	*outsize = 0;
	for (uint32_t i = 0; i < file->nr_slices; i++) {
		size_t size;
		void *sbuf;

		sbuf = sha1_file_read(file->slices[i].sha1, &size);
		if (!sbuf)
			goto err;
		strbuf_add(&buf, sbuf, size);
		*outsize += size;
	}

	object = xmalloc(*outsize);
	strbuf_copyout(&buf, object, *outsize);
	strbuf_release(&buf);
	return object;
err:
	strbuf_release(&buf);
	return NULL;
}
