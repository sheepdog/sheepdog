/*
 * Copyright (C) 2011 Taobao Inc.
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

/*
 *   sha1_file provide us some useful features:
 *
 *   - Regardless of object type, all objects are all in deflated with zlib,
 *     and have a header that not only specifies their tag, but also size
 *     information about the data in the object.
 *
 *   - the general consistency of an object can always be tested independently
 *     of the contents or the type of the object: all objects can be validated
 *     by verifying that their hashes match the content of the file.
 */
#include <sys/types.h>

#include "farm.h"
#include "util.h"

static void fill_sha1_path(char *pathbuf, const unsigned char *sha1)
{
	int i;
	for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
		static const char hex[] = "0123456789abcdef";
		unsigned int val = sha1[i];
		char *pos = pathbuf + i*2 + (i > 0);
		*pos++ = hex[val >> 4];
		*pos = hex[val & 0xf];
	}
}

static char *sha1_to_path(const unsigned char *sha1)
{
	static __thread char buf[PATH_MAX];
	const char *objdir;
	int len;

	objdir = get_object_directory();
	len = strlen(objdir);

	/* '/' + sha1(2) + '/' + sha1(38) + '\0' */
	memcpy(buf, objdir, len);
	buf[len] = '/';
	buf[len+3] = '/';
	buf[len+42] = '\0';
	fill_sha1_path(buf + len + 1, sha1);
	return buf;
}

static int sha1_buffer_write(const unsigned char *sha1,
			     void *buf, unsigned int size)
{
	char *filename = sha1_to_path(sha1);
	int fd, ret = 0, len;

	fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0666);
	if (fd < 0) {
		if (errno != EEXIST) {
			sd_err("failed to open file %s with error: %m",
			       filename);
			ret = -1;
		}
		goto err_open;
	}
	len = xwrite(fd, buf, size);
	if (len != size) {
		sd_err("%m");
		close(fd);
		return -1;
	}

	close(fd);
err_open:
	return ret;
}

int sha1_file_write(void *buf, size_t len, unsigned char *outsha1)
{
	unsigned char sha1[SHA1_DIGEST_SIZE];

	sha1_from_buffer(buf, len, sha1);
	if (sha1_buffer_write(sha1, buf, len) < 0)
		return -1;
	if (outsha1)
		memcpy(outsha1, sha1, SHA1_DIGEST_SIZE);
	return 0;
}

static int verify_sha1_file(const unsigned char *sha1,
			    void *buf, unsigned long len)
{
	unsigned char tmp[SHA1_DIGEST_SIZE];

	sha1_from_buffer(buf, len, tmp);
	if (memcmp((char *)tmp, (char *)sha1, SHA1_DIGEST_SIZE) != 0) {
		sd_err("failed, %s != %s", sha1_to_hex(sha1), sha1_to_hex(tmp));
		return -1;
	}
	return 0;
}

void *sha1_file_read(const unsigned char *sha1, size_t *size)
{
	char *filename = sha1_to_path(sha1);
	int fd = open(filename, O_RDONLY);
	struct stat st;
	void *buf = NULL;

	if (fd < 0) {
		perror(filename);
		return NULL;
	}
	if (fstat(fd, &st) < 0) {
		sd_err("%m");
		goto out;
	}

	buf = xmalloc(st.st_size);
	if (!buf)
		goto out;

	if (xread(fd, buf, st.st_size) != st.st_size) {
		free(buf);
		buf = NULL;
		goto out;
	}

	if (verify_sha1_file(sha1, buf, st.st_size) < 0) {
		free(buf);
		buf = NULL;
		goto out;
	}

	*size = st.st_size;
out:
	close(fd);
	return buf;
}
