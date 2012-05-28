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
#include <sys/xattr.h>

#include "farm.h"
#include "util.h"

static inline char *get_object_directory(void)
{
	return farm_obj_dir;
}

static void fill_sha1_path(char *pathbuf, const unsigned char *sha1)
{
	int i;
	for (i = 0; i < SHA1_LEN; i++) {
		static char hex[] = "0123456789abcdef";
		unsigned int val = sha1[i];
		char *pos = pathbuf + i*2 + (i > 0);
		*pos++ = hex[val >> 4];
		*pos = hex[val & 0xf];
	}
}

char *sha1_to_path(const unsigned char *sha1)
{

	static char buf[PATH_MAX];
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

#define CNAME	"user.farm.count"
#define CSIZE	sizeof(uint32_t)

static void get_sha1_file(char *name)
{
	uint32_t count;
	if (getxattr(name, CNAME, &count, CSIZE) < 0) {
		if (errno == ENODATA) {
			count = 1;
			if (setxattr(name, CNAME, &count, CSIZE, 0) < 0)
				panic("%m\n");
			return;
		} else
			panic("%m\n");
	}
	count++;
	if (setxattr(name, CNAME, &count, CSIZE, 0) < 0)
			panic("%m\n");
}

static int put_sha1_file(char *name)
{
	uint32_t count;

	if (getxattr(name, CNAME, &count, CSIZE) < 0) {
		if (errno == ENOENT) {
			dprintf("sha1 file doesn't exist\n");
			return -1;
		} else {
			panic("%m\n");
		}
	}

	count--;
	if (count == 0) {
		if (unlink(name) < 0) {
			dprintf("%m\n");
			return -1;
		}
		dprintf("%s deleted\n", name);
	} else {
		if (setxattr(name, CNAME, &count, CSIZE, 0) < 0)
			panic("%m\n");
	}
	return 0;
}

static int sha1_buffer_write(const unsigned char *sha1, void *buf, unsigned int size)
{
	char *filename = sha1_to_path(sha1);
	int fd, ret = 0, len;

	fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0666);
	if (fd < 0) {
		if (errno != EEXIST)
			ret = -1;
		goto err_open;
	}
	len = xwrite(fd, buf, size);
	if (len != size) {
		close(fd);
		return -1;
	}

	close(fd);
	get_sha1_file(filename);
err_open:
	return ret;
}

int sha1_file_write(unsigned char *buf, unsigned len, unsigned char *outsha1)
{
	unsigned char sha1[SHA1_LEN];
	SHA_CTX c;

	SHA1_Init(&c);
	SHA1_Update(&c, buf, len);
	SHA1_Final(sha1, &c);

	if (sha1_buffer_write(sha1, buf, len) < 0)
		return -1;
	if (outsha1)
		memcpy(outsha1, sha1, SHA1_LEN);
	return 0;
}

static void *map_sha1_file(const unsigned char *sha1, unsigned long *size)
{
	char *filename = sha1_to_path(sha1);
	int fd = open(filename, O_RDONLY);
	struct stat st;
	void *map;

	if (fd < 0) {
		perror(filename);
		return NULL;
	}
	if (fstat(fd, &st) < 0) {
		close(fd);
		return NULL;
	}
	map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (map == MAP_FAILED)
		return NULL;
	*size = st.st_size;
	return map;
}

static void *unpack_sha1_file(void *map, unsigned long mapsize, struct sha1_file_hdr *hdr)
{
	int hdr_len;
	char *buf;

	memcpy(hdr, map, sizeof(*hdr));
	hdr_len = sizeof(*hdr);
	buf = valloc(hdr->size);
	if (!buf) {
		dprintf("%m\n");
		return NULL;
	}

	memcpy(buf, (char *)map + hdr_len, mapsize - hdr_len);
	return buf;
}

static int verify_sha1_file(const unsigned char *sha1, void *buf, unsigned long len)
{
	unsigned char tmp[SHA1_LEN];
	SHA_CTX c;

	SHA1_Init(&c);
	SHA1_Update(&c, buf, len);
	SHA1_Final(tmp, &c);

	if (memcmp((char *)tmp, (char *)sha1, SHA1_LEN) != 0) {
		dprintf("failed, %s != %s\n", sha1_to_hex(sha1),
			sha1_to_hex(tmp));
		return -1;
	}
	return 0;
}

void *sha1_file_read(const unsigned char *sha1, struct sha1_file_hdr *hdr)
{
	unsigned long mapsize;
	void *map, *buf;

	map = map_sha1_file(sha1, &mapsize);
	if (map) {
		if (verify_sha1_file(sha1, map, mapsize) < 0)
			return NULL;
		buf = unpack_sha1_file(map, mapsize, hdr);
		munmap(map, mapsize);
		return buf;
	}
	return NULL;
}

int sha1_file_try_delete(const unsigned char *sha1)
{
	char *filename = sha1_to_path(sha1);

	return put_sha1_file(filename);
}

static unsigned hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return ~0;
}

int get_sha1_hex(const char *hex, unsigned char *sha1)
{
	int i;
	for (i = 0; i < SHA1_LEN; i++) {
		unsigned int val = (hexval(hex[0]) << 4) | hexval(hex[1]);
		if (val & ~0xff)
			return -1;
		*sha1++ = val;
		hex += 2;
	}
	return 0;
}

char *sha1_to_hex(const unsigned char *sha1)
{
	static char buffer[50];
	static const char hex[] = "0123456789abcdef";
	char *buf = buffer;
	int i;

	for (i = 0; i < SHA1_LEN; i++) {
		unsigned int val = *sha1++;
		*buf++ = hex[val >> 4];
		*buf++ = hex[val & 0xf];
	}
	return buffer;
}
