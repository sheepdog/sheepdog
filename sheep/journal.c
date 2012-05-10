/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>

#include "sheep_priv.h"

#define JRNL_END_MARK           0x87654321UL

/* Journal header for data object */
struct jrnl_head {
	uint64_t offset;
	uint64_t size;
	char target_path[256];
};

struct jrnl_descriptor {
	struct jrnl_head head;
	const void *data;
	int fd;      /* Open file fd */
	int target_fd;
	char path[256];
};

/* Journal APIs */
static int jrnl_open(struct jrnl_descriptor *jd, const char *path)
{
	strcpy(jd->path, path);
	jd->fd = open(path, O_RDONLY);

	if (jd->fd < 0) {
		eprintf("failed to open %s: %m\n", jd->path);
		if (errno == ENOENT)
			return SD_RES_NO_OBJ;
		else
			return SD_RES_UNKNOWN;
	}

	return SD_RES_SUCCESS;
}

static int jrnl_close(struct jrnl_descriptor *jd)
{
	close(jd->fd);
	jd->fd = -1;

	return 0;
}

static int jrnl_create(struct jrnl_descriptor *jd, const char *jrnl_dir)
{
	snprintf(jd->path, sizeof(jd->path), "%sXXXXXX", jrnl_dir);
	jd->fd = mkostemp(jd->path, O_DSYNC);

	if (jd->fd < 0) {
		eprintf("failed to create %s: %m\n", jd->path);
		return SD_RES_UNKNOWN;
	}

	return SD_RES_SUCCESS;
}

static int jrnl_remove(struct jrnl_descriptor *jd)
{
	int ret;

	ret = unlink(jd->path);
	if (ret) {
		eprintf("failed to remove %s: %m\n", jd->path);
		ret = SD_RES_EIO;
	} else
		ret = SD_RES_SUCCESS;

	return ret;
}

static int jrnl_write_header(struct jrnl_descriptor *jd)
{
	ssize_t ret;
	struct jrnl_head *head = (struct jrnl_head *) &jd->head;

	ret = pwrite64(jd->fd, head, sizeof(*head), 0);

	if (ret != sizeof(*head)) {
		if (errno == ENOSPC)
			ret = SD_RES_NO_SPACE;
		else
			ret = SD_RES_EIO;
	} else
		ret = SD_RES_SUCCESS;

	return ret;
}

static int jrnl_write_data(struct jrnl_descriptor *jd)
{
	ssize_t ret;
	struct jrnl_head *head = (struct jrnl_head *) &jd->head;

	ret = pwrite64(jd->fd, jd->data, head->size, sizeof(*head));

	if (ret != head->size) {
		if (errno == ENOSPC)
			ret = SD_RES_NO_SPACE;
		else
			ret = SD_RES_EIO;
	} else
		ret = SD_RES_SUCCESS;

	return ret;
}

static int jrnl_write_end_mark(struct jrnl_descriptor *jd)
{
	ssize_t retsize;
	int ret;
	uint32_t end_mark = JRNL_END_MARK;
	struct jrnl_head *head = (struct jrnl_head *) &jd->head;

	retsize = pwrite64(jd->fd, &end_mark, sizeof(end_mark),
			   sizeof(*head) + head->size);

	if (retsize != sizeof(end_mark)) {
		if (errno == ENOSPC)
			ret = SD_RES_NO_SPACE;
		else
			ret = SD_RES_EIO;
	} else
		ret = SD_RES_SUCCESS;

	return ret;
}

static int jrnl_apply_to_target_object(struct jrnl_descriptor *jd)
{
	char *buf = NULL;
	int buf_len, res = 0;
	ssize_t retsize;

	/* FIXME: handle larger size */
	buf_len = (1 << 22);
	buf = zalloc(buf_len);
	if (!buf) {
		eprintf("failed to allocate memory\n");
		return SD_RES_NO_MEM;
	}

	/* Flush out journal to disk (VDI object) */
	retsize = pread64(jd->fd, &jd->head, sizeof(jd->head), 0);
	retsize = pread64(jd->fd, buf, jd->head.size, sizeof(jd->head));
	retsize = pwrite64(jd->target_fd, buf, jd->head.size, jd->head.offset);
	if (retsize != jd->head.size) {
		if (errno == ENOSPC)
			res = SD_RES_NO_SPACE;
		else
			res = SD_RES_EIO;
	}

	/* Clean up */
	free(buf);

	return res;
}

/*
 * We cannot use this function for concurrent write operations
 */
struct jrnl_descriptor *jrnl_begin(const void *buf, size_t count, off_t offset,
		 const char *path, const char *jrnl_dir)
{
	int ret;
	struct jrnl_descriptor *jd = xzalloc(sizeof(*jd));

	jd->head.offset = offset;
	jd->head.size = count;
	strcpy(jd->head.target_path, path);

	jd->data = buf;

	ret = jrnl_create(jd, jrnl_dir);
	if (ret)
		goto err;

	ret = jrnl_write_header(jd);
	if (ret)
		goto err;

	ret = jrnl_write_data(jd);
	if (ret)
		goto err;

	ret = jrnl_write_end_mark(jd);
	if (ret)
		goto err;
	return jd;
err:
	free(jd);
	return NULL;
}

int jrnl_end(struct jrnl_descriptor * jd)
{
	int ret = 0;
	if (!jd)
		return ret;

	ret = jrnl_close(jd);
	if (ret)
		goto err;

	ret = jrnl_remove(jd);
err:
	free(jd);
	return ret;
}

int jrnl_recover(const char *jrnl_dir)
{
	DIR *dir;
	struct dirent *d;
	char jrnl_file_path[PATH_MAX];

	eprintf("opening the directory %s\n", jrnl_dir);
	dir = opendir(jrnl_dir);
	if (!dir)
		return -1;

	vprintf(SDOG_NOTICE, "starting journal recovery\n");
	while ((d = readdir(dir))) {
		struct jrnl_descriptor jd;
		uint32_t end_mark = 0;
		int ret;

		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		snprintf(jrnl_file_path, sizeof(jrnl_file_path), "%s%s",
			 jrnl_dir, d->d_name);
		ret = jrnl_open(&jd, jrnl_file_path);
		if (ret) {
			eprintf("unable to open the journal file %s for reading\n",
				jrnl_file_path);
			goto end_while_3;
		}

		ret = pread64(jd.fd, &end_mark, sizeof(end_mark),
				sizeof(jd.head) + jd.head.size);
		if (ret != sizeof(end_mark)) {
			eprintf("can't read journal end mark for object %s\n",
				jd.head.target_path);
			goto end_while_2;
		}

		if (end_mark != JRNL_END_MARK)
			goto end_while_2;

		jd.target_fd = open(jd.head.target_path, O_DSYNC | O_RDWR);
		if (ret) {
			eprintf("unable to open the object file %s for recovery\n",
				jd.head.target_path);
			goto end_while_2;
		}
		ret = jrnl_apply_to_target_object(&jd);
		if (ret)
			eprintf("unable to recover the object %s\n",
				jd.head.target_path);

		close(jd.target_fd);
		jd.target_fd = -1;
end_while_2:
		jrnl_close(&jd);
end_while_3:
		vprintf(SDOG_INFO, "recovered the object %s from the journal\n",
			jrnl_file_path);
		jrnl_remove(&jd);
	}
	closedir(dir);
	vprintf(SDOG_NOTICE, "journal recovery complete\n");

	return 0;
}
