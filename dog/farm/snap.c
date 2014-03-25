/*
 * Copyright (C) 2011 Taobao Inc.
 * Copyright (C) 2013 Zelin.io
 *
 * Liu Yuan <namei.unix@gmail.com>
 * Kai Zhang <kyle@zelin.io>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/* Snap object is the meta data that describes the cluster snapshot. */

#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#include "farm.h"

static char snap_log_path[PATH_MAX];

int snap_init(const char *farm_dir)
{
	int fd, ret = -1;
	struct strbuf buf = STRBUF_INIT;

	strbuf_addstr(&buf, farm_dir);
	strbuf_addf(&buf, "/%s", "user_snap");

	if (!strlen(snap_log_path))
		strbuf_copyout(&buf, snap_log_path, sizeof(snap_log_path));

	fd = open(snap_log_path, O_CREAT | O_EXCL, 0666);
	if (fd < 0) {
		if (errno != EEXIST) {
			sd_err("%m");
			goto out;
		}
	}

	ret = 0;
	close(fd);
out:
	strbuf_release(&buf);
	return ret;
}

int snap_log_write(uint32_t idx, const char *tag, unsigned char *sha1)
{
	int fd, ret = -1;
	struct strbuf buf = STRBUF_INIT;
	struct snap_log log = { .idx = idx,
				.time = time(NULL) };
	pstrcpy(log.tag, SD_MAX_SNAPSHOT_TAG_LEN, tag);
	memcpy(log.trunk_sha1, sha1, SHA1_DIGEST_SIZE);

	fd = open(snap_log_path, O_WRONLY | O_APPEND);
	if (fd < 0) {
		sd_err("%m");
		goto out;
	}

	strbuf_reset(&buf);
	strbuf_add(&buf, &log, sizeof(log));
	ret = xwrite(fd, buf.buf, buf.len);
	if (ret != buf.len)
		goto out_close;

	ret = 0;
out_close:
	close(fd);
out:
	strbuf_release(&buf);
	return ret;
}

void *snap_log_read(int *out_nr)
{
	struct stat st;
	void *buffer = NULL;
	int len, fd;

	fd = open(snap_log_path, O_RDONLY);
	if (fd < 0) {
		sd_err("%m");
		goto out;
	}
	if (fstat(fd, &st) < 0) {
		sd_err("%m");
		goto out_close;
	}

	len = st.st_size;
	buffer = xmalloc(len);
	len = xread(fd, buffer, len);
	if (len != st.st_size) {
		free(buffer);
		buffer = NULL;
		goto out_close;
	}
	*out_nr = len / sizeof(struct snap_log);
out_close:
	close(fd);
out:
	return buffer;
}
