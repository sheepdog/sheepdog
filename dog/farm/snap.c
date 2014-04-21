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

int snap_log_append(uint32_t idx, const char *tag, unsigned char *sha1)
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

/*
 * Empty file, return 0;
 * Failure, return -1;
 * Success, return > 0;
 */
int snap_log_read_hdr(struct snap_log_hdr *hdr)
{
	struct stat st;
	int fd, ret = -1;

	fd = open(snap_log_path, O_RDONLY);
	if (fd < 0) {
		sd_err("%m");
		goto out;
	}

	if (fstat(fd, &st) < 0) {
		sd_err("%m");
		goto out_close;
	}

	if (st.st_size == 0) {
		ret = 0;
		goto out_close;
	}

	ret = xread(fd, hdr, sizeof(*hdr));
	if (ret != sizeof(*hdr)) {
		sd_err("failed to read log header, %m, ret = %d", ret);
		ret = -1;
		goto out_close;
	}
	if (hdr->magic != FARM_MAGIC) {
		sd_err("magic number mismatch");
		ret = -1;
		goto out_close;
	}
	/* If we don't keep backward compatibility, check version */
out_close:
	close(fd);
out:
	return ret;
}

void *snap_log_read(int *out_nr)
{
	struct stat st;
	void *buffer = (void *)-1;
	struct snap_log_hdr hdr;
	int len, fd, ret;

	ret = snap_log_read_hdr(&hdr);
	if (ret < 0)
		goto out;
	else if (ret == 0) {
		*out_nr = 0;
		buffer = NULL;
		goto out;
	}

	fd = open(snap_log_path, O_RDONLY);
	if (fd < 0) {
		sd_err("%m");
		goto out;
	}
	if (fstat(fd, &st) < 0) {
		sd_err("%m");
		goto out_close;
	}

	len = st.st_size - sizeof(hdr);
	buffer = xmalloc(len);
	ret = xpread(fd, buffer, len, sizeof(hdr));
	if (ret != len) {
		free(buffer);
		buffer = (void *)-1;
		goto out_close;
	}
	*out_nr = len / sizeof(struct snap_log);
out_close:
	close(fd);
out:
	return buffer;
}

int snap_log_write_hdr(struct snap_log_hdr *hdr)
{
	int fd, ret;

	fd = open(snap_log_path, O_WRONLY);
	if (fd < 0) {
		sd_err("%m");
		return -1;
	}

	ret = xwrite(fd, hdr, sizeof(*hdr));
	if (ret != sizeof(*hdr)) {
		sd_err("failed to write log hdr, %m, ret = %d", ret);
		return -1;
	}
	return 0;
}
