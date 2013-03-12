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

#include <pthread.h>
#include <linux/limits.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include "farm.h"
#include "sheep_priv.h"
#include "sheepdog_proto.h"
#include "sheep.h"

char farm_obj_dir[PATH_MAX];
char farm_dir[PATH_MAX];

static int create_directory(const char *p)
{
	int i, ret = 0;
	struct strbuf buf = STRBUF_INIT;

	strbuf_addstr(&buf, p);
	strbuf_addstr(&buf, ".farm");
	if (mkdir(buf.buf, 0755) < 0) {
		if (errno != EEXIST) {
			sd_eprintf("%m");
			ret = -1;
			goto err;
		}
	}

	if (!strlen(farm_dir))
		strbuf_copyout(&buf, farm_dir, sizeof(farm_dir));

	strbuf_addstr(&buf, "/objects");
	if (mkdir(buf.buf, 0755) < 0) {
		if (errno != EEXIST) {
			sd_eprintf("%m");
			ret = -1;
			goto err;
		}
	}
	for (i = 0; i < 256; i++) {
		strbuf_addf(&buf, "/%02x", i);
		if (mkdir(buf.buf, 0755) < 0) {
			if (errno != EEXIST) {
				sd_eprintf("%m");
				ret = -1;
				goto err;
			}
		}
		strbuf_remove(&buf, buf.len - 3, 3);
	}

	if (!strlen(farm_obj_dir))
		strbuf_copyout(&buf, farm_obj_dir, sizeof(farm_obj_dir));
err:
	strbuf_release(&buf);
	return ret;
}

static int get_trunk_sha1(uint32_t epoch, unsigned char *outsha1)
{
	int i, nr_logs = -1, ret = -1;
	struct snap_log *log_buf, *log_free = NULL;
	void *snap_buf = NULL;
	struct sha1_file_hdr hdr;

	log_free = log_buf = snap_log_read(&nr_logs);
	sd_dprintf("%d", nr_logs);
	if (nr_logs < 0)
		goto out;

	for (i = 0; i < nr_logs; i++, log_buf++) {
		if (log_buf->epoch != epoch)
			continue;
		snap_buf = snap_file_read(log_buf->sha1, &hdr);
		if (!snap_buf)
			goto out;
		memcpy(outsha1, snap_buf, SHA1_LEN);
		ret = 0;
		break;
	}
out:
	free(log_free);
	free(snap_buf);
	return ret;
}

static int farm_init(const char *p)
{
	sd_dprintf("use farm store driver");
	if (create_directory(p) < 0)
		goto err;

	if (!is_xattr_enabled(p)) {
		sd_eprintf("xattrs are not enabled on %s", p);
		goto err;
	}

	if (snap_init() < 0)
		goto err;

	if (default_init(p) < 0)
		goto err;

	return SD_RES_SUCCESS;
err:
	return SD_RES_EIO;
}

static int farm_snapshot(const struct siocb *iocb)
{
	unsigned char snap_sha1[SHA1_LEN];
	unsigned char trunk_sha1[SHA1_LEN];
	struct sd_node nodes[SD_MAX_NODES];
	int nr_nodes;
	void *buffer;
	int log_nr, ret = SD_RES_EIO, epoch;

	buffer = snap_log_read(&log_nr);
	if (!buffer)
		goto out;

	epoch = log_nr + 1;
	sd_dprintf("user epoch %d", epoch);

	nr_nodes = epoch_log_read(sys->epoch, nodes, sizeof(nodes));
	if (nr_nodes < 0)
		goto out;

	if (trunk_file_write(trunk_sha1) < 0)
		goto out;

	if (snap_file_write(sys->epoch, nodes, nr_nodes,
			    trunk_sha1, snap_sha1) < 0)
		goto out;

	if (snap_log_write(epoch, snap_sha1) < 0)
		goto out;

	ret = SD_RES_SUCCESS;
out:
	free(buffer);
	return ret;
}

static int restore_objects_from_snap(uint32_t epoch)
{
	struct sha1_file_hdr hdr;
	struct trunk_entry *trunk_buf, *trunk_free = NULL;
	unsigned char trunk_sha1[SHA1_LEN];
	uint64_t nr_trunks, i;
	int ret = SD_RES_EIO;

	if (get_trunk_sha1(epoch, trunk_sha1) < 0)
		goto out;

	trunk_free = trunk_buf = trunk_file_read(trunk_sha1, &hdr);
	if (!trunk_buf)
		goto out;

	nr_trunks = hdr.priv;
	ret = SD_RES_SUCCESS;
	for (i = 0; i < nr_trunks; i++, trunk_buf++) {
		struct sha1_file_hdr h;
		struct siocb io = { 0 };
		uint64_t oid;
		void *buffer = NULL;

		oid = trunk_buf->oid;
		buffer = sha1_file_read(trunk_buf->sha1, &h);
		if (!buffer) {
			sd_eprintf("oid %"PRIx64" not restored", oid);
			goto out;
		}
		io.length = h.size;
		io.buf = buffer;
		ret = default_create_and_write(oid, &io);
		if (ret != SD_RES_SUCCESS) {
			sd_eprintf("oid %"PRIx64" not restored", oid);
			goto out;
		} else
			sd_dprintf("oid %"PRIx64" restored", oid);

		free(buffer);
	}
out:
	free(trunk_free);
	return ret;
}

static int rm_object(uint64_t oid, char *path, void *arg)
{
	char p[PATH_MAX];
	int ret = SD_RES_SUCCESS;

	snprintf(p, sizeof(p), "%s/%"PRIx64, path, oid);
	if (unlink(path) < 0) {
		sd_eprintf("failed to remove cached object %m");
		if (errno == ENOENT)
			return SD_RES_SUCCESS;
		ret = SD_RES_EIO;
		goto out;
	}
out:
	return ret;
}

static int farm_restore(const struct siocb *iocb)
{
	int ret = SD_RES_EIO, epoch = iocb->epoch;

	sd_dprintf("try recover user epoch %d", epoch);

	/* Remove all the objects of WD and object cache */
	for_each_object_in_wd(rm_object, true, NULL);
	if (sys->enable_object_cache)
		object_cache_format();

	ret = restore_objects_from_snap(epoch);
	if (ret != SD_RES_SUCCESS)
		goto out;
out:
	return ret;
}

static int farm_get_snap_file(struct siocb *iocb)
{
	int ret = SD_RES_EIO;
	void *buffer = NULL;
	size_t size;
	int nr;

	sd_dprintf("try get snap file");
	buffer = snap_log_read(&nr);
	if (!buffer)
		goto out;
	size = nr * sizeof(struct snap_log);
	memcpy(iocb->buf, buffer, size);
	iocb->length = size;
	ret = SD_RES_SUCCESS;
out:
	free(buffer);
	return ret;
}

static struct store_driver farm = {
	.name = "farm",
	.init = farm_init,
	.exist = default_exist,
	.create_and_write = default_create_and_write,
	.write = default_write,
	.read = default_read,
	.link = default_link,
	.end_recover = default_end_recover,
	.snapshot = farm_snapshot,
	.cleanup = default_cleanup,
	.restore = farm_restore,
	.get_snap_file = farm_get_snap_file,
	.format = default_format,
	.purge_obj = default_purge_obj,
	.remove_object = default_remove_object,
};

add_store_driver(farm);
