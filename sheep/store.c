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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <pthread.h>

#include "sheep_priv.h"
#include "strbuf.h"
#include "util.h"
#include "farm/farm.h"

struct sheepdog_config {
	uint64_t ctime;
	uint16_t flags;
	uint8_t copies;
	uint8_t store[STORE_LEN];
};

char *obj_path;
char *mnt_path;
char *jrnl_path;
char *epoch_path;
static char *config_path;

mode_t def_dmode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP;
mode_t def_fmode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

struct store_driver *sd_store;
LIST_HEAD(store_drivers);

int do_local_io(struct request *req, uint32_t epoch)
{
	dprintf("%x, %" PRIx64" , %u\n",
		req->rq.opcode, req->rq.obj.oid, epoch);

	req->rq.epoch = epoch;
	return do_process_work(req);
}

int update_epoch_log(uint32_t epoch, struct sd_node *nodes, size_t nr_nodes)
{
	int fd, ret, len;
	time_t t;
	char path[PATH_MAX];

	dprintf("update epoch: %d, %zd\n", epoch, nr_nodes);

	snprintf(path, sizeof(path), "%s%08u", epoch_path, epoch);
	fd = open(path, O_RDWR | O_CREAT | O_DSYNC, def_fmode);
	if (fd < 0) {
		ret = fd;
		goto err_open;
	}

	len = nr_nodes * sizeof(struct sd_node);
	ret = write(fd, (char *)nodes, len);
	if (ret != len)
		goto err;

	time(&t);
	len = sizeof(t);
	ret = write(fd, (char *)&t, len);
	if (ret != len)
		goto err;

	close(fd);
	return 0;
err:
	close(fd);
err_open:
	dprintf("%s\n", strerror(errno));
	return -1;
}

void do_io_request(struct work *work)
{
	struct request *req = container_of(work, struct request, work);
	uint32_t epoch;
	int ret;

	if (req->rq.flags & SD_FLAG_CMD_RECOVERY)
		epoch = req->rq.obj.tgt_epoch;
	else
		epoch = req->rq.epoch;

	dprintf("%x, %" PRIx64" , %u\n",
		req->rq.opcode, req->rq.obj.oid, epoch);

	ret = do_local_io(req, epoch);

	if (ret != SD_RES_SUCCESS)
		dprintf("failed: %x, %" PRIx64" , %u, %"PRIx32"\n",
			req->rq.opcode, req->rq.obj.oid, epoch, ret);
	req->rp.result = ret;
}

int epoch_log_read_remote(uint32_t epoch, char *buf, int len)
{
	int i, ret;
	unsigned int nr, le = get_latest_epoch();
	struct sd_node nodes[SD_MAX_NODES];

	nr = epoch_log_read(le, (char *)nodes, sizeof(nodes));
	nr /= sizeof(nodes[0]);

	for (i = 0; i < nr; i++) {
		struct sd_req hdr;
		struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
		char host[128];
		unsigned int rlen, wlen;
		int fd;

		if (is_myself(nodes[i].addr, nodes[i].port))
			continue;

		addr_to_str(host, sizeof(host), nodes[i].addr, 0);
		fd = connect_to(host, nodes[i].port);
		if (fd < 0) {
			vprintf(SDOG_ERR, "failed to connect to %s: %m\n", host);
			continue;
		}

		memset(&hdr, 0, sizeof(hdr));
		hdr.opcode = SD_OP_GET_EPOCH;
		hdr.data_length = rlen = len;
		hdr.obj.tgt_epoch = epoch;

		wlen = 0;

		ret = exec_req(fd, &hdr, buf, &wlen, &rlen);
		close(fd);

		if (ret)
			continue;
		if (rsp->result == SD_RES_SUCCESS) {
			ret = rsp->data_length;
			goto out;
		}
	}
	ret = 0; /* If no one has targeted epoch file, we can safely return 0 */
out:
	return ret;
}

int epoch_log_read_nr(uint32_t epoch, char *buf, int len)
{
	int nr;

	nr = epoch_log_read(epoch, buf, len);
	if (nr < 0)
		return nr;
	nr /= sizeof(struct sd_node);
	return nr;
}

int epoch_log_read(uint32_t epoch, char *buf, int len)
{
	int fd;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s%08u", epoch_path, epoch);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	len = read(fd, buf, len);

	close(fd);

	return len;
}

uint32_t get_latest_epoch(void)
{
	DIR *dir;
	struct dirent *d;
	uint32_t e, epoch = 0;
	char *p;

	dir = opendir(epoch_path);
	if (!dir) {
		vprintf(SDOG_EMERG, "failed to get the latest epoch: %m\n");
		abort();
	}

	while ((d = readdir(dir))) {
		e = strtol(d->d_name, &p, 10);
		if (d->d_name == p)
			continue;

		if (e > epoch)
			epoch = e;
	}
	closedir(dir);

	return epoch;
}

int set_cluster_ctime(uint64_t ct)
{
	int fd, ret;
	void *jd;

	fd = open(config_path, O_DSYNC | O_WRONLY);
	if (fd < 0)
		return SD_RES_EIO;

	jd = jrnl_begin(&ct, sizeof(ct),
			offsetof(struct sheepdog_config, ctime),
			config_path, jrnl_path);
	if (!jd) {
		ret = SD_RES_EIO;
		goto err;
	}
	ret = xpwrite(fd, &ct, sizeof(ct), offsetof(struct sheepdog_config, ctime));
	if (ret != sizeof(ct))
		ret = SD_RES_EIO;
	else
		ret = SD_RES_SUCCESS;

	jrnl_end(jd);
err:
	close(fd);
	return ret;
}

uint64_t get_cluster_ctime(void)
{
	int fd, ret;
	uint64_t ct;

	fd = open(config_path, O_RDONLY);
	if (fd < 0)
		return 0;

	ret = xpread(fd, &ct, sizeof(ct),
		     offsetof(struct sheepdog_config, ctime));
	close(fd);

	if (ret != sizeof(ct))
		return 0;
	return ct;
}

static int init_path(const char *d, int *new)
{
	int ret, retry = 0;
	struct stat s;

	*new = 0;
again:
	ret = stat(d, &s);
	if (ret) {
		if (retry || errno != ENOENT) {
			eprintf("cannot handle the directory %s: %m\n", d);
			return 1;
		}

		ret = mkdir(d, def_dmode);
		if (ret) {
			eprintf("cannot create the directory %s: %m\n", d);
			return 1;
		} else {
			*new = 1;
			retry++;
			goto again;
		}
	}

	if (!S_ISDIR(s.st_mode)) {
		eprintf("%s is not a directory\n", d);
		return 1;
	}

	return 0;
}

#define LOCK_PATH "/lock"

static int lock_base_dir(const char *d)
{
	char *lock_path;
	int ret = 0;
	int fd;

	lock_path = zalloc(strlen(d) + strlen(LOCK_PATH) + 1);
	sprintf(lock_path, "%s" LOCK_PATH, d);

	fd = open(lock_path, O_WRONLY|O_CREAT, def_fmode);
	if (fd < 0) {
		eprintf("failed to open lock file %s (%s)\n",
			lock_path, strerror(errno));
		ret = -1;
		goto out;
	}

	if (lockf(fd, F_TLOCK, 1) < 0) {
		if (errno == EACCES || errno == EAGAIN) {
			eprintf("another sheep daemon is using %s\n", d);
		} else {
			eprintf("unable to get base dir lock (%s)\n",
				strerror(errno));
		}
		ret = -1;
		goto out;
	}

out:
	free(lock_path);
	return ret;
}

int init_base_path(const char *d)
{
	int new = 0;
	int ret;

	ret = init_path(d, &new);
	if (ret)
		return ret;
	return lock_base_dir(d);
}

#define OBJ_PATH "/obj/"

static int init_obj_path(const char *base_path)
{
	int new, len;

	len = strlen(base_path);
	/* farm needs extra HEX_LEN + 3 chars to store snapshot objects.
	 * HEX_LEN + 3 = '/' + hex(2) + '/' + hex(38) + '\0'
	 */
	if (len + HEX_LEN + 3 > PATH_MAX) {
		eprintf("insanely long object directory %s", base_path);
		return -1;
	}

	obj_path = zalloc(strlen(base_path) + strlen(OBJ_PATH) + 1);
	sprintf(obj_path, "%s" OBJ_PATH, base_path);

	return init_path(obj_path, &new);
}

#define EPOCH_PATH "/epoch/"

static int init_epoch_path(const char *base_path)
{
	int new;

	epoch_path = zalloc(strlen(base_path) + strlen(EPOCH_PATH) + 1);
	sprintf(epoch_path, "%s" EPOCH_PATH, base_path);

	return init_path(epoch_path, &new);
}

static int init_mnt_path(const char *base_path)
{
	int ret;
	FILE *fp;
	struct mntent *mnt;
	struct stat s, ms;

	ret = stat(base_path, &s);
	if (ret)
		return 1;

	fp = setmntent(MOUNTED, "r");
	if (!fp)
		return 1;

	while ((mnt = getmntent(fp))) {
		ret = stat(mnt->mnt_dir, &ms);
		if (ret)
			continue;

		if (ms.st_dev == s.st_dev) {
			mnt_path = strdup(mnt->mnt_dir);
			break;
		}
	}

	endmntent(fp);

	return 0;
}

#define JRNL_PATH "/journal/"

static int init_jrnl_path(const char *base_path)
{
	int new, ret;

	/* Create journal directory */
	jrnl_path = zalloc(strlen(base_path) + strlen(JRNL_PATH) + 1);
	sprintf(jrnl_path, "%s" JRNL_PATH, base_path);

	ret = init_path(jrnl_path, &new);
	/* Error during directory creation */
	if (ret)
		return ret;

	/* If journal is newly created */
	if (new)
		return 0;

	jrnl_recover(jrnl_path);

	return 0;
}

#define CONFIG_PATH "/config"

static int init_config_path(const char *base_path)
{
	config_path = zalloc(strlen(base_path) + strlen(CONFIG_PATH) + 1);
	sprintf(config_path, "%s" CONFIG_PATH, base_path);

	mknod(config_path, def_fmode, S_IFREG);

	return 0;
}

static int init_store_driver(void)
{
	char driver_name[STORE_LEN], *p;
	int ret;

	memset(driver_name, '\0', sizeof(driver_name));
	ret = get_cluster_store(driver_name);
	if (ret != SD_RES_SUCCESS)
		return ret;

	p = memchr(driver_name, '\0', STORE_LEN);
	if (!p) {
		/*
		 * If the driver name is not NUL terminated we are in deep
		 * trouble, let's get out here.
		 */
		dprintf("store name not NUL terminated\n");
		return SD_RES_NO_STORE;
	}

	/*
	 * The store file might not exist in case this is a new sheep that
	 * never joined a cluster before.
	 */
	if (p == driver_name)
		return 0;

	sd_store = find_store_driver(driver_name);
	if (!sd_store) {
		dprintf("store %s not found\n", driver_name);
		return SD_RES_NO_STORE;
	}

	return sd_store->init(obj_path);
}

int init_store(const char *d, int enable_write_cache)
{
	int ret;

	ret = init_obj_path(d);
	if (ret)
		return ret;

	ret = init_epoch_path(d);
	if (ret)
		return ret;

	ret = init_mnt_path(d);
	if (ret)
		return ret;

	ret = init_jrnl_path(d);
	if (ret)
		return ret;

	ret = init_config_path(d);
	if (ret)
		return ret;

	ret = init_store_driver();
	if (ret)
		return ret;

	if (enable_write_cache) {
		sys->enable_write_cache = 1;
		ret = object_cache_init(d);
		if (ret)
			return 1;
	}

	return ret;
}

int read_epoch(uint32_t *epoch, uint64_t *ct,
	       struct sd_node *entries, int *nr_entries)
{
	int ret;

	*epoch = get_latest_epoch();
	ret = epoch_log_read(*epoch, (char *)entries,
			     *nr_entries * sizeof(*entries));
	if (ret == -1) {
		eprintf("failed to read epoch %"PRIu32"\n", *epoch);
		*nr_entries = 0;
		return SD_RES_EIO;
	}
	*nr_entries = ret / sizeof(*entries);

	*ct = get_cluster_ctime();

	return SD_RES_SUCCESS;
}

static int write_object_local(uint64_t oid, char *data, unsigned int datalen,
			      uint64_t offset, uint16_t flags, int copies,
			      uint32_t epoch, int create)
{
	int ret;
	struct request *req;
	struct sd_req *hdr;

	req = zalloc(sizeof(*req));
	if (!req)
		return SD_RES_NO_MEM;
	hdr = &req->rq;

	if (create)
		hdr->opcode = SD_OP_CREATE_AND_WRITE_OBJ;
	else
		hdr->opcode = SD_OP_WRITE_OBJ;
	hdr->flags = flags | SD_FLAG_CMD_WRITE;
	hdr->data_length = datalen;

	hdr->obj.oid = oid;
	hdr->obj.offset = offset;
	hdr->obj.copies = copies;

	req->data = data;
	req->op = get_sd_op(hdr->opcode);

	ret = do_local_io(req, epoch);

	free(req);

	return ret;
}

static int write_inode_cache(uint64_t oid, char *data, unsigned int datalen,
				uint64_t offset, uint16_t flags, int copies,
				uint32_t epoch, int create)
{
	int ret;
	struct request *req;
	uint32_t vid = oid_to_vid(oid);
	uint32_t idx = data_oid_to_idx(oid);
	struct object_cache *cache;

	idx |= 1 << CACHE_VDI_SHIFT;

	cache = find_object_cache(vid, 0);

	req = zalloc(sizeof(*req));
	if (!req)
		return SD_RES_NO_MEM;

	if (create)
		req->rq.opcode = SD_OP_CREATE_AND_WRITE_OBJ;
	else
		req->rq.opcode = SD_OP_WRITE_OBJ;
	req->rq.flags = flags | SD_FLAG_CMD_WRITE;
	req->rq.data_length = datalen;

	req->rq.obj.oid = oid;
	req->rq.obj.offset = offset;
	req->rq.obj.copies = copies;

	req->data = data;
	req->op = get_sd_op(req->rq.opcode);

	ret = object_cache_rw(cache, idx, req);

	free(req);
	return ret;
}

int write_object(struct vnode_info *vnodes, uint32_t node_version,
		 uint64_t oid, char *data, unsigned int datalen,
		 uint64_t offset, uint16_t flags, int nr_copies, int create)
{
	struct sd_vnode *obj_vnodes[SD_MAX_COPIES];
	int i, fd, ret;

	if (sys->enable_write_cache && object_is_cached(oid)) {
		ret = write_inode_cache(oid, data, datalen, offset,
			flags, nr_copies, node_version, create);
		if (ret != 0) {
			eprintf("fail %"PRIx64" %"PRIx32"\n", oid, ret);
			return -1;
		}
	}

	oid_to_vnodes(vnodes, oid, nr_copies, obj_vnodes);
	for (i = 0; i < nr_copies; i++) {
		struct sd_req hdr;
		unsigned rlen = 0, wlen = datalen;
		struct sd_vnode *v;
		char name[128];

		v = obj_vnodes[i];
		if (vnode_is_local(v)) {
			ret = write_object_local(oid, data, datalen, offset,
						 flags, nr_copies, node_version,
						 create);

			if (ret != 0) {
				eprintf("fail %"PRIx64" %"PRIx32"\n", oid, ret);
				return -1;
			}

			continue;
		}

		addr_to_str(name, sizeof(name), v->addr, 0);

		fd = connect_to(name, v->port);
		if (fd < 0) {
			eprintf("failed to connect to host %s\n", name);
			return -1;
		}

		memset(&hdr, 0, sizeof(hdr));
		hdr.epoch = node_version;
		if (create)
			hdr.opcode = SD_OP_CREATE_AND_WRITE_OBJ;
		else
			hdr.opcode = SD_OP_WRITE_OBJ;

		hdr.flags = flags;
		hdr.flags |= SD_FLAG_CMD_WRITE | SD_FLAG_CMD_IO_LOCAL;
		hdr.data_length = wlen;

		hdr.obj.oid = oid;
		hdr.obj.offset = offset;
		hdr.obj.copies = nr_copies;

		ret = exec_req(fd, &hdr, data, &wlen, &rlen);
		close(fd);
		if (ret) {
			eprintf("failed to update host %s\n", name);
			return -1;
		}
	}

	return 0;
}

static int read_object_local(uint64_t oid, char *data, unsigned int datalen,
			     uint64_t offset, int copies, uint32_t epoch)
{
	int ret;
	struct request *req;

	req = zalloc(sizeof(*req));
	if (!req)
		return SD_RES_NO_MEM;

	req->rq.opcode = SD_OP_READ_OBJ;
	req->rq.flags = 0;
	req->rq.data_length = datalen;

	req->rq.obj.oid = oid;
	req->rq.obj.copies = copies;
	req->rq.obj.offset = offset;

	req->data = data;
	req->op = get_sd_op(req->rq.opcode);

	ret = do_local_io(req, epoch);

	free(req);
	return ret;
}

static int read_object_cache(uint64_t oid, char *data, unsigned int datalen,
			     uint64_t offset, int copies, uint32_t epoch)
{
	int ret;
	struct request *req;
	uint32_t vid = oid_to_vid(oid);
	uint32_t idx = data_oid_to_idx(oid);
	struct object_cache *cache;

	if (is_vdi_obj(oid))
		idx |= 1 << CACHE_VDI_SHIFT;

	cache = find_object_cache(vid, 0);

	req = zalloc(sizeof(*req));
	if (!req)
		return SD_RES_NO_MEM;

	req->rq.opcode = SD_OP_READ_OBJ;
	req->rq.data_length = datalen;

	req->rq.obj.oid = oid;
	req->rq.obj.offset = offset;
	req->rq.obj.copies = copies;

	req->data = data;
	req->op = get_sd_op(req->rq.opcode);

	ret = object_cache_rw(cache, idx, req);

	free(req);

	return ret;
}

int read_object(struct vnode_info *vnodes, uint32_t node_version,
		uint64_t oid, char *data, unsigned int datalen,
		uint64_t offset, int nr_copies)
{
	struct sd_vnode *v;
	struct sd_vnode *obj_vnodes[SD_MAX_COPIES];
	char name[128];
	int i = 0, fd, ret, last_error = SD_RES_SUCCESS;

	if (sys->enable_write_cache && object_is_cached(oid)) {
		ret = read_object_cache(oid, data, datalen, offset,
					nr_copies, node_version);
		if (ret != SD_RES_SUCCESS)
			eprintf("fail %"PRIx64" %"PRIx32"\n", oid, ret);

		return ret;
	}

	/* search a local object first */
	oid_to_vnodes(vnodes, oid, nr_copies, obj_vnodes);
	for (i = 0; i < nr_copies; i++) {
		v = obj_vnodes[i];
		if (vnode_is_local(v)) {
			ret = read_object_local(oid, data, datalen, offset,
						nr_copies, node_version);

			if (ret != SD_RES_SUCCESS) {
				eprintf("fail %"PRIx64" %"PRId32"\n", oid, ret);
				return ret;
			}

			return SD_RES_SUCCESS;
		}

	}

	for (i = 0; i < nr_copies; i++) {
		struct sd_req hdr;
		struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
		unsigned wlen = 0, rlen = datalen;

		v = obj_vnodes[i];
		addr_to_str(name, sizeof(name), v->addr, 0);

		fd = connect_to(name, v->port);
		if (fd < 0) {
			printf("%s(%d): %s, %m\n", __func__, __LINE__,
			       name);
			return SD_RES_EIO;
		}

		memset(&hdr, 0, sizeof(hdr));
		hdr.epoch = node_version;
		hdr.opcode = SD_OP_READ_OBJ;
		hdr.flags =  SD_FLAG_CMD_IO_LOCAL;
		hdr.data_length = rlen;

		hdr.obj.oid = oid;
		hdr.obj.offset = offset;

		ret = exec_req(fd, &hdr, data, &wlen, &rlen);
		close(fd);

		if (ret) {
			last_error = SD_RES_EIO;
			continue;
		}

		if (rsp->result == SD_RES_SUCCESS)
			return SD_RES_SUCCESS;

		last_error = rsp->result;
	}

	return last_error;
}

int remove_object(struct vnode_info *vnodes, uint32_t node_version,
		  uint64_t oid, int nr)
{
	struct sd_vnode *obj_vnodes[SD_MAX_COPIES];
	int err = 0, i = 0;

	oid_to_vnodes(vnodes, oid, nr, obj_vnodes);
	for (i = 0; i < nr; i++) {
		struct sd_req hdr;
		struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
		struct sd_vnode *v;
		unsigned wlen = 0, rlen = 0;
		char name[128];
		int fd, ret;

		v = obj_vnodes[i];
		addr_to_str(name, sizeof(name), v->addr, 0);

		fd = connect_to(name, v->port);
		if (fd < 0) {
			rsp->result = SD_RES_EIO;
			return -1;
		}

		memset(&hdr, 0, sizeof(hdr));
		hdr.epoch = node_version;
		hdr.opcode = SD_OP_REMOVE_OBJ;
		hdr.flags = 0;
		hdr.data_length = rlen;

		hdr.obj.oid = oid;

		ret = exec_req(fd, &hdr, NULL, &wlen, &rlen);
		close(fd);

		if (ret)
			return -1;

		if (rsp->result != SD_RES_SUCCESS)
			err = 1;
	}

	if (err)
		return -1;

	return 0;
}

int set_cluster_copies(uint8_t copies)
{
	int fd, ret;
	void *jd;

	fd = open(config_path, O_DSYNC | O_WRONLY);
	if (fd < 0)
		return SD_RES_EIO;

	jd = jrnl_begin(&copies, sizeof(copies),
			offsetof(struct sheepdog_config, copies),
			config_path, jrnl_path);
	if (!jd) {
		ret = SD_RES_EIO;
		goto err;
	}

	ret = xpwrite(fd, &copies, sizeof(copies), offsetof(struct sheepdog_config, copies));
	if (ret != sizeof(copies))
		ret = SD_RES_EIO;
	else
		ret = SD_RES_SUCCESS;
	jrnl_end(jd);
err:
	close(fd);
	return ret;
}

int get_cluster_copies(uint8_t *copies)
{
	int fd, ret;

	fd = open(config_path, O_RDONLY);
	if (fd < 0)
		return SD_RES_EIO;

	ret = xpread(fd, copies, sizeof(*copies),
		     offsetof(struct sheepdog_config, copies));
	close(fd);

	if (ret != sizeof(*copies))
		return SD_RES_EIO;

	return SD_RES_SUCCESS;
}

int set_cluster_flags(uint16_t flags)
{
	int fd, ret = SD_RES_EIO;
	void *jd;

	fd = open(config_path, O_DSYNC | O_WRONLY);
	if (fd < 0)
		goto out;

	jd = jrnl_begin(&flags, sizeof(flags),
			offsetof(struct sheepdog_config, flags),
			config_path, jrnl_path);
	if (!jd) {
		ret = SD_RES_EIO;
		goto err;
	}
	ret = xpwrite(fd, &flags, sizeof(flags), offsetof(struct sheepdog_config, flags));
	if (ret != sizeof(flags))
		ret = SD_RES_EIO;
	else
		ret = SD_RES_SUCCESS;
	jrnl_end(jd);
err:
	close(fd);
out:
	return ret;
}

int get_cluster_flags(uint16_t *flags)
{
	int fd, ret = SD_RES_EIO;

	fd = open(config_path, O_RDONLY);
	if (fd < 0)
		goto out;

	ret = xpread(fd, flags, sizeof(*flags),
		     offsetof(struct sheepdog_config, flags));
	if (ret != sizeof(*flags))
		ret = SD_RES_EIO;
	else
		ret = SD_RES_SUCCESS;

	close(fd);
out:
	return ret;
}

int set_cluster_store(const char *name)
{
	int fd, ret = SD_RES_EIO, len;
	void *jd;

	fd = open(config_path, O_DSYNC | O_WRONLY);
	if (fd < 0)
		goto out;

	len = strlen(name) + 1;
	if (len > STORE_LEN)
		goto err;
	jd = jrnl_begin(name, len,
			offsetof(struct sheepdog_config, store),
			config_path, jrnl_path);
	if (!jd) {
		ret = SD_RES_EIO;
		goto err;
	}
	ret = xpwrite(fd, name, len, offsetof(struct sheepdog_config, store));
	if (ret != len)
		ret = SD_RES_EIO;
	else
		ret = SD_RES_SUCCESS;
	jrnl_end(jd);
err:
	close(fd);
out:
	return ret;
}

int get_cluster_store(char *buf)
{
	int fd, ret = SD_RES_EIO;

	fd = open(config_path, O_RDONLY);
	if (fd < 0)
		goto out;

	ret = pread(fd, buf, STORE_LEN,
		    offsetof(struct sheepdog_config, store));

	if (ret == -1)
		ret = SD_RES_EIO;
	else
		ret = SD_RES_SUCCESS;

	close(fd);
out:
	return ret;
}
