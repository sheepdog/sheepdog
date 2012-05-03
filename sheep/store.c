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

static int do_local_io(struct request *req, uint32_t epoch)
{
	struct sd_obj_req *hdr = (struct sd_obj_req *)&req->rq;

	hdr->epoch = epoch;
	dprintf("%x, %" PRIx64" , %u\n", hdr->opcode, hdr->oid, epoch);

	return do_process_work(req->op, &req->rq, &req->rp, req);
}

static int forward_read_obj_req(struct request *req)
{
	int i, fd, ret = SD_RES_SUCCESS;
	unsigned wlen, rlen;
	struct sd_obj_req hdr = *(struct sd_obj_req *)&req->rq;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
	struct sd_vnode *v;
	uint64_t oid = hdr.oid;
	int nr_copies;

	hdr.flags |= SD_FLAG_CMD_IO_LOCAL;

	if (hdr.copies)
		nr_copies = hdr.copies;
	else
		nr_copies = get_nr_copies(req->vnodes);

	/* TODO: we can do better; we need to check this first */
	for (i = 0; i < nr_copies; i++) {
		v = oid_to_vnode(req->vnodes, oid, i);
		if (vnode_is_local(v)) {
			ret = do_local_io(req, hdr.epoch);
			if (ret != SD_RES_SUCCESS)
				goto read_remote;
			return ret;
		}
	}

read_remote:
	for (i = 0; i < nr_copies; i++) {
		v = oid_to_vnode(req->vnodes, oid, i);
		if (vnode_is_local(v))
			continue;

		fd = get_sheep_fd(v->addr, v->port, v->node_idx, hdr.epoch);
		if (fd < 0) {
			ret = SD_RES_NETWORK_ERROR;
			continue;
		}

		wlen = 0;
		rlen = hdr.data_length;

		ret = exec_req(fd, (struct sd_req *)&hdr, req->data, &wlen, &rlen);

		if (ret) { /* network errors */
			del_sheep_fd(fd);
			ret = SD_RES_NETWORK_ERROR;
			continue;
		} else {
			memcpy(&req->rp, rsp, sizeof(*rsp));
			ret = rsp->result;
			break;
		}
	}
	return ret;
}

int forward_write_obj_req(struct request *req)
{
	int i, fd, ret, pollret;
	unsigned wlen;
	char name[128];
	struct sd_obj_req hdr = *(struct sd_obj_req *)&req->rq;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&req->rp;
	struct sd_vnode *v;
	uint64_t oid = hdr.oid;
	int nr_copies;
	struct pollfd pfds[SD_MAX_REDUNDANCY];
	int nr_fds, local = 0;

	dprintf("%"PRIx64"\n", oid);

	nr_fds = 0;
	memset(pfds, 0, sizeof(pfds));
	for (i = 0; i < ARRAY_SIZE(pfds); i++)
		pfds[i].fd = -1;

	hdr.flags |= SD_FLAG_CMD_IO_LOCAL;

	wlen = hdr.data_length;

	nr_copies = get_nr_copies(req->vnodes);
	for (i = 0; i < nr_copies; i++) {
		v = oid_to_vnode(req->vnodes, oid, i);

		addr_to_str(name, sizeof(name), v->addr, 0);

		if (vnode_is_local(v)) {
			local = 1;
			continue;
		}

		fd = get_sheep_fd(v->addr, v->port, v->node_idx, hdr.epoch);
		if (fd < 0) {
			eprintf("failed to connect to %s:%"PRIu32"\n", name, v->port);
			ret = SD_RES_NETWORK_ERROR;
			goto out;
		}

		ret = send_req(fd, (struct sd_req *)&hdr, req->data, &wlen);
		if (ret) { /* network errors */
			del_sheep_fd(fd);
			ret = SD_RES_NETWORK_ERROR;
			dprintf("fail %"PRIu32"\n", ret);
			goto out;
		}

		pfds[nr_fds].fd = fd;
		pfds[nr_fds].events = POLLIN;
		nr_fds++;
	}

	if (local) {
		ret = do_local_io(req, hdr.epoch);
		rsp->result = ret;

		if (nr_fds == 0) {
			eprintf("exit %"PRIu32"\n", ret);
			goto out;
		}

		if (rsp->result != SD_RES_SUCCESS) {
			eprintf("fail %"PRIu32"\n", ret);
			goto out;
		}
	}

	ret = SD_RES_SUCCESS;
again:
	pollret = poll(pfds, nr_fds, DEFAULT_SOCKET_TIMEOUT * 1000);
	if (pollret < 0) {
		if (errno == EINTR)
			goto again;

		ret = SD_RES_EIO;
	} else if (pollret == 0) { /* poll time out */
		eprintf("timeout\n");

		for (i = 0; i < nr_fds; i++)
			del_sheep_fd(pfds[i].fd);

		ret = SD_RES_NETWORK_ERROR;
		goto out;
	}

	for (i = 0; i < nr_fds; i++) {
		if (pfds[i].fd < 0)
			break;

		if (pfds[i].revents & POLLERR || pfds[i].revents & POLLHUP || pfds[i].revents & POLLNVAL) {
			del_sheep_fd(pfds[i].fd);
			ret = SD_RES_NETWORK_ERROR;
			break;
		}

		if (!(pfds[i].revents & POLLIN))
			continue;

		if (do_read(pfds[i].fd, rsp, sizeof(*rsp))) {
			eprintf("failed to read a response: %m\n");
			del_sheep_fd(pfds[i].fd);
			ret = SD_RES_NETWORK_ERROR;
			break;
		}

		if (rsp->result != SD_RES_SUCCESS) {
			eprintf("fail %"PRIu32"\n", rsp->result);
			ret = rsp->result;
		}

		break;
	}
	if (i < nr_fds) {
		nr_fds--;
		memmove(pfds + i, pfds + i + 1, sizeof(*pfds) * (nr_fds - i));
	}

	dprintf("%"PRIx64" %"PRIu32"\n", oid, nr_fds);

	if (nr_fds > 0) {
		goto again;
	}
out:
	return ret;
}

int update_epoch_store(uint32_t epoch)
{
	if (!strcmp(sd_store->name, "simple")) {
		char new[1024];

		snprintf(new, sizeof(new), "%s%08u/", obj_path, epoch);
		mkdir(new, def_dmode);
	}
	return 0;
}

int update_epoch_log(uint32_t epoch)
{
	int fd, ret, len;
	time_t t;
	char path[PATH_MAX];

	dprintf("update epoch: %d, %d\n", epoch, sys->nr_nodes);

	snprintf(path, sizeof(path), "%s%08u", epoch_path, epoch);
	fd = open(path, O_RDWR | O_CREAT | O_DSYNC, def_fmode);
	if (fd < 0) {
		ret = fd;
		goto err_open;
	}

	len = sys->nr_nodes * sizeof(struct sd_node);
	ret = write(fd, (char *)sys->nodes, len);
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

static int fix_object_consistency(struct request *req)
{
	int ret = SD_RES_NO_MEM;
	unsigned int data_length;
	struct sd_obj_req *hdr = (struct sd_obj_req *)&req->rq;
	struct sd_obj_req req_bak = *((struct sd_obj_req *)&req->rq);
	struct sd_obj_rsp rsp_bak = *((struct sd_obj_rsp *)&req->rp);
	void *data = req->data, *buf;
	uint64_t oid = hdr->oid;
	int old_opcode = hdr->opcode;

	if (is_vdi_obj(hdr->oid))
		data_length = SD_INODE_SIZE;
	else if (is_vdi_attr_obj(hdr->oid))
		data_length = SD_ATTR_OBJ_SIZE;
	else
		data_length = SD_DATA_OBJ_SIZE;

	buf = valloc(data_length);
	if (buf == NULL) {
		eprintf("failed to allocate memory\n");
		goto out;
	}
	memset(buf, 0, data_length);

	req->data = buf;
	hdr->offset = 0;
	hdr->data_length = data_length;
	hdr->opcode = SD_OP_READ_OBJ;
	hdr->flags = 0;
	req->op = get_sd_op(SD_OP_READ_OBJ);
	ret = forward_read_obj_req(req);
	if (ret != SD_RES_SUCCESS) {
		eprintf("failed to read object %x\n", ret);
		goto out;
	}

	hdr->opcode = SD_OP_CREATE_AND_WRITE_OBJ;
	hdr->flags = SD_FLAG_CMD_WRITE;
	hdr->oid = oid;
	req->op = get_sd_op(hdr->opcode);
	ret = forward_write_obj_req(req);
	if (ret != SD_RES_SUCCESS) {
		eprintf("failed to write object %x\n", ret);
		goto out;
	}
out:
	free(buf);
	req->data = data;
	req->op = get_sd_op(old_opcode);
	*((struct sd_obj_req *)&req->rq) = req_bak;
	*((struct sd_obj_rsp *)&req->rp) = rsp_bak;

	return ret;
}

static int handle_gateway_request(struct request *req)
{
	struct sd_obj_req *hdr = (struct sd_obj_req *)&req->rq;
	uint64_t oid = hdr->oid;
	uint32_t vid = oid_to_vid(oid);
	uint32_t idx = data_oid_to_idx(oid);
	struct object_cache *cache;
	int ret, create = 0;

	if (is_vdi_obj(oid))
		idx |= 1 << CACHE_VDI_SHIFT;

	cache = find_object_cache(vid, 1);

	if (hdr->opcode == SD_OP_CREATE_AND_WRITE_OBJ)
		create = 1;

	if (object_cache_lookup(cache, idx, create) < 0) {
		ret = object_cache_pull(cache, idx);
		if (ret != SD_RES_SUCCESS)
			return ret;
	}
	return object_cache_rw(cache, idx, req);
}

static int bypass_object_cache(struct sd_obj_req *hdr)
{
	uint64_t oid = hdr->oid;

	if (!(hdr->flags & SD_FLAG_CMD_CACHE)) {
		uint32_t vid = oid_to_vid(oid);
		struct object_cache *cache;

		cache = find_object_cache(vid, 0);
		if (!cache)
			return 1;
		if (hdr->flags & SD_FLAG_CMD_WRITE) {
			object_cache_flush_and_delete(cache);
			return 1;
		} else  {
			/* For read requet, we can read cache if any */
			uint32_t idx = data_oid_to_idx(oid);
			if (is_vdi_obj(oid))
				idx |= 1 << CACHE_VDI_SHIFT;

			if (object_cache_lookup(cache, idx, 0) < 0)
				return 1;
			else
				return 0;
		}
	}

	/*
	 * For vmstate && vdi_attr object, we don't do caching
	 */
	if (is_vmstate_obj(oid) || is_vdi_attr_obj(oid) ||
	    hdr->flags & SD_FLAG_CMD_COW)
		return 1;
	return 0;
}

void do_io_request(struct work *work)
{
	struct request *req = container_of(work, struct request, work);
	int ret = SD_RES_SUCCESS;
	struct sd_obj_req *hdr = (struct sd_obj_req *)&req->rq;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&req->rp;
	uint64_t oid = hdr->oid;
	uint32_t opcode = hdr->opcode;
	uint32_t epoch = hdr->epoch;

	dprintf("%x, %" PRIx64" , %u\n", opcode, oid, epoch);

	if (hdr->flags & SD_FLAG_CMD_RECOVERY)
		epoch = hdr->tgt_epoch;

	if (hdr->flags & SD_FLAG_CMD_IO_LOCAL) {
		ret = do_local_io(req, epoch);
	} else {
		if (bypass_object_cache(hdr)) {
			/* fix object consistency when we read the object for the first time */
			if (req->check_consistency) {
				ret = fix_object_consistency(req);
				if (ret != SD_RES_SUCCESS)
					goto out;
			}
			if (hdr->flags & SD_FLAG_CMD_WRITE)
				ret = forward_write_obj_req(req);
			else
				ret = forward_read_obj_req(req);
		} else
			ret = handle_gateway_request(req);
	}
out:
	if (ret != SD_RES_SUCCESS)
		dprintf("failed: %x, %" PRIx64" , %u, %"PRIx32"\n",
			opcode, oid, epoch, ret);
	rsp->result = ret;
}

int epoch_log_read_remote(uint32_t epoch, char *buf, int len)
{
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
	int fd, i, ret;
	unsigned int rlen, wlen, nr, le = get_latest_epoch();
	char host[128];
	struct sd_node nodes[SD_MAX_NODES];

	nr = epoch_log_read(le, (char *)nodes, sizeof(nodes));
	nr /= sizeof(nodes[0]);
	for (i = 0; i < nr; i++) {
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
		hdr.tgt_epoch = epoch;
		hdr.data_length = len;
		rlen = hdr.data_length;
		wlen = 0;

		ret = exec_req(fd, (struct sd_req *)&hdr, buf, &wlen, &rlen);
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

/* remove directory recursively */
int rmdir_r(char *dir_path)
{
	int ret;
	struct stat s;
	DIR *dir;
	struct dirent *d;
	char path[PATH_MAX];

	dir = opendir(dir_path);
	if (!dir) {
		if (errno != ENOENT)
			eprintf("failed to open %s: %m\n", dir_path);
		return -errno;
	}

	while ((d = readdir(dir))) {
		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		snprintf(path, sizeof(path), "%s/%s", dir_path, d->d_name);
		ret = stat(path, &s);
		if (ret) {
			eprintf("failed to stat %s: %m\n", path);
			goto out;
		}
		if (S_ISDIR(s.st_mode))
			ret = rmdir_r(path);
		else
			ret = unlink(path);

		if (ret != 0) {
			eprintf("failed to remove %s %s: %m\n",
				S_ISDIR(s.st_mode) ? "directory" : "file",
				path);
			goto out;
		}
	}

	ret = rmdir(dir_path);
out:
	closedir(dir);
	return ret;
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

int init_base_path(const char *d)
{
	int new = 0;

	return init_path(d, &new);
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

int init_store(const char *d)
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

	ret = init_objlist_cache();
	if (ret)
		return ret;

	ret = object_cache_init(d);
	if (ret)
		return 1;
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
	struct sd_obj_req *hdr;

	req = zalloc(sizeof(*req));
	if (!req)
		return SD_RES_NO_MEM;
	hdr = (struct sd_obj_req *)&req->rq;

	hdr->oid = oid;
	if (create)
		hdr->opcode = SD_OP_CREATE_AND_WRITE_OBJ;
	else
		hdr->opcode = SD_OP_WRITE_OBJ;
	hdr->copies = copies;
	hdr->flags = flags | SD_FLAG_CMD_WRITE;
	hdr->offset = offset;
	hdr->data_length = datalen;
	req->data = data;
	req->op = get_sd_op(hdr->opcode);

	ret = do_local_io(req, epoch);

	free(req);

	return ret;
}
int write_object(struct vnode_info *vnodes, uint32_t node_version,
		 uint64_t oid, char *data, unsigned int datalen,
		 uint64_t offset, uint16_t flags, int nr_copies, int create)
{
	struct sd_obj_req hdr;
	struct sd_vnode *v;
	int i, fd, ret;
	char name[128];

	for (i = 0; i < nr_copies; i++) {
		unsigned rlen = 0, wlen = datalen;

		v = oid_to_vnode(vnodes, oid, i);
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

		hdr.oid = oid;
		hdr.copies = nr_copies;

		hdr.flags = flags;
		hdr.flags |= SD_FLAG_CMD_WRITE | SD_FLAG_CMD_IO_LOCAL;
		hdr.data_length = wlen;
		hdr.offset = offset;

		ret = exec_req(fd, (struct sd_req *)&hdr, data, &wlen, &rlen);
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
	struct sd_obj_req *hdr;

	req = zalloc(sizeof(*req));
	if (!req)
		return SD_RES_NO_MEM;
	hdr = (struct sd_obj_req *)&req->rq;

	hdr->oid = oid;
	hdr->opcode = SD_OP_READ_OBJ;
	hdr->copies = copies;
	hdr->flags = 0;
	hdr->offset = offset;
	hdr->data_length = datalen;
	req->data = data;
	req->op = get_sd_op(hdr->opcode);

	ret = do_local_io(req, epoch);

	free(req);
	return ret;
}
int read_object(struct vnode_info *vnodes, uint32_t node_version,
		uint64_t oid, char *data, unsigned int datalen,
		uint64_t offset, int nr_copies)
{
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
	struct sd_vnode *v;
	char name[128];
	int i = 0, fd, ret, last_error = SD_RES_SUCCESS;

	/* search a local object first */
	for (i = 0; i < nr_copies; i++) {
		v = oid_to_vnode(vnodes, oid, i);
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
		unsigned wlen = 0, rlen = datalen;

		v = oid_to_vnode(vnodes, oid, i);

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
		hdr.oid = oid;

		hdr.flags =  SD_FLAG_CMD_IO_LOCAL;
		hdr.data_length = rlen;
		hdr.offset = offset;

		ret = exec_req(fd, (struct sd_req *)&hdr, data, &wlen, &rlen);
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
	char name[128];
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
	struct sd_vnode *v;
	int i = 0, fd, ret, err = 0;

	for (i = 0; i < nr; i++) {
		unsigned wlen = 0, rlen = 0;

		v = oid_to_vnode(vnodes, oid, i);

		addr_to_str(name, sizeof(name), v->addr, 0);

		fd = connect_to(name, v->port);
		if (fd < 0) {
			rsp->result = SD_RES_EIO;
			return -1;
		}

		memset(&hdr, 0, sizeof(hdr));
		hdr.epoch = node_version;
		hdr.opcode = SD_OP_REMOVE_OBJ;
		hdr.oid = oid;

		hdr.flags = 0;
		hdr.data_length = rlen;

		ret = exec_req(fd, (struct sd_req *)&hdr, NULL, &wlen, &rlen);
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
