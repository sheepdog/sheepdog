/*
 * Copyright (C) 2009 Nippon Telegraph and Telephone Corporation.
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
#include <sys/xattr.h>
#include <sys/statvfs.h>

#include "collie.h"
#include "meta.h"

#define ANAME_CTIME "user.sheepdog.ctime"
#define ANAME_COPIES "user.sheepdog.copies"

static char *obj_path;
static char *epoch_path;
static char *mnt_path;

static char *zero_block;

static mode_t def_dmode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP;
static mode_t def_fmode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

struct work_queue *dobj_queue;

static int stat_sheep(uint64_t *store_size, uint64_t *store_free, uint32_t epoch)
{
	struct statvfs vs;
	int ret;
	DIR *dir;
	struct dirent *d;
	uint64_t used = 0;
	struct stat s;
	char path[1024], store_dir[1024];

	ret = statvfs(mnt_path, &vs);
	if (ret)
		return SD_RES_EIO;

	snprintf(store_dir, sizeof(store_dir), "%s%08u", obj_path, epoch);
	dir = opendir(store_dir);
	if (!dir)
		return SD_RES_EIO;

	while ((d = readdir(dir))) {
		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		snprintf(path, sizeof(path), "%s/%s", store_dir, d->d_name);

		ret = stat(path, &s);
		if (ret)
			continue;

		used += s.st_size;
	}

	closedir(dir);

	*store_size = vs.f_frsize * vs.f_bfree + used;
	*store_free = vs.f_frsize * vs.f_bfree;

	return SD_RES_SUCCESS;
}

static int get_obj_list(struct request *req)
{
	DIR *dir;
	struct dirent *d;
	struct sd_obj_req *hdr = (struct sd_obj_req *)&req->rq;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&req->rp;
	uint64_t oid;
	uint64_t oid_hash;
	uint64_t start_hash = hdr->oid;
	uint64_t end_hash = hdr->cow_oid;
	char path[1024];
	uint64_t *p = (uint64_t *)req->data;
	int nr = 0;

	snprintf(path, sizeof(path), "%s%08u/", obj_path, hdr->obj_ver);

	dprintf("%d\n", sys->this_node.port);

	dir = opendir(path);
	if (!dir) {
		eprintf("%s\n", path);
		return SD_RES_EIO;
	}

	while ((d = readdir(dir))) {
		int got = 0;

		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		oid = strtoull(d->d_name, NULL, 16);
		oid_hash = fnv_64a_buf(&oid, sizeof(oid), FNV1A_64_INIT);

		if ((nr + 1) * sizeof(uint64_t) > hdr->data_length)
			break;

		if (start_hash < end_hash) {
			if (oid_hash >= start_hash && oid_hash < end_hash)
				got = 1;
		} else
			if (end_hash <= oid_hash || oid_hash < start_hash)
				got = 1;

		dprintf("%d, %u, %016lx, %016lx, %016lx %016lx\n", got, hdr->obj_ver,
			oid, oid_hash, start_hash, end_hash);

		if (got) {
			*(p + nr) = oid;
			nr++;
		}
	}

	rsp->data_length = nr * 8;

	closedir(dir);

	return SD_RES_SUCCESS;
}

static int read_from_one(uint64_t oid,
			 unsigned *ori_rlen, void *buf, uint64_t offset)
{
	int i, n, nr, fd, ret;
	unsigned wlen, rlen;
	char name[128];
	struct sheepdog_node_list_entry *e;
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;

	e = zalloc(SD_MAX_NODES * sizeof(struct sheepdog_node_list_entry));
again:
	nr = build_node_list(&sys->sd_node_list, e);

	for (i = 0; i < nr; i++) {
		n = obj_to_sheep(e, nr, oid, i);

		addr_to_str(name, sizeof(name), e[n].addr, 0);

		/* FIXME: do like store_queue_request_local() */
		if (e[n].id == sys->this_node.id)
			continue;

		fd = connect_to(name, e[n].port);
		if (fd < 0)
			continue;

		memset(&hdr, 0, sizeof(hdr));
		hdr.opcode = SD_OP_READ_OBJ;
		hdr.oid = oid;
		hdr.epoch = sys->epoch;

		rlen = *ori_rlen;
		wlen = 0;
		hdr.flags = 0;
		hdr.data_length = rlen;
		hdr.offset = offset;

		ret = exec_req(fd, (struct sd_req *)&hdr, buf, &wlen, &rlen);

		close(fd);

		if (ret)
			continue;

		switch (rsp->result) {
		case SD_RES_SUCCESS:
			*ori_rlen = rlen;
			return 0;
		case SD_RES_OLD_NODE_VER:
		case SD_RES_NEW_NODE_VER:
			/* waits for the node list timer */
			sleep(2);
			goto again;
			break;
		default:
			;
		}
	}

	free(e);

	return -1;
}

static int read_from_other_sheeps(uint64_t oid, char *buf, int copies)
{
	int ret;
	unsigned int rlen;

	rlen = SD_DATA_OBJ_SIZE;

	ret = read_from_one(oid, &rlen, buf, 0);

	return ret;
}

static int store_queue_request_local(struct request *req, char *buf, uint32_t epoch);

static int forward_obj_req(struct request *req, char *buf)
{
	int i, n, nr, fd, ret;
	unsigned wlen, rlen;
	char name[128];
	struct sd_obj_req *hdr = (struct sd_obj_req *)&req->rq;
	struct sheepdog_node_list_entry *e;
	struct sd_obj_req hdr2;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr2;
	uint64_t oid = hdr->oid;
	int copies;

	e = zalloc(SD_MAX_NODES * sizeof(struct sheepdog_node_list_entry));
again:
	nr = build_node_list(&sys->sd_node_list, e);

	copies = hdr->copies;

	/* temporary hack */
	if (!copies)
		copies = sys->nr_sobjs;

	for (i = 0; i < copies; i++) {
		n = obj_to_sheep(e, nr, oid, i);

		addr_to_str(name, sizeof(name), e[n].addr, 0);

		/* TODO: we can do better; we need to chech this first */
		if (e[n].id == sys->this_node.id) {
			ret = store_queue_request_local(req, buf, sys->epoch);
			memcpy(rsp, &req->rp, sizeof(*rsp));
			rsp->result = ret;
			goto done;
		}

		fd = connect_to(name, e[n].port);
		if (fd < 0)
			goto again;

		memcpy(&hdr2, hdr, sizeof(hdr2));

		if (hdr->flags & SD_FLAG_CMD_WRITE) {
			wlen = hdr->data_length;
			rlen = 0;
		} else {
			wlen = 0;
			rlen = hdr->data_length;
		}

		hdr2.flags |= SD_FLAG_CMD_FORWARD;
		hdr2.epoch = sys->epoch;

		ret = exec_req(fd, (struct sd_req *)&hdr2, req->data, &wlen, &rlen);

		close(fd);

		if (ret) /* network errors */
			goto again;

	done:
		if (hdr->flags & SD_FLAG_CMD_WRITE) {
			if (rsp->result != SD_RES_SUCCESS) {
				free(e);
				return rsp->result;
			}
		} else {
			if (rsp->result == SD_RES_SUCCESS) {
				memcpy(&req->rp, rsp, sizeof(req->rp));
				free(e);
				return SD_RES_SUCCESS;
			}
		}
	}

	free(e);

	return (hdr->flags & SD_FLAG_CMD_WRITE) ? SD_RES_SUCCESS: rsp->result;
}

static int check_epoch(struct request *req)
{
	struct sd_req *hdr = (struct sd_req *)&req->rq;
	uint32_t req_epoch = hdr->epoch;
	uint32_t opcode = hdr->opcode;
	int ret = SD_RES_SUCCESS;

	if (before(req_epoch, sys->epoch)) {
		ret = SD_RES_OLD_NODE_VER;
		eprintf("old node version %u %u, %x\n",
			sys->epoch, req_epoch, opcode);
	} else if (after(req_epoch, sys->epoch)) {
		ret = SD_RES_NEW_NODE_VER;
			eprintf("new node version %u %u %x\n",
				sys->epoch, req_epoch, opcode);
	}

	return ret;
}

static int ob_open(uint32_t epoch, uint64_t oid, int aflags, int *ret)
{
	char path[1024];
	int flags = O_RDWR | aflags;
	int fd;

	snprintf(path, sizeof(path), "%s%08u/%016" PRIx64, obj_path, epoch, oid);

	fd = open(path, flags, def_fmode);
	if (fd < 0) {
		eprintf("failed to open %s, %s\n", path, strerror(errno));
		if (errno == ENOENT)
			*ret = SD_RES_NO_OBJ;
		else
			*ret = SD_RES_UNKNOWN;
	} else
		*ret = 0;

	return fd;
}

static int is_my_obj(uint64_t oid, int copies)
{
	int i, n, nr;
	struct sheepdog_node_list_entry e[SD_MAX_NODES];

	nr = build_node_list(&sys->sd_node_list, e);

	for (i = 0; i < copies; i++) {
		n = obj_to_sheep(e, nr, oid, i);
		if (e[n].id == sys->this_node.id)
			return 1;
	}

	return 0;
}

int update_epoch_store(uint32_t epoch)
{
	int ret;
	char new[1024], old[1024];
	struct stat s;
	DIR *dir;
	struct dirent *d;
	uint64_t oid;

	snprintf(new, sizeof(new), "%s%08u/", obj_path, epoch);
	mkdir(new, def_dmode);

	snprintf(old, sizeof(old), "%s%08u/", obj_path, epoch - 1);

	ret = stat(old, &s);
	if (ret)
		return 0;

	dir = opendir(old);
	if (!dir) {
		eprintf("%s, %s, %m\n", old, new);
		return 1;
	}

	while ((d = readdir(dir))) {
		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		oid = strtoull(d->d_name, NULL, 16);
		/* TODO: use proper object coipes */
		if (is_my_obj(oid, sys->nr_sobjs)) {
			snprintf(new, sizeof(new), "%s%08u/%s", obj_path, epoch,
				d->d_name);
			snprintf(old, sizeof(old), "%s%08u/%s", obj_path, epoch - 1,
				d->d_name);
			link(old, new);
		}
	}

	closedir(dir);

	return 0;
}

static int store_queue_request_local(struct request *req, char *buf, uint32_t epoch)
{
	int fd = -1, copies;
	int ret = SD_RES_SUCCESS;
	struct sd_obj_req *hdr = (struct sd_obj_req *)&req->rq;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&req->rp;
	uint64_t oid = hdr->oid;
	uint32_t opcode = hdr->opcode;
	char path[1024];

	switch (opcode) {
	case SD_OP_CREATE_AND_WRITE_OBJ:
	case SD_OP_WRITE_OBJ:
	case SD_OP_READ_OBJ:
	case SD_OP_SYNC_OBJ:
		if (opcode == SD_OP_CREATE_AND_WRITE_OBJ)
			fd = ob_open(epoch, oid, O_CREAT, &ret);
		else
			fd = ob_open(epoch, oid, 0, &ret);

		if (fd < 0)
			goto out;

		if (opcode != SD_OP_CREATE_AND_WRITE_OBJ)
			break;

		if (!hdr->copies) {
			eprintf("zero copies is invalid\n");
			ret = SD_RES_INVALID_PARMS;
			goto out;
		}

		ret = ftruncate(fd, 0);
		if (ret) {
			ret = SD_RES_EIO;
			goto out;
		}

		ret = fsetxattr(fd, ANAME_COPIES, &hdr->copies,
				sizeof(hdr->copies), 0);
		if (ret) {
			eprintf("use 'user_xattr' option?\n");
			ret = SD_RES_SYSTEM_ERROR;
			goto out;
		}

		if (!is_data_obj(oid))
			break;

		if (hdr->flags & SD_FLAG_CMD_COW) {
			dprintf("%" PRIu64 "\n", hdr->cow_oid);

			ret = read_from_other_sheeps(hdr->cow_oid, buf,
						     hdr->copies);
			if (ret) {
				ret = 1;
				goto out;
			}
		} else {
			dprintf("%" PRIu64 "\n", oid);
			memset(buf, 0, SD_DATA_OBJ_SIZE);
		}

		dprintf("%" PRIu64 "\n", oid);

		ret = pwrite64(fd, buf, SD_DATA_OBJ_SIZE, 0);
		if (ret != SD_DATA_OBJ_SIZE) {
			ret = SD_RES_EIO;
			goto out;
		}
	default:
		break;
	}

	switch (opcode) {
	case SD_OP_REMOVE_OBJ:
		snprintf(path, sizeof(path), "%s%" PRIx64, obj_path, oid);
		ret = unlink(path);
		if (ret)
			ret = 1;
		break;
	case SD_OP_READ_OBJ:
		/*
		 * TODO: should be optional (we can use the flags) for
		 * performance; qemu doesn't always need the copies.
		 */
		copies = 0;
		ret = fgetxattr(fd, ANAME_COPIES, &copies, sizeof(copies));
		if (ret != sizeof(copies)) {
			ret = SD_RES_SYSTEM_ERROR;
			goto out;
		}

		ret = pread64(fd, req->data, hdr->data_length, hdr->offset);
		if (ret < 0)
			ret = SD_RES_EIO;
		else {
			rsp->data_length = ret;
			rsp->copies = copies;
			ret = SD_RES_SUCCESS;
		}
		break;
	case SD_OP_CREATE_AND_WRITE_OBJ:
	case SD_OP_WRITE_OBJ:
		ret = pwrite64(fd, req->data, hdr->data_length, hdr->offset);
		if (ret != hdr->data_length) {
			ret = SD_RES_EIO;
			goto out;
		}

		ret = SD_RES_SUCCESS;
		break;
	case SD_OP_SYNC_OBJ:
		ret = fsync(fd);
		if (ret) {
			if (errno == EIO)
				ret = SD_RES_EIO;
			else
				ret = SD_RES_UNKNOWN;
		}
		break;
	}
out:
	if (fd != -1)
		close(fd);

	return ret;
}

void store_queue_request(struct work *work, int idx)
{
	struct request *req = container_of(work, struct request, work);
	int ret = SD_RES_SUCCESS;
	char *buf = zero_block + idx * SD_DATA_OBJ_SIZE;
	struct sd_obj_req *hdr = (struct sd_obj_req *)&req->rq;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&req->rp;
	uint64_t oid = hdr->oid;
	uint32_t opcode = hdr->opcode;
	uint32_t epoch = sys->epoch;
	uint32_t req_epoch = hdr->epoch;
	struct sd_node_rsp *nrsp = (struct sd_node_rsp *)&req->rp;

	dprintf("%d, %x, %" PRIx64" , %u, %u\n", idx, opcode, oid, epoch, req_epoch);

	if (list_empty(&sys->sd_node_list)) {
		/* we haven't got SD_OP_GET_NODE_LIST response yet. */
		ret = SD_RES_SYSTEM_ERROR;
		goto out;
	}

	if (hdr->flags & SD_FLAG_CMD_FORWARD) {
		ret = check_epoch(req);
		if (ret != SD_RES_SUCCESS)
			goto out;
	}

	if (opcode == SD_OP_STAT_SHEEP) {
		ret = stat_sheep(&nrsp->store_size, &nrsp->store_free, epoch);
		goto out;
	}

	if (opcode == SD_OP_GET_OBJ_LIST) {
		ret = get_obj_list(req);
		goto out;
	}

	if (!(hdr->flags & SD_FLAG_CMD_FORWARD)) {
		ret = forward_obj_req(req, buf);
		goto out;
	}

	ret = store_queue_request_local(req, buf, epoch);
out:
	if (ret != SD_RES_SUCCESS) {
		dprintf("failed, %d, %x, %" PRIx64" , %u, %u, %x\n",
			idx, opcode, oid, epoch, req_epoch, ret);
		rsp->result = ret;
	}
}

int epoch_log_write(uint32_t epoch, char *buf, int len)
{
	int fd, ret;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s%08u", epoch_path, epoch);
	fd = open(path, O_RDWR | O_CREAT |O_SYNC, def_fmode);
	if (fd < 0)
		return -1;

	ret = write(fd, buf, len);

	close(fd);

	if (ret != len)
		return -1;

	return 0;
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

int get_latest_epoch(void)
{
	DIR *dir;
	struct dirent *d;
	uint32_t e, epoch = 0;

	dir = opendir(epoch_path);
	if (!dir)
		return -1;

	while ((d = readdir(dir))) {
		e = atoi(d->d_name);
		if (e > epoch)
			epoch = e;
	}
	closedir(dir);

	return epoch;
}

/* remove directory recursively */
static int rmdir_r(char *dir_path)
{
	int ret;
	struct stat s;
	DIR *dir;
	struct dirent *d;
	char path[PATH_MAX];

	dir = opendir(dir_path);
	if (!dir) {
		if (errno != ENOENT)
			eprintf("failed, %s, %d\n", dir_path, errno);
		return -errno;
	}

	while ((d = readdir(dir))) {
		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		snprintf(path, sizeof(path), "%s/%s", dir_path, d->d_name);
		ret = stat(path, &s);
		if (ret) {
			eprintf("cannot remove directory %s\n", path);
			goto out;
		}
		if (S_ISDIR(s.st_mode))
			ret = rmdir_r(path);
		else
			ret = unlink(path);

		if (ret != 0) {
			eprintf("failed, %s, %d, %d\n", path, S_ISDIR(s.st_mode), errno);
			goto out;
		}
	}

	ret = rmdir(dir_path);
out:
	closedir(dir);
	return ret;
}

int remove_epoch(int epoch)
{
	int ret;
	char path[PATH_MAX];

	dprintf("remove epoch %d\n", epoch);
	snprintf(path, sizeof(path), "%s%08u", epoch_path, epoch);
	ret = unlink(path);
	if (ret && ret != -ENOENT) {
		eprintf("failed to remove %s, %s\n", path, strerror(-ret));
		return SD_RES_EIO;
	}

	snprintf(path, sizeof(path), "%s%08u", obj_path, epoch);
	ret = rmdir_r(path);
	if (ret && ret != -ENOENT) {
		eprintf("failed to remove %s, %s\n", path, strerror(-ret));
		return SD_RES_EIO;
	}
	return 0;
}

int set_cluster_ctime(uint64_t ctime)
{
	int fd, ret;

	fd = open(epoch_path, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = fsetxattr(fd, ANAME_CTIME, &ctime, sizeof(ctime), 0);
	close(fd);

	if (ret)
		return -1;
	return 0;
}

uint64_t get_cluster_ctime(void)
{
	int fd, ret;
	uint64_t ctime;

	fd = open(epoch_path, O_RDONLY);
	if (fd < 0)
		return 0;

	ret = fgetxattr(fd, ANAME_CTIME, &ctime, sizeof(ctime));
	close(fd);

	if (ret != sizeof(ctime))
		return 0;
	return ctime;
}

static int node_distance(int my, int her, int nr)
{
	return (my + nr - her) % nr;
}

static int node_from_distance(int my, int dist, int nr)
{
	return (my + nr - dist) % nr;
}

struct recovery_work {
	uint32_t epoch;
	uint32_t done;

	uint32_t iteration;

	struct sheepdog_node_list_entry e;

	struct work work;
	struct list_head rw_siblings;

	int count;
	char *buf;
};

static LIST_HEAD(recovery_work_list);
static int recovering;

static void recover_one(struct work *work, int idx)
{
	struct recovery_work *rw = container_of(work, struct recovery_work, work);
	struct sheepdog_node_list_entry *e = &rw->e;
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp;
	char name[128];
	char *buf = zero_block + idx * SD_DATA_OBJ_SIZE;
	unsigned wlen = 0, rlen = SD_DATA_OBJ_SIZE;
	int fd, ret;
	uint64_t oid = *(((uint64_t *)rw->buf) + rw->done);

	eprintf("%d %d, %16lx\n", rw->done, rw->count, oid);

	addr_to_str(name, sizeof(name), e->addr, 0);

	fd = connect_to(name, e->port);
	if (fd < 0) {
		eprintf("%s %d\n", name, e->port);
		return;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = SD_OP_READ_OBJ;
	hdr.oid = oid;
	hdr.epoch = sys->epoch;
	hdr.flags = 0;
	hdr.data_length = rlen;

	ret = exec_req(fd, (struct sd_req *)&hdr, buf, &wlen, &rlen);

	close(fd);

	rsp = (struct sd_obj_rsp *)&hdr;

	if (rsp->result != SD_RES_SUCCESS) {
		eprintf("%d\n", rsp->result);
		return;
	}

	fd = ob_open(rw->epoch, oid, O_CREAT, &ret);
	write(fd, buf, SD_DATA_OBJ_SIZE);
}

static void __start_recovery(struct work *work, int idx);
static void __start_recovery_done(struct work *work, int idx);

static void recover_one_done(struct work *work, int idx)
{
	struct recovery_work *rw = container_of(work, struct recovery_work, work);

	if (rw->done < rw->count) {
		rw->done++;
		queue_work(dobj_queue, &rw->work);
		return;
	}

	if (rw->iteration) {
		if (++rw->iteration <= sys->nr_sobjs) {
			free(rw->buf);

			rw->done = 0;

			rw->work.fn = __start_recovery;
			rw->work.done = __start_recovery_done;

			queue_work(dobj_queue, &rw->work);

			return;
		}
	}

	recovering--;

	list_del(&rw->rw_siblings);

	if (rw->buf)
		free(rw->buf);
	free(rw);

	if (!list_empty(&recovery_work_list)) {
		rw = list_first_entry(&recovery_work_list,
				      struct recovery_work, rw_siblings);

		recovering++;
		queue_work(dobj_queue, &rw->work);
	}
}

static int fill_obj_list(struct recovery_work *rw,
			 struct sheepdog_node_list_entry *e,
			 uint64_t start_hash, uint64_t end_hash)
{
	int fd, ret;
	uint32_t epoch = rw->epoch;
	unsigned wlen, rlen;
	char name[128];
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp;

	addr_to_str(name, sizeof(name), e->addr, 0);

	dprintf("%s %d\n", name, e->port);

	fd = connect_to(name, e->port);
	if (fd < 0) {
		eprintf("%s %d\n", name, e->port);
		return -1;
	}

	wlen = 0;
	rlen = 1 << 20;

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = SD_OP_GET_OBJ_LIST;
	hdr.epoch = sys->epoch;
	hdr.oid = start_hash;
	hdr.cow_oid = end_hash;
	hdr.obj_ver = epoch - 1;
	hdr.flags = 0;
	hdr.data_length = rlen;

	dprintf("%016lx, %016lx\n", hdr.oid, hdr.cow_oid);

	rw->buf = malloc(rlen);
	memcpy(&rw->e, e, sizeof(rw->e));

	ret = exec_req(fd, (struct sd_req *)&hdr, rw->buf, &wlen, &rlen);

	close(fd);

	rsp = (struct sd_obj_rsp *)&hdr;

	if (rsp->result != SD_RES_SUCCESS) {
		eprintf("%d\n", rsp->result);
		return -1;
	}

	dprintf("%d\n", rsp->data_length);

	if (rsp->data_length)
		rw->count = rsp->data_length / sizeof(uint64_t);
	else
		rw->count = 0;

	return 0;
}

static void __start_recovery(struct work *work, int idx)
{
	struct recovery_work *rw = container_of(work, struct recovery_work, work);
	uint32_t epoch = rw->epoch;
	struct sheepdog_node_list_entry old_entry[SD_MAX_NODES],
		cur_entry[SD_MAX_NODES];
	int old_nr, cur_nr;
	int my_idx = -1, ch_idx = -1;
	int i, j, n;
	uint64_t start_hash, end_hash;

	dprintf("%u\n", epoch);

	cur_nr = epoch_log_read(epoch, (char *)cur_entry, sizeof(cur_entry));
	if (cur_nr <= 0)
		goto fail;
	cur_nr /= sizeof(struct sheepdog_node_list_entry);

	old_nr = epoch_log_read(epoch - 1, (char *)old_entry, sizeof(old_entry));
	if (old_nr <= 0)
		goto fail;
	old_nr /= sizeof(struct sheepdog_node_list_entry);

	if (!sys->nr_sobjs || cur_nr < sys->nr_sobjs || old_nr < sys->nr_sobjs)
		goto fail;

	if (cur_nr < old_nr) {
		for (i = 0; i < old_nr; i++) {
			if (old_entry[i].id == sys->this_node.id) {
				my_idx = i;
				break;
			}
		}

		dprintf("%u %u %u, %d\n", cur_nr, old_nr, epoch, my_idx);

		for (i = 0; i < old_nr; i++) {
			for (j = 0; j < cur_nr; j++) {
				if (old_entry[i].id == cur_entry[j].id)
					break;
			}

			if (j == cur_nr)
				ch_idx = i;
		}

		dprintf("%u %u %u\n", my_idx, ch_idx,
			node_distance(my_idx, ch_idx, old_nr));

		if (node_distance(my_idx, ch_idx, old_nr) > sys->nr_sobjs)
			return;

		n = node_from_distance(my_idx, sys->nr_sobjs, old_nr);

		dprintf("%d %d\n", n, sys->nr_sobjs);

		start_hash = old_entry[(n - 1 + old_nr) % old_nr].id;
		end_hash = old_entry[n].id;

		/* FIXME */
		if (node_distance(my_idx, ch_idx, old_nr) == sys->nr_sobjs) {
			n++;
			n %= old_nr;
		}

		fill_obj_list(rw, old_entry + n, start_hash, end_hash);
	} else {
		for (i = 0; i < cur_nr; i++) {
			if (cur_entry[i].id == sys->this_node.id) {
				my_idx = i;
				break;
			}
		}

		dprintf("%u %u %u, %d\n", cur_nr, old_nr, epoch, my_idx);

		if (my_idx == -1)
			return;

		n = node_from_distance(my_idx, rw->iteration, cur_nr);
		start_hash = cur_entry[n].id;
		end_hash = cur_entry[(n + 1 + cur_nr) % cur_nr].id;

		if (rw->iteration == 1)
			n = (my_idx + 1 + cur_nr) % cur_nr;
		else
			n = (n + 1 + cur_nr) % cur_nr;

		dprintf("%u %u %u\n", my_idx, n, rw->iteration);

		start_hash = cur_entry[n].id;
		end_hash = cur_entry[(n - 1 + cur_nr) % cur_nr].id;

		fill_obj_list(rw, cur_entry + n, start_hash, end_hash);
	}

	return;

fail:
	rw->count = 0;
	rw->iteration = 0;
	return;
}

static void __start_recovery_done(struct work *work, int idx)
{
	struct recovery_work *rw = container_of(work, struct recovery_work, work);

	if (!rw->count) {
		if (rw->iteration) {
			if (++rw->iteration <= sys->nr_sobjs) {
				free(rw->buf);

				rw->work.fn = __start_recovery;
				rw->work.done = __start_recovery_done;

				queue_work(dobj_queue, &rw->work);

				return;
			}
		}

		free(rw->buf);
		free(rw);
		return;
	}

	rw->work.fn = recover_one;
	rw->work.done = recover_one_done;

	/* TODO: we should avoid races with qemu I/Os */
/* 	rw->work.attr = WORK_ORDERED; */

	queue_work(dobj_queue, &rw->work);
}

int start_recovery(uint32_t epoch, int add)
{
	struct recovery_work *rw;

	/* disable for now */
	if (add)
		return 0;

	rw = zalloc(sizeof(struct recovery_work));
	if (!rw)
		return -1;

	rw->epoch = epoch;
	rw->count = 0;

	if (add)
		rw->iteration = 1;

	rw->work.fn = __start_recovery;
	rw->work.done = __start_recovery_done;

	list_add_tail(&rw->rw_siblings, &recovery_work_list);

	if (!recovering) {
		recovering++;
		queue_work(dobj_queue, &rw->work);
	}

	return 0;
}

static int init_path(char *d, int *new)
{
	int ret, retry = 0;
	struct stat s;
again:
	ret = stat(d, &s);
	if (ret) {
		if (retry || errno != ENOENT) {
			eprintf("can't handle the dir %s, %m\n", d);
			return 1;
		}

		ret = mkdir(d, def_dmode);
		if (ret) {
			eprintf("can't create the dir %s, %m\n", d);
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

static int init_base_path(char *d, int *new)
{
	return init_path(d, new);
}

#define OBJ_PATH "/obj/"

static int init_obj_path(char *base_path)
{
	int new;

	obj_path = zalloc(strlen(base_path) + strlen(OBJ_PATH) + 1);
	sprintf(obj_path, "%s" OBJ_PATH, base_path);

	return init_path(obj_path, &new);
}

#define EPOCH_PATH "/epoch/"

static int init_epoch_path(char *base_path)
{
	int new;

	epoch_path = zalloc(strlen(base_path) + strlen(EPOCH_PATH) + 1);
	sprintf(epoch_path, "%s" EPOCH_PATH, base_path);

	return init_path(epoch_path, &new);
}

static int init_mnt_path(char *base_path)
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

int init_store(char *d)
{
	int ret, new = 0;

	ret = init_base_path(d, &new);
	if (ret)
		return ret;

	ret = init_obj_path(d);
	if (ret)
		return ret;

	ret = init_epoch_path(d);
	if (ret)
		return ret;

	ret = init_mnt_path(d);
	if (ret)
		return ret;

	zero_block = zalloc(SD_DATA_OBJ_SIZE * DATA_OBJ_NR_WORKER_THREAD);
	if (!zero_block)
		return 1;

	return ret;
}

int read_epoch(uint32_t *epoch, uint64_t *ctime,
	       struct sheepdog_node_list_entry *entries, int *nr_entries)
{
	int ret;

	*epoch = get_latest_epoch();
	ret = epoch_log_read(*epoch, (char *)entries,
			     *nr_entries * sizeof(*entries));
	if (ret == -1) {
		eprintf("failed to read epoch %d\n", *epoch);
		*nr_entries = 0;
		return SD_RES_EIO;
	}
	*nr_entries = ret / sizeof(*entries);

	*ctime = get_cluster_ctime();

	return SD_RES_SUCCESS;
}

void epoch_queue_request(struct work *work, int idx)
{
	struct request *req = container_of(work, struct request, work);
	int ret = SD_RES_SUCCESS, n;
	struct sd_epoch_req *hdr = (struct sd_epoch_req *)&req->rq;
	struct sd_epoch_rsp *rsp = (struct sd_epoch_rsp *)&req->rp;
	uint32_t opcode = hdr->opcode;
	struct sheepdog_node_list_entry *entries;

	switch (opcode) {
	case SD_OP_READ_EPOCH:
		entries = req->data;
		n = hdr->data_length / sizeof(*entries);
		ret = read_epoch(&rsp->latest_epoch, &rsp->ctime, entries, &n);
		rsp->data_length = n * sizeof(*entries);
		break;
	}
	if (ret != SD_RES_SUCCESS) {
		dprintf("failed, %d, %x, %x\n", idx, opcode, ret);
		rsp->result = ret;
	}
}

static int global_nr_copies(uint32_t *copies, int set)
{
	int ret, fd;

	fd = open(epoch_path, O_RDONLY);
	if (fd < 0)
		return SD_RES_EIO;

	if (set)
		ret = fsetxattr(fd, ANAME_COPIES, copies, sizeof(*copies), 0);
	else
		ret = fgetxattr(fd, ANAME_COPIES, copies, sizeof(*copies));

	close(fd);

	if (set) {
		if (ret) {
			eprintf("use 'user_xattr' option?\n");
			return SD_RES_SYSTEM_ERROR;
		}
	} else {
		if (ret != sizeof(*copies)) {
			return SD_RES_SYSTEM_ERROR;
		}
	}

	return SD_RES_SUCCESS;
}

int set_global_nr_copies(uint32_t copies)
{
	return global_nr_copies(&copies, 1);
}

int get_global_nr_copies(uint32_t *copies)
{
	return global_nr_copies(copies, 1);
}
