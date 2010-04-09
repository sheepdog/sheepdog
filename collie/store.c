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
#define ANAME_NODEID "user.sheepdog.nodeid"

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

static int is_obj_in_range(uint64_t oid, uint64_t start, uint64_t end)
{
	uint64_t hval = fnv_64a_buf(&oid, sizeof(oid), FNV1A_64_INIT);

	if (start < end)
		return (start < hval && hval <= end);
	else
		return (start < hval || hval <= end);
}

static int get_obj_list(struct request *req, char *buf, int buf_len)
{
	DIR *dir;
	struct dirent *d;
	struct sd_list_req *hdr = (struct sd_list_req *)&req->rq;
	struct sd_list_rsp *rsp = (struct sd_list_rsp *)&req->rp;
	uint64_t oid;
	uint64_t start_hash = hdr->start;
	uint64_t end_hash = hdr->end;
	uint32_t epoch = hdr->tgt_epoch;
	char path[1024];
	uint64_t *p = (uint64_t *)req->data;
	int nr = 0;
	uint64_t *objlist = NULL;
	int obj_nr = 0, fd, i;
	struct sheepdog_node_list_entry *e;
	int e_nr;
	int idx;
	int res = SD_RES_SUCCESS;

	if (epoch == 1)
		goto local;

	snprintf(path, sizeof(path), "%s%08u/list", obj_path, epoch);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		eprintf("failed to open %s, %s\n", path, strerror(errno));
		close(fd);
		return SD_RES_EIO;
	}
	obj_nr = read(fd, buf, buf_len);
	obj_nr /= sizeof(uint64_t);
	objlist = (uint64_t *)buf;
	for (i = 0; i < obj_nr; i++) {
		if (is_obj_in_range(objlist[i], start_hash, end_hash)) {
			dprintf("%u, %016lx, %016lx %016lx\n", epoch,
				objlist[i], start_hash, end_hash);
			p[nr++] = objlist[i];
		}

		if (nr * sizeof(uint64_t) >= hdr->data_length)
			break;
	}
	close(fd);

local:
	snprintf(path, sizeof(path), "%s%08u/", obj_path, hdr->tgt_epoch);

	dprintf("%d, %s\n", sys->this_node.port, path);

	dir = opendir(path);
	if (!dir) {
		eprintf("%s\n", path);
		return SD_RES_EIO;
	}

	while ((d = readdir(dir))) {
		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		oid = strtoull(d->d_name, NULL, 16);
		if (oid == 0)
			continue;

		for (i = 0; i < obj_nr; i++)
			if (objlist[i] == oid)
				break;
		if (i < obj_nr)
			continue;

		if (is_obj_in_range(oid, start_hash, end_hash)) {
			dprintf("%u, %016lx, %016lx %016lx\n", epoch,
				oid, start_hash, end_hash);
			p[nr++] = oid;
		}

		if (nr * sizeof(uint64_t) >= hdr->data_length)
			break;
	}

	eprintf("nr = %d\n", nr);
	rsp->data_length = nr * sizeof(uint64_t);

	e_nr = epoch_log_read(epoch, buf, buf_len);
	e_nr /= sizeof(*e);
	e = (struct sheepdog_node_list_entry *)buf;

	if (e_nr <= sys->nr_sobjs) {
		rsp->next = end_hash;
		goto out;
	}

	for (idx = 0; idx < e_nr; idx++) {
		if (e[idx].id == sys->this_node.id)
			break;
	}
	if (idx != e_nr) {
		uint64_t hval = e[idx % e_nr].id;

		rsp->next = end_hash;

		if (start_hash < end_hash) {
			if (start_hash < hval && hval <= end_hash)
				rsp->next = hval;
		} else
			if (start_hash < hval || hval <= end_hash)
				rsp->next = hval;

		dprintf("%u, %016lx, %016lx %016lx\n", epoch, hval,
			start_hash, end_hash);
	} else
		res = SD_RES_SYSTEM_ERROR;

out:
	closedir(dir);

	return res;
}

static int ob_open(uint32_t epoch, uint64_t oid, int aflags, int *ret);

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

		if (is_myself(&e[n])) {
			fd = ob_open(sys->epoch, oid, 0, &ret);
			if (fd < 0 || ret != 0)
				continue;

			ret = pread64(fd, buf, *ori_rlen, offset);
			if (ret < 0)
				continue;
			*ori_rlen = ret;
			ret = 0;
			goto out;
		}

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
			ret = 0;
			goto out;
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

	ret = -1;
out:
	free(e);

	return ret;
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
	uint32_t epoch;

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
		if (is_myself(&e[n])) {
			if (hdr->flags & SD_FLAG_CMD_RECOVERY)
				epoch = hdr->tgt_epoch;
			else
				epoch = sys->epoch;
			ret = store_queue_request_local(req, buf, epoch);
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

int update_epoch_store(uint32_t epoch)
{
	char new[1024];

	snprintf(new, sizeof(new), "%s%08u/", obj_path, epoch);
	mkdir(new, def_dmode);

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

		if (hdr->flags & SD_FLAG_CMD_COW) {
			dprintf("%" PRIx64 "\n", hdr->cow_oid);

			ret = read_from_other_sheeps(hdr->cow_oid, buf,
						     hdr->copies);
			if (ret) {
				eprintf("failed to read old object\n");
				ret = SD_RES_EIO;
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
		snprintf(path, sizeof(path), "%s%08u/%016" PRIx64, obj_path,
			 epoch, oid);
		ret = unlink(path);
		if (ret) {
			if (errno == ENOENT)
				ret = SD_RES_NO_OBJ;
			else
				ret = SD_RES_EIO;
		}
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

	if (ret == SD_RES_NO_OBJ && hdr->flags & SD_FLAG_CMD_RECOVERY) {
		int len  = epoch_log_read(epoch - 1, req->data, hdr->data_length);
		if (len < 0)
			len = 0;
		rsp->data_length = len;
	}

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

	if (hdr->flags & SD_FLAG_CMD_RECOVERY)
		epoch = hdr->tgt_epoch;

	if (opcode == SD_OP_STAT_SHEEP) {
		ret = stat_sheep(&nrsp->store_size, &nrsp->store_free, epoch);
		goto out;
	}

	if (opcode == SD_OP_GET_OBJ_LIST) {
		ret = get_obj_list(req, buf, SD_DATA_OBJ_SIZE);
		goto out;
	}

	if (!(hdr->flags & SD_FLAG_CMD_FORWARD)) {
		ret = forward_obj_req(req, buf);
		goto out;
	}

	ret = store_queue_request_local(req, buf, epoch);
out:
	if (ret != SD_RES_SUCCESS) {
		dprintf("failed, %d, %x, %" PRIx64" , %u, %u, %d\n",
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

static int contains_node(uint64_t id, struct sheepdog_node_list_entry *entry,
			 int nr, int base_idx)
{
	int i;

	for (i = 0; i < sys->nr_sobjs; i++) {
		if (entry[(base_idx + i) % nr].id == id)
			return (base_idx + i) % nr;
	}
	return -1;
}

struct recovery_work {
	uint32_t epoch;
	uint32_t done;

	struct sheepdog_node_list_entry e;

	struct timer timer;
	int retry;
	struct work work;
	struct list_head rw_siblings;

	int count;
	char *buf;
};

static LIST_HEAD(recovery_work_list);
static int recovering;

static int find_tgt_node(struct sheepdog_node_list_entry *old_entry, int old_nr, int old_idx,
			 struct sheepdog_node_list_entry *cur_entry, int cur_nr, int cur_idx,
			 int copy_idx)
{
	int i, idx;

	dprintf("%d, %d, %d, %d, %d\n", old_idx, old_nr, cur_idx, cur_nr, copy_idx);

	if (copy_idx < cur_nr) {
		idx = contains_node(cur_entry[(cur_idx + copy_idx) % cur_nr].id,
				    old_entry, old_nr, old_idx);
		if (idx >= 0) {
			dprintf("%d, %d, %d, %d\n", idx, copy_idx, cur_idx, cur_nr);
			return idx;
		}
	}

	for (i = 0; ; i++) {
		if (i < cur_nr) {
			idx = contains_node(cur_entry[(cur_idx + i) % cur_nr].id,
					    old_entry, old_nr, old_idx);
			if (idx >= 0)
				continue;

			while (contains_node(old_entry[old_idx].id, cur_entry, cur_nr, cur_idx) >= 0)
				old_idx = (old_idx + 1) % old_nr;

		}
		if (i == copy_idx) {
			dprintf("%d, %d, %d, %d\n", old_idx, copy_idx, cur_idx, cur_nr);
			return old_idx;
		}

		old_idx = (old_idx + 1) % old_nr;
	}
	return -1;
}

static int __recover_one(struct recovery_work *rw,
			 struct sheepdog_node_list_entry *_old_entry, int old_nr,
			 struct sheepdog_node_list_entry *_cur_entry, int cur_nr, int cur_idx,
			 int copy_idx, uint32_t epoch, uint32_t tgt_epoch,
			 uint64_t oid, char *buf, int buf_len)
{
	struct sheepdog_node_list_entry *e;
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
	char name[128];
	unsigned wlen = 0, rlen = SD_DATA_OBJ_SIZE;
	int fd, ret;
	struct sheepdog_node_list_entry old_entry[SD_MAX_NODES],
		cur_entry[SD_MAX_NODES], *next_entry;
	int next_nr;
	int tgt_idx = -1;
	int old_idx;

	memcpy(old_entry, _old_entry, sizeof(*old_entry) * old_nr);
	memcpy(cur_entry, _cur_entry, sizeof(*cur_entry) * cur_nr);
next:
	dprintf("recover obj %lx from epoch %d\n", oid, tgt_epoch);
	old_idx = obj_to_sheep(old_entry, old_nr, oid, 0);

	tgt_idx = find_tgt_node(old_entry, old_nr, old_idx, cur_entry, cur_nr, cur_idx, copy_idx);
	if (tgt_idx < 0) {
		eprintf("cannot find target node, %lx\n", oid);
		return -1;
	}
	e = old_entry + tgt_idx;

	if (e->id == sys->this_node.id) {
		char old[PATH_MAX], new[PATH_MAX];

		snprintf(old, sizeof(old), "%s%08u/%016" PRIx64, obj_path,
			 tgt_epoch, oid);
		snprintf(new, sizeof(new), "%s%08u/%016" PRIx64, obj_path,
			 epoch, oid);
		dprintf("link from %s to %s\n", old, new);
		if (link(old, new) == 0)
			return 0;

		if (errno == ENOENT) {
			next_nr = epoch_log_read(tgt_epoch, buf, buf_len);
			if (next_nr <= 0) {
				eprintf("no previous epoch, %d\n", tgt_epoch);
				return -1;
			}
			next_entry = (struct sheepdog_node_list_entry *)buf;
			next_nr /= sizeof(*next_entry);
			goto not_found;
		}

		eprintf("cannot recover from local, %s, %s\n", old, new);
		return -1;
	}

	addr_to_str(name, sizeof(name), e->addr, 0);

	fd = connect_to(name, e->port);
	if (fd < 0) {
		eprintf("failed to connect to %s:%d\n", name, e->port);
		return -1;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = SD_OP_READ_OBJ;
	hdr.oid = oid;
	hdr.epoch = sys->epoch;
	hdr.flags = SD_FLAG_CMD_RECOVERY | SD_FLAG_CMD_FORWARD;
	hdr.tgt_epoch = tgt_epoch;
	hdr.data_length = rlen;

	ret = exec_req(fd, (struct sd_req *)&hdr, buf, &wlen, &rlen);

	close(fd);

	if (ret < 0) {
		eprintf("%d\n", rsp->result);
		return -1;
	}

	rsp = (struct sd_obj_rsp *)&hdr;

	if (rsp->result == SD_RES_SUCCESS) {
		fd = ob_open(epoch, oid, O_CREAT, &ret);
		ret = write(fd, buf, SD_DATA_OBJ_SIZE);
		if (ret != SD_DATA_OBJ_SIZE) {
			eprintf("failed to write object\n");
			return -1;
		}

		ret = fsetxattr(fd, ANAME_COPIES, &rsp->copies,
				sizeof(rsp->copies), 0);
		if (ret) {
			eprintf("couldn't set xattr\n");
			return -1;
		}

		close(fd);
		dprintf("recovered oid %lx to epoch %d\n", oid, epoch);
		return 0;
	}

	if (rsp->result == SD_RES_NEW_NODE_VER || rsp->result == SD_RES_OLD_NODE_VER) {
		eprintf("try again, %d, %lx\n", rsp->result, oid);
		rw->retry = 1;
		return 0;
	}

	if (rsp->result != SD_RES_NO_OBJ || rsp->data_length == 0) {
		eprintf("%d\n", rsp->result);
		return -1;
	}
	next_entry = (struct sheepdog_node_list_entry *)buf;
	next_nr = rsp->data_length / sizeof(*old_entry);

not_found:
	copy_idx = node_distance(tgt_idx, old_idx, old_nr);
	dprintf("%d, %d, %d, %d, %d, %d\n", rsp->result, rsp->data_length, tgt_idx,
		old_idx, old_nr, copy_idx);

	memcpy(cur_entry, old_entry, sizeof(*old_entry) * old_nr);
	cur_nr = old_nr;
	cur_idx = old_idx;

	memcpy(old_entry, next_entry, next_nr * sizeof(*next_entry));
	old_nr = next_nr;

	tgt_epoch--;
	goto next;
}

static void recover_one(struct work *work, int idx)
{
	struct recovery_work *rw = container_of(work, struct recovery_work, work);
	char *buf = zero_block + idx * SD_DATA_OBJ_SIZE;
	int ret;
	uint64_t oid = *(((uint64_t *)rw->buf) + rw->done);
	struct sheepdog_node_list_entry old_entry[SD_MAX_NODES],
		cur_entry[SD_MAX_NODES];
	int old_nr, cur_nr;
	uint32_t epoch = rw->epoch;
	int i, my_idx = -1, copy_idx, cur_idx = -1;

	eprintf("%d %d, %16lx\n", rw->done, rw->count, oid);

	cur_nr = epoch_log_read(epoch, (char *)cur_entry, sizeof(cur_entry));
	if (cur_nr <= 0) {
		eprintf("failed to read current epoch, %d\n", epoch);
		return;
	}
	cur_nr /= sizeof(struct sheepdog_node_list_entry);

	old_nr = epoch_log_read(epoch - 1, (char *)old_entry, sizeof(old_entry));
	if (old_nr <= 0) {
		eprintf("failed to read previous epoch, %d\n", epoch - 1);
		goto fail;
	}
	old_nr /= sizeof(struct sheepdog_node_list_entry);

	if (!sys->nr_sobjs)
		goto fail;

	cur_idx = obj_to_sheep(cur_entry, cur_nr, oid, 0);

	for (i = 0; i < cur_nr; i++) {
		if (cur_entry[i].id == sys->this_node.id) {
			my_idx = i;
			break;
		}
	}
	copy_idx = node_distance(my_idx, cur_idx, cur_nr);
	dprintf("%d, %d, %d, %d\n", my_idx, cur_idx, cur_nr, copy_idx);

	ret = __recover_one(rw, old_entry, old_nr, cur_entry, cur_nr, cur_idx,
			    copy_idx, epoch, epoch - 1, oid, buf, SD_DATA_OBJ_SIZE);
	if (ret == 0)
		return;

	for (i = 0; i < sys->nr_sobjs; i++) {
		if (i == copy_idx)
			continue;
		ret = __recover_one(rw, old_entry, old_nr,
				    cur_entry, cur_nr, cur_idx, i,
				    epoch, epoch - 1, oid, buf, SD_DATA_OBJ_SIZE);
		if (ret == 0)
			return;
	}
fail:
	eprintf("failed to recover object %lx\n", oid);
}

static void __start_recovery(struct work *work, int idx);
static void __start_recovery_done(struct work *work, int idx);

static void recover_one_timer(void *data)
{
	struct recovery_work *rw = (struct recovery_work *)data;
	queue_work(dobj_queue, &rw->work);
}

static void recover_one_done(struct work *work, int idx)
{
	struct recovery_work *rw = container_of(work, struct recovery_work, work);

	if (rw->retry) {
		rw->retry = 0;

		rw->timer.callback = recover_one_timer;
		rw->timer.data = rw;
		add_timer(&rw->timer, 2);
		return;
	}

	rw->done++;

	if (rw->done < rw->count && rw->rw_siblings.next == &recovery_work_list) {
		queue_work(dobj_queue, &rw->work);
		return;
	}

	dprintf("recovery done, %d\n", rw->epoch);
	recovering--;

	list_del(&rw->rw_siblings);

	free(rw->buf);
	free(rw);

	if (!list_empty(&recovery_work_list)) {
		rw = list_first_entry(&recovery_work_list,
				      struct recovery_work, rw_siblings);

		recovering++;
		queue_work(dobj_queue, &rw->work);
	}
}

static int __fill_obj_list(struct recovery_work *rw,
			   struct sheepdog_node_list_entry *e,
			   uint64_t start_hash, uint64_t end_hash, uint64_t *done_hash)
{
	int fd, ret;
	uint32_t epoch = rw->epoch;
	unsigned wlen, rlen;
	char name[128];
	struct sd_list_req hdr;
	struct sd_list_rsp *rsp;

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
	hdr.start = start_hash;
	hdr.end = end_hash;
	hdr.tgt_epoch = epoch - 1;
	hdr.flags = 0;
	hdr.data_length = rlen;

	dprintf("%016lx, %016lx\n", hdr.start, hdr.end);

	memcpy(&rw->e, e, sizeof(rw->e));

	ret = exec_req(fd, (struct sd_req *)&hdr, rw->buf + rw->count * sizeof(uint64_t), &wlen, &rlen);

	close(fd);

	rsp = (struct sd_list_rsp *)&hdr;

	if (rsp->result != SD_RES_SUCCESS) {
		rw->retry = 1;
		*done_hash = end_hash;
		eprintf("try again, %d\n", rsp->result);
		return 0;
	}

	dprintf("%d\n", rsp->data_length);

	if (rsp->data_length)
		rw->count += rsp->data_length / sizeof(uint64_t);

	*done_hash = rsp->next;

	return 0;
}

static int fill_obj_list(struct recovery_work *rw,
			 struct sheepdog_node_list_entry *old_entry, int old_nr,
			 struct sheepdog_node_list_entry *cur_entry, int cur_nr,
			 uint64_t start_hval, uint64_t end_hval)
{
	int i, idx, old_idx, cur_idx;
	uint64_t hval, done_hval = end_hval;

	hval = start_hval;
again:
	old_idx = hval_to_sheep(old_entry, old_nr, hval + 1, 0);
	cur_idx = hval_to_sheep(cur_entry, cur_nr, hval + 1, 0);

	for (i = 0; i < sys->nr_sobjs; i++) {
		idx = find_tgt_node(old_entry, old_nr, old_idx, cur_entry, cur_nr, cur_idx, i);
		dprintf("%d, %d\n", idx, i);
		if (__fill_obj_list(rw, old_entry + idx, hval, end_hval, &done_hval) == 0)
			break;
	}
	if (i == sys->nr_sobjs)
		return -1;

	if (done_hval != end_hval) {
		dprintf("%lx, %lx\n", done_hval, end_hval);
		hval = done_hval;
		goto again;
	}

	return 0;
}

static void __start_recovery(struct work *work, int idx)
{
	struct recovery_work *rw = container_of(work, struct recovery_work, work);
	uint32_t epoch = rw->epoch;
	struct sheepdog_node_list_entry old_entry[SD_MAX_NODES],
		cur_entry[SD_MAX_NODES];
	int old_nr, cur_nr;
	int my_idx = -1;
	int i, fd;
	uint64_t start_hash, end_hash;
	char path[PATH_MAX];

	dprintf("%u\n", epoch);

	cur_nr = epoch_log_read(epoch, (char *)cur_entry, sizeof(cur_entry));
	if (cur_nr <= 0) {
		eprintf("failed to read epoch log, %d\n", epoch);
		goto fail;
	}
	cur_nr /= sizeof(struct sheepdog_node_list_entry);

	old_nr = epoch_log_read(epoch - 1, (char *)old_entry, sizeof(old_entry));
	if (old_nr <= 0) {
		eprintf("failed to read epoch log, %d\n", epoch - 1);
		goto fail;
	}
	old_nr /= sizeof(struct sheepdog_node_list_entry);

	if (!sys->nr_sobjs)
		goto fail;

	for (i = 0; i < cur_nr; i++) {
		if (cur_entry[i].id == sys->this_node.id) {
			my_idx = i;
			break;
		}
	}
	start_hash = cur_entry[(my_idx - sys->nr_sobjs + cur_nr) % cur_nr].id;
	end_hash = cur_entry[my_idx].id;

	dprintf("fill obj list (from 0x%lx to 0x%lx)\n", start_hash, end_hash);
	if (fill_obj_list(rw, old_entry, old_nr, cur_entry, cur_nr,
			  start_hash, end_hash) != 0) {
		eprintf("fatal recovery error\n");
		goto fail;
	}

	snprintf(path, sizeof(path), "%s%08u/list", obj_path, epoch);
	dprintf("write object list file to %s\n", path);

	fd = open(path, O_RDWR | O_CREAT, def_fmode);
	if (fd < 0) {
		eprintf("failed to open %s, %s\n", path, strerror(errno));
		goto fail;
	}
	write(fd, rw->buf, sizeof(uint64_t) * rw->count);
	close(fd);

	return;
fail:
	rw->count = 0;
	return;
}

static void start_recovery_timer(void *data)
{
	struct recovery_work *rw = (struct recovery_work *)data;
	queue_work(dobj_queue, &rw->work);
}

static void __start_recovery_done(struct work *work, int idx)
{
	struct recovery_work *rw = container_of(work, struct recovery_work, work);

	if (rw->retry) {
		rw->retry = 0;

		rw->timer.callback = start_recovery_timer;
		rw->timer.data = rw;
		add_timer(&rw->timer, 1);
		return;
	}

	if (rw->count && rw->rw_siblings.next == &recovery_work_list) {
		rw->work.fn = recover_one;
		rw->work.done = recover_one_done;

		/* TODO: we should avoid races with qemu I/Os */
		/* rw->work.attr = WORK_ORDERED; */

		queue_work(dobj_queue, &rw->work);
		return;
	}

	dprintf("recovery done, %d\n", rw->epoch);
	recovering--;

	list_del(&rw->rw_siblings);

	free(rw->buf);
	free(rw);

	if (!list_empty(&recovery_work_list)) {
		rw = list_first_entry(&recovery_work_list,
				      struct recovery_work, rw_siblings);

		recovering++;
		queue_work(dobj_queue, &rw->work);
	}
}

int start_recovery(uint32_t epoch)
{
	struct recovery_work *rw;

	rw = zalloc(sizeof(struct recovery_work));
	if (!rw)
		return -1;

	rw->buf = malloc(1 << 20); /* FIXME */
	rw->epoch = epoch;
	rw->count = 0;

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

	*new = 0;
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


static int attr(char *path, char *attr, void *var, int len, int set)
{
	int ret, fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return SD_RES_EIO;

	if (set)
		ret = fsetxattr(fd, attr, var, len, 0);
	else
		ret = fgetxattr(fd, attr, var, len);

	close(fd);

	if (set) {
		if (ret) {
			eprintf("use 'user_xattr' option?, %s\n", attr);
			return SD_RES_SYSTEM_ERROR;
		}
	} else {
		if (ret != len)
			return SD_RES_SYSTEM_ERROR;
	}

	return SD_RES_SUCCESS;
}

int set_nodeid(uint64_t nodeid)
{
	return attr(epoch_path, ANAME_NODEID, &nodeid, sizeof(nodeid), 1);
}

int get_nodeid(uint64_t *nodeid)
{
	return attr(epoch_path, ANAME_NODEID, nodeid, sizeof(*nodeid), 0);
}

int init_base_path(char *d)
{
	int new = 0;

	return init_path(d, &new);
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
	int new, ret;
	uint32_t epoch;
	DIR *dir;
	char path[1024];
	struct dirent *dent;
	uint64_t oid;

	epoch_path = zalloc(strlen(base_path) + strlen(EPOCH_PATH) + 1);
	sprintf(epoch_path, "%s" EPOCH_PATH, base_path);

	ret = init_path(epoch_path, &new);
	if (new || ret)
		return ret;

	epoch = get_latest_epoch();

	snprintf(path, sizeof(path), "%s/%08u", obj_path, epoch);

	vprintf(SDOG_INFO "found the epoch dir, %s\n", path);

	dir = opendir(path);
	if (!dir) {
		vprintf(SDOG_ERR "failed to open the epoch dir, %m\n");
		return SD_RES_EIO;
	}

	while ((dent = readdir(dir))) {
		if (!strcmp(dent->d_name, ".") ||
		    !strcmp(dent->d_name, ".."))
			continue;

		oid = strtoull(dent->d_name, NULL, 16);

		if (is_data_obj(oid))
			continue;

		vprintf(SDOG_DEBUG "found the vdi obj, %" PRIx64 " %lu\n",
			oid, oid_to_bit(oid));

		set_bit(oid_to_bit(oid), sys->vdi_inuse);
	}
	closedir(dir);

	return 0;
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
	int ret;

	ret = init_base_path(d);
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

int set_global_nr_copies(uint32_t copies)
{
	return attr(epoch_path, ANAME_COPIES, &copies, sizeof(copies), 1);
}

int get_global_nr_copies(uint32_t *copies)
{
	return attr(epoch_path, ANAME_COPIES, copies, sizeof(*copies), 0);
}
