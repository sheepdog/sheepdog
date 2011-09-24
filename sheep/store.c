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
#include <sys/xattr.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "sheep_priv.h"

#define ANAME_CTIME "user.sheepdog.ctime"
#define ANAME_COPIES "user.sheepdog.copies"

static char *obj_path;
static char *epoch_path;
static char *mnt_path;
static char *jrnl_path;

static mode_t def_dmode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP;
static mode_t def_fmode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

/* Journal internal data structures */
/* Journal Handlers for Data Object */
static int jrnl_vdi_has_end_mark(struct jrnl_descriptor *jd);
static int jrnl_vdi_write_header(struct jrnl_descriptor *jd);
static int jrnl_vdi_write_data(struct jrnl_descriptor *jd);
static int jrnl_vdi_write_end_mark(struct jrnl_descriptor *jd);
static int jrnl_vdi_apply_to_target_object(struct jrnl_file_desc *jfd);
static int jrnl_vdi_commit_data(struct jrnl_descriptor *jd);

static struct jrnl_handler jrnl_handlers[JRNL_MAX_TYPES] = {
	{
		.has_end_mark = jrnl_vdi_has_end_mark,
		.write_header = jrnl_vdi_write_header,
		.write_data = jrnl_vdi_write_data,
		.write_end_mark = jrnl_vdi_write_end_mark,
		.apply_to_target_object = jrnl_vdi_apply_to_target_object,
		.commit_data = jrnl_vdi_commit_data
	}
};

static int obj_cmp(const void *oid1, const void *oid2)
{
	const uint64_t hval1 = fnv_64a_buf((void *)oid1, sizeof(uint64_t), FNV1A_64_INIT);
	const uint64_t hval2 = fnv_64a_buf((void *)oid2, sizeof(uint64_t), FNV1A_64_INIT);

	if (hval1 < hval2)
		return -1;
	if (hval1 > hval2)
		return 1;
	return 0;
}

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

	*store_size = (uint64_t)vs.f_frsize * vs.f_bfree + used;
	*store_free = (uint64_t)vs.f_frsize * vs.f_bfree;

	return SD_RES_SUCCESS;
}

static int merge_objlist(struct sheepdog_vnode_list_entry *entries, int nr_entries,
			 uint64_t *list1, int nr_list1,
			 uint64_t *list2, int nr_list2, int nr_objs);

static int get_obj_list(struct request *req)
{
	DIR *dir;
	struct dirent *d;
	struct sd_list_req *hdr = (struct sd_list_req *)&req->rq;
	struct sd_list_rsp *rsp = (struct sd_list_rsp *)&req->rp;
	uint64_t oid;
	uint32_t epoch;
	char path[1024];
	uint64_t *p = (uint64_t *)req->data;
	int nr = 0;
	uint64_t *objlist = NULL;
	int obj_nr, i;
	int res = SD_RES_SUCCESS;
	int buf_len;
	char *buf;

	/* FIXME: handle larger size */
	buf_len = (1 << 22);
	buf = zalloc(buf_len);
	if (!buf) {
		eprintf("failed to allocate memory\n");
		res = SD_RES_NO_MEM;
		goto out;
	}

	objlist = (uint64_t *)buf;
	for (epoch = 1; epoch <= hdr->tgt_epoch; epoch++) {
		snprintf(path, sizeof(path), "%s%08u/", obj_path, epoch);

		dprintf("%"PRIu32", %s\n", sys->this_node.port, path);

		dir = opendir(path);
		if (!dir) {
			eprintf("%s\n", path);
			continue;
		}

		obj_nr = 0;
		while ((d = readdir(dir))) {
			if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
				continue;

			oid = strtoull(d->d_name, NULL, 16);
			if (oid == 0)
				continue;

			objlist[obj_nr++] = oid;
		}

		closedir(dir);

		nr = merge_objlist(NULL, 0, p, nr, objlist, obj_nr, 0);
	}
out:
	free(buf);
	rsp->data_length = nr * sizeof(uint64_t);
	for (i = 0; i < nr; i++) {
		eprintf("oid %"PRIx64", %"PRIx64"\n", *(p + i), p[i]);
	}
	return res;
}

static int ob_open(uint32_t epoch, uint64_t oid, int aflags, int *ret);

static int read_from_one(struct request *req, uint32_t epoch, uint64_t oid,
			 unsigned *ori_rlen, void *buf, uint64_t offset)
{
	int i, n, nr, fd, ret;
	unsigned wlen, rlen;
	char name[128];
	struct sheepdog_vnode_list_entry *e;
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;

	e = req->entry;
	nr = req->nr_vnodes;

	for (i = 0; i < nr; i++) {
		n = obj_to_sheep(e, nr, oid, i);

		addr_to_str(name, sizeof(name), e[n].addr, 0);

		if (is_myself(e[n].addr, e[n].port)) {
			fd = ob_open(epoch, oid, 0, &ret);
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
		hdr.epoch = epoch;

		rlen = *ori_rlen;
		wlen = 0;
		hdr.flags = SD_FLAG_CMD_DIRECT;
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
			break;
		default:
			;
		}
	}

	ret = -1;
out:
	return ret;
}

static int read_from_other_sheeps(struct request *req, uint32_t epoch,
				  uint64_t oid, char *buf, int copies)
{
	int ret;
	unsigned int rlen;

	rlen = SD_DATA_OBJ_SIZE;

	ret = read_from_one(req, epoch, oid, &rlen, buf, 0);

	return ret;
}

static int store_queue_request_local(struct request *req, uint32_t epoch);

static int forward_read_obj_req(struct request *req, int idx)
{
	int i, n, nr, fd, ret;
	unsigned wlen, rlen;
	struct sd_obj_req hdr = *(struct sd_obj_req *)&req->rq;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
	struct sheepdog_vnode_list_entry *e;
	uint64_t oid = hdr.oid;
	int copies;

	e = req->entry;
	nr = req->nr_vnodes;

	copies = hdr.copies;

	/* temporary hack */
	if (!copies)
		copies = sys->nr_sobjs;
	if (copies > req->nr_zones)
		copies = req->nr_zones;

	hdr.flags |= SD_FLAG_CMD_DIRECT;

	/* TODO: we can do better; we need to check this first */
	for (i = 0; i < copies; i++) {
		n = obj_to_sheep(e, nr, oid, i);

		if (is_myself(e[n].addr, e[n].port)) {
			ret = store_queue_request_local(req, hdr.epoch);
			goto out;
		}
	}

	n = obj_to_sheep(e, nr, oid, 0);

	fd = get_sheep_fd(e[n].addr, e[n].port, e[n].node_idx, hdr.epoch, idx);
	if (fd < 0) {
		ret = SD_RES_NETWORK_ERROR;
		goto out;
	}

	wlen = 0;
	rlen = hdr.data_length;

	ret = exec_req(fd, (struct sd_req *)&hdr, req->data, &wlen, &rlen);

	if (ret) /* network errors */
		ret = SD_RES_NETWORK_ERROR;
	else {
		memcpy(&req->rp, rsp, sizeof(*rsp));
		ret = rsp->result;
	}
out:
	return ret;
}

static int forward_write_obj_req(struct request *req, int idx)
{
	int i, n, nr, fd, ret;
	unsigned wlen, rlen;
	char name[128];
	struct sd_obj_req hdr = *(struct sd_obj_req *)&req->rq;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&req->rp;
	struct sheepdog_vnode_list_entry *e;
	uint64_t oid = hdr.oid;
	int copies;
	struct pollfd pfds[SD_MAX_REDUNDANCY];
	int nr_fds, local = 0;

	dprintf("%"PRIx64"\n", oid);
	e = req->entry;
	nr = req->nr_vnodes;

	copies = hdr.copies;

	/* temporary hack */
	if (!copies)
		copies = sys->nr_sobjs;
	if (copies > req->nr_zones)
		copies = req->nr_zones;

	nr_fds = 0;
	memset(pfds, 0, sizeof(pfds));
	for (i = 0; i < ARRAY_SIZE(pfds); i++)
		pfds[i].fd = -1;

	hdr.flags |= SD_FLAG_CMD_DIRECT;

	wlen = hdr.data_length;
	rlen = 0;

	for (i = 0; i < copies; i++) {
		n = obj_to_sheep(e, nr, oid, i);

		addr_to_str(name, sizeof(name), e[n].addr, 0);

		if (is_myself(e[n].addr, e[n].port)) {
			local = 1;
			continue;
		}

		fd = get_sheep_fd(e[n].addr, e[n].port, e[n].node_idx, hdr.epoch, idx);
		if (fd < 0) {
			eprintf("failed to connect to %s:%"PRIu32"\n", name, e[n].port);
			ret = SD_RES_NETWORK_ERROR;
			goto out;
		}

		ret = send_req(fd, (struct sd_req *)&hdr, req->data, &wlen);
		if (ret) { /* network errors */
			ret = SD_RES_NETWORK_ERROR;
			dprintf("fail %"PRIu32"\n", ret);
			goto out;
		}

		pfds[nr_fds].fd = fd;
		pfds[nr_fds].events = POLLIN;
		nr_fds++;
	}

	if (local) {
		ret = store_queue_request_local(req, hdr.epoch);
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
	if (poll(pfds, nr_fds, -1) < 0) {
		if (errno == EINTR)
			goto again;

		ret = SD_RES_EIO;
	}

	for (i = 0; i < nr_fds; i++) {
		if (pfds[i].fd < 0)
			break;

		if (pfds[i].revents & POLLERR || pfds[i].revents & POLLHUP || pfds[i].revents & POLLNVAL) {
			ret = SD_RES_NETWORK_ERROR;
			break;
		}

		if (!(pfds[i].revents & POLLIN))
			continue;

		if (do_read(pfds[i].fd, rsp, sizeof(*rsp))) {
			eprintf("failed to get a rsp, %m\n");
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

static int ob_open(uint32_t epoch, uint64_t oid, int aflags, int *ret)
{
	char path[1024];
	int flags;
	int fd;

	if (sys->use_directio && is_data_obj(oid))
		flags = O_DIRECT | O_RDWR | aflags;
	else
		flags = O_SYNC | O_RDWR | aflags;

	snprintf(path, sizeof(path), "%s%08u/%016" PRIx64, obj_path, epoch, oid);

	fd = open(path, flags, def_fmode);
	if (fd < 0) {
		eprintf("failed to open %s, %s\n", path, strerror(errno));
		if (errno == ENOENT) {
			struct stat s;

			*ret = SD_RES_NO_OBJ;
			if (stat(obj_path, &s) < 0) {
				/* store directory is corrupted */
				eprintf("corrupted\n");
				*ret = SD_RES_EIO;
			}
		} else
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

int write_object_local(uint64_t oid, char *data, unsigned int datalen,
		       uint64_t offset, int copies, uint32_t epoch, int create)
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
	hdr->flags = SD_FLAG_CMD_WRITE;
	hdr->offset = offset;
	hdr->data_length = datalen;
	req->data = data;

	ret = store_queue_request_local(req, epoch);

	free(req);

	return ret;
}

int read_object_local(uint64_t oid, char *data, unsigned int datalen,
		      uint64_t offset, int copies, uint32_t epoch)
{
	int ret;
	struct request *req;
	struct sd_obj_req *hdr;
	struct sd_obj_rsp *rsp;
	unsigned int rsp_data_length;

	req = zalloc(sizeof(*req));
	if (!req)
		return -SD_RES_NO_MEM;
	hdr = (struct sd_obj_req *)&req->rq;
	rsp = (struct sd_obj_rsp *)&req->rp;

	hdr->oid = oid;
	hdr->opcode = SD_OP_READ_OBJ;
	hdr->copies = copies;
	hdr->flags = 0;
	hdr->offset = offset;
	hdr->data_length = datalen;
	req->data = data;

	ret = store_queue_request_local(req, epoch);

	rsp_data_length = rsp->data_length;
	free(req);

	if (ret != 0)
		return -ret;

	if (rsp_data_length != datalen)
		return -SD_RES_EIO;

	return rsp_data_length;
}

static int store_queue_request_local(struct request *req, uint32_t epoch)
{
	int fd = -1, copies;
	int ret = SD_RES_SUCCESS;
	struct sd_obj_req *hdr = (struct sd_obj_req *)&req->rq;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&req->rp;
	uint64_t oid = hdr->oid;
	uint32_t opcode = hdr->opcode;
	char path[1024], *buf = NULL;
	struct jrnl_descriptor jd;
	struct jrnl_vdi_head jh;

	dprintf("%x, %" PRIx64" , %u\n", opcode, oid, epoch);

	switch (opcode) {
	case SD_OP_CREATE_AND_WRITE_OBJ:
	case SD_OP_WRITE_OBJ:
	case SD_OP_READ_OBJ:
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
			dprintf("%" PRIu64 ", %" PRIx64 "\n", oid, hdr->cow_oid);

			buf = valloc(SD_DATA_OBJ_SIZE);
			if (!buf) {
				eprintf("failed to allocate memory\n");
				ret = SD_RES_NO_MEM;
				goto out;
			}
			ret = read_from_other_sheeps(req, hdr->epoch, hdr->cow_oid, buf,
						     hdr->copies);
			if (ret) {
				eprintf("failed to read old object\n");
				ret = SD_RES_EIO;
				goto out;
			}
			ret = pwrite64(fd, buf, SD_DATA_OBJ_SIZE, 0);
			if (ret != SD_DATA_OBJ_SIZE) {
				if (errno == ENOSPC)
					ret = SD_RES_NO_SPACE;
				else
					ret = SD_RES_EIO;
				goto out;
			}
			free(buf);
			buf = NULL;
		} else {
			int size = SECTOR_SIZE;
			buf = valloc(size);
			if (!buf) {
				eprintf("failed to allocate memory\n");
				ret = SD_RES_NO_MEM;
				goto out;
			}
			memset(buf, 0, size);
			ret = pwrite64(fd, buf, size, SD_DATA_OBJ_SIZE - size);
			free(buf);
			buf = NULL;

			if (ret != size) {
				if (errno == ENOSPC)
					ret = SD_RES_NO_SPACE;
				else
					ret = SD_RES_EIO;
				goto out;
			}
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
		if (ret < 0) {
			ret = SD_RES_EIO;
			goto out;
		}

		rsp->data_length = ret;
		rsp->copies = copies;

		ret = SD_RES_SUCCESS;
		break;
	case SD_OP_WRITE_OBJ:
	case SD_OP_CREATE_AND_WRITE_OBJ:
		if (hdr->flags & SD_FLAG_CMD_TRUNCATE) {
			ret = ftruncate(fd, hdr->offset + hdr->data_length);
			if (ret) {
				ret = SD_RES_EIO;
				goto out;
			}
		}

		if (is_vdi_obj(oid)) {
			jd.jdf_epoch = epoch;
			jd.jdf_oid = oid;
			jd.jdf_target_fd = fd;

			memset(&jh, 0, sizeof(jh));
			jh.jh_type = JRNL_TYPE_VDI;
			jh.jh_offset = hdr->offset;
			jh.jh_size = hdr->data_length;

			jd.jd_head = &jh;
			jd.jd_data = req->data;
			jd.jd_end_mark = SET_END_MARK;

			ret = jrnl_perform(&jd);
			if (ret)
				goto out;
		} else {
			ret = pwrite64(fd, req->data, hdr->data_length,
				       hdr->offset);
			if (ret != hdr->data_length) {
				if (errno == ENOSPC)
					ret = SD_RES_NO_SPACE;
				else
					ret = SD_RES_EIO;
				goto out;
			}
		}

		ret = SD_RES_SUCCESS;
		break;
	}
out:
	if (buf)
		free(buf);

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

static int fix_object_consistency(struct request *req, int idx)
{
	int ret = SD_RES_NO_MEM;
	unsigned int data_length;
	struct sd_obj_req *hdr = (struct sd_obj_req *)&req->rq;
	struct sd_obj_req req_bak = *((struct sd_obj_req *)&req->rq);
	struct sd_obj_rsp rsp_bak = *((struct sd_obj_rsp *)&req->rp);
	void *data = req->data, *buf;
	uint64_t oid = hdr->oid;

	if (is_vdi_obj(hdr->oid))
		data_length = sizeof(struct sheepdog_inode);
	else if (is_vdi_attr_obj(hdr->oid))
		data_length = SD_MAX_VDI_ATTR_VALUE_LEN;
	else
		data_length = SD_DATA_OBJ_SIZE;

	buf = valloc(data_length);
	if (buf == NULL) {
		eprintf("out of memory\n");
		goto out;
	}
	memset(buf, 0, data_length);

	req->data = buf;
	hdr->offset = 0;
	hdr->data_length = data_length;
	hdr->opcode = SD_OP_READ_OBJ;
	hdr->flags = 0;
	ret = forward_read_obj_req(req, idx);
	if (ret != SD_RES_SUCCESS) {
		eprintf("failed to read object, %d\n", ret);
		goto out;
	}

	hdr->opcode = SD_OP_WRITE_OBJ;
	hdr->flags = SD_FLAG_CMD_WRITE;
	hdr->oid = oid;
	ret = forward_write_obj_req(req, idx);
	if (ret != SD_RES_SUCCESS) {
		eprintf("failed to write object, %d\n", ret);
		goto out;
	}
out:
	free(buf);
	req->data = data;
	*((struct sd_obj_req *)&req->rq) = req_bak;
	*((struct sd_obj_rsp *)&req->rp) = rsp_bak;

	return ret;
}

void store_queue_request(struct work *work, int idx)
{
	struct request *req = container_of(work, struct request, work);
	int ret = SD_RES_SUCCESS;
	struct sd_obj_req *hdr = (struct sd_obj_req *)&req->rq;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&req->rp;
	uint64_t oid = hdr->oid;
	uint32_t opcode = hdr->opcode;
	uint32_t epoch = hdr->epoch;
	struct sd_node_rsp *nrsp = (struct sd_node_rsp *)&req->rp;

	dprintf("%"PRIu32", %x, %" PRIx64" , %u\n", idx, opcode, oid, epoch);

	if (hdr->flags & SD_FLAG_CMD_RECOVERY)
		epoch = hdr->tgt_epoch;

	if (opcode == SD_OP_STAT_SHEEP) {
		ret = stat_sheep(&nrsp->store_size, &nrsp->store_free, epoch);
		goto out;
	}

	if (opcode == SD_OP_GET_OBJ_LIST) {
		ret = get_obj_list(req);
		goto out;
	}

	if (!(hdr->flags & SD_FLAG_CMD_DIRECT)) {
		/* fix object consistency when we read the object for the first time */
		if (req->check_consistency) {
			ret = fix_object_consistency(req, idx);
			if (ret != SD_RES_SUCCESS)
				goto out;
		}

		if (hdr->flags & SD_FLAG_CMD_WRITE)
			ret = forward_write_obj_req(req, idx);
		else
			ret = forward_read_obj_req(req, idx);
		goto out;
	}

	ret = store_queue_request_local(req, epoch);
out:
	if (ret != SD_RES_SUCCESS) {
		dprintf("failed, %"PRIu32", %x, %" PRIx64" , %u, %"PRIu32"\n",
			idx, opcode, oid, epoch, ret);
		if (!(ret == SD_RES_NO_OBJ && hdr->flags & SD_FLAG_CMD_RECOVERY))
			rsp->data_length = 0;
	}
	rsp->result = ret;
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

int epoch_log_read_remote(uint32_t epoch, char *buf, int len)
{
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
	int fd, i, ret;
	unsigned int rlen, wlen, nr, le = get_latest_epoch();
	char host[128];
	struct sheepdog_node_list_entry nodes[SD_MAX_NODES];

	nr = epoch_log_read(le, (char *)nodes, ARRAY_SIZE(nodes));
	nr /= sizeof(nodes[0]);
	for (i = 0; i < nr; i++) {
		if (is_myself(nodes[i].addr, nodes[i].port))
			continue;

		addr_to_str(host, sizeof(host), nodes[i].addr, 0);
		fd = connect_to(host, nodes[i].port);
		if (fd < 0) {
			vprintf(SDOG_ERR "can't connect to %s, %m\n", host);
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
	if (!dir) {
		vprintf(SDOG_EMERG "failed to get the latest epoch, %m\n");
		abort();
	}

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
			eprintf("failed, %s, %"PRIu32"\n", dir_path, errno);
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
			eprintf("failed, %s, %"PRIu32", %"PRIu32"\n", path, S_ISDIR(s.st_mode), errno);
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

	dprintf("remove epoch %"PRIu32"\n", epoch);
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

	snprintf(path, sizeof(path), "%s%08u/", jrnl_path, epoch);
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

static int get_max_copies(struct sheepdog_node_list_entry *entries, int nr)
{
	int i, j;
	unsigned int nr_zones = 0;
	uint32_t zones[SD_MAX_REDUNDANCY];

	for (i = 0; i < nr; i++) {
		if (nr_zones >= ARRAY_SIZE(zones))
			break;

		for (j = 0; j < nr_zones; j++) {
			if (zones[j] == entries[i].zone)
				break;
		}
		if (j == nr_zones)
			zones[nr_zones++] = entries[i].zone;
	}

	return min(sys->nr_sobjs, nr_zones);
}

/*
 * contains_node - checks that the node id is included in the target nodes
 *
 * The target nodes to store replicated objects are the first N nodes
 * from the base_idx'th on the consistent hash ring, where N is the
 * number of copies of objects.
 */
static int contains_node(struct sheepdog_vnode_list_entry *key,
			 struct sheepdog_vnode_list_entry *entry,
			 int nr, int base_idx, int copies)
{
	int i;

	for (i = 0; i < copies; i++) {
		int idx = get_nth_node(entry, nr, base_idx, i);
		if (memcmp(key->addr, entry[idx].addr, sizeof(key->addr)) == 0
		    && key->port == entry[idx].port)
			return idx;
	}
	return -1;
}

enum rw_state {
	RW_INIT,
	RW_RUN,
};

struct recovery_work {
	enum rw_state state;

	uint32_t epoch;
	uint32_t done;

	struct timer timer;
	int retry;
	struct work work;
	struct list_head rw_siblings;

	int nr_blocking;
	int count;
	uint64_t *oids;

	int old_nr_nodes;
	struct sheepdog_node_list_entry old_nodes[SD_MAX_NODES];
	int cur_nr_nodes;
	struct sheepdog_node_list_entry cur_nodes[SD_MAX_NODES];
	int old_nr_vnodes;
	struct sheepdog_vnode_list_entry old_vnodes[SD_MAX_VNODES];
	int cur_nr_vnodes;
	struct sheepdog_vnode_list_entry cur_vnodes[SD_MAX_VNODES];
};

static LIST_HEAD(recovery_work_list);
static struct recovery_work *recovering_work;

/*
 * find_tgt_node - find the node from which we should recover objects
 *
 * This function compares two node lists, the current target nodes and
 * the previous target nodes, and finds the node from the previous
 * target nodes which corresponds to the copy_idx'th node of the
 * current target nodes.  The correspondence is injective and
 * maximizes the number of nodes which can recover objects locally.
 *
 * For example, consider the number of redundancy is 5, the consistent
 * hash ring is {A, B, C, D, E, F}, and the node G is newly added.
 * The parameters of this function are
 *   old_entry = {A, B, C, D, E, F},    old_nr = 6, old_idx = 3
 *   cur_entry = {A, B, C, D, E, F, G}, cur_nr = 7, cur_idx = 3
 *
 * In this case:
 *   the previous target nodes: {D, E, F, A, B}
 *     (the first 5 nodes from the 3rd node on the previous hash ring)
 *   the current target nodes : {D, E, F, G, A}
 *     (the first 5 nodes from the 3rd node on the current hash ring)
 *
 * The correspondence between copy_idx and return value are as follows:
 * ----------------------------
 * copy_idx       0  1  2  3  4
 * src_node       D  E  F  G  A
 * tgt_node       D  E  F  B  A
 * return value   0  1  2  4  3
 * ----------------------------
 *
 * The node D, E, F, and A can recover objects from local, and the
 * node G recovers from the node B.
 */
static int find_tgt_node(struct sheepdog_vnode_list_entry *old_entry,
			 int old_nr, int old_idx, int old_copies,
			 struct sheepdog_vnode_list_entry *cur_entry,
			 int cur_nr, int cur_idx, int cur_copies,
			 int copy_idx)
{
	int i, j, idx;

	dprintf("%"PRIu32", %"PRIu32", %"PRIu32", %"PRIu32", %"PRIu32", %"PRIu32", %"PRIu32"\n",
		old_idx, old_nr, old_copies, cur_idx, cur_nr, cur_copies, copy_idx);

	/* If the same node is in the previous target nodes, return its index */
	idx = contains_node(cur_entry + get_nth_node(cur_entry, cur_nr, cur_idx, copy_idx),
			    old_entry, old_nr, old_idx, old_copies);
	if (idx >= 0) {
		dprintf("%"PRIu32", %"PRIu32", %"PRIu32", %"PRIu32"\n", idx, copy_idx, cur_idx, cur_nr);
		return idx;
	}

	for (i = 0, j = 0; ; i++, j++) {
		if (i < copy_idx) {
			/* Skip if the node can recover from its local */
			idx = contains_node(cur_entry + get_nth_node(cur_entry, cur_nr, cur_idx, i),
					    old_entry, old_nr, old_idx, old_copies);
			if (idx >= 0)
				continue;

			/* Find the next target which needs to recover from remote */
			while (j < old_copies &&
			       contains_node(old_entry + get_nth_node(old_entry, old_nr, old_idx, j),
					     cur_entry, cur_nr, cur_idx, cur_copies) >= 0)
				j++;
		}
		if (j == old_copies) {
			/*
			 * Cannot find the target because the number of zones
			 * is smaller than the number of copies.  We can select
			 * any node in this case, so select the first one.
			 */
			return old_idx;
		}

		if (i == copy_idx) {
			/* Found the target node correspoinding to copy_idx */
			dprintf("%"PRIu32", %"PRIu32", %"PRIu32"\n",
				get_nth_node(old_entry, old_nr, old_idx, j),
				copy_idx, (cur_idx + i) % cur_nr);
			return get_nth_node(old_entry, old_nr, old_idx, j);
		}

	}

	return -1;
}

static int __recover_one(struct recovery_work *rw,
			 struct sheepdog_vnode_list_entry *_old_entry,
			 int old_nr, int old_copies,
			 struct sheepdog_vnode_list_entry *_cur_entry,
			 int cur_nr, int cur_copies, int cur_idx,
			 int copy_idx, uint32_t epoch, uint32_t tgt_epoch,
			 uint64_t oid, char *buf, int buf_len)
{
	struct sheepdog_vnode_list_entry *e;
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
	char name[128];
	unsigned wlen = 0, rlen;
	int fd, ret;
	struct sheepdog_vnode_list_entry *old_entry, *cur_entry, *next_entry;
	int next_nr, next_copies;
	int tgt_idx = -1;
	int old_idx;

	old_entry = malloc(sizeof(*old_entry) * SD_MAX_VNODES);
	cur_entry = malloc(sizeof(*cur_entry) * SD_MAX_VNODES);
	next_entry = malloc(sizeof(*next_entry) * SD_MAX_VNODES);
	if (!old_entry || !cur_entry || !next_entry) {
		eprintf("oom\n");
		goto err;
	}

	memcpy(old_entry, _old_entry, sizeof(*old_entry) * old_nr);
	memcpy(cur_entry, _cur_entry, sizeof(*cur_entry) * cur_nr);
next:
	dprintf("recover obj %"PRIx64" from epoch %"PRIu32"\n", oid, tgt_epoch);
	old_idx = obj_to_sheep(old_entry, old_nr, oid, 0);

	tgt_idx = find_tgt_node(old_entry, old_nr, old_idx, old_copies,
				cur_entry, cur_nr, cur_idx, cur_copies, copy_idx);
	if (tgt_idx < 0) {
		eprintf("cannot find target node, %"PRIx64"\n", oid);
		goto err;
	}
	e = old_entry + tgt_idx;

	if (is_myself(e->addr, e->port)) {
		char old[PATH_MAX], new[PATH_MAX];

		snprintf(old, sizeof(old), "%s%08u/%016" PRIx64, obj_path,
			 tgt_epoch, oid);
		snprintf(new, sizeof(new), "%s%08u/%016" PRIx64, obj_path,
			 epoch, oid);
		dprintf("link from %s to %s\n", old, new);
		if (link(old, new) == 0)
			goto out;

		if (errno == ENOENT) {
			next_nr = epoch_log_read(tgt_epoch - 1, buf, buf_len);
			if (next_nr <= 0) {
				eprintf("no previous epoch, %"PRIu32"\n", tgt_epoch - 1);
				goto err;
			}
			next_nr /= sizeof(struct sheepdog_node_list_entry);
			next_copies = get_max_copies((struct sheepdog_node_list_entry *)buf,
						     next_nr);
			next_nr = nodes_to_vnodes((struct sheepdog_node_list_entry *)buf,
						  next_nr, next_entry);
			goto not_found;
		}

		eprintf("cannot recover from local, %s, %s\n", old, new);
		goto err;
	}

	addr_to_str(name, sizeof(name), e->addr, 0);

	fd = connect_to(name, e->port);
	if (fd < 0) {
		eprintf("failed to connect to %s:%"PRIu32"\n", name, e->port);
		goto err;
	}

	if (is_vdi_obj(oid))
		rlen = sizeof(struct sheepdog_inode);
	else if (is_vdi_attr_obj(oid))
		rlen = SD_MAX_VDI_ATTR_VALUE_LEN;
	else
		rlen = SD_DATA_OBJ_SIZE;

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = SD_OP_READ_OBJ;
	hdr.oid = oid;
	hdr.epoch = epoch;
	hdr.flags = SD_FLAG_CMD_RECOVERY | SD_FLAG_CMD_DIRECT;
	hdr.tgt_epoch = tgt_epoch;
	hdr.data_length = rlen;

	ret = exec_req(fd, (struct sd_req *)&hdr, buf, &wlen, &rlen);

	close(fd);

	if (ret != 0) {
		eprintf("%"PRIu32"\n", rsp->result);
		goto err;
	}

	rsp = (struct sd_obj_rsp *)&hdr;

	if (rsp->result == SD_RES_SUCCESS) {
		char path[PATH_MAX], tmp_path[PATH_MAX];
		int flags = O_SYNC | O_RDWR | O_CREAT;

		snprintf(path, sizeof(path), "%s%08u/%016" PRIx64, obj_path,
			 epoch, oid);
		snprintf(tmp_path, sizeof(tmp_path), "%s%08u/%016" PRIx64 ".tmp",
			 obj_path, epoch, oid);

		fd = open(tmp_path, flags, def_fmode);
		if (fd < 0) {
			eprintf("failed to open %s, %s\n", tmp_path, strerror(errno));
			goto err;
		}

		ret = write(fd, buf, rlen);
		if (ret != rlen) {
			eprintf("failed to write object\n");
			goto err;
		}

		ret = fsetxattr(fd, ANAME_COPIES, &rsp->copies,
				sizeof(rsp->copies), 0);
		if (ret) {
			eprintf("couldn't set xattr\n");
			goto err;
		}

		close(fd);

		dprintf("rename %s to %s\n", tmp_path, path);
		ret = rename(tmp_path, path);
		if (ret < 0) {
			eprintf("failed to rename %s to %s, %m\n", tmp_path, path);
			goto err;
		}
		dprintf("recovered oid %"PRIx64" to epoch %"PRIu32"\n", oid, epoch);
		goto out;
	}

	if (rsp->result == SD_RES_NEW_NODE_VER || rsp->result == SD_RES_OLD_NODE_VER
	    || rsp->result == SD_RES_NETWORK_ERROR) {
		eprintf("try again, %"PRIu32", %"PRIx64"\n", rsp->result, oid);
		rw->retry = 1;
		goto out;
	}

	if (rsp->result != SD_RES_NO_OBJ || rsp->data_length == 0) {
		eprintf("%"PRIu32"\n", rsp->result);
		goto err;
	}
	next_nr = rsp->data_length / sizeof(struct sheepdog_node_list_entry);
	next_copies = get_max_copies((struct sheepdog_node_list_entry *)buf, next_nr);
	next_nr = nodes_to_vnodes((struct sheepdog_node_list_entry *)buf,
				  next_nr, next_entry);

not_found:
	for (copy_idx = 0; copy_idx < old_copies; copy_idx++)
		if (get_nth_node(old_entry, old_nr, old_idx, copy_idx) == tgt_idx)
			break;
	if (copy_idx == old_copies) {
		eprintf("bug: cannot find the proper copy_idx\n");
		goto err;
	}

	dprintf("%"PRIu32", %"PRIu32", %"PRIu32", %"PRIu32", %"PRIu32", %"PRIu32"\n", rsp->result, rsp->data_length, tgt_idx,
		old_idx, old_nr, copy_idx);
	memcpy(cur_entry, old_entry, sizeof(*old_entry) * old_nr);
	cur_copies = old_copies;
	cur_nr = old_nr;
	cur_idx = old_idx;

	memcpy(old_entry, next_entry, next_nr * sizeof(*next_entry));
	old_copies = next_copies;
	old_nr = next_nr;

	tgt_epoch--;
	goto next;
out:
	free(old_entry);
	free(cur_entry);
	free(next_entry);
	return 0;
err:
	free(old_entry);
	free(cur_entry);
	free(next_entry);
	return -1;
}

static void recover_one(struct work *work, int idx)
{
	struct recovery_work *rw = container_of(work, struct recovery_work, work);
	char *buf = NULL;
	int ret;
	uint64_t oid = rw->oids[rw->done];
	int old_copies, cur_copies;
	uint32_t epoch = rw->epoch;
	int i, copy_idx = 0, cur_idx = -1;
	int fd;

	eprintf("%"PRIu32" %"PRIu32", %16"PRIx64"\n", rw->done, rw->count, oid);

	fd = ob_open(epoch, oid, 0, &ret);
	if (fd != -1) {
		/* the object is already recovered */
		close(fd);
		goto out;
	}

	if (is_vdi_obj(oid))
		buf = malloc(sizeof(struct sheepdog_inode));
	else if (is_vdi_attr_obj(oid))
		buf = malloc(SD_MAX_VDI_ATTR_VALUE_LEN);
	else if (is_data_obj(oid))
		buf = valloc(SD_DATA_OBJ_SIZE);
	else
		buf = malloc(SD_DATA_OBJ_SIZE);

	if (!sys->nr_sobjs)
		goto fail;

	cur_idx = obj_to_sheep(rw->cur_vnodes, rw->cur_nr_vnodes, oid, 0);

	old_copies = get_max_copies(rw->old_nodes, rw->old_nr_nodes);
	cur_copies = get_max_copies(rw->cur_nodes, rw->cur_nr_nodes);

	copy_idx = -1;
	for (i = 0; i < cur_copies; i++) {
		int n = obj_to_sheep(rw->cur_vnodes, rw->cur_nr_vnodes, oid, i);
		if (is_myself(rw->cur_vnodes[n].addr, rw->cur_vnodes[n].port)) {
			copy_idx = i;
			break;
		}
	}
	if (copy_idx < 0) {
		eprintf("shouldn't happen\n");
		goto out;
	}

	dprintf("%"PRIu32", %"PRIu32", %"PRIu32"\n", cur_idx, rw->cur_nr_nodes,
		copy_idx);

	ret = __recover_one(rw, rw->old_vnodes, rw->old_nr_vnodes, old_copies,
			    rw->cur_vnodes, rw->cur_nr_vnodes, cur_copies,
			    cur_idx, copy_idx, epoch, epoch - 1, oid,
			    buf, SD_DATA_OBJ_SIZE);
	if (ret == 0)
		goto out;

	for (i = 0; i < cur_copies; i++) {
		if (i == copy_idx)
			continue;
		ret = __recover_one(rw, rw->old_vnodes, rw->old_nr_vnodes, old_copies,
				    rw->cur_vnodes, rw->cur_nr_vnodes, cur_copies, cur_idx, i,
				    epoch, epoch - 1, oid, buf, SD_DATA_OBJ_SIZE);
		if (ret == 0)
			goto out;
	}
fail:
	eprintf("failed to recover object %"PRIx64"\n", oid);
out:
	free(buf);
}

static struct recovery_work *suspended_recovery_work;

static void __start_recovery(struct work *work, int idx);

static void recover_timer(void *data)
{
	struct recovery_work *rw = (struct recovery_work *)data;
	uint64_t oid = rw->oids[rw->done];

	if (is_access_to_busy_objects(oid)) {
		suspended_recovery_work = rw;
		return;
	}

	queue_work(sys->recovery_wqueue, &rw->work);
}

void resume_recovery_work(void)
{
	struct recovery_work *rw;
	uint64_t oid;

	if (!suspended_recovery_work)
		return;

	rw = suspended_recovery_work;

	oid =  rw->oids[rw->done];
	if (is_access_to_busy_objects(oid))
		return;

	suspended_recovery_work = NULL;
	queue_work(sys->recovery_wqueue, &rw->work);
}

int is_recoverying_oid(uint64_t oid)
{
	uint64_t hval = fnv_64a_buf(&oid, sizeof(uint64_t), FNV1A_64_INIT);
	uint64_t min_hval;
	struct recovery_work *rw = recovering_work;
	int ret, fd, i;

	if (oid == 0)
		return 0;

	if (!rw)
		return 0; /* there is no thread working for object recovery */

	min_hval = fnv_64a_buf(&rw->oids[rw->done + rw->nr_blocking], sizeof(uint64_t), FNV1A_64_INIT);

	if (before(rw->epoch, sys->epoch))
		return 1;

	if (rw->state == RW_INIT)
		return 1;

	fd = ob_open(sys->epoch, oid, 0, &ret);
	if (fd != -1) {
		dprintf("the object %" PRIx64 " is already recoverd\n", oid);
		close(fd);
		return 0;
	}

	/* the first 'rw->nr_blocking' objects were already scheduled to be done earlier */
	for (i = 0; i < rw->nr_blocking; i++)
		if (rw->oids[rw->done + i] == oid)
			return 1;

	if (min_hval <= hval) {
		uint64_t *p;
		p = bsearch(&oid, rw->oids + rw->done + rw->nr_blocking,
			    rw->count - rw->done - rw->nr_blocking, sizeof(oid), obj_cmp);
		if (p) {
			dprintf("recover the object %" PRIx64 " first\n", oid);
			if (rw->nr_blocking == 0)
				rw->nr_blocking = 1; /* the first oid may be processed now */
			if (p > rw->oids + rw->done + rw->nr_blocking) {
				/* this object should be recovered earlier */
				memmove(rw->oids + rw->done + rw->nr_blocking + 1,
					rw->oids + rw->done + rw->nr_blocking,
					sizeof(uint64_t) * (p - (rw->oids + rw->done + rw->nr_blocking)));
				rw->oids[rw->done + rw->nr_blocking] = oid;
				rw->nr_blocking++;
			}
			return 1;
		}
	}

	dprintf("the object %" PRIx64 " is not found\n", oid);
	return 0;
}

static void recover_done(struct work *work, int idx)
{
	struct recovery_work *rw = container_of(work, struct recovery_work, work);
	uint64_t oid;

	if (rw->state == RW_INIT)
		rw->state = RW_RUN;
	else if (!rw->retry) {
		rw->done++;
		if (rw->nr_blocking > 0)
			rw->nr_blocking--;
	}

	oid = rw->oids[rw->done];

	if (rw->retry && list_empty(&recovery_work_list)) {
		rw->retry = 0;

		rw->timer.callback = recover_timer;
		rw->timer.data = rw;
		add_timer(&rw->timer, 2);
		return;
	}

	if (rw->done < rw->count && list_empty(&recovery_work_list)) {
		rw->work.fn = recover_one;

		if (is_access_to_busy_objects(oid)) {
			suspended_recovery_work = rw;
			return;
		}
		resume_pending_requests();
		queue_work(sys->recovery_wqueue, &rw->work);
		return;
	}

	dprintf("recovery done, %"PRIu32"\n", rw->epoch);
	recovering_work = NULL;

	sys->recovered_epoch = rw->epoch;
	resume_pending_requests();

	free(rw->oids);
	free(rw);

	if (!list_empty(&recovery_work_list)) {
		rw = list_first_entry(&recovery_work_list,
				      struct recovery_work, rw_siblings);

		list_del(&rw->rw_siblings);

		recovering_work = rw;
		queue_work(sys->recovery_wqueue, &rw->work);
	}
}

static int __fill_obj_list(struct sheepdog_node_list_entry *e, uint32_t epoch,
			   uint8_t *buf, size_t buf_size)
{
	int fd, ret;
	unsigned wlen, rlen;
	char name[128];
	struct sd_list_req hdr;
	struct sd_list_rsp *rsp;

	addr_to_str(name, sizeof(name), e->addr, 0);

	dprintf("%s %"PRIu32"\n", name, e->port);

	fd = connect_to(name, e->port);
	if (fd < 0) {
		eprintf("%s %"PRIu32"\n", name, e->port);
		return -1;
	}

	wlen = 0;
	rlen = buf_size;

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = SD_OP_GET_OBJ_LIST;
	hdr.tgt_epoch = epoch - 1;
	hdr.flags = 0;
	hdr.data_length = rlen;

	ret = exec_req(fd, (struct sd_req *)&hdr, buf, &wlen, &rlen);

	close(fd);

	rsp = (struct sd_list_rsp *)&hdr;

	if (ret || rsp->result != SD_RES_SUCCESS) {
		eprintf("try again, %"PRIu32", %"PRIu32"\n", ret, rsp->result);
		return -1;
	}

	dprintf("%"PRIu32"\n", rsp->data_length);

	return rsp->data_length / sizeof(uint64_t);
}

static int merge_objlist(struct sheepdog_vnode_list_entry *entries, int nr_entries,
			 uint64_t *list1, int nr_list1,
			 uint64_t *list2, int nr_list2, int nr_objs)
{
	int i, j, idx;
	int old_nr_list1 = nr_list1;

	for (i = 0; i < nr_list2; i++) {
		if (entries) {
			for (j = 0; j < nr_objs; j++) {
				idx = obj_to_sheep(entries, nr_entries, list2[i], j);
				if (is_myself(entries[idx].addr, entries[idx].port))
					break;
			}
			if (j == nr_objs)
				continue;
		}

		if (bsearch(list2 + i, list1, old_nr_list1, sizeof(*list1), obj_cmp))
			continue;

		list1[nr_list1++] = list2[i];
	}

	qsort(list1, nr_list1, sizeof(*list1), obj_cmp);

	return nr_list1;
}

#define MAX_RETRY_CNT  6

static int fill_obj_list(struct recovery_work *rw,
			 struct sheepdog_node_list_entry *old_entry, int old_nr,
			 struct sheepdog_node_list_entry *cur_entry, int cur_nr,
			 int nr_objs)
{
	int i, j;
	uint8_t *buf = NULL;
	size_t buf_size = SD_DATA_OBJ_SIZE; /* FIXME */
	struct sheepdog_vnode_list_entry *vnodes;
	int nr_vnodes, retry_cnt = 0;

	vnodes = malloc(sizeof(*vnodes) * SD_MAX_VNODES);
	buf = malloc(buf_size);
	if (!buf || !vnodes)
		goto fail;

	nr_vnodes = nodes_to_vnodes(cur_entry, cur_nr, vnodes);
	for (i = 0; i < cur_nr; i++) {
		int nr;

		for (j = 0; j < old_nr; j++)
			if (node_cmp(cur_entry + i, old_entry + j) == 0)
				break;

		if (j == old_nr)
			/* cur_entry[i] doesn't have a list file */
			continue;

	retry:
		nr  = __fill_obj_list(cur_entry + i, rw->epoch, buf, buf_size);
		if (nr < 0) {
			retry_cnt++;
			if (retry_cnt > MAX_RETRY_CNT) {
				eprintf("failed to get object list\n");
				eprintf("some objects may be lost\n");
				continue;
			} else {
				dprintf("retry get object list\n");
				sleep(1);
				goto retry;
			}
		}
		rw->count = merge_objlist(vnodes, nr_vnodes, rw->oids,
					  rw->count, (uint64_t *)buf, nr, nr_objs);
	}

	free(vnodes);
	free(buf);
	return 0;
fail:
	free(vnodes);
	free(buf);
	rw->retry = 1;
	return -1;
}

static void __start_recovery(struct work *work, int idx)
{
	struct recovery_work *rw = container_of(work, struct recovery_work, work);
	uint32_t epoch = rw->epoch;
	int nr_objs;

	dprintf("%u\n", epoch);

	if (rw->cur_nr_nodes == 0) {
		/* setup node list and virtual node list */
		rw->cur_nr_nodes = epoch_log_read(epoch, (char *)rw->cur_nodes,
						  sizeof(rw->cur_nodes));
		if (rw->cur_nr_nodes <= 0) {
			eprintf("failed to read epoch log, %"PRIu32"\n", epoch);
			goto fail;
		}
		rw->cur_nr_nodes /= sizeof(struct sheepdog_node_list_entry);

		rw->old_nr_nodes = epoch_log_read(epoch - 1, (char *)rw->old_nodes,
						  sizeof(rw->old_nodes));
		if (rw->old_nr_nodes <= 0) {
			eprintf("failed to read epoch log, %"PRIu32"\n", epoch - 1);
			goto fail;
		}
		rw->old_nr_nodes /= sizeof(struct sheepdog_node_list_entry);

		rw->old_nr_vnodes = nodes_to_vnodes(rw->old_nodes, rw->old_nr_nodes,
						    rw->old_vnodes);
		rw->cur_nr_vnodes = nodes_to_vnodes(rw->cur_nodes, rw->cur_nr_nodes,
						    rw->cur_vnodes);
	}

	if (!sys->nr_sobjs)
		goto fail;
	nr_objs = get_max_copies(rw->cur_nodes, rw->cur_nr_nodes);

	if (fill_obj_list(rw, rw->old_nodes, rw->old_nr_nodes, rw->cur_nodes,
			  rw->cur_nr_nodes, nr_objs) != 0) {
		eprintf("fatal recovery error\n");
		goto fail;
	}

	return;
fail:
	rw->count = 0;
	return;
}

int start_recovery(uint32_t epoch)
{
	struct recovery_work *rw;

	rw = zalloc(sizeof(struct recovery_work));
	if (!rw)
		return -1;

	rw->state = RW_INIT;
	rw->oids = malloc(1 << 20); /* FIXME */
	rw->epoch = epoch;
	rw->count = 0;

	rw->work.fn = __start_recovery;
	rw->work.done = recover_done;

	if (recovering_work != NULL)
		list_add_tail(&rw->rw_siblings, &recovery_work_list);
	else {
		recovering_work = rw;
		queue_work(sys->recovery_wqueue, &rw->work);
	}

	return 0;
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


static int attr(char *path, const char *name, void *var, int len, int set)
{
	int ret, fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return SD_RES_EIO;

	if (set)
		ret = fsetxattr(fd, name, var, len, 0);
	else
		ret = fgetxattr(fd, name, var, len);

	close(fd);

	if (set) {
		if (ret) {
			eprintf("use 'user_xattr' option?, %s\n", name);
			return SD_RES_SYSTEM_ERROR;
		}
	} else {
		if (ret != len)
			return SD_RES_SYSTEM_ERROR;
	}

	return SD_RES_SUCCESS;
}

int init_base_path(const char *d)
{
	int new = 0;

	return init_path(d, &new);
}

#define OBJ_PATH "/obj/"

static int init_obj_path(const char *base_path)
{
	int new;

	obj_path = zalloc(strlen(base_path) + strlen(OBJ_PATH) + 1);
	sprintf(obj_path, "%s" OBJ_PATH, base_path);

	return init_path(obj_path, &new);
}

#define EPOCH_PATH "/epoch/"

static int init_epoch_path(const char *base_path)
{
	int new, ret;
	uint32_t epoch, latest_epoch;
	DIR *dir;
	char path[1024];
	struct dirent *dent;
	uint64_t oid;

	epoch_path = zalloc(strlen(base_path) + strlen(EPOCH_PATH) + 1);
	sprintf(epoch_path, "%s" EPOCH_PATH, base_path);

	ret = init_path(epoch_path, &new);
	if (new || ret)
		return ret;

	latest_epoch = get_latest_epoch();

	for (epoch = 1; epoch <= latest_epoch; epoch++) {
		snprintf(path, sizeof(path), "%s/%08u", obj_path, epoch);

		vprintf(SDOG_INFO "found the obj dir, %s\n", path);

		dir = opendir(path);
		if (!dir) {
			if (errno == ENOENT)
				continue;

			vprintf(SDOG_ERR "failed to open the epoch dir, %m\n");
			return SD_RES_EIO;
		}

		while ((dent = readdir(dir))) {
			if (!strcmp(dent->d_name, ".") ||
			    !strcmp(dent->d_name, ".."))
				continue;

			oid = strtoull(dent->d_name, NULL, 16);

			if (!is_vdi_obj(oid))
				continue;

			vprintf(SDOG_DEBUG "found the vdi obj, %" PRIx64 "\n", oid);

			set_bit(oid_to_vid(oid), sys->vdi_inuse);
		}
		closedir(dir);
	}

	return 0;
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

	return 0;
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
		eprintf("failed to read epoch %"PRIu32"\n", *epoch);
		*nr_entries = 0;
		return SD_RES_EIO;
	}
	*nr_entries = ret / sizeof(*entries);

	*ctime = get_cluster_ctime();

	return SD_RES_SUCCESS;
}

int set_global_nr_copies(uint32_t copies)
{
	return attr(epoch_path, ANAME_COPIES, &copies, sizeof(copies), 1);
}

int get_global_nr_copies(uint32_t *copies)
{
	return attr(epoch_path, ANAME_COPIES, copies, sizeof(*copies), 0);
}

/* Journal APIs */
int jrnl_exists(struct jrnl_file_desc *jfd)
{
	int ret;
	char path[1024];
	struct stat s;

	snprintf(path, sizeof(path), "%s%08u/%016" PRIx64, jrnl_path,
		 jfd->jf_epoch, jfd->jf_oid);

	ret = stat(path, &s);
	if (ret)
		return 1;

	return 0;
}

int jrnl_update_epoch_store(uint32_t epoch)
{
	char new[1024];
	struct stat s;

	snprintf(new, sizeof(new), "%s%08u/", jrnl_path, epoch);
	if (stat(new, &s) < 0)
		if (errno == ENOENT)
			mkdir(new, def_dmode);

	return 0;
}

int jrnl_open(struct jrnl_file_desc *jfd, int aflags)
{
	char path[1024];
	int flags = aflags;
	int fd, ret;


	jrnl_update_epoch_store(jfd->jf_epoch);
	snprintf(path, sizeof(path), "%s%08u/%016" PRIx64, jrnl_path,
		 jfd->jf_epoch, jfd->jf_oid);

	fd = open(path, flags, def_fmode);
	if (fd < 0) {
		eprintf("failed to open %s, %s\n", path, strerror(errno));
		if (errno == ENOENT)
			ret = SD_RES_NO_OBJ;
		else
			ret = SD_RES_UNKNOWN;
	} else {
		jfd->jf_fd = fd;
		ret = SD_RES_SUCCESS;
	}

	return ret;
}

int jrnl_close(struct jrnl_file_desc *jfd)
{
	close(jfd->jf_fd);
	jfd->jf_fd = -1;

	return 0;
}

int jrnl_create(struct jrnl_file_desc *jfd)
{
	return jrnl_open(jfd, O_RDWR | O_CREAT);
}

inline uint32_t jrnl_get_type(struct jrnl_descriptor *jd)
{
	return *((uint32_t *) jd->jd_head);
}

int jrnl_get_type_from_file(struct jrnl_file_desc *jfd, uint32_t *jrnl_type)
{
	ssize_t retsize;

	retsize = pread64(jfd->jf_fd, jrnl_type, sizeof(*jrnl_type), 0);

	if (retsize != sizeof(*jrnl_type))
		return SD_RES_EIO;
	else
		return SD_RES_SUCCESS;
}

int jrnl_remove(struct jrnl_file_desc *jfd)
{
	char path[1024];
	int ret;

	snprintf(path, sizeof(path), "%s%08u/%016" PRIx64, jrnl_path,
		 jfd->jf_epoch, jfd->jf_oid);
	ret = unlink(path);
	if (ret) {
		eprintf("failed to remove %s, %s\n", path, strerror(errno));
		ret = SD_RES_EIO;
	} else
		ret = SD_RES_SUCCESS;

	return ret;
}

inline int jrnl_has_end_mark(struct jrnl_descriptor *jd)
{
	return jrnl_handlers[jrnl_get_type(jd)].has_end_mark(jd);
}

inline int jrnl_write_header(struct jrnl_descriptor *jd)
{
	return jrnl_handlers[jrnl_get_type(jd)].write_header(jd);
}

inline int jrnl_write_data(struct jrnl_descriptor *jd)
{
	return jrnl_handlers[jrnl_get_type(jd)].write_data(jd);
}

inline int jrnl_write_end_mark(struct jrnl_descriptor *jd)
{
	return jrnl_handlers[jrnl_get_type(jd)].write_end_mark(jd);
}

inline int jrnl_apply_to_target_object(struct jrnl_file_desc *jfd)
{
	int ret;
	uint32_t jrnl_type;

	ret = jrnl_get_type_from_file(jfd, &jrnl_type);
	if (ret)
		return ret;

	return jrnl_handlers[jrnl_type].apply_to_target_object(jfd);
}

inline int jrnl_commit_data(struct jrnl_descriptor *jd)
{
	return jrnl_handlers[jrnl_get_type(jd)].commit_data(jd);
}

int jrnl_perform(struct jrnl_descriptor *jd)
{
	int ret;

	ret = jrnl_create(&jd->jd_jfd);
	if (ret)
		goto out;

	ret = jrnl_write_header(jd);
	if (ret)
		goto out;

	ret = jrnl_write_data(jd);
	if (ret)
		goto out;

	ret = jrnl_write_end_mark(jd);
	if (ret)
		goto out;

	ret = jrnl_commit_data(jd);
	if (ret)
		goto out;

	ret = jrnl_close(&jd->jd_jfd);
	if (ret)
		goto out;

	ret = jrnl_remove(&jd->jd_jfd);

out:
	return ret;
}

int jrnl_recover(void)
{
	DIR *dir;
	struct dirent *d;
	char jrnl_dir[PATH_MAX], jrnl_file_path[PATH_MAX], obj_file_path[PATH_MAX];
	int epoch;

	epoch = get_latest_epoch();
	if (epoch < 0)
		return 1;

	snprintf(jrnl_dir, sizeof(jrnl_dir), "%s%08u/", jrnl_path, epoch);

	eprintf("Openning the directory %s.\n", jrnl_dir);
	dir = opendir(jrnl_dir);
	if (!dir)
		return -1;

	vprintf(SDOG_NOTICE "start jrnl_recovery.\n");
	while ((d = readdir(dir))) {
		int ret;
		struct jrnl_file_desc jfd;

		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		jfd.jf_epoch = epoch;
		sscanf(d->d_name, "%" PRIx64, &jfd.jf_oid);
		snprintf(jrnl_file_path, sizeof(jrnl_file_path), "%s%016" PRIx64,
			 jrnl_dir, jfd.jf_oid);
		snprintf(obj_file_path, sizeof(obj_file_path), "%s%08u/%016" PRIx64,
			 obj_path, epoch, jfd.jf_oid);
		ret = jrnl_open(&jfd, O_RDONLY);
		if (ret) {
			eprintf("Unable to open the journal file, %s, for reading.\n",
				jrnl_file_path);
			goto end_while_3;
		}
		jfd.jf_target_fd = ob_open(epoch, jfd.jf_oid, 0, &ret);
		if (ret) {
			eprintf("Unable to open the object file, %s, to recover.\n",
				obj_file_path);
			goto end_while_2;
		}
		ret = jrnl_apply_to_target_object(&jfd);
		if (ret)
			eprintf("Unable to recover the object, %s.\n",
				obj_file_path);

		close(jfd.jf_target_fd);
		jfd.jf_target_fd = -1;
end_while_2:
		jrnl_close(&jfd);
end_while_3:
		vprintf(SDOG_INFO "recovered the object in journal, %s\n",
			jrnl_file_path);
		jrnl_remove(&jfd);
	}
	closedir(dir);
	vprintf(SDOG_NOTICE "end jrnl_recovery.\n");

	return 0;
}

/* VDI data journalling functions */
static int jrnl_vdi_has_end_mark(struct jrnl_descriptor *jd)
{
	ssize_t ret;
	uint32_t end_mark = UNSET_END_MARK;
	struct jrnl_vdi_head *head = (struct jrnl_vdi_head *) jd->jd_head;

	ret = pread64(jd->jdf_fd, &end_mark, sizeof(end_mark),
		      sizeof(*head) + head->jh_size);

	return IS_END_MARK_SET(end_mark) ? SET_END_MARK : UNSET_END_MARK;
}

static int jrnl_vdi_write_header(struct jrnl_descriptor *jd)
{
	ssize_t ret;
	struct jrnl_vdi_head *head = (struct jrnl_vdi_head *) jd->jd_head;

	ret = pwrite64(jd->jdf_fd, head, sizeof(*head), 0);

	if (ret != sizeof(*head)) {
		if (errno == ENOSPC)
			ret = SD_RES_NO_SPACE;
		else
			ret = SD_RES_EIO;
	} else
		ret = SD_RES_SUCCESS;

	return ret;
}

static int jrnl_vdi_write_data(struct jrnl_descriptor *jd)
{
	ssize_t ret;
	struct jrnl_vdi_head *head = (struct jrnl_vdi_head *) jd->jd_head;

	ret = pwrite64(jd->jdf_fd, jd->jd_data, head->jh_size, sizeof(*head));

	if (ret != head->jh_size) {
		if (errno == ENOSPC)
			ret = SD_RES_NO_SPACE;
		else
			ret = SD_RES_EIO;
	} else
		ret = SD_RES_SUCCESS;

	return ret;
}

static int jrnl_vdi_write_end_mark(struct jrnl_descriptor *jd)
{
	ssize_t retsize;
	int ret;
	uint32_t end_mark = SET_END_MARK;
	struct jrnl_vdi_head *head = (struct jrnl_vdi_head *) jd->jd_head;

	retsize = pwrite64(jd->jdf_fd, &end_mark, sizeof(end_mark),
			   sizeof(*head) + head->jh_size);

	if (retsize != sizeof(end_mark)) {
		if (errno == ENOSPC)
			ret = SD_RES_NO_SPACE;
		else
			ret = SD_RES_EIO;
	} else
		ret = SD_RES_SUCCESS;

	jd->jd_end_mark = end_mark;

	return ret;
}

static int jrnl_vdi_apply_to_target_object(struct jrnl_file_desc *jfd)
{
	char *buf = NULL;
	int buf_len, res = 0;
	ssize_t retsize;
	struct jrnl_vdi_head jh;

	/* FIXME: handle larger size */
	buf_len = (1 << 22);
	buf = zalloc(buf_len);
	if (!buf) {
		eprintf("failed to allocate memory\n");
		return SD_RES_NO_MEM;
	}

	/* Flush out journal to disk (vdi object) */
	retsize = pread64(jfd->jf_fd, &jh, sizeof(jh), 0);
	retsize = pread64(jfd->jf_fd, buf, jh.jh_size, sizeof(jh));
	retsize = pwrite64(jfd->jf_target_fd, buf, jh.jh_size, jh.jh_offset);
	if (retsize != jh.jh_size) {
		if (errno == ENOSPC)
			res = SD_RES_NO_SPACE;
		else
			res = SD_RES_EIO;
	}

	/* Clean up */
	free(buf);

	return res;
}

static int jrnl_vdi_commit_data(struct jrnl_descriptor *jd)
{
	int ret = 0;
	ssize_t retsize;
	struct jrnl_vdi_head *head = (struct jrnl_vdi_head *) jd->jd_head;

	retsize = pwrite64(jd->jdf_target_fd, jd->jd_data, head->jh_size,
			   head->jh_offset);
	if (retsize != head->jh_size) {
		if (errno == ENOSPC)
			ret = SD_RES_NO_SPACE;
		else
			ret = SD_RES_EIO;
	}

	return ret;
}
