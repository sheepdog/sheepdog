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
#include <time.h>

#include "sheep_priv.h"
#include "strbuf.h"
#include "util.h"

struct sheepdog_config {
	uint64_t ctime;
	uint16_t flags;
	uint8_t copies;
	uint8_t pad[3];
};

char *obj_path;
static char *epoch_path;
static char *mnt_path;
static char *jrnl_path;
static char *config_path;

static mode_t def_dmode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP;
mode_t def_fmode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

extern struct store_driver store;

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

int stat_sheep(uint64_t *store_size, uint64_t *store_free, uint32_t epoch)
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

static int merge_objlist(uint64_t *list1, int nr_list1,
			 uint64_t *list2, int nr_list2);

int get_obj_list(const struct sd_list_req *hdr, struct sd_list_rsp *rsp, void *data)
{
	uint64_t *list = (uint64_t *)data;
	int i, nr = 0;
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

	for (i = 1; i <= hdr->tgt_epoch; i++) {
		struct siocb iocb = { 0 };

		iocb.buf = buf;
		iocb.length = 0;
		iocb.epoch = i;
		store.get_objlist(&iocb);
		nr = merge_objlist(list, nr, (uint64_t *)iocb.buf, iocb.length);
	}
out:
	free(buf);
	rsp->data_length = nr * sizeof(uint64_t);
	for (i = 0; i < nr; i++) {
		dprintf("oid %"PRIx64"\n", list[i]);
	}
	return res;
}

static int read_copy_from_cluster(struct request *req, uint32_t epoch,
				  uint64_t oid, char *buf)
{
	int i, n, nr, ret;
	unsigned wlen, rlen;
	char name[128];
	struct sheepdog_vnode_list_entry *e;
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
	struct siocb iocb;
	int fd;

	e = req->entry;
	nr = req->nr_vnodes;

	for (i = 0; i < nr; i++) {
		n = obj_to_sheep(e, nr, oid, i);

		addr_to_str(name, sizeof(name), e[n].addr, 0);

		if (is_myself(e[n].addr, e[n].port)) {
			memset(&iocb, 0, sizeof(iocb));
			iocb.epoch = epoch;
			ret = store.open(oid, &iocb, 0);
			if (ret != SD_RES_SUCCESS)
				continue;

			iocb.buf = buf;
			iocb.length = SD_DATA_OBJ_SIZE;
			iocb.offset = 0;
			ret = store.read(oid, &iocb);
			if (ret != SD_RES_SUCCESS)
				continue;
			store.close(oid, &iocb);
			goto out;
		}

		fd = connect_to(name, e[n].port);
		if (fd < 0)
			continue;

		memset(&hdr, 0, sizeof(hdr));
		hdr.opcode = SD_OP_READ_OBJ;
		hdr.oid = oid;
		hdr.epoch = epoch;

		rlen = SD_DATA_OBJ_SIZE;
		wlen = 0;
		hdr.flags = SD_FLAG_CMD_IO_LOCAL;
		hdr.data_length = rlen;
		hdr.offset = 0;

		ret = exec_req(fd, (struct sd_req *)&hdr, buf, &wlen, &rlen);

		close(fd);

		if (ret)
			continue;

		switch (rsp->result) {
		case SD_RES_SUCCESS:
			ret = SD_RES_SUCCESS;
			goto out;
		case SD_RES_OLD_NODE_VER:
		case SD_RES_NEW_NODE_VER:
			/* waits for the node list timer */
			break;
		default:
			;
		}
	}

	ret = SD_RES_EIO;
out:
	return ret;
}

static int do_local_io(struct request *req, uint32_t epoch);

static int forward_read_obj_req(struct request *req)
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

	hdr.flags |= SD_FLAG_CMD_IO_LOCAL;

	/* TODO: we can do better; we need to check this first */
	for (i = 0; i < copies; i++) {
		n = obj_to_sheep(e, nr, oid, i);

		if (is_myself(e[n].addr, e[n].port)) {
			ret = do_local_io(req, hdr.epoch);
			goto out;
		}
	}

	n = obj_to_sheep(e, nr, oid, 0);

	fd = get_sheep_fd(e[n].addr, e[n].port, e[n].node_idx, hdr.epoch);
	if (fd < 0) {
		ret = SD_RES_NETWORK_ERROR;
		goto out;
	}

	wlen = 0;
	rlen = hdr.data_length;

	ret = exec_req(fd, (struct sd_req *)&hdr, req->data, &wlen, &rlen);

	if (ret) { /* network errors */
		del_sheep_fd(fd);
		ret = SD_RES_NETWORK_ERROR;
	} else {
		memcpy(&req->rp, rsp, sizeof(*rsp));
		ret = rsp->result;
	}
out:
	return ret;
}

static int forward_write_obj_req(struct request *req)
{
	int i, n, nr, fd, ret, pollret;
	unsigned wlen;
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

	hdr.flags |= SD_FLAG_CMD_IO_LOCAL;

	wlen = hdr.data_length;

	for (i = 0; i < copies; i++) {
		n = obj_to_sheep(e, nr, oid, i);

		addr_to_str(name, sizeof(name), e[n].addr, 0);

		if (is_myself(e[n].addr, e[n].port)) {
			local = 1;
			continue;
		}

		fd = get_sheep_fd(e[n].addr, e[n].port, e[n].node_idx, hdr.epoch);
		if (fd < 0) {
			eprintf("failed to connect to %s:%"PRIu32"\n", name, e[n].port);
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
	char new[1024];

	snprintf(new, sizeof(new), "%s%08u/", obj_path, epoch);
	mkdir(new, def_dmode);

	return 0;
}

int update_epoch_log(int epoch)
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

	len = sys->nr_nodes * sizeof(struct sheepdog_node_list_entry);
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

int write_object_local(uint64_t oid, char *data, unsigned int datalen,
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
		return SD_RES_NO_MEM;
	hdr = (struct sd_obj_req *)&req->rq;
	rsp = (struct sd_obj_rsp *)&req->rp;

	hdr->oid = oid;
	hdr->opcode = SD_OP_READ_OBJ;
	hdr->copies = copies;
	hdr->flags = 0;
	hdr->offset = offset;
	hdr->data_length = datalen;
	req->data = data;
	req->op = get_sd_op(hdr->opcode);

	ret = do_local_io(req, epoch);

	rsp_data_length = rsp->data_length;
	free(req);

	return ret;
}

int store_remove_obj(const struct sd_req *req, struct sd_rsp *rsp, void *data)
{
	struct sd_obj_req *hdr = (struct sd_obj_req *)req;
	uint32_t epoch = hdr->epoch;
	char path[1024];

	snprintf(path, sizeof(path), "%s%08u/%016" PRIx64, obj_path,
		 epoch, hdr->oid);

	if (unlink(path) < 0) {
		if (errno == ENOENT)
			return SD_RES_NO_OBJ;
		eprintf("%m\n");
		return SD_RES_EIO;
	}

	return SD_RES_SUCCESS;
}

int store_read_obj(const struct sd_req *req, struct sd_rsp *rsp, void *data)
{
	struct sd_obj_req *hdr = (struct sd_obj_req *)req;
	struct sd_obj_rsp *rsps = (struct sd_obj_rsp *)rsp;
	struct request *request = (struct request *)data;
	int ret;
	uint32_t epoch = hdr->epoch;
	struct siocb iocb;

	memset(&iocb, 0, sizeof(iocb));
	iocb.epoch = epoch;
	iocb.flags = hdr->flags;
	ret = store.open(hdr->oid, &iocb, 0);
	if (ret != SD_RES_SUCCESS)
		return ret;

	iocb.buf = request->data;
	iocb.length = hdr->data_length;
	iocb.offset = hdr->offset;
	ret = store.read(hdr->oid, &iocb);
	if (ret != SD_RES_SUCCESS)
		goto out;

	rsps->data_length = hdr->data_length;
	rsps->copies = sys->nr_sobjs;
out:
	store.close(hdr->oid, &iocb);
	return ret;
}

static int do_write_obj(struct siocb *iocb, struct sd_obj_req *req, uint32_t epoch, void *data)
{
	struct sd_obj_req *hdr = (struct sd_obj_req *)req;
	uint64_t oid = hdr->oid;
	int ret = SD_RES_SUCCESS;
	void *jd = NULL;

	iocb->buf = data;
	iocb->length = hdr->data_length;
	iocb->offset = hdr->offset;
	if (is_vdi_obj(oid)) {
		char path[1024];

		snprintf(path, sizeof(path), "%s%08u/%016" PRIx64, obj_path,
			 epoch, oid);
		jd = jrnl_begin(data, hdr->data_length,
				   hdr->offset, path, jrnl_path);
		if (!jd)
			return SD_RES_EIO;
		ret = store.write(oid, iocb);
		jrnl_end(jd);
	} else
		ret = store.write(oid, iocb);

	return ret;
}

int store_write_obj(const struct sd_req *req, struct sd_rsp *rsp, void *data)
{
	struct sd_obj_req *hdr = (struct sd_obj_req *)req;
	struct request *request = (struct request *)data;
	int ret;
	uint32_t epoch = hdr->epoch;
	struct siocb iocb;

	memset(&iocb, 0, sizeof(iocb));
	iocb.epoch = epoch;
	iocb.flags = hdr->flags;
	ret = store.open(hdr->oid, &iocb, 0);
	if (ret != SD_RES_SUCCESS)
		return ret;

	ret = do_write_obj(&iocb, hdr, epoch, request->data);

	store.close(hdr->oid, &iocb);
	return ret;
}

int store_create_and_write_obj(const struct sd_req *req, struct sd_rsp *rsp, void *data)
{
	struct sd_obj_req *hdr = (struct sd_obj_req *)req;
	struct request *request = (struct request *)data;
	int ret;
	uint32_t epoch = hdr->epoch;
	char *buf = NULL;
	struct siocb iocb;

	if (!hdr->copies) {
		eprintf("the number of copies cannot be zero\n");
		return SD_RES_INVALID_PARMS;
	}

	memset(&iocb, 0, sizeof(iocb));
	iocb.epoch = epoch;
	iocb.flags = hdr->flags;
	ret = store.open(hdr->oid, &iocb, 1);
	if (ret != SD_RES_SUCCESS)
		return ret;
	if (hdr->flags & SD_FLAG_CMD_COW) {
		dprintf("%" PRIu64 ", %" PRIx64 "\n", hdr->oid, hdr->cow_oid);

		buf = xzalloc(SD_DATA_OBJ_SIZE);
		ret = read_copy_from_cluster(request, hdr->epoch, hdr->cow_oid, buf);
		if (ret != SD_RES_SUCCESS) {
			eprintf("failed to read cow object\n");
			goto out;
		}
		iocb.buf = buf;
		iocb.length = SD_DATA_OBJ_SIZE;
		iocb.offset = 0;
		ret = store.write(hdr->oid, &iocb);
		if (ret != SD_RES_SUCCESS)
			goto out;
	}
	ret = do_write_obj(&iocb, hdr, epoch, request->data);
out:
	free(buf);
	store.close(hdr->oid, &iocb);
	return ret;
}

static int do_local_io(struct request *req, uint32_t epoch)
{
	struct sd_obj_req *hdr = (struct sd_obj_req *)&req->rq;
	int ret = SD_RES_SUCCESS;

	hdr->epoch = epoch;
	dprintf("%x, %" PRIx64" , %u\n", hdr->opcode, hdr->oid, epoch);

	ret = do_process_work(req->op, &req->rq, &req->rp, req);

	if (ret == SD_RES_NO_OBJ && hdr->flags & SD_FLAG_CMD_RECOVERY) {
		struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&req->rp;
		int len = epoch_log_read(epoch - 1, req->data, hdr->data_length);
		if (len < 0)
			len = 0;
		rsp->data_length = len;
	}

	return ret;
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
		data_length = sizeof(struct sheepdog_inode);
	else if (is_vdi_attr_obj(hdr->oid))
		data_length = SD_MAX_VDI_ATTR_VALUE_LEN;
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
		eprintf("failed to read object %d\n", ret);
		goto out;
	}

	hdr->opcode = SD_OP_WRITE_OBJ;
	hdr->flags = SD_FLAG_CMD_WRITE;
	hdr->oid = oid;
	req->op = get_sd_op(SD_OP_WRITE_OBJ);
	ret = forward_write_obj_req(req);
	if (ret != SD_RES_SUCCESS) {
		eprintf("failed to write object %d\n", ret);
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
	}
out:
	if (ret != SD_RES_SUCCESS)
		dprintf("failed: %x, %" PRIx64" , %u, %"PRIu32"\n",
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
	struct sheepdog_node_list_entry nodes[SD_MAX_NODES];

	nr = epoch_log_read(le, (char *)nodes, ARRAY_SIZE(nodes));
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
	nr /= sizeof(struct sheepdog_node_list_entry);
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

int get_latest_epoch(void)
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

int remove_epoch(int epoch)
{
	int ret;
	char path[PATH_MAX];

	dprintf("remove epoch %"PRIu32"\n", epoch);
	snprintf(path, sizeof(path), "%s%08u", epoch_path, epoch);
	ret = unlink(path);
	if (ret && ret != -ENOENT) {
		eprintf("failed to remove %s: %s\n", path, strerror(-ret));
		return SD_RES_EIO;
	}

	snprintf(path, sizeof(path), "%s%08u", obj_path, epoch);
	ret = rmdir_r(path);
	if (ret && ret != -ENOENT) {
		eprintf("failed to remove %s: %s\n", path, strerror(-ret));
		return SD_RES_EIO;
	}

	snprintf(path, sizeof(path), "%s%08u/", jrnl_path, epoch);
	ret = rmdir_r(path);
	if (ret && ret != -ENOENT) {
		eprintf("failed to remove %s: %s\n", path, strerror(-ret));
		return SD_RES_EIO;
	}
	return 0;
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

static struct recovery_work *next_rw;
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
		eprintf("failed to allocate memory\n");
		goto err;
	}

	memcpy(old_entry, _old_entry, sizeof(*old_entry) * old_nr);
	memcpy(cur_entry, _cur_entry, sizeof(*cur_entry) * cur_nr);
next:
	dprintf("recover object %"PRIx64" from epoch %"PRIu32"\n", oid, tgt_epoch);
	old_idx = obj_to_sheep(old_entry, old_nr, oid, 0);

	tgt_idx = find_tgt_node(old_entry, old_nr, old_idx, old_copies,
				cur_entry, cur_nr, cur_idx, cur_copies, copy_idx);
	if (tgt_idx < 0) {
		eprintf("cannot find target node %"PRIx64"\n", oid);
		goto err;
	}
	e = old_entry + tgt_idx;

	if (is_myself(e->addr, e->port)) {
		struct siocb iocb = { 0 };

		iocb.epoch = epoch;
		ret = store.link(oid, &iocb, tgt_epoch);
		if (ret == SD_RES_SUCCESS)
			goto out;

		if (ret == SD_RES_NO_OBJ) {
			next_nr = epoch_log_read(tgt_epoch - 1, buf, buf_len);
			if (next_nr <= 0) {
				eprintf("no previous epoch: %"PRIu32"\n", tgt_epoch - 1);
				goto err;
			}
			next_nr /= sizeof(struct sheepdog_node_list_entry);
			next_copies = get_max_copies((struct sheepdog_node_list_entry *)buf,
						     next_nr);
			next_nr = nodes_to_vnodes((struct sheepdog_node_list_entry *)buf,
						  next_nr, next_entry);
			goto not_found;
		}

		eprintf("Cannot recover from local store for %"PRIx64"\n", oid);
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
	hdr.flags = SD_FLAG_CMD_RECOVERY | SD_FLAG_CMD_IO_LOCAL;
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
		int flags = O_DSYNC | O_RDWR | O_CREAT;

		snprintf(path, sizeof(path), "%s%08u/%016" PRIx64, obj_path,
			 epoch, oid);
		snprintf(tmp_path, sizeof(tmp_path), "%s%08u/%016" PRIx64 ".tmp",
			 obj_path, epoch, oid);

		fd = open(tmp_path, flags, def_fmode);
		if (fd < 0) {
			eprintf("failed to open %s: %m\n", tmp_path);
			goto err;
		}

		ret = write(fd, buf, rlen);
		if (ret != rlen) {
			eprintf("failed to write object\n");
			goto err;
		}

		close(fd);

		dprintf("rename %s to %s\n", tmp_path, path);
		ret = rename(tmp_path, path);
		if (ret < 0) {
			eprintf("failed to rename %s to %s: %m\n", tmp_path, path);
			goto err;
		}
		dprintf("recovered oid %"PRIx64" to epoch %"PRIu32"\n", oid, epoch);
		goto out;
	}

	if (rsp->result == SD_RES_NEW_NODE_VER || rsp->result == SD_RES_OLD_NODE_VER
	    || rsp->result == SD_RES_NETWORK_ERROR) {
		eprintf("retrying: %"PRIu32", %"PRIx64"\n", rsp->result, oid);
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

static void recover_one(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work, work);
	char *buf = NULL;
	int ret;
	uint64_t oid = rw->oids[rw->done];
	int old_copies, cur_copies;
	uint32_t epoch = rw->epoch;
	int i, copy_idx = 0, cur_idx = -1;
	struct siocb iocb;

	eprintf("%"PRIu32" %"PRIu32", %16"PRIx64"\n", rw->done, rw->count, oid);

	memset(&iocb, 0, sizeof(iocb));
	iocb.epoch = epoch;
	ret = store.open(oid, &iocb, 0);
	if (ret == SD_RES_SUCCESS) {
		/* the object is already recovered */
		store.close(oid, &iocb);
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
		eprintf("bug: copy_idx < 0\n");
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
	int ret, i;
	struct siocb iocb;

	if (oid == 0)
		return 0;

	if (!rw)
		return 0; /* there is no thread working for object recovery */

	min_hval = fnv_64a_buf(&rw->oids[rw->done + rw->nr_blocking], sizeof(uint64_t), FNV1A_64_INIT);

	if (before(rw->epoch, sys->epoch))
		return 1;

	if (rw->state == RW_INIT)
		return 1;

	memset(&iocb, 0, sizeof(iocb));
	iocb.epoch = sys->epoch;
	ret = store.open(oid, &iocb, 0);
	if (ret == SD_RES_SUCCESS) {
		dprintf("the object %" PRIx64 " is already recoverd\n", oid);
		store.close(oid, &iocb);
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

static void recover_done(struct work *work)
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

	if (rw->retry && !next_rw) {
		rw->retry = 0;

		rw->timer.callback = recover_timer;
		rw->timer.data = rw;
		add_timer(&rw->timer, 2);
		return;
	}

	if (rw->done < rw->count && !next_rw) {
		rw->work.fn = recover_one;

		if (is_access_to_busy_objects(oid)) {
			suspended_recovery_work = rw;
			return;
		}
		resume_pending_requests();
		queue_work(sys->recovery_wqueue, &rw->work);
		return;
	}

	dprintf("recovery complete: new epoch %"PRIu32"\n", rw->epoch);
	recovering_work = NULL;

	sys->recovered_epoch = rw->epoch;

	free(rw->oids);
	free(rw);

	if (next_rw) {
		rw = next_rw;
		next_rw = NULL;

		recovering_work = rw;
		queue_work(sys->recovery_wqueue, &rw->work);
	}

	resume_pending_requests();
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
		eprintf("retrying: %"PRIu32", %"PRIu32"\n", ret, rsp->result);
		return -1;
	}

	dprintf("%lu\n", rsp->data_length / sizeof(uint64_t));

	return rsp->data_length / sizeof(uint64_t);
}

static int merge_objlist(uint64_t *list1, int nr_list1, uint64_t *list2, int nr_list2)
{
	int i;
	int old_nr_list1 = nr_list1;

	for (i = 0; i < nr_list2; i++) {
		if (bsearch(list2 + i, list1, old_nr_list1, sizeof(*list1), obj_cmp))
			continue;

		list1[nr_list1++] = list2[i];
	}

	qsort(list1, nr_list1, sizeof(*list1), obj_cmp);

	return nr_list1;
}

static int screen_obj_list(struct sheepdog_vnode_list_entry *nodes, int nodes_nr,
			   uint64_t *list, int list_nr, int nr_objs)
{
	int ret, i, cp, idx;
	struct strbuf buf = STRBUF_INIT;

	for (i = 0; i < list_nr; i++) {
		for (cp = 0; cp < nr_objs; cp++) {
			idx = obj_to_sheep(nodes, nodes_nr, list[i], cp);
			if (is_myself(nodes[idx].addr, nodes[idx].port))
				break;
		}
		if (cp == nr_objs)
			continue;
		strbuf_add(&buf, &list[i], sizeof(uint64_t));
	}
	memcpy(list, buf.buf, buf.len);

	ret = buf.len / sizeof(uint64_t);
	dprintf("%d\n", ret);
	strbuf_release(&buf);

	return ret;
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
	int retry_cnt;

	buf = malloc(buf_size);
	if (!buf)
		goto fail;

	for (i = 0; i < cur_nr; i++) {
		int nr;

		for (j = 0; j < old_nr; j++)
			if (node_cmp(cur_entry + i, old_entry + j) == 0)
				break;

		if (j == old_nr)
			/* cur_entry[i] doesn't have a list file */
			continue;

		retry_cnt = 0;
	retry:
		nr  = __fill_obj_list(cur_entry + i, rw->epoch, buf, buf_size);
		if (nr < 0) {
			retry_cnt++;
			if (retry_cnt > MAX_RETRY_CNT) {
				eprintf("failed to get object list\n");
				eprintf("some objects may be lost\n");
				continue;
			} else {
				if (next_rw) {
					dprintf("go to the next recovery\n");
					break;
				}
				dprintf("trying to get object list again\n");
				sleep(1);
				goto retry;
			}
		}
		nr = screen_obj_list(rw->cur_vnodes, rw->cur_nr_vnodes, (uint64_t *)buf,
				     nr, nr_objs);
		if (nr)
			rw->count = merge_objlist(rw->oids, rw->count, (uint64_t *)buf, nr);
	}

	dprintf("%d\n", rw->count);
	free(buf);
	return 0;
fail:
	free(buf);
	rw->retry = 1;
	return -1;
}

static void __start_recovery(struct work *work)
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
			eprintf("failed to read epoch log for epoch %"PRIu32"\n", epoch);
			goto fail;
		}
		rw->cur_nr_nodes /= sizeof(struct sheepdog_node_list_entry);

		rw->old_nr_nodes = epoch_log_read(epoch - 1, (char *)rw->old_nodes,
						  sizeof(rw->old_nodes));
		if (rw->old_nr_nodes <= 0) {
			eprintf("failed to read epoch log for epoch %"PRIu32"\n", epoch - 1);
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

	if (recovering_work != NULL) {
		if (next_rw) {
			/* skip the previous epoch recovery */
			free(next_rw->oids);
			free(next_rw);
		}
		next_rw = rw;
	} else {
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

		vprintf(SDOG_INFO, "found the object directory %s\n", path);

		dir = opendir(path);
		if (!dir) {
			if (errno == ENOENT)
				continue;

			vprintf(SDOG_ERR, "failed to open the epoch directory: %m\n");
			return SD_RES_EIO;
		}

		while ((dent = readdir(dir))) {
			if (!strcmp(dent->d_name, ".") ||
			    !strcmp(dent->d_name, ".."))
				continue;

			oid = strtoull(dent->d_name, NULL, 16);

			if (!is_vdi_obj(oid))
				continue;

			vprintf(SDOG_DEBUG, "found the VDI object %" PRIx64 "\n", oid);

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

	ret = store.init(obj_path);
	if (ret)
		return ret;

	return ret;
}

int read_epoch(uint32_t *epoch, uint64_t *ct,
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

	*ct = get_cluster_ctime();

	return SD_RES_SUCCESS;
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
