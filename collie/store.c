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

#define ANAME_LAST_OID "user.sheepdog.last_oid"
#define ANAME_COPIES "user.sheepdog.copies"
#define ANAME_CURRENT "user.sheepdog.current"

static char *obj_dir;
static char *mnt_dir;
static char *zero_block;

static int stat_sheep(uint64_t *store_size, uint64_t *store_free)
{
	struct statvfs vs;
	int ret;
	DIR *dir;
	struct dirent *d;
	uint64_t used = 0;
	struct stat s;
	char path[1024];

	ret = statvfs(mnt_dir, &vs);
	if (ret)
		return SD_RES_EIO;

	dir = opendir(obj_dir);
	if (!dir)
		return SD_RES_EIO;

	while ((d = readdir(dir))) {
		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		snprintf(path, sizeof(path), "%s/%s", obj_dir, d->d_name);

		ret = stat(path, &s);
		if (ret)
			continue;

		used += s.st_size;
	}

	*store_size = vs.f_frsize * vs.f_bfree;
	*store_free = vs.f_frsize * vs.f_bfree - used;

	return SD_RES_SUCCESS;
}

static int read_from_one(struct cluster_info *cluster, uint64_t oid,
			 unsigned *rlen, void *buf, uint64_t offset)
{
	int i, n, nr, fd, ret;
	unsigned wlen;
	char name[128];
	struct sheepdog_node_list_entry *e;
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;

	e = zalloc(SD_MAX_NODES * sizeof(struct sheepdog_node_list_entry));
again:
	nr = build_node_list(&cluster->node_list, e);

	for (i = 0; i < nr; i++) {
		n = obj_to_sheep(e, nr, oid, i);

		snprintf(name, sizeof(name), "%d.%d.%d.%d",
			 e[n].addr[12], e[n].addr[13],
			 e[n].addr[14], e[n].addr[15]);

		fd = connect_to(name, e[n].port);
		if (fd < 0)
			continue;

		memset(&hdr, 0, sizeof(hdr));
		hdr.opcode = SD_OP_READ_OBJ;
		hdr.oid = oid;
		hdr.epoch = cluster->epoch;

		hdr.flags = 0;
		hdr.data_length = *rlen;
		hdr.offset = offset;

		ret = exec_req(fd, (struct sd_req *)&hdr, buf, &wlen, rlen);

		close(fd);

		if (ret)
			continue;

		switch (rsp->result) {
		case SD_RES_SUCCESS:
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

	return -1;
}

static int read_from_other_sheeps(struct cluster_info *cluster,
				  uint64_t oid, char *buf, int copies)
{
	int ret;
	unsigned int rlen;

	rlen = SD_DATA_OBJ_SIZE;

	ret = read_from_one(cluster, oid, &rlen, buf, 0);

	return ret;
}

static int check_epoch(struct cluster_info *cluster, struct request *req)
{
	struct sd_req *hdr = (struct sd_req *)&req->rq;
	uint32_t req_epoch = hdr->epoch;
	uint32_t opcode = hdr->opcode;
	int ret = SD_RES_SUCCESS;

	if (before(req_epoch, cluster->epoch)) {
		ret = SD_RES_OLD_NODE_VER;
		eprintf("old node version %u %u, %x\n",
			cluster->epoch, req_epoch, opcode);
	} else if (after(req_epoch, cluster->epoch)) {
		ret = SD_RES_NEW_NODE_VER;
			eprintf("new node version %u %u %x\n",
				cluster->epoch, req_epoch, opcode);
	}

	return ret;
}

static int ob_open(uint64_t oid, int aflags, int *ret)
{
	char path[1024];
	int flags = O_RDWR | aflags;
	int fd;

	snprintf(path, sizeof(path), "%s/%" PRIx64, obj_dir, oid);

	fd = open(path, flags, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (fd < 0) {
		if (errno == ENOENT)
			*ret = SD_RES_NO_OBJ;
		else
			*ret = SD_RES_UNKNOWN;
	} else
		*ret = 0;

	return fd;
}

void store_queue_request(struct work *work, int idx)
{
	struct request *req = container_of(work, struct request, work);
	struct cluster_info *cluster = req->ci->cluster;
	char path[1024];
	int fd = -1, ret = SD_RES_SUCCESS;
	char *buf = zero_block + idx * SD_DATA_OBJ_SIZE;
	struct sd_obj_req *hdr = (struct sd_obj_req *)&req->rq;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&req->rp;
	uint64_t oid = hdr->oid;
	uint32_t opcode = hdr->opcode;
	uint32_t epoch = cluster->epoch;
	uint32_t req_epoch = hdr->epoch;
	struct sd_node_rsp *nrsp = (struct sd_node_rsp *)&req->rp;
	int copies;

	/* use le_to_cpu */

	snprintf(path, sizeof(path), "%s/%" PRIx64, obj_dir, oid);

	dprintf("%d, %x, %s, %u, %u\n", idx, opcode, path, epoch, req_epoch);

	if (list_empty(&cluster->node_list)) {
		/* we haven't got SD_OP_GET_NODE_LIST response yet. */
		ret = SD_RES_SYSTEM_ERROR;
		goto out;
	}

	if (opcode != SD_OP_GET_NODE_LIST) {
		ret = check_epoch(cluster, req);
		if (ret != SD_RES_SUCCESS)
			goto out;
	}

	switch (opcode) {
	case SD_OP_CREATE_AND_WRITE_OBJ:
	case SD_OP_WRITE_OBJ:
	case SD_OP_READ_OBJ:
	case SD_OP_SYNC_OBJ:

		if (opcode == SD_OP_CREATE_AND_WRITE_OBJ)
			fd = ob_open(oid, O_CREAT, &ret);
		else
			fd = ob_open(oid, 0, &ret);

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

			ret = read_from_other_sheeps(cluster,
						     hdr->cow_oid, buf,
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
		} else
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
	case SD_OP_STAT_SHEEP:
		ret = stat_sheep(&nrsp->store_size, &nrsp->store_free);
		break;
	}
out:
	if (ret != SD_RES_SUCCESS) {
		dprintf("failed, %d, %d, %x, %s, %u, %u\n", ret, idx, opcode,
			path, epoch, req_epoch);

		rsp->result = ret;
	}

	if (fd != -1)
		close(fd);
}

static int so_read_vdis(struct request *req)
{
	struct sd_so_rsp *rsp = (struct sd_so_rsp *)&req->rp;
	DIR *dir, *vdir;
	struct dirent *dent, *vdent;
	char *p;
	int fd, ret;
	uint64_t coid;
	char path[1024], vpath[1024];
	struct sheepdog_dir_entry *sde = req->data;

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/vdi", obj_dir);

	dir = opendir(path);
	if (!dir)
		return SD_RES_NO_SUPER_OBJ;

	while ((dent = readdir(dir))) {
		if (!strcmp(dent->d_name, ".") ||
		    !strcmp(dent->d_name, ".."))
			continue;

		memcpy(vpath, path, sizeof(vpath));
		snprintf(vpath + strlen(vpath), sizeof(vpath) - strlen(vpath),
			 "/%s", dent->d_name);

		fd = open(vpath, O_RDONLY);
		if (fd < 0) {
			eprintf("%m\n");
			return SD_RES_EIO;
		}

		ret = fgetxattr(fd, ANAME_CURRENT, &coid,
				sizeof(coid));
		if (ret != sizeof(coid)) {
			close(fd);
			eprintf("%s, %m\n", path);
			return SD_RES_EIO;
		}

		dprintf("%lx\n", coid);

		close(fd);

		vdir = opendir(vpath);
		if (!vdir)
			return SD_RES_NO_VDI;

		while ((vdent = readdir(vdir))) {
			if (!strcmp(vdent->d_name, ".") ||
			    !strcmp(vdent->d_name, ".."))
				continue;

			p = strchr(vdent->d_name, '-');
			if (!p) {
				eprintf("bug %s\n", vdent->d_name);
				continue;
			}

			dprintf("%s\n", vdent->d_name);

			*p = '\0';

			sde->oid = strtoull(vdent->d_name, NULL, 16);
			sde->tag = strtoull(p + 1, NULL, 16);

			if (sde->oid == coid)
				sde->flags = FLAG_CURRENT;

			sde->name_len = strlen(dent->d_name);
			strcpy(sde->name, dent->d_name);
			sde = next_entry(sde);
		}
	}

	rsp->data_length = (char *)sde - (char *)req->data;
	dprintf("%d\n", rsp->data_length);

	return SD_RES_SUCCESS;
}

static int so_lookup_vdi(struct request *req)
{
	struct sd_so_req *hdr = (struct sd_so_req *)&req->rq;
	struct sd_so_rsp *rsp = (struct sd_so_rsp *)&req->rp;
	DIR *dir;
	struct dirent *dent;
	char *p;
	int fd, ret;
	uint64_t coid, oid;
	char path[1024];

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/vdi/", obj_dir);
	strncpy(path + strlen(path), (char *)req->data,	hdr->data_length);

	dprintf("%s, %x\n", path, hdr->tag);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		eprintf("%m\n");
		return SD_RES_EIO;
	}

	ret = fgetxattr(fd, ANAME_CURRENT, &coid,
			sizeof(coid));
	if (ret != sizeof(coid)) {
		close(fd);
		eprintf("%m\n");
		return SD_RES_EIO;
	}

	dprintf("%lx, %x\n", coid, hdr->tag);

	close(fd);

	if (hdr->tag == 0xffffffff) {
		close(fd);
		rsp->oid = coid;
		rsp->flags = SD_VDI_RSP_FLAG_CURRENT;
		return SD_RES_SUCCESS;
	}

	dir = opendir(path);
	if (!dir)
		return SD_RES_NO_VDI;

	while ((dent = readdir(dir))) {
		if (!strcmp(dent->d_name, ".") ||
		    !strcmp(dent->d_name, ".."))
			continue;

		p = strchr(dent->d_name, '-');
		if (!p) {
			eprintf("bug %s\n", dent->d_name);
			continue;
		}

		if (strtoull(p + 1, NULL, 16) == hdr->tag) {
			*p = '\0';
			oid = strtoull(dent->d_name, NULL, 16);
			rsp->oid = oid;
			dprintf("%lx, %x\n", oid, hdr->tag);
			if (oid == coid)
				rsp->flags = SD_VDI_RSP_FLAG_CURRENT;

			ret = SD_RES_SUCCESS;
			break;
		}
	}
	closedir(dir);

	return SD_RES_SUCCESS;
}

void so_queue_request(struct work *work, int idx)
{
	struct request *req = container_of(work, struct request, work);
	struct sd_so_req *hdr = (struct sd_so_req *)&req->rq;
	struct sd_so_rsp *rsp = (struct sd_so_rsp *)&req->rp;
	struct cluster_info *cluster = req->ci->cluster;
	int nfd, fd = -1, ret, result = SD_RES_SUCCESS;
	uint32_t opcode = hdr->opcode;
	uint64_t last_oid = 0;
	char path[1024];

	if (list_empty(&cluster->node_list)) {
		/* we haven't got SD_OP_GET_NODE_LIST response yet. */
		result = SD_RES_SYSTEM_ERROR;
		goto out;
	}

	result = check_epoch(cluster, req);
	if (result != SD_RES_SUCCESS)
		goto out;

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/vdi", obj_dir);

	switch (opcode) {
	case SD_OP_SO:
		ret = mkdir(path, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP |
			    S_IWGRP | S_IXGRP);
		if (ret && errno != EEXIST) {
			result = SD_RES_EIO;
			goto out;
		}

		fd = open(path, O_RDONLY);
		if (fd < 0) {
			result = SD_RES_EIO;
			goto out;
		}

		ret = fsetxattr(fd, ANAME_LAST_OID, &last_oid,
				sizeof(last_oid), 0);
		if (ret) {
			close(fd);
			result = SD_RES_EIO;
			goto out;
		}

		ret = fsetxattr(fd, ANAME_COPIES, &hdr->copies,
				sizeof(hdr->copies), 0);
		if (ret)
			result = SD_RES_EIO;
		break;
	case SD_OP_SO_NEW_VDI:
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			result = SD_RES_EIO;
			goto out;
		}

		ret = fgetxattr(fd, ANAME_LAST_OID, &last_oid,
				sizeof(last_oid));
		if (ret != sizeof(last_oid)) {
			close(fd);
			result = SD_RES_EIO;
			goto out;
		}

		strncpy(path + strlen(path), "/", 1);
		strncpy(path + strlen(path), (char *)req->data,	hdr->data_length);

		if (hdr->tag)
			;
		else {
			ret = mkdir(path, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP |
				    S_IWGRP | S_IXGRP);
			if (ret) {
				eprintf("%m\n");
				result = SD_RES_EIO;
				goto out;
			}
		}

		nfd = open(path, O_RDONLY);
		if (nfd < 0) {
			eprintf("%m\n");
			result = SD_RES_EIO;
			goto out;
		}

		last_oid += MAX_DATA_OBJS;

		snprintf(path+ strlen(path), sizeof(path) - strlen(path),
			 "/%016lx-%08x", last_oid, hdr->tag);
		ret = creat(path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
		if (ret < 0) {
			eprintf("%m\n");
			result = SD_RES_EIO;
			goto out;
		}
		close(ret);

		ret = fsetxattr(fd, ANAME_LAST_OID, &last_oid,
				sizeof(last_oid), 0);
		if (ret) {
			eprintf("%m\n");
			close(fd);
			result = SD_RES_EIO;
			goto out;
		}

		close(fd);

		ret = fsetxattr(nfd, ANAME_CURRENT, &last_oid,
				sizeof(last_oid), 0);

		close(nfd);

		eprintf("%lx\n", last_oid);
		rsp->oid = last_oid;
		break;

	case SD_OP_SO_LOOKUP_VDI:
		ret = so_lookup_vdi(req);
		break;
	case SD_OP_SO_READ_VDIS:
		ret = so_read_vdis(req);
		break;
	case SD_OP_SO_STAT:
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			result = SD_RES_EIO;
			goto out;
		}

		rsp->oid = 0;
		ret = fgetxattr(fd, ANAME_LAST_OID, &rsp->oid,
				sizeof(rsp->oid));
		if (ret != sizeof(rsp->oid)) {
			close(fd);
			result = SD_RES_SYSTEM_ERROR;
			goto out;
		}

		rsp->copies = 0;
		ret = fgetxattr(fd, ANAME_COPIES, &rsp->copies,
				sizeof(rsp->copies));
		if (ret != sizeof(rsp->copies)) {
			close(fd);
			result = SD_RES_SYSTEM_ERROR;
			goto out;
		}

		result = SD_RES_SUCCESS;
		break;
	}

out:
	if (result != SD_RES_SUCCESS)
		rsp->result = result;

	if (fd != -1)
		close(fd);
}

int init_store(char *dir)
{
	int ret;
	struct mntent *mnt;
	struct stat s, ms;
	FILE *fp;

	ret = stat(dir, &s);
	if (ret) {
		if (errno == ENOENT) {
			ret = mkdir(dir, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP |
				    S_IWGRP | S_IXGRP);
			if (ret) {
				eprintf("can't create the object dir %s, %m\n",
					dir);
				return 1;
			} else {
				ret = stat(dir, &s);
				if (ret)
					return 1;

				eprintf("created the object dir %s\n", dir);
			}
		} else {
			eprintf("can't handle the object dir %s, %m\n", dir);
			return 1;
		}
	} else if (!S_ISDIR(s.st_mode)) {
		eprintf("%s is not a directory\n", dir);
		return 1;
	}

	obj_dir = dir;

	fp = setmntent(MOUNTED, "r");
	if (!fp)
		return 1;

	while ((mnt = getmntent(fp))) {
		ret = stat(mnt->mnt_dir, &ms);
		if (ret)
			continue;

		if (ms.st_dev == s.st_dev) {
			mnt_dir = strdup(mnt->mnt_dir);
			break;
		}
	}

	endmntent(fp);

	zero_block = zalloc(SD_DATA_OBJ_SIZE * NR_WORKER_THREAD);
	if (!zero_block)
		return 1;

	return ret;
}
