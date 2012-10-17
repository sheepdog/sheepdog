/*
 * Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "collie.h"

bool is_current(const struct sheepdog_inode *i)
{
	return !i->snap_ctime;
}

char *size_to_str(uint64_t _size, char *str, int str_size)
{
	const char *units[] = {"MB", "GB", "TB", "PB", "EB", "ZB", "YB"};
	int i = 0;
	double size;

	if (raw_output) {
		snprintf(str, str_size, "%" PRIu64, _size);
		return str;
	}

	size = (double)_size;
	size /= 1024 * 1024;
	while (i < ARRAY_SIZE(units) - 1 && size >= 1024) {
		i++;
		size /= 1024;
	}

	if (size >= 10)
		snprintf(str, str_size, "%.0lf %s", size, units[i]);
	else
		snprintf(str, str_size, "%.1lf %s", size, units[i]);

	return str;
}

int sd_read_object(uint64_t oid, void *data, unsigned int datalen,
		   uint64_t offset, bool direct)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int fd, ret;

	fd = connect_to(sdhost, sdport);
	if (fd < 0) {
		fprintf(stderr, "Failed to connect\n");
		return SD_RES_EIO;
	}

	sd_init_req(&hdr, SD_OP_READ_OBJ);
	hdr.data_length = datalen;

	hdr.obj.oid = oid;
	hdr.obj.offset = offset;
	if (direct)
		hdr.flags |= SD_FLAG_CMD_DIRECT;

	ret = exec_req(fd, &hdr, data);
	close(fd);

	if (ret) {
		fprintf(stderr, "Failed to read object %" PRIx64 "\n", oid);
		return SD_RES_EIO;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to read object %" PRIx64 " %s\n", oid,
			sd_strerror(rsp->result));
		return rsp->result;
	}

	set_trimmed_sectors(data, rsp->obj.offset, rsp->data_length, datalen);

	return SD_RES_SUCCESS;
}

int sd_write_object(uint64_t oid, uint64_t cow_oid, void *data,
		    unsigned int datalen, uint64_t offset, uint32_t flags,
		    int copies, bool create, bool direct)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int fd, ret;

	fd = connect_to(sdhost, sdport);
	if (fd < 0) {
		fprintf(stderr, "Failed to connect\n");
		return SD_RES_EIO;
	}

	if (create)
		sd_init_req(&hdr, SD_OP_CREATE_AND_WRITE_OBJ);
	else
		sd_init_req(&hdr, SD_OP_WRITE_OBJ);

	hdr.data_length = datalen;
	hdr.flags = flags | SD_FLAG_CMD_WRITE;
	if (cow_oid)
		hdr.flags |= SD_FLAG_CMD_COW;
	if (direct)
		hdr.flags |= SD_FLAG_CMD_DIRECT;

	hdr.obj.copies = copies;
	hdr.obj.oid = oid;
	hdr.obj.cow_oid = cow_oid;
	hdr.obj.offset = offset;

	ret = exec_req(fd, &hdr, data);
	close(fd);

	if (ret) {
		fprintf(stderr, "Failed to write object %" PRIx64 "\n", oid);
		return SD_RES_EIO;
	}
	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to write object %" PRIx64 ": %s\n", oid,
				sd_strerror(rsp->result));
		return rsp->result;
	}

	return SD_RES_SUCCESS;
}

int parse_vdi(vdi_parser_func_t func, size_t size, void *data)
{
	int ret, fd, count;
	struct vdi_copy *vc;
	unsigned long nr;
	static struct sheepdog_inode i;
	struct sd_req req;
	struct sd_rsp *rsp = (struct sd_rsp *)&req;
	unsigned int rlen = SD_DATA_OBJ_SIZE; /* FIXME */

	vc = zalloc(rlen);
	if (!vc) {
		fprintf(stderr, "Failed to allocate memory\n");
		return -1;
	}

	fd = connect_to(sdhost, sdport);
	if (fd < 0) {
		fprintf(stderr, "Failed to connect to %s:%d\n", sdhost, sdport);
		ret = -1;
		goto out;
	}

	sd_init_req(&req, SD_OP_GET_VDI_COPIES);
	req.data_length = rlen;

	ret = exec_req(fd, &req, (char *)vc);
	if (ret < 0) {
		fprintf(stderr, "Failed to read VDIs from %s:%d\n",
			sdhost, sdport);
		close(fd);
		goto out;
	}
	close(fd);

	count = rsp->data_length / sizeof(*vc);
	for (nr = 0; nr < count; nr++) {
		uint64_t oid;

		oid = vid_to_vdi_oid(vc[nr].vid);

		memset(&i, 0, sizeof(i));
		ret = sd_read_object(oid, &i, SD_INODE_HEADER_SIZE, 0, true);
		if (ret != SD_RES_SUCCESS) {
			fprintf(stderr, "Failed to read inode header\n");
			continue;
		}

		if (i.name[0] == '\0') /* this VDI has been deleted */
			continue;

		if (size > SD_INODE_HEADER_SIZE) {
			rlen = DIV_ROUND_UP(i.vdi_size, SD_DATA_OBJ_SIZE) *
				sizeof(i.data_vdi_id[0]);
			if (rlen > size - SD_INODE_HEADER_SIZE)
				rlen = size - SD_INODE_HEADER_SIZE;

			ret = sd_read_object(oid, ((char *)&i) + SD_INODE_HEADER_SIZE,
					     rlen, SD_INODE_HEADER_SIZE, true);

			if (ret != SD_RES_SUCCESS) {
				fprintf(stderr, "Failed to read inode\n");
				continue;
			}
		}

		func(i.vdi_id, i.name, i.tag, i.snap_id, 0, &i, data);
	}

out:
	free(vc);
	return 0;
}

int send_light_req_get_response(struct sd_req *hdr, const char *host, int port)
{
	int fd, ret;
	struct sd_rsp *rsp = (struct sd_rsp *)hdr;

	fd = connect_to(host, port);
	if (fd < 0)
		return -1;

	ret = exec_req(fd, hdr, NULL);
	close(fd);
	if (ret) {
		fprintf(stderr, "failed to connect to  %s:%d\n",
			host, port);
		return -1;
	}

	if (rsp->result != SD_RES_SUCCESS)
		return rsp->result;

	return SD_RES_SUCCESS;
}

/*
 * Light request only contains header, without body content.
 */
int send_light_req(struct sd_req *hdr, const char *host, int port)
{
	int ret = send_light_req_get_response(hdr, host, port);

	if (ret == -1)
		return -1;

	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "Response's result: %s\n",
			sd_strerror(ret));
		return -1;
	}

	return 0;
}
