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

int is_current(struct sheepdog_inode *i)
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
	while (i < ARRAY_SIZE(units) && size >= 1024) {
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
		   uint64_t offset)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int fd, ret;
	unsigned wlen = 0, rlen = datalen;

	fd = connect_to(sdhost, sdport);
	if (fd < 0) {
		fprintf(stderr, "Failed to connect\n");
		return SD_RES_EIO;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.epoch = node_list_version;
	hdr.opcode = SD_OP_READ_OBJ;
	hdr.flags = SD_FLAG_CMD_WEAK_CONSISTENCY;
	hdr.data_length = rlen;

	hdr.obj.oid = oid;
	hdr.obj.offset = offset;

	ret = exec_req(fd, &hdr, data, &wlen, &rlen);
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

	return SD_RES_SUCCESS;
}

int sd_write_object(uint64_t oid, uint64_t cow_oid, void *data, unsigned int datalen,
		    uint64_t offset, uint32_t flags, int copies, int create)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int fd, ret;
	unsigned wlen = datalen, rlen;

	fd = connect_to(sdhost, sdport);
	if (fd < 0) {
		fprintf(stderr, "Failed to connect\n");
		return SD_RES_EIO;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.epoch = node_list_version;
	if (create)
		hdr.opcode = SD_OP_CREATE_AND_WRITE_OBJ;
	else
		hdr.opcode = SD_OP_WRITE_OBJ;
	hdr.data_length = wlen;
	hdr.flags = (flags & ~SD_FLAG_CMD_IO_LOCAL) | SD_FLAG_CMD_WRITE;

	hdr.obj.copies = copies;
	hdr.obj.oid = oid;
	hdr.obj.cow_oid = cow_oid;
	hdr.obj.offset = offset;

	ret = exec_req(fd, &hdr, data, &wlen, &rlen);
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
	int ret, fd;
	unsigned long nr;
	static struct sheepdog_inode i;
	struct sd_req req;
	static DECLARE_BITMAP(vdi_inuse, SD_NR_VDIS);
	unsigned int rlen, wlen = 0;

	fd = connect_to(sdhost, sdport);
	if (fd < 0) {
		fprintf(stderr, "Failed to connect to %s:%d\n", sdhost, sdport);
		return fd;
	}

	memset(&req, 0, sizeof(req));

	req.opcode = SD_OP_READ_VDIS;
	req.data_length = sizeof(vdi_inuse);
	req.epoch = node_list_version;

	rlen = sizeof(vdi_inuse);
	ret = exec_req(fd, &req, vdi_inuse, &wlen, &rlen);
	if (ret < 0) {
		fprintf(stderr, "Failed to read VDIs from %s:%d\n",
			sdhost, sdport);
		close(fd);
		return ret;
	}
	close(fd);

	for (nr = 0; nr < SD_NR_VDIS; nr++) {
		uint64_t oid;

		if (!test_bit(nr, vdi_inuse))
			continue;

		oid = vid_to_vdi_oid(nr);

		memset(&i, 0, sizeof(i));
		ret = sd_read_object(oid, &i, SD_INODE_HEADER_SIZE, 0);
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
					     rlen, SD_INODE_HEADER_SIZE);

			if (ret != SD_RES_SUCCESS) {
				fprintf(stderr, "Failed to read inode\n");
				continue;
			}
		}

		func(i.vdi_id, i.name, i.tag, i.snap_id, 0, &i, data);
	}

	return 0;
}
