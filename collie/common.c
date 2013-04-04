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

	ret = collie_exec_req(fd, &hdr, data);
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

	untrim_zero_sectors(data, rsp->obj.offset, rsp->data_length, datalen);

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

	ret = collie_exec_req(fd, &hdr, data);
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
	unsigned int rlen = sizeof(vdi_inuse);

	fd = connect_to(sdhost, sdport);
	if (fd < 0) {
		fprintf(stderr, "Failed to connect to %s:%d\n", sdhost, sdport);
		ret = -1;
		goto out;
	}

	sd_init_req(&req, SD_OP_READ_VDIS);
	req.data_length = sizeof(vdi_inuse);

	ret = collie_exec_req(fd, &req, &vdi_inuse);
	if (ret < 0) {
		fprintf(stderr, "Failed to read VDIs from %s:%d\n",
			sdhost, sdport);
		close(fd);
		goto out;
	}
	close(fd);

	for (nr = 0; nr < SD_NR_VDIS; nr++) {
		uint64_t oid;
		uint32_t snapid;

		if (!test_bit(nr, vdi_inuse))
			continue;

		oid = vid_to_vdi_oid(nr);

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

		snapid = is_current(&i) ? 0 : i.snap_id;
		func(i.vdi_id, i.name, i.tag, snapid, 0, &i, data);
	}

out:
	return ret;
}

int send_light_req_get_response(struct sd_req *hdr, const char *host, int port)
{
	int fd, ret;
	struct sd_rsp *rsp = (struct sd_rsp *)hdr;

	fd = connect_to(host, port);
	if (fd < 0)
		return -1;

	ret = collie_exec_req(fd, hdr, NULL);
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

/* Light request only contains header, without body content. */
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


int collie_exec_req(int sockfd, struct sd_req *hdr, void *data)
{
	/* Retry hard for collie because we can't get the newest epoch */
	return exec_req(sockfd, hdr, data, NULL, 0);
}

int do_generic_subcommand(struct subcommand *sub, int argc, char **argv)
{
	int i, ret;

	for (i = 0; sub[i].name; i++) {
		if (!strcmp(sub[i].name, argv[optind])) {
			unsigned long flags = sub[i].flags;

			if (flags & SUBCMD_FLAG_NEED_NODELIST) {
				ret = update_node_list(SD_MAX_NODES, 0);
				if (ret < 0) {
					fprintf(stderr,
						"Failed to get node list\n");
					exit(EXIT_SYSFAIL);
				}
			}

			if (flags & SUBCMD_FLAG_NEED_ARG
			    && argc != 5)
				subcommand_usage(argv[1], argv[2], EXIT_USAGE);
			optind++;
			return sub[i].fn(argc, argv);
		}
	}

	subcommand_usage(argv[1], argv[2], EXIT_FAILURE);
	return EXIT_FAILURE;
}
