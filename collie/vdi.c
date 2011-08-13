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

#include <ctype.h>
#include <time.h>
#include <sys/time.h>

#include "collie.h"
#include "treeview.h"

struct vdi_cmd_data {
	unsigned int index;
	int snapshot_id;
	char snapshot_tag[SD_MAX_VDI_TAG_LEN];
	int exclusive;
	int delete;
	int prealloc;
} vdi_cmd_data = { ~0, };

struct get_vdi_info {
	char *name;
	char *tag;
	uint32_t vid;
	uint32_t snapid;
};

static int parse_option_size(const char *value, uint64_t *ret)
{
	char *postfix;
	double sizef;

	sizef = strtod(value, &postfix);
	switch (*postfix) {
	case 'T':
		sizef *= 1024;
	case 'G':
		sizef *= 1024;
	case 'M':
		sizef *= 1024;
	case 'K':
	case 'k':
		sizef *= 1024;
	case 'b':
	case '\0':
		*ret = (uint64_t) sizef;
		break;
	default:
		fprintf(stderr, "invalid parameter, %s\n", value);
		fprintf(stderr, "You may use k, M, G or T suffixes for "
			"kilobytes, megabytes, gigabytes and terabytes.\n");
		return -1;
	}

	return 0;
}

static void print_vdi_list(uint32_t vid, char *name, char *tag, uint32_t snapid,
			   uint32_t flags, struct sheepdog_inode *i, void *data)
{
	int idx;
	uint64_t my_objs, cow_objs;
	char vdi_size_str[16], my_objs_str[16], cow_objs_str[16];
	time_t ti;
	struct tm tm;
	char dbuf[128];
	struct get_vdi_info *info = data;

	if (info && strcmp(name, info->name) != 0)
		return;

	ti = i->ctime >> 32;
	if (raw_output) {
		snprintf(dbuf, sizeof(dbuf), "%" PRIu64, (uint64_t) ti);
	} else {
		localtime_r(&ti, &tm);
		strftime(dbuf, sizeof(dbuf),
			 "%Y-%m-%d %H:%M", &tm);
	}

	my_objs = 0;
	cow_objs = 0;
	for (idx = 0; idx < MAX_DATA_OBJS; idx++) {
		if (!i->data_vdi_id[idx])
			continue;
		if (is_data_obj_writeable(i, idx))
			my_objs++;
		else
			cow_objs++;
	}

	size_to_str(i->vdi_size, vdi_size_str, sizeof(vdi_size_str));
	size_to_str(my_objs * SD_DATA_OBJ_SIZE, my_objs_str, sizeof(my_objs_str));
	size_to_str(cow_objs * SD_DATA_OBJ_SIZE, cow_objs_str, sizeof(cow_objs_str));

	if (raw_output) {
		printf("%c ", is_current(i) ? '=' : 's');
		while (*name) {
			if (isspace(*name) || *name == '\\')
				putchar('\\');
			putchar(*name++);
		}
		printf(" %d %s %s %s %s %" PRIx32 "\n", snapid,
				vdi_size_str, my_objs_str, cow_objs_str, dbuf, vid);
	} else {
		printf("%c %-8s %5d %7s %7s %7s %s  %7" PRIx32 "\n",
				is_current(i) ? ' ' : 's', name, snapid,
				vdi_size_str, my_objs_str, cow_objs_str, dbuf, vid);
	}
}

static void print_vdi_tree(uint32_t vid, char *name, char * tag, uint32_t snapid,
			   uint32_t flags, struct sheepdog_inode *i, void *data)
{
	time_t ti;
	struct tm tm;
	char buf[128];

	if (is_current(i))
		strcpy(buf, "(You Are Here)");
	else {
		ti = i->ctime >> 32;
		localtime_r(&ti, &tm);

		strftime(buf, sizeof(buf),
			 "[%Y-%m-%d %H:%M]", &tm);
	}

	add_vdi_tree(name, buf, vid, i->parent_vdi_id, highlight && is_current(i));
}

static void print_vdi_graph(uint32_t vid, char *name, char * tag, uint32_t snapid,
			    uint32_t flags, struct sheepdog_inode *i, void *data)
{
	time_t ti;
	struct tm tm;
	char dbuf[128], tbuf[128], size_str[128];

	ti = i->ctime >> 32;
	localtime_r(&ti, &tm);

	strftime(dbuf, sizeof(dbuf), "%Y-%m-%d", &tm);
	strftime(tbuf, sizeof(tbuf), "%H:%M:%S", &tm);
	size_to_str(i->vdi_size, size_str, sizeof(size_str));

	printf("  \"%x\" -> \"%x\";\n", i->parent_vdi_id, vid);
	printf("  \"%x\" [\n"
	       "    group = \"%s\",\n"
	       "    label = \"",
	       vid, name);
	printf("name: %10s\\n"
	       "tag : %10x\\n"
	       "size: %10s\\n"
	       "date: %10s\\n"
	       "time: %10s",
	       name, snapid, size_str, dbuf, tbuf);

	if (is_current(i))
		printf("\",\n    color=\"red\"\n  ];\n\n");
	else
		printf("\"\n  ];\n\n");

}

static void get_oid(uint32_t vid, char *name, char *tag, uint32_t snapid,
		    uint32_t flags, struct sheepdog_inode *i, void *data)
{
	struct get_vdi_info *info = data;

	if (info->name) {
		if (info->tag) {
			if (!strcmp(name, info->name) && !strcmp(tag, info->tag))
				info->vid = vid;
		} else if (info->snapid) {
			if (!strcmp(name, info->name) && snapid == info->snapid)
				info->vid = vid;
		} else {
			if (!strcmp(name, info->name))
				info->vid = vid;
		}
	}
}

typedef void (*obj_parser_func_t)(char *sheep, uint64_t oid,
				  struct sd_obj_rsp *rsp, char *buf, void *data);

static void do_print_obj(char *sheep, uint64_t oid, struct sd_obj_rsp *rsp,
			 char *buf, void *data)
{
	switch (rsp->result) {
	case SD_RES_SUCCESS:
		printf("%s: has the object (should be %d copies)\n",
		       sheep, rsp->copies);
		break;
	case SD_RES_NO_OBJ:
		printf("%s: doesn't have\n", sheep);
		break;
	case SD_RES_OLD_NODE_VER:
	case SD_RES_NEW_NODE_VER:
		printf("the node list has changed, try again\n");
		break;
	default:
		printf("%s: hit an expected error, %d\n",
		       sheep, rsp->result);
		break;
	}
}

struct get_data_oid_info {
	int success;
	uint64_t data_oid;
	unsigned idx;
};

static void get_data_oid(char *sheep, uint64_t oid, struct sd_obj_rsp *rsp,
			 char *buf, void *data)
{
	struct get_data_oid_info *info = data;
	struct sheepdog_inode *inode = (struct sheepdog_inode *)buf;

	switch (rsp->result) {
	case SD_RES_SUCCESS:
		if (info->success)
			break;
		info->success = 1;
		if (inode->data_vdi_id[info->idx])
			info->data_oid = vid_to_data_oid(inode->data_vdi_id[info->idx], info->idx);
		break;
	case SD_RES_NO_OBJ:
		break;
	case SD_RES_OLD_NODE_VER:
	case SD_RES_NEW_NODE_VER:
		printf("the node list has changed, try again\n");
		break;
	default:
		printf("%s: hit an expected error, %d\n",
		       sheep, rsp->result);
		break;
	}
}

static void parse_objs(uint64_t oid, obj_parser_func_t func, void *data)
{
	char name[128];
	int i, fd, ret;
	char *buf;

	buf = zalloc(sizeof(struct sheepdog_inode));
	if (!buf) {
		fprintf(stderr, "out of memory\n");
		return;
	}

	for (i = 0; i < nr_nodes; i++) {
		unsigned wlen = 0, rlen = sizeof(struct sheepdog_inode);
		struct sd_obj_req hdr;
		struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;

		addr_to_str(name, sizeof(name), node_list_entries[i].addr, 0);

		fd = connect_to(name, node_list_entries[i].port);
		if (fd < 0)
			break;

		memset(&hdr, 0, sizeof(hdr));

		hdr.opcode = SD_OP_READ_OBJ;
		hdr.data_length = rlen;
		hdr.flags = SD_FLAG_CMD_DIRECT;
		hdr.oid = oid;
		hdr.epoch = node_list_version;

		ret = exec_req(fd, (struct sd_req *)&hdr, buf, &wlen, &rlen);
		close(fd);

		sprintf(name + strlen(name), ":%d", node_list_entries[i].port);

		if (ret)
			printf("%s: can't connect\n", name);
		else
			func(name, oid, rsp, buf, data);
	}

	free(buf);
}


static int vdi_list(int argc, char **argv)
{
	char *vdiname = argv[optind];

	if (!raw_output) {
		printf("  name        id    size    used  shared    creation time   vdi id\n");
		printf("------------------------------------------------------------------\n");
	}

	if (vdiname) {
		struct get_vdi_info info;
		memset(&info, 0, sizeof(info));
		info.name = vdiname;
		parse_vdi(print_vdi_list, SD_INODE_SIZE, &info);
		return EXIT_SUCCESS;
	} else {
		parse_vdi(print_vdi_list, SD_INODE_SIZE, NULL);
		return EXIT_SUCCESS;
	}
}

static int vdi_tree(int argc, char **argv)
{
	init_tree();
	parse_vdi(print_vdi_tree, SD_INODE_HEADER_SIZE, NULL);
	dump_tree();

	return EXIT_SUCCESS;
}

static int vdi_graph(int argc, char **argv)
{
	/* print a header */
	printf("digraph G {\n");
	printf("  node [shape = \"box\", fontname = \"Courier\"];\n\n");
	printf("  \"0\" [shape = \"ellipse\", label = \"root\"];\n\n");

	parse_vdi(print_vdi_graph, SD_INODE_HEADER_SIZE, NULL);

	/* print a footer */
	printf("}\n");

	return EXIT_SUCCESS;
}

static int find_vdi_name(char *vdiname, uint32_t snapid, const char *tag,
			 uint32_t *vid, int for_snapshot)
{
	int ret, fd;
	struct sd_vdi_req hdr;
	struct sd_vdi_rsp *rsp = (struct sd_vdi_rsp *)&hdr;
	unsigned int wlen, rlen = 0;
	char buf[SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN];

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return -1;

	memset(buf, 0, sizeof(buf));
	strncpy(buf, vdiname, SD_MAX_VDI_LEN);
	strncpy(buf + SD_MAX_VDI_LEN, tag, SD_MAX_VDI_TAG_LEN);

	memset(&hdr, 0, sizeof(hdr));
	if (for_snapshot)
		hdr.opcode = SD_OP_GET_VDI_INFO;
	else
		hdr.opcode = SD_OP_LOCK_VDI;
	wlen = SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN;
	hdr.proto_ver = SD_PROTO_VER;
	hdr.data_length = wlen;
	hdr.snapid = snapid;
	hdr.flags = SD_FLAG_CMD_WRITE;

	ret = exec_req(fd, (struct sd_req *)&hdr, buf, &wlen, &rlen);
	if (ret) {
		ret = -1;
		goto out;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "cannot get vdi info, %s, %s %d %s\n",
			sd_strerror(rsp->result), vdiname, snapid, tag);
		ret = -1;
		goto out;
	}
	*vid = rsp->vdi_id;

	ret = 0;
out:
	close(fd);
	return ret;
}

static int do_vdi_create(char *vdiname, int64_t vdi_size, uint32_t base_vid,
			 uint32_t *vdi_id, int snapshot)
{
	struct sd_vdi_req hdr;
	struct sd_vdi_rsp *rsp = (struct sd_vdi_rsp *)&hdr;
	int fd, ret;
	unsigned int wlen, rlen = 0;
	char buf[SD_MAX_VDI_LEN];

	fd = connect_to(sdhost, sdport);
	if (fd < 0) {
		fprintf(stderr, "failed to connect\n");
		return EXIT_SYSFAIL;
	}

	memset(buf, 0, sizeof(buf));
	strncpy(buf, vdiname, SD_MAX_VDI_LEN);

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = SD_OP_NEW_VDI;
	hdr.base_vdi_id = base_vid;

	wlen = SD_MAX_VDI_LEN;

	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.snapid = snapshot;

	hdr.data_length = wlen;
	hdr.vdi_size = vdi_size;

	ret = exec_req(fd, (struct sd_req *)&hdr, buf, &wlen, &rlen);

	close(fd);

	if (ret) {
		fprintf(stderr, "failed to send a request\n");
		return EXIT_SYSFAIL;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "%s, %s\n", sd_strerror(rsp->result), vdiname);
		return EXIT_FAILURE;
	}

	if (vdi_id)
		*vdi_id = rsp->vdi_id;

	return EXIT_SUCCESS;
}

static int vdi_create(int argc, char **argv)
{
	char *vdiname = argv[optind++];
	uint64_t size;
	uint32_t vid;
	uint64_t oid;
	int idx, max_idx, ret;
	struct sheepdog_inode *inode = NULL;
	char *buf = NULL;

	if (!argv[optind]) {
		fprintf(stderr, "please specify the size of vdi\n");
		return EXIT_USAGE;
	}
	ret = parse_option_size(argv[optind], &size);
	if (ret < 0)
		return EXIT_USAGE;
	if (size > SD_MAX_VDI_SIZE) {
		fprintf(stderr, "too big image size, %s\n", argv[optind]);
		return EXIT_USAGE;
	}

	ret = do_vdi_create(vdiname, size, 0, &vid, 0);
	if (ret != EXIT_SUCCESS || !vdi_cmd_data.prealloc)
		goto out;

	inode = malloc(sizeof(*inode));
	buf = zalloc(SD_DATA_OBJ_SIZE);
	if (!inode || !buf) {
		fprintf(stderr, "oom\n");
		ret = EXIT_SYSFAIL;
		goto out;
	}

	ret = sd_read_object(vid_to_vdi_oid(vid), inode, sizeof(*inode), 0);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "failed to read a newly created vdi object\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	max_idx = DIV_ROUND_UP(size, SD_DATA_OBJ_SIZE);

	for (idx = 0; idx < max_idx; idx++) {
		oid = vid_to_data_oid(vid, idx);

		ret = sd_write_object(oid, 0, buf, SD_DATA_OBJ_SIZE, 0, 0,
				      inode->nr_copies, 1);
		if (ret != SD_RES_SUCCESS) {
			ret = EXIT_FAILURE;
			goto out;
		}

		inode->data_vdi_id[idx] = vid;
		ret = sd_write_object(vid_to_vdi_oid(vid), 0, &vid, sizeof(vid),
				      SD_INODE_HEADER_SIZE + sizeof(vid) * idx, 0,
				      inode->nr_copies, 0);
		if (ret) {
			ret = EXIT_FAILURE;
			goto out;
		}
	}
	ret = EXIT_SUCCESS;
out:
	free(inode);
	free(buf);
	return ret;
}

static int vdi_snapshot(int argc, char **argv)
{
	char *vdiname = argv[optind++];
	uint32_t vid;
	int ret;
	char buf[SD_INODE_HEADER_SIZE];
	struct sheepdog_inode *inode = (struct sheepdog_inode *)buf;

	if (vdi_cmd_data.snapshot_id != 0) {
		fprintf(stderr, "please specify a non-integer value for "
			"a snapshot tag name\n");
		return EXIT_USAGE;
	}

	ret = find_vdi_name(vdiname, 0, "", &vid, 0);
	if (ret < 0) {
		fprintf(stderr, "failed to open vdi %s\n", vdiname);
		return EXIT_FAILURE;
	}

	ret = sd_read_object(vid_to_vdi_oid(vid), inode, SD_INODE_HEADER_SIZE, 0);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "failed to read an inode header\n");
		return EXIT_FAILURE;
	}

	if (vdi_cmd_data.snapshot_tag[0]) {
		ret = sd_write_object(vid_to_vdi_oid(vid), 0, vdi_cmd_data.snapshot_tag,
				      SD_MAX_VDI_TAG_LEN,
				      offsetof(struct sheepdog_inode, tag),
				      0, inode->nr_copies, 0);
	}

	return do_vdi_create(vdiname, inode->vdi_size, vid, NULL, 1);
}

static int vdi_clone(int argc, char **argv)
{
	char *src_vdi = argv[optind++], *dst_vdi;
	uint32_t base_vid, new_vid;
	uint64_t oid;
	int idx, max_idx, ret;
	struct sheepdog_inode *inode = NULL;
	char *buf = NULL;

	dst_vdi = argv[optind];
	if (!dst_vdi) {
		fprintf(stderr, "a dst vdi must be specified\n");
		ret = EXIT_USAGE;
		goto out;
	}

	if (!vdi_cmd_data.snapshot_id && !vdi_cmd_data.snapshot_tag[0]) {
		fprintf(stderr, "it is not supported to create a clone image of "
			"the non-snapshot vdi\n");
		fprintf(stderr, "please specify a '-s' option\n");
		ret = EXIT_USAGE;
		goto out;
	}

	ret = find_vdi_name(src_vdi, vdi_cmd_data.snapshot_id,
			    vdi_cmd_data.snapshot_tag, &base_vid, 0);
	if (ret < 0) {
		fprintf(stderr, "failed to open vdi %s\n", src_vdi);
		ret = EXIT_FAILURE;
		goto out;
	}

	inode = malloc(sizeof(*inode));
	if (!inode) {
		fprintf(stderr, "oom\n");
		ret = EXIT_SYSFAIL;
		goto out;
	}
	ret = sd_read_object(vid_to_vdi_oid(base_vid), inode, SD_INODE_SIZE, 0);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "failed to read a base inode\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	ret = do_vdi_create(dst_vdi, inode->vdi_size, base_vid, &new_vid, 0);
	if (ret != EXIT_SUCCESS || !vdi_cmd_data.prealloc)
		goto out;

	buf = zalloc(SD_DATA_OBJ_SIZE);
	if (!buf) {
		fprintf(stderr, "oom\n");
		ret = EXIT_SYSFAIL;
		goto out;
	}

	max_idx = DIV_ROUND_UP(inode->vdi_size, SD_DATA_OBJ_SIZE);

	for (idx = 0; idx < max_idx; idx++) {
		if (inode->data_vdi_id[idx]) {
			oid = vid_to_data_oid(inode->data_vdi_id[idx], idx);
			ret = sd_read_object(oid, buf, SD_DATA_OBJ_SIZE, 0);
			if (ret) {
				ret = EXIT_FAILURE;
				goto out;
			}
		} else
			memset(buf, 0, SD_DATA_OBJ_SIZE);

		oid = vid_to_data_oid(new_vid, idx);
		ret = sd_write_object(oid, 0, buf, SD_DATA_OBJ_SIZE, 0, 0,
				      inode->nr_copies, 1);
		if (ret != SD_RES_SUCCESS) {
			ret = EXIT_FAILURE;
			goto out;
		}

		ret = sd_write_object(vid_to_vdi_oid(new_vid), 0, &new_vid, sizeof(new_vid),
				      SD_INODE_HEADER_SIZE + sizeof(new_vid) * idx, 0,
				      inode->nr_copies, 0);
		if (ret) {
			ret = EXIT_FAILURE;
			goto out;
		}
	}
	ret = EXIT_SUCCESS;
out:
	free(inode);
	free(buf);
	return ret;
}

static int vdi_resize(int argc, char **argv)
{
	char *vdiname = argv[optind++];
	uint64_t new_size;
	uint32_t vid;
	int ret;
	char buf[SD_INODE_HEADER_SIZE];
	struct sheepdog_inode *inode = (struct sheepdog_inode *)buf;

	if (!argv[optind]) {
		fprintf(stderr, "please specify a new size of vdi\n");
		return EXIT_USAGE;
	}
	ret = parse_option_size(argv[optind], &new_size);
	if (ret < 0)
		return EXIT_USAGE;
	if (new_size > SD_MAX_VDI_SIZE) {
		fprintf(stderr, "too big image size, %s\n", argv[optind]);
		return EXIT_USAGE;
	}

	ret = find_vdi_name(vdiname, 0, "", &vid, 0);
	if (ret < 0) {
		fprintf(stderr, "failed to open vdi %s\n", vdiname);
		return EXIT_FAILURE;
	}

	ret = sd_read_object(vid_to_vdi_oid(vid), inode, SD_INODE_HEADER_SIZE, 0);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "failed to read an inode header\n");
		return EXIT_FAILURE;
	}

	if (new_size < inode->vdi_size) {
		fprintf(stderr, "shrinking is not implemented\n");
		return EXIT_USAGE;
	}
	inode->vdi_size = new_size;

	ret = sd_write_object(vid_to_vdi_oid(vid), 0, inode, SD_INODE_HEADER_SIZE, 0,
			      0, inode->nr_copies, 0);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "failed to update an inode header\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int vdi_delete(int argc, char **argv)
{
	char *data = argv[optind];
	int fd, ret;
	struct sd_vdi_req hdr;
	struct sd_vdi_rsp *rsp = (struct sd_vdi_rsp *)&hdr;
	unsigned rlen, wlen;
	char vdiname[SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN];

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return EXIT_SYSFAIL;

	memset(&hdr, 0, sizeof(hdr));

	rlen = 0;
	wlen = sizeof(vdiname);

	hdr.opcode = SD_OP_DEL_VDI;
	hdr.snapid = vdi_cmd_data.snapshot_id;
	hdr.epoch = node_list_version;
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = wlen;
	memset(vdiname, 0, sizeof(vdiname));
	strncpy(vdiname, data, SD_MAX_VDI_LEN);
	strncpy(vdiname + SD_MAX_VDI_LEN, vdi_cmd_data.snapshot_tag,
		SD_MAX_VDI_TAG_LEN);

	ret = exec_req(fd, (struct sd_req *)&hdr, vdiname, &wlen, &rlen);
	close(fd);

	if (ret) {
		fprintf(stderr, "failed to connect\n");
		return EXIT_SYSFAIL;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "%s: %s\n", vdiname, sd_strerror(rsp->result));
		if (rsp->result == SD_RES_NO_VDI)
			return EXIT_MISSING;
		else
			return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int vdi_object(int argc, char **argv)
{
	char *vdiname = argv[optind];
	unsigned idx = vdi_cmd_data.index;
	int ret;
	struct get_vdi_info info;
	uint32_t vid;

	memset(&info, 0, sizeof(info));
	info.name = vdiname;
	info.tag = vdi_cmd_data.snapshot_tag;
	info.vid = 0;
	info.snapid = vdi_cmd_data.snapshot_id;

	ret = parse_vdi(get_oid, SD_INODE_HEADER_SIZE, &info);

	vid = info.vid;
	if (vid == 0) {
		printf("No such vdi\n");
		return EXIT_MISSING;
	}

	if (idx == ~0) {
		printf("Looking for the inode object 0x%" PRIx32 " with %d nodes\n\n",
		       vid, nr_nodes);
		parse_objs(vid_to_vdi_oid(vid), do_print_obj, NULL);
	} else {
		struct get_data_oid_info old_info;

		old_info.success = 0;
		old_info.idx = idx;

		if (idx >= MAX_DATA_OBJS) {
			printf("The offset is too large!\n");
			exit(EXIT_FAILURE);
		}

		parse_objs(vid_to_vdi_oid(vid), get_data_oid, &old_info);

		if (old_info.success) {
			if (old_info.data_oid) {
				printf("Looking for the object 0x%" PRIx64
				       " (the inode vid 0x%" PRIx32 " idx %u) with %d nodes\n\n",
				       old_info.data_oid, vid, idx, nr_nodes);

				parse_objs(old_info.data_oid, do_print_obj, NULL);
			} else
				printf("The inode object 0x%" PRIx32 " idx %u is not allocated\n",
				       vid, idx);
		} else
			printf("failed to read the inode object 0x%" PRIx32 "\n", vid);
	}

	return EXIT_SUCCESS;
}

static int find_vdi_attr_oid(char *vdiname, char *tag, uint32_t snapid,
			     char *key, uint32_t *vid, uint64_t *oid,
			     unsigned int *nr_copies, int creat, int excl)
{
	struct sd_vdi_req hdr;
	struct sd_vdi_rsp *rsp = (struct sd_vdi_rsp *)&hdr;
	int fd, ret;
	unsigned int wlen, rlen;
	char buf[SD_ATTR_HEADER_SIZE];

	memset(buf, 0, sizeof(buf));
	strncpy(buf, vdiname, SD_MAX_VDI_LEN);
	strncpy(buf + SD_MAX_VDI_LEN, vdi_cmd_data.snapshot_tag,
		SD_MAX_VDI_TAG_LEN);
	memcpy(buf + SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN,
	       &vdi_cmd_data.snapshot_id, sizeof(uint32_t));
	strncpy(buf + SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN + sizeof(uint32_t),
		key, SD_MAX_VDI_ATTR_KEY_LEN);

	fd = connect_to(sdhost, sdport);
	if (fd < 0) {
		fprintf(stderr, "failed to connect\n\n");
		return SD_RES_EIO;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = SD_OP_GET_VDI_ATTR;
	wlen = SD_ATTR_HEADER_SIZE;
	rlen = 0;
	hdr.proto_ver = SD_PROTO_VER;
	hdr.data_length = wlen;
	hdr.snapid = vdi_cmd_data.snapshot_id;
	hdr.flags = SD_FLAG_CMD_WRITE;
	if (creat)
		hdr.flags |= SD_FLAG_CMD_CREAT;
	if (excl)
		hdr.flags |= SD_FLAG_CMD_EXCL;

	ret = exec_req(fd, (struct sd_req *)&hdr, buf, &wlen, &rlen);
	if (ret) {
		ret = SD_RES_EIO;
		goto out;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		ret = rsp->result;
		goto out;
	}

	*vid = rsp->vdi_id;
	*oid = vid_to_attr_oid(rsp->vdi_id, rsp->attr_id);
	*nr_copies = rsp->copies;

	ret = SD_RES_SUCCESS;
out:
	close(fd);
	return ret;
}

static int vdi_setattr(int argc, char **argv)
{
	int ret;
	uint64_t oid, attr_oid = 0;
	uint32_t vid = 0, nr_copies = 0;
	char *vdiname = argv[optind++], *key, *value;
	uint64_t offset;

	key = argv[optind++];
	if (!key) {
		fprintf(stderr, "please specify the name of key\n");
		return EXIT_USAGE;
	}

	value = argv[optind++];
	if (!value && !vdi_cmd_data.delete) {
		value = malloc(SD_MAX_VDI_ATTR_VALUE_LEN);
		if (!value) {
			fprintf(stderr, "failed to allocate memory\n");
			return EXIT_SYSFAIL;
		}

		offset = 0;
reread:
		ret = read(STDIN_FILENO, value + offset,
			   SD_MAX_VDI_ATTR_VALUE_LEN - offset);
		if (ret < 0) {
			fprintf(stderr, "failed to read from stdin, %m\n");
			return EXIT_SYSFAIL;
		}
		if (ret > 0) {
			offset += ret;
			goto reread;
		}
	}

	ret = find_vdi_attr_oid(vdiname, vdi_cmd_data.snapshot_tag,
				vdi_cmd_data.snapshot_id, key, &vid, &attr_oid,
				&nr_copies, !vdi_cmd_data.delete,
				vdi_cmd_data.exclusive);
	if (ret) {
		if (ret == SD_RES_VDI_EXIST) {
			fprintf(stderr, "the attribute already exists, %s\n", key);
			return EXIT_EXISTS;
		} else if (ret == SD_RES_NO_OBJ) {
			fprintf(stderr, "no such attribute, %s\n", key);
			return EXIT_MISSING;
		} else if (ret == SD_RES_NO_VDI) {
			fprintf(stderr, "vdi not found\n");
			return EXIT_MISSING;
		} else
			fprintf(stderr, "failed to find attr oid, %s\n",
				sd_strerror(ret));
		return EXIT_FAILURE;
	}

	oid = attr_oid;

	if (vdi_cmd_data.delete)
		ret = sd_write_object(oid, 0, (char *)"", 1,
				      offsetof(struct sheepdog_inode, name), 0,
				      nr_copies, 0);
	else
		ret = sd_write_object(oid, 0, value, strlen(value),
				      SD_ATTR_HEADER_SIZE, SD_FLAG_CMD_TRUNCATE,
				      nr_copies, 0);

	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "failed to set attribute\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int vdi_getattr(int argc, char **argv)
{
	int ret;
	uint64_t oid, attr_oid = 0;
	uint32_t vid = 0, nr_copies = 0;
	char *vdiname = argv[optind++], *key, *value;

	key = argv[optind++];
	if (!key) {
		fprintf(stderr, "please specify the name of key\n");
		return EXIT_USAGE;
	}

	ret = find_vdi_attr_oid(vdiname, vdi_cmd_data.snapshot_tag,
				vdi_cmd_data.snapshot_id, key, &vid, &attr_oid,
				&nr_copies, 0, 0);
	if (ret == SD_RES_NO_OBJ) {
		fprintf(stderr, "no such attribute, %s\n", key);
		return EXIT_MISSING;
	} else if (ret == SD_RES_NO_VDI) {
		fprintf(stderr, "vdi not found\n");
		return EXIT_MISSING;
	} else if (ret) {
		fprintf(stderr, "failed to find attr oid, %s\n",
			sd_strerror(ret));
		return EXIT_MISSING;
	}

	oid = attr_oid;
	value = malloc(SD_MAX_VDI_ATTR_VALUE_LEN);
	if (!value) {
		fprintf(stderr, "failed to allocate memory\n");
		return EXIT_SYSFAIL;
	}

	ret = sd_read_object(oid, value, SD_MAX_VDI_ATTR_VALUE_LEN,
			     SD_ATTR_HEADER_SIZE);
	if (ret == SD_RES_SUCCESS) {
		printf("%s", value);
		free(value);
		return EXIT_SUCCESS;
	}

	free(value);
	return EXIT_FAILURE;
}

static int vdi_read(int argc, char **argv)
{
	char *vdiname = argv[optind++];
	uint32_t vid;
	int ret, idx;
	struct sheepdog_inode *inode = NULL;
	uint64_t offset = 0, oid, done = 0, total = (uint64_t) -1;
	unsigned int len;
	char *buf = NULL;

	if (argv[optind]) {
		ret = parse_option_size(argv[optind++], &offset);
		if (ret < 0)
			return EXIT_USAGE;
		if (argv[optind]) {
			ret = parse_option_size(argv[optind++], &total);
			if (ret < 0)
				return EXIT_USAGE;
		}
	}

	inode = malloc(sizeof(*inode));
	buf = malloc(SD_DATA_OBJ_SIZE);
	if (!inode || !buf) {
		fprintf(stderr, "oom\n");
		ret = EXIT_SYSFAIL;
		goto out;
	}

	ret = find_vdi_name(vdiname, vdi_cmd_data.snapshot_id,
			    vdi_cmd_data.snapshot_tag, &vid, 0);
	if (ret < 0) {
		fprintf(stderr, "failed to open vdi %s\n", vdiname);
		ret = EXIT_FAILURE;
		goto out;
	}
	ret = sd_read_object(vid_to_vdi_oid(vid), inode, SD_INODE_SIZE, 0);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "failed to read an inode\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	if (inode->vdi_size < offset) {
		fprintf(stderr, "offset beyond end of vdi\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	total = min(total, inode->vdi_size - offset);
	idx = offset / SD_DATA_OBJ_SIZE;
	while (done < total) {
		len = min(total - done, SD_DATA_OBJ_SIZE - offset);

		if (inode->data_vdi_id[idx]) {
			oid = vid_to_data_oid(inode->data_vdi_id[idx], idx);
			ret = sd_read_object(oid, buf, len, offset);
			if (ret != SD_RES_SUCCESS) {
				fprintf(stderr, "failed to read vdi\n");
				ret = EXIT_FAILURE;
				goto out;
			}
		} else
			memset(buf, 0, len);

		ret = write(STDOUT_FILENO, buf, len);
		if (ret < 0) {
			fprintf(stderr, "failed to output, %m\n");
			ret = EXIT_SYSFAIL;
			goto out;
		}

		offset = 0;
		idx++;
		done += len;
	}
	fsync(STDOUT_FILENO);
	ret = EXIT_SUCCESS;
out:
	free(inode);
	free(buf);

	return ret;
}

static int vdi_write(int argc, char **argv)
{
	char *vdiname = argv[optind++];
	uint32_t vid, flags;
	int ret, idx;
	struct sheepdog_inode *inode = NULL;
	uint64_t offset = 0, oid, old_oid, done = 0, total = (uint64_t) -1;
	unsigned int len;
	char *buf = NULL;
	int create;

	if (argv[optind]) {
		ret = parse_option_size(argv[optind++], &offset);
		if (ret < 0)
			return EXIT_USAGE;
		if (argv[optind]) {
			ret = parse_option_size(argv[optind++], &total);
			if (ret < 0)
				return EXIT_USAGE;
		}
	}

	inode = malloc(sizeof(*inode));
	buf = malloc(SD_DATA_OBJ_SIZE);
	if (!inode || !buf) {
		fprintf(stderr, "oom\n");
		ret = EXIT_SYSFAIL;
		goto out;
	}

	ret = find_vdi_name(vdiname, 0, "", &vid, 0);
	if (ret < 0) {
		fprintf(stderr, "failed to open vdi %s\n", vdiname);
		ret = EXIT_FAILURE;
		goto out;
	}
	ret = sd_read_object(vid_to_vdi_oid(vid), inode, SD_INODE_SIZE, 0);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "failed to read an inode\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	if (inode->vdi_size < offset) {
		fprintf(stderr, "offset beyond end of vdi\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	total = min(total, inode->vdi_size - offset);
	idx = offset / SD_DATA_OBJ_SIZE;
	while (done < total) {
		create = 0;
		old_oid = 0;
		flags = 0;
		len = min(total - done, SD_DATA_OBJ_SIZE - offset);

		if (!inode->data_vdi_id[idx])
			create = 1;
		else if (!is_data_obj_writeable(inode, idx)) {
			create = 1;
			old_oid = vid_to_data_oid(inode->data_vdi_id[idx], idx);
			flags = SD_FLAG_CMD_COW;
		}

		ret = read(STDIN_FILENO, buf, len);
		if (ret == 0)
			break;
		else if (ret < 0) {
			fprintf(stderr, "%m\n");
			ret = EXIT_SYSFAIL;
			goto out;
		}
		len = ret;

		inode->data_vdi_id[idx] = inode->vdi_id;
		oid = vid_to_data_oid(inode->data_vdi_id[idx], idx);
		ret = sd_write_object(oid, old_oid, buf, len, offset, flags,
				      inode->nr_copies, create);
		if (ret != SD_RES_SUCCESS) {
			fprintf(stderr, "failed to write vdi\n");
			ret = EXIT_FAILURE;
			goto out;
		}

		if (create) {
			ret = sd_write_object(vid_to_vdi_oid(vid), 0, &vid, sizeof(vid),
					      SD_INODE_HEADER_SIZE + sizeof(vid) * idx, 0,
					      inode->nr_copies, 0);
			if (ret) {
				ret = EXIT_FAILURE;
				goto out;
			}
		}

		offset += len;
		if (offset == SD_DATA_OBJ_SIZE) {
			offset = 0;
			idx++;
		}
		done += len;
	}
	ret = EXIT_SUCCESS;
out:
	free(inode);
	free(buf);

	return ret;
}

static struct subcommand vdi_cmd[] = {
	{"create", "<vdiname> <size>", "Paph", "create a image",
	 SUBCMD_FLAG_NEED_NODELIST|SUBCMD_FLAG_NEED_THIRD_ARG, vdi_create},
	{"snapshot", "<vdiname>", "saph", "create a snapshot",
	 SUBCMD_FLAG_NEED_NODELIST|SUBCMD_FLAG_NEED_THIRD_ARG, vdi_snapshot},
	{"clone", "<src vdi> <dst vdi>", "sPaph", "create a clone image",
	 SUBCMD_FLAG_NEED_NODELIST|SUBCMD_FLAG_NEED_THIRD_ARG, vdi_clone},
	{"delete", "<vdiname>", "saph", "delete a image",
	 SUBCMD_FLAG_NEED_NODELIST|SUBCMD_FLAG_NEED_THIRD_ARG, vdi_delete},
	{"list", "[vdiname]", "aprh", "list images",
	 SUBCMD_FLAG_NEED_NODELIST, vdi_list},
	{"tree", NULL, "aph", "show images in tree view format",
	 SUBCMD_FLAG_NEED_NODELIST, vdi_tree},
	{"graph", NULL, "aph", "show images with Graphviz dot format",
	 SUBCMD_FLAG_NEED_NODELIST, vdi_graph},
	{"object", "<vdiname>", "isaph", "show object information in the image",
	 SUBCMD_FLAG_NEED_NODELIST|SUBCMD_FLAG_NEED_THIRD_ARG, vdi_object},
	{"setattr", "<vdiname> <key> [value]", "dxaph", "set a vdi attribute",
	 SUBCMD_FLAG_NEED_NODELIST|SUBCMD_FLAG_NEED_THIRD_ARG, vdi_setattr},
	{"getattr", "<vdiname> <key>", "aph", "get a vdi attribute",
	 SUBCMD_FLAG_NEED_NODELIST|SUBCMD_FLAG_NEED_THIRD_ARG, vdi_getattr},
	{"resize", "<vdiname> <new size>", "aph", "resize a image",
	 SUBCMD_FLAG_NEED_NODELIST|SUBCMD_FLAG_NEED_THIRD_ARG, vdi_resize},
	{"read", "<vdiname> [<offset> [<len>]]", "saph", "read data from a image",
	 SUBCMD_FLAG_NEED_NODELIST|SUBCMD_FLAG_NEED_THIRD_ARG, vdi_read},
	{"write", "<vdiname> [<offset> [<len>]]", "aph", "write data to a image",
	 SUBCMD_FLAG_NEED_NODELIST|SUBCMD_FLAG_NEED_THIRD_ARG, vdi_write},
	{NULL,},
};

static int vdi_parser(int ch, char *opt)
{
	switch (ch) {
	case 'P':
		vdi_cmd_data.prealloc = 1;
		break;
	case 'i':
		vdi_cmd_data.index = atoi(opt);
		break;
	case 's':
		vdi_cmd_data.snapshot_id = atoi(opt);
		if (vdi_cmd_data.snapshot_id == 0)
			strncpy(vdi_cmd_data.snapshot_tag, opt,
				sizeof(vdi_cmd_data.snapshot_tag));
		break;
	case 'x':
		vdi_cmd_data.exclusive = 1;
		break;
	case 'd':
		vdi_cmd_data.delete = 1;
		break;
	}

	return 0;
}

struct command vdi_command = {
	"vdi",
	vdi_cmd,
	vdi_parser
};
