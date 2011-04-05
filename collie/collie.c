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
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <sys/time.h>

#include "sheepdog_proto.h"
#include "sheep.h"
#include "net.h"
#include "treeview.h"

static char program_name[] = "collie";
static const char *sdhost = "localhost";
static int sdport = SD_LISTEN_PORT;
static int highlight = 1;

#define TEXT_NORMAL "\033[0m"
#define TEXT_BOLD   "\033[1m"

#define COMMON_LONG_OPTIONS				\
	{"address", required_argument, NULL, 'a'},	\
	{"port", required_argument, NULL, 'p'},		\
	{"help", no_argument, NULL, 'h'},		\

#define COMMON_SHORT_OPTIONS "a:p:h"

static void usage(int status)
{
	if (status)
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	else {
		printf("Usage: %s command subcommand [options]\n", program_name);
		printf("Sheepdog Administrator Utilty\n\
\n\
Command syntax:\n\
  cluster (info|format|shutdown)\n\
  node (info|list)\n\
  vdi (list|tree|graph|delete|object|setattr|getattr)\n\
\n\
Common parameters:\n\
  -a, --address           specify the daemon address (default: localhost)\n\
  -p, --port              specify the daemon port\n\
  -h, --help              display this help and exit\n\
");
	}
	exit(status);
}

static uint64_t node_list_version;

static struct sheepdog_node_list_entry node_list_entries[SD_MAX_NODES];
static struct sheepdog_vnode_list_entry vnode_list_entries[SD_MAX_VNODES];
static int nr_nodes, nr_vnodes;
static unsigned master_idx;

static int is_current(struct sheepdog_inode *i)
{
	return !i->snap_ctime;
}

static char *size_to_str(uint64_t _size, char *str, int str_size)
{
	const char *units[] = {"MB", "GB", "TB", "PB", "EB", "ZB", "YB"};
	int i = 0;
	double size = (double)_size;

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

static int update_node_list(int max_nodes, int epoch)
{
	int fd, ret;
	unsigned int size, wlen;
	char *buf = NULL;
	struct sheepdog_node_list_entry *ent;
	struct sd_node_req hdr;
	struct sd_node_rsp *rsp = (struct sd_node_rsp *)&hdr;

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return -1;

	size = sizeof(*ent) * max_nodes;
	buf = zalloc(size);
	if (!buf) {
		ret = -1;
		goto out;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = SD_OP_GET_NODE_LIST;
	hdr.request_ver = epoch;

	hdr.data_length = size;

	wlen = 0;

	ret = exec_req(fd, (struct sd_req *)&hdr, buf, &wlen, &size);
	if (ret) {
		ret = -1;
		goto out;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "%s\n", sd_strerror(rsp->result));
		ret = -1;
		goto out;
	}

	nr_nodes = size / sizeof(*ent);

	/* FIXME */
	if (nr_nodes > max_nodes) {
		ret = -1;
		goto out;
	}

	memcpy(node_list_entries, buf, size);
	nr_vnodes = nodes_to_vnodes(node_list_entries, nr_nodes, vnode_list_entries);
	node_list_version = hdr.epoch;
	master_idx = rsp->master_idx;
out:
	if (buf)
		free(buf);
	if (fd >= 0)
		close(fd);

	return ret;
}

struct cluster_cmd_data {
	int copies;
} cluster_cmd_data;

struct vdi_cmd_data {
	unsigned int index;
	int snapshot_id;
	char snapshot_tag[SD_MAX_VDI_TAG_LEN];
	int exclusive;
	int delete;
} vdi_cmd_data = { ~0, };

static int cluster_format(int argc, char **argv)
{
	int fd, ret;
	struct sd_so_req hdr;
	struct sd_so_rsp *rsp = (struct sd_so_rsp *)&hdr;
	unsigned rlen, wlen;
	struct timeval tv;

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return -1;

	gettimeofday(&tv, NULL);

	memset(&hdr, 0, sizeof(hdr));

	hdr.opcode = SD_OP_MAKE_FS;
	hdr.copies = cluster_cmd_data.copies;
	hdr.epoch = node_list_version;
	hdr.ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;

	rlen = 0;
	wlen = 0;
	ret = exec_req(fd, (struct sd_req *)&hdr, NULL, &wlen, &rlen);
	close(fd);

	if (ret) {
		fprintf(stderr, "failed to connect\n");
		return ret;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "%s\n", sd_strerror(rsp->result));
		return 1;
	}

	return 0;
}

static int shutdown_sheepdog(void)
{
	int fd, ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	unsigned rlen, wlen;

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return -1;

	memset(&hdr, 0, sizeof(hdr));

	hdr.opcode = SD_OP_SHUTDOWN;
	hdr.epoch = node_list_version;

	rlen = 0;
	wlen = 0;
	ret = exec_req(fd, &hdr, NULL, &wlen, &rlen);
	close(fd);

	if (ret) {
		fprintf(stderr, "failed to connect\n");
		return ret;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "%s\n", sd_strerror(rsp->result));
		return 1;
	}

	return 0;
}

typedef void (*vdi_parser_func_t)(uint32_t vid, char *name, char *tag,
				  uint32_t snapid, uint32_t flags,
				  struct sheepdog_inode *i, void *data);

static int parse_vdi(vdi_parser_func_t func, size_t size, void *data)
{
	int ret, fd;
	unsigned long nr;
	static struct sheepdog_inode i;
	struct sd_req req;
	static DECLARE_BITMAP(vdi_inuse, SD_NR_VDIS);
	unsigned int rlen, wlen = 0;

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return fd;

	memset(&req, 0, sizeof(req));

	req.opcode = SD_OP_READ_VDIS;
	req.data_length = sizeof(vdi_inuse);
	req.epoch = node_list_version;

	rlen = sizeof(vdi_inuse);
	ret = exec_req(fd, &req, vdi_inuse, &wlen, &rlen);
	if (ret < 0) {
		close(fd);
		return ret;
	}
	close(fd);

	for (nr = 0; nr < SD_NR_VDIS; nr++) {
		struct sd_obj_req hdr;
		struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
		uint64_t oid;
		int n;
		char name[128];

		if (!test_bit(nr, vdi_inuse))
			continue;

		oid = vid_to_vdi_oid(nr);
		n = obj_to_sheep(vnode_list_entries, nr_vnodes, oid, 0);
		addr_to_str(name, sizeof(name), vnode_list_entries[n].addr, 0);

		fd = connect_to(name, vnode_list_entries[n].port);
		if (fd < 0) {
			printf("failed to connect %s:%d\n", name,
			       vnode_list_entries[n].port);
			continue;
		}

		wlen = 0;
		rlen = SD_INODE_HEADER_SIZE;
		memset(&i, 0, sizeof(i));

		memset(&hdr, 0, sizeof(hdr));
		hdr.opcode = SD_OP_READ_OBJ;
		hdr.oid = oid;
		hdr.data_length = rlen;
		hdr.flags = SD_FLAG_CMD_DIRECT;
		hdr.epoch = node_list_version;

		ret = exec_req(fd, (struct sd_req *)&hdr, &i, &wlen, &rlen);

		if (ret || rsp->result != SD_RES_SUCCESS) {
			printf("failed to read a inode header %lu, %d, %x\n",
			       nr, ret, rsp->result);
			goto next;
		}

		if (i.name[0] == '\0') /* this vdi is deleted */
			goto next;

		if (size > SD_INODE_HEADER_SIZE) {
			wlen = 0;
			rlen = DIV_ROUND_UP(i.vdi_size, SD_DATA_OBJ_SIZE) *
				sizeof(i.data_vdi_id[0]);
			if (rlen > size - SD_INODE_HEADER_SIZE)
				rlen = size - SD_INODE_HEADER_SIZE;

			memset(&hdr, 0, sizeof(hdr));
			hdr.opcode = SD_OP_READ_OBJ;
			hdr.oid = oid;
			hdr.offset = SD_INODE_HEADER_SIZE;
			hdr.data_length = rlen;
			hdr.flags = SD_FLAG_CMD_DIRECT;
			hdr.epoch = node_list_version;

			ret = exec_req(fd, (struct sd_req *)&hdr,
				       ((char *)&i) + SD_INODE_HEADER_SIZE,
				       &wlen, &rlen);

			if (ret || rsp->result != SD_RES_SUCCESS) {
				printf("failed to read inode %lu, %d, %x\n",
				       nr, ret, rsp->result);
				goto next;
			}
		}

		func(i.vdi_id, i.name, i.tag, i.snap_id, 0, &i, data);
	next:
		close(fd);
	}

	return 0;
}

static void print_vdi_list(uint32_t vid, char *name, char *tag, uint32_t snapid,
			   uint32_t flags, struct sheepdog_inode *i, void *data)
{
	int idx;
	uint64_t my_objs, cow_objs;
	char vdi_size_str[8], my_objs_str[8], cow_objs_str[8];
	time_t ti;
	struct tm tm;
	char dbuf[128];

	ti = i->ctime >> 32;
	localtime_r(&ti, &tm);

	strftime(dbuf, sizeof(dbuf),
		 "%Y-%m-%d %H:%M", &tm);

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

	if (!data || strcmp(name, data) == 0) {
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

static void cal_total_vdi_size(uint32_t vid, char *name, char * tag,
			       uint32_t snapid, uint32_t flags,
			       struct sheepdog_inode *i, void *data)
{
	uint64_t *size = data;

	if (is_current(i))
		*size += i->vdi_size;
}

struct get_vid_info {
	char *name;
	char *tag;
	uint32_t vid;
	uint32_t snapid;
};

static void get_oid(uint32_t vid, char *name, char *tag, uint32_t snapid,
		    uint32_t flags, struct sheepdog_inode *i, void *data)
{
	struct get_vid_info *info = data;

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

#define SUBCMD_FLAG_NEED_NOEDLIST (1 << 0)
#define SUBCMD_FLAG_NEED_THIRD_ARG (1 << 1)

struct subcommand {
	const char *name;
	unsigned long flags;
	int (*fn)(int, char **);
};

static int node_list(int argc, char **argv)
{
	int i;

	printf("   Idx - Host:Port              Number of vnodes\n");
	printf("------------------------------------------------\n");
	for (i = 0; i < nr_nodes; i++) {
		char data[128];

		addr_to_str(data, sizeof(data), node_list_entries[i].addr,
			    node_list_entries[i].port);

		if (i == master_idx) {
			if (highlight)
				printf(TEXT_BOLD);
			printf("* %4d - %-20s\t%d\n", i, data, node_list_entries[i].nr_vnodes);
			if (highlight)
				printf(TEXT_NORMAL);
		} else
			printf("  %4d - %-20s\t%d\n", i, data, node_list_entries[i].nr_vnodes);
	}

	return 0;
}

static int node_info(int argc, char **argv)
{
	int i, ret, success = 0;
	uint64_t total_size = 0, total_avail = 0, total_vdi_size = 0;
	char total_str[8], avail_str[8], vdi_size_str[8];

	printf("Id\tSize\tUsed\tUse%%\n");

	for (i = 0; i < nr_nodes; i++) {
		char name[128];
		int fd;
		unsigned wlen, rlen;
		struct sd_node_req req;
		struct sd_node_rsp *rsp = (struct sd_node_rsp *)&req;
		char store_str[8], free_str[8];

		addr_to_str(name, sizeof(name), node_list_entries[i].addr, 0);

		fd = connect_to(name, node_list_entries[i].port);
		if (fd < 0)
			return 1;

		memset(&req, 0, sizeof(req));

		req.opcode = SD_OP_STAT_SHEEP;
		req.epoch = node_list_version;

		wlen = 0;
		rlen = 0;
		ret = exec_req(fd, (struct sd_req *)&req, NULL, &wlen, &rlen);
		close(fd);

		size_to_str(rsp->store_size, store_str, sizeof(store_str));
		size_to_str(rsp->store_size - rsp->store_free, free_str,
			    sizeof(free_str));
		if (!ret && rsp->result == SD_RES_SUCCESS) {
			printf("%2d\t%s\t%s\t%3d%%\n", i, store_str, free_str,
			       (int)(((double)(rsp->store_size - rsp->store_free) / rsp->store_size) * 100));
			success++;
		}

		total_size += rsp->store_size;
		total_avail += rsp->store_free;
	}

	printf("\n");

	if (success == 0) {
		fprintf(stderr, "cannot get information from any nodes\n");
		return 1;
	}

	parse_vdi(cal_total_vdi_size, SD_INODE_HEADER_SIZE, &total_vdi_size);

	size_to_str(total_size, total_str, sizeof(total_str));
	size_to_str(total_size - total_avail, avail_str, sizeof(avail_str));
	size_to_str(total_vdi_size, vdi_size_str, sizeof(vdi_size_str));
	printf("Total\t%s\t%s\t%3d%%, total virtual VDI Size\t%s\n",
	       total_str, avail_str,
	       (int)(((double)(total_size - total_avail) / total_size) * 100),
	       vdi_size_str);

	return 0;
}

static struct subcommand node_cmd[] = {
	{"list", SUBCMD_FLAG_NEED_NOEDLIST, node_list},
	{"info", SUBCMD_FLAG_NEED_NOEDLIST, node_info},
	{NULL,},
};

static int vdi_list(int argc, char **argv)
{
	printf("  name        id    size    used  shared    creation time   vdi id\n");
	printf("------------------------------------------------------------------\n");

	parse_vdi(print_vdi_list, SD_INODE_SIZE, NULL);
	return 0;
}

static int vdi_tree(int argc, char **argv)
{
	init_tree();
	parse_vdi(print_vdi_tree, SD_INODE_HEADER_SIZE, NULL);
	dump_tree();

	return 0;
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

	return 0;
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
		return -1;

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
		return ret;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "%s: %s\n", vdiname, sd_strerror(rsp->result));
		return 1;
	}

	return 0;
}

static int vdi_object(int argc, char **argv)
{
	char *vdiname = argv[optind];
	unsigned idx = vdi_cmd_data.index;
	int ret;
	struct get_vid_info info;
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
		return 1;
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
			exit(1);
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

	return 0;
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
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
	char name[128];
	int i = 0, n, fd, ret;
	uint64_t oid, attr_oid = 0;
	uint32_t vid = 0, nr_copies = 0;
	char *vdiname = argv[optind++], *key, *value;
	unsigned int wlen = 0, rlen = 0;
	uint64_t offset;

	key = argv[optind++];
	if (!key) {
		fprintf(stderr, "please specify the name of key\n");
		return 1;
	}

	value = argv[optind++];
	if (!value) {
		value = malloc(SD_MAX_VDI_ATTR_VALUE_LEN);
		if (!value) {
			fprintf(stderr, "failed to allocate memory\n");
			return 1;
		}

		offset = 0;
reread:
		ret = read(STDIN_FILENO, value + offset,
			   SD_MAX_VDI_ATTR_VALUE_LEN - offset);
		if (ret < 0) {
			fprintf(stderr, "failed to read from stdin, %m\n");
			return 1;
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
		} else if (ret == SD_RES_NO_OBJ) {
			fprintf(stderr, "no such attribute, %s\n", key);
		} else
			fprintf(stderr, "failed to find attr oid, %s\n",
				sd_strerror(ret));
		return 1;
	}

	oid = attr_oid;
	for (i = 0; i < nr_copies; i++) {
		rlen = 0;
		if (vdi_cmd_data.delete)
			wlen = 1;
		else
			wlen = strlen(value);

		n = obj_to_sheep(vnode_list_entries, nr_vnodes, oid, i);

		addr_to_str(name, sizeof(name), vnode_list_entries[n].addr, 0);

		fd = connect_to(name, vnode_list_entries[n].port);
		if (fd < 0) {
			printf("%s(%d): %s, %m\n", __func__, __LINE__,
			       name);
			break;
		}

		memset(&hdr, 0, sizeof(hdr));
		hdr.epoch = node_list_version;
		hdr.opcode = SD_OP_WRITE_OBJ;
		hdr.oid = oid;

		hdr.data_length = wlen;
		if (vdi_cmd_data.delete) {
			hdr.flags =  SD_FLAG_CMD_DIRECT | SD_FLAG_CMD_WRITE;
			hdr.offset = offsetof(struct sheepdog_inode, name);
			value = (char *)"";
		} else {
			hdr.flags =  SD_FLAG_CMD_DIRECT | SD_FLAG_CMD_WRITE |
				SD_FLAG_CMD_TRUNCATE;
			hdr.offset = SD_ATTR_HEADER_SIZE;
		}

		ret = exec_req(fd, (struct sd_req *)&hdr, value, &wlen, &rlen);
		close(fd);

		if (ret) {
			fprintf(stderr, "failed to set attribute\n");
			return 1;
		}
		if (rsp->result != SD_RES_SUCCESS) {
			fprintf(stderr, "failed to set attribute, %s\n",
				sd_strerror(rsp->result));
			return 1;
		}
	}

	return 0;
}

static int vdi_getattr(int argc, char **argv)
{
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
	char name[128];
	int i = 0, n, fd, ret;
	uint64_t oid, attr_oid = 0;
	uint32_t vid = 0, nr_copies = 0;
	char *vdiname = argv[optind++], *key, *value;
	unsigned int wlen = 0, rlen = 0;

	key = argv[optind++];
	if (!key) {
		fprintf(stderr, "please specify the name of key\n");
		return 1;
	}

	ret = find_vdi_attr_oid(vdiname, vdi_cmd_data.snapshot_tag,
				vdi_cmd_data.snapshot_id, key, &vid, &attr_oid,
				&nr_copies, 0, 0);
	if (ret == SD_RES_NO_OBJ) {
		fprintf(stderr, "no such attribute, %s\n", key);
		return 1;
	} else if (ret) {
		fprintf(stderr, "failed to find attr oid, %s\n",
			sd_strerror(ret));
		return 1;
	}

	oid = attr_oid;
	value = malloc(SD_MAX_VDI_ATTR_VALUE_LEN);
	if (!value) {
		fprintf(stderr, "failed to allocate memory\n");
		return 1;
	}
	for (i = 0; i < nr_copies; i++) {
		rlen = SD_MAX_VDI_ATTR_VALUE_LEN;
		wlen = 0;

		n = obj_to_sheep(vnode_list_entries, nr_vnodes, oid, i);

		addr_to_str(name, sizeof(name), vnode_list_entries[n].addr, 0);

		fd = connect_to(name, vnode_list_entries[n].port);
		if (fd < 0) {
			printf("%s(%d): %s, %m\n", __func__, __LINE__,
			       name);
			goto out;
		}

		memset(&hdr, 0, sizeof(hdr));
		hdr.epoch = node_list_version;
		hdr.opcode = SD_OP_READ_OBJ;
		hdr.oid = oid;

		hdr.data_length = rlen;
		hdr.flags =  SD_FLAG_CMD_DIRECT;
		hdr.offset = SD_ATTR_HEADER_SIZE;

		ret = exec_req(fd, (struct sd_req *)&hdr, value, &wlen, &rlen);
		close(fd);

		if (!ret) {
			if (rsp->result == SD_RES_SUCCESS) {
				printf("%s", value);
				free(value);
				return 0;
			}
		}
	}
out:
	free(value);
	return 1;
}

static struct subcommand vdi_cmd[] = {
	{"delete", SUBCMD_FLAG_NEED_NOEDLIST|SUBCMD_FLAG_NEED_THIRD_ARG, vdi_delete},
	{"list", SUBCMD_FLAG_NEED_NOEDLIST, vdi_list},
	{"tree", SUBCMD_FLAG_NEED_NOEDLIST, vdi_tree},
	{"graph", SUBCMD_FLAG_NEED_NOEDLIST, vdi_graph},
	{"object", SUBCMD_FLAG_NEED_NOEDLIST|SUBCMD_FLAG_NEED_THIRD_ARG, vdi_object},
	{"setattr", SUBCMD_FLAG_NEED_NOEDLIST|SUBCMD_FLAG_NEED_THIRD_ARG, vdi_setattr},
	{"getattr", SUBCMD_FLAG_NEED_NOEDLIST|SUBCMD_FLAG_NEED_THIRD_ARG, vdi_getattr},
	{NULL,},
};

static struct option vdi_long_options[] =
{
	COMMON_LONG_OPTIONS
	{"index", required_argument, NULL, 'i'},
	{"snapshot", required_argument, NULL, 's'},
	{"exclusive", no_argument, NULL, 'x'},
	{"delete", no_argument, NULL, 'd'},
	{NULL, 0, NULL, 0},
};

static int vdi_parser(int ch, char *opt)
{
	switch (ch) {
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

static int cluster_info(int argc, char **argv)
{
	int i, fd, ret;
	struct sd_vdi_req hdr;
	struct sd_vdi_rsp *rsp = (struct sd_vdi_rsp *)&hdr;
	unsigned rlen, wlen;
	struct epoch_log logs[8];
	int nr_logs;
	time_t ti;
	struct tm tm;
	char time_str[128];

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return 1;

	memset(&hdr, 0, sizeof(hdr));

	hdr.opcode = SD_OP_STAT_CLUSTER;
	hdr.epoch = node_list_version;
	hdr.data_length = sizeof(logs);

	rlen = hdr.data_length;
	wlen = 0;
	ret = exec_req(fd, (struct sd_req *)&hdr, logs, &wlen, &rlen);
	close(fd);

	if (ret != 0)
		return 1;

	if (rsp->result == SD_RES_SUCCESS)
		printf("running\n");
	else
		printf("%s\n", sd_strerror(rsp->result));

	printf("\n");
	printf("Ctime                Epoch Nodes\n");
	nr_logs = rsp->data_length / sizeof(struct epoch_log);
	for (i = 0; i < nr_logs; i++) {
		int j;
		char name[128];
		struct sheepdog_node_list_entry *entry;

		ti = logs[i].ctime >> 32;
		localtime_r(&ti, &tm);
		strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm);

		printf("%s %6d", time_str, logs[i].epoch);
		printf(" [");
		for (j = 0; j < logs[i].nr_nodes; j++) {
			entry = logs[i].nodes + j;
			printf("%s%s",
			       (j == 0) ? "" : ", ",
			       addr_to_str(name, sizeof(name),
					   entry->addr, entry->port));
		}
		printf("]\n");
	}

	return 0;
}

static int cluster_parser(int ch, char *opt)
{
	switch (ch) {
	case 'c':
		cluster_cmd_data.copies = atoi(opt);
		break;
	}

	return 0;
}

static int cluster_shoutdown(int argc, char **argv)
{
	shutdown_sheepdog();
	return 0;
}

static struct subcommand cluster_cmd[] = {
	{"info", 0, cluster_info},
	{"format", 0, cluster_format},
	{"shutdown", SUBCMD_FLAG_NEED_NOEDLIST, cluster_shoutdown},
	{NULL,},
};

static struct option cluster_long_options[] =
{
	COMMON_LONG_OPTIONS
	{"copies", required_argument, NULL, 'c'},
	{NULL, 0, NULL, 0},
};

static struct {
	const char *name;
	struct subcommand *sub;
	struct option *lopts;
	const char *sopts;
	int (*parser)(int, char *);
	void (*help)(void);
} commands[] = {
	{"vdi", vdi_cmd,
	 vdi_long_options,
	 COMMON_SHORT_OPTIONS "i:s:xd",
	 vdi_parser,},
	{"node", node_cmd,},
	{"cluster", cluster_cmd,
	 cluster_long_options,
	 COMMON_SHORT_OPTIONS "c:",
	 cluster_parser,},
};

static struct option common_long_options[] =
{
	COMMON_LONG_OPTIONS
	{NULL, 0, NULL, 0},
};

static struct option *long_options = common_long_options;
static const char *short_options = COMMON_SHORT_OPTIONS;
static int (*command_parser)(int, char *);
static int (*command_fn)(int, char **);
static void (*command_help)(void);

static unsigned long setup_command(char *cmd, char *subcmd)
{
	int i, found = 0;
	struct subcommand *s;
	unsigned long flags = 0;

	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (!strncmp(commands[i].name, cmd, strlen(commands[i].name))) {
			found = 1;
			if (commands[i].parser) {
				command_parser = commands[i].parser;
				long_options = commands[i].lopts;
				short_options = commands[i].sopts;
			}
			break;
		}
	}

	if (!found) {
		fprintf(stderr, "'%s' is not a valid command\n", cmd);
		usage(1);
	}

	for (s = commands[i].sub; s->name; s++) {
		if (!strncmp(s->name, subcmd, strlen(s->name))) {
			command_fn = s->fn;
			flags = s->flags;
			break;
		}
	}

	if (!command_fn) {
		fprintf(stderr, "'%s' is not a valid subcommand\n", subcmd);
		fprintf(stderr, "'%s' supports the following subcommand:\n", cmd);
		for (s = commands[i].sub; s->name; s++)
			fprintf(stderr, "%s\n", s->name);
		exit(1);
	}

	return flags;
}

int main(int argc, char **argv)
{
	int ch, longindex, ret;
	unsigned long flags;

	if (argc < 3)
		usage(0);

	flags = setup_command(argv[1], argv[2]);

	optind = 3;

	while ((ch = getopt_long(argc, argv, short_options, long_options,
				&longindex)) >= 0) {

		switch (ch) {
		case 'a':
			sdhost = optarg;
			break;
		case 'p':
			sdport = atoi(optarg);
			break;
		case 'h':
			if (command_help)
				command_help();
			break;
		case '?':
			usage(1);
			break;
		default:
			if (command_parser)
				command_parser(ch, optarg);
			else
				usage(1);
			break;
		}
	}

	if (!isatty(STDOUT_FILENO))
		highlight = 0;

	if (flags & SUBCMD_FLAG_NEED_NOEDLIST) {
		ret = update_node_list(SD_MAX_NODES, 0);
		if (ret < 0) {
			fprintf(stderr, "failed to get node list\n");
			exit(1);
		}
	}

	if (flags & SUBCMD_FLAG_NEED_THIRD_ARG && argc == optind) {
		fprintf(stderr, "'%s %s' needs the third argument\n", argv[1], argv[2]);
		exit(1);
	}

	return command_fn(argc, argv);
}
