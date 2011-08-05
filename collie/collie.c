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
#include <ctype.h>
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
#include "exits.h"

static char program_name[] = "collie";
static const char *sdhost = "localhost";
static int sdport = SD_LISTEN_PORT;
static int highlight = 1;
static int raw_output = 0;

#define TEXT_NORMAL "\033[0m"
#define TEXT_BOLD   "\033[1m"

struct sd_option {
	int val;
	const char *name;
	int has_arg;
	const char *desc;
};

static const struct sd_option collie_options[] = {

	/* common options */
	{'a', "address", 1, "specify the daemon address (default: localhost)"},
	{'p', "port", 1, "specify the daemon port"},
	{'r', "raw", 0, "raw output mode: omit headers, separate fields with\n\
                          single spaces and print all sizes in decimal bytes"},
	{'h', "help", 0, "display this help and exit"},

	/* vdi options */
	{'P', "prealloc", 0, "preallocate all the data objects"},
	{'i', "index", 1, "specify the index of data objects"},
	{'s', "snapshot", 1, "specify a snapshot id or tag name"},
	{'x', "exclusive", 0, "write in an exclusive mode"},
	{'d', "delete", 0, "delete a key"},

	/* cluster options */
	{'c', "copies", 1, "set the number of data redundancy"},

	{ 0, NULL, 0, NULL },
};

static void usage(int status);

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

static int sd_read_object(uint64_t oid, void *data, unsigned int datalen,
			  uint64_t offset)
{
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
	char name[128];
	int n, fd, ret;
	unsigned wlen = 0, rlen = datalen;

	n = obj_to_sheep(vnode_list_entries, nr_vnodes, oid, 0);

	addr_to_str(name, sizeof(name), vnode_list_entries[n].addr, 0);

	fd = connect_to(name, vnode_list_entries[n].port);
	if (fd < 0) {
		fprintf(stderr, "failed to connect %s:%d\n", name,
			vnode_list_entries[n].port);
		return SD_RES_EIO;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.epoch = node_list_version;
	hdr.opcode = SD_OP_READ_OBJ;
	hdr.oid = oid;
	/* use direct to avoid checking consistency */
	hdr.flags =  SD_FLAG_CMD_DIRECT;
	hdr.data_length = rlen;
	hdr.offset = offset;

	ret = exec_req(fd, (struct sd_req *)&hdr, data, &wlen, &rlen);
	close(fd);

	if (ret) {
		fprintf(stderr, "failed to read object, %lx\n", oid);
		return SD_RES_EIO;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "failed to read object, %lx %s\n", oid,
			sd_strerror(rsp->result));
		return rsp->result;
	}

	return SD_RES_SUCCESS;
}

static int sd_write_object(uint64_t oid, void *data, unsigned int datalen,
			   uint64_t offset, uint32_t flags, int copies, int create)
{
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
	int fd, ret;
	unsigned wlen = datalen, rlen;

	fd = connect_to(sdhost, sdport);
	if (fd < 0) {
		fprintf(stderr, "failed to connect\n");
		return SD_RES_EIO;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.epoch = node_list_version;
	if (create)
		hdr.opcode = SD_OP_CREATE_AND_WRITE_OBJ;
	else
		hdr.opcode = SD_OP_WRITE_OBJ;
	hdr.oid = oid;
	hdr.copies = copies;
	hdr.data_length = wlen;
	hdr.flags = (flags & ~SD_FLAG_CMD_DIRECT) | SD_FLAG_CMD_WRITE;
	hdr.offset = offset;

	ret = exec_req(fd, (struct sd_req *)&hdr, data, &wlen, &rlen);
	close(fd);

	if (ret) {
		fprintf(stderr, "failed to write object, %lx\n", oid);
		return SD_RES_EIO;
	}
	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "failed to write object, %lx %s\n", oid,
			sd_strerror(rsp->result));
		return rsp->result;
	}

	return SD_RES_SUCCESS;
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
	int prealloc;
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
		return EXIT_SYSFAIL;

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
		return EXIT_SYSFAIL;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "%s\n", sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int shutdown_sheepdog(void)
{
	int fd, ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	unsigned rlen, wlen;

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return EXIT_SYSFAIL;

	memset(&hdr, 0, sizeof(hdr));

	hdr.opcode = SD_OP_SHUTDOWN;
	hdr.epoch = node_list_version;

	rlen = 0;
	wlen = 0;
	ret = exec_req(fd, &hdr, NULL, &wlen, &rlen);
	close(fd);

	if (ret) {
		fprintf(stderr, "failed to connect\n");
		return EXIT_SYSFAIL;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "%s\n", sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
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
		uint64_t oid;

		if (!test_bit(nr, vdi_inuse))
			continue;

		oid = vid_to_vdi_oid(nr);

		memset(&i, 0, sizeof(i));
		ret = sd_read_object(oid, &i, SD_INODE_HEADER_SIZE, 0);
		if (ret != SD_RES_SUCCESS) {
			fprintf(stderr, "failed to read a inode header\n");
			continue;
		}

		if (i.name[0] == '\0') /* this vdi is deleted */
			continue;

		if (size > SD_INODE_HEADER_SIZE) {
			rlen = DIV_ROUND_UP(i.vdi_size, SD_DATA_OBJ_SIZE) *
				sizeof(i.data_vdi_id[0]);
			if (rlen > size - SD_INODE_HEADER_SIZE)
				rlen = size - SD_INODE_HEADER_SIZE;

			ret = sd_read_object(oid, ((char *)&i) + SD_INODE_HEADER_SIZE,
					     rlen, SD_INODE_HEADER_SIZE);

			if (ret != SD_RES_SUCCESS) {
				fprintf(stderr, "failed to read inode\n");
				continue;
			}
		}

		func(i.vdi_id, i.name, i.tag, i.snap_id, 0, &i, data);
	}

	return 0;
}

struct get_vdi_info {
	char *name;
	char *tag;
	uint32_t vid;
	uint32_t snapid;
};

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

static void cal_total_vdi_size(uint32_t vid, char *name, char * tag,
			       uint32_t snapid, uint32_t flags,
			       struct sheepdog_inode *i, void *data)
{
	uint64_t *size = data;

	if (is_current(i))
		*size += i->vdi_size;
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

#define SUBCMD_FLAG_NEED_NODELIST (1 << 0)
#define SUBCMD_FLAG_NEED_THIRD_ARG (1 << 1)

struct subcommand {
	const char *name;
	const char *arg;
	const char *opts;
	const char *desc;
	unsigned long flags;
	int (*fn)(int, char **);
};

static int node_list(int argc, char **argv)
{
	int i;

	if (!raw_output) {
		printf("   Idx - Host:Port          Vnodes   Zone\n");
		printf("-----------------------------------------\n");
	}
	for (i = 0; i < nr_nodes; i++) {
		char data[128];

		addr_to_str(data, sizeof(data), node_list_entries[i].addr,
			    node_list_entries[i].port);

		if (i == master_idx) {
			if (highlight)
				printf(TEXT_BOLD);
			printf(raw_output ? "* %d %s %d %d\n" : "* %4d - %-20s\t%d\t%d\n",
			       i, data, node_list_entries[i].nr_vnodes,
			       node_list_entries[i].zone);
			if (highlight)
				printf(TEXT_NORMAL);
		} else
			printf(raw_output ? "- %d %s %d %d\n" : "  %4d - %-20s\t%d\t%d\n",
			       i, data, node_list_entries[i].nr_vnodes,
			       node_list_entries[i].zone);
	}

	return EXIT_SUCCESS;
}

static int node_info(int argc, char **argv)
{
	int i, ret, success = 0;
	uint64_t total_size = 0, total_avail = 0, total_vdi_size = 0;
	char total_str[8], avail_str[8], vdi_size_str[8];

	if (!raw_output)
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
			printf(raw_output ? "%d %s %s %d%%\n" : "%2d\t%s\t%s\t%3d%%\n",
			       i, store_str, free_str,
			       (int)(((double)(rsp->store_size - rsp->store_free) / rsp->store_size) * 100));
			success++;
		}

		total_size += rsp->store_size;
		total_avail += rsp->store_free;
	}

	if (success == 0) {
		fprintf(stderr, "cannot get information from any nodes\n");
		return EXIT_SYSFAIL;
	}

	parse_vdi(cal_total_vdi_size, SD_INODE_HEADER_SIZE, &total_vdi_size);

	size_to_str(total_size, total_str, sizeof(total_str));
	size_to_str(total_size - total_avail, avail_str, sizeof(avail_str));
	size_to_str(total_vdi_size, vdi_size_str, sizeof(vdi_size_str));
	printf(raw_output ? "Total %s %s %d%% %s\n"
			  : "\nTotal\t%s\t%s\t%3d%%, total virtual VDI Size\t%s\n",
	       total_str, avail_str,
	       (int)(((double)(total_size - total_avail) / total_size) * 100),
	       vdi_size_str);

	return EXIT_SUCCESS;
}

static struct subcommand node_cmd[] = {
	{"list", NULL, "aprh", "list nodes",
	 SUBCMD_FLAG_NEED_NODELIST, node_list},
	{"info", NULL, "aprh", "show each node information",
	 SUBCMD_FLAG_NEED_NODELIST, node_info},
	{NULL,},
};

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

		ret = sd_write_object(oid, buf, SD_DATA_OBJ_SIZE, 0, 0,
				      inode->nr_copies, 1);
		if (ret != SD_RES_SUCCESS) {
			ret = EXIT_FAILURE;
			goto out;
		}

		inode->data_vdi_id[idx] = vid;
		ret = sd_write_object(vid_to_vdi_oid(vid), &vid, sizeof(vid),
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
		ret = sd_write_object(oid, (char *)"", 1,
				      offsetof(struct sheepdog_inode, name), 0,
				      nr_copies, 0);
	else
		ret = sd_write_object(oid, value, strlen(value),
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
	if (ret) {
		printf("%s", value);
		free(value);
		return EXIT_SUCCESS;
	}

	free(value);
	return EXIT_FAILURE;
}

static struct subcommand vdi_cmd[] = {
	{"create", "<vdiname> <size>", "Paph", "create a image",
	 SUBCMD_FLAG_NEED_NODELIST|SUBCMD_FLAG_NEED_THIRD_ARG, vdi_create},
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
		return EXIT_SYSFAIL;

	memset(&hdr, 0, sizeof(hdr));

	hdr.opcode = SD_OP_STAT_CLUSTER;
	hdr.epoch = node_list_version;
	hdr.data_length = sizeof(logs);

	rlen = hdr.data_length;
	wlen = 0;
	ret = exec_req(fd, (struct sd_req *)&hdr, logs, &wlen, &rlen);
	close(fd);

	if (ret != 0)
		return EXIT_SYSFAIL;

	if (!raw_output)
		printf("Cluster status: ");
	if (rsp->result == SD_RES_SUCCESS)
		printf("running\n");
	else
		printf("%s\n", sd_strerror(rsp->result));

	if (!raw_output)
		printf("\nCreation time        Epoch Nodes\n");

	nr_logs = rsp->data_length / sizeof(struct epoch_log);
	for (i = 0; i < nr_logs; i++) {
		int j;
		char name[128];
		struct sheepdog_node_list_entry *entry;

		ti = logs[i].ctime >> 32;
		if (raw_output) {
			snprintf(time_str, sizeof(time_str), "%" PRIu64, (uint64_t) ti);
		} else {
			localtime_r(&ti, &tm);
			strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm);
		}

		printf(raw_output ? "%s %d" : "%s %6d", time_str, logs[i].epoch);
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

	return EXIT_SUCCESS;
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

static int cluster_shutdown(int argc, char **argv)
{
	return shutdown_sheepdog();
}

static struct subcommand cluster_cmd[] = {
	{"info", NULL, "aprh", "show cluster information",
	 0, cluster_info},
	{"format", NULL, "caph", "create a Sheepdog storage",
	 0, cluster_format},
	{"shutdown", NULL, "aph", "stop Sheepdog",
	 SUBCMD_FLAG_NEED_NODELIST, cluster_shutdown},
	{NULL,},
};

static struct {
	const char *name;
	struct subcommand *sub;
	int (*parser)(int, char *);
} commands[] = {
	{"vdi", vdi_cmd,
	 vdi_parser,},
	{"node", node_cmd,},
	{"cluster", cluster_cmd,
	 cluster_parser,},
};

static int (*command_parser)(int, char *);
static int (*command_fn)(int, char **);
static const char *command_options;
static const char *command_arg;
static const char *command_desc;

static const struct sd_option *find_opt(int ch)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(collie_options); i++) {
		if (collie_options[i].val == ch)
			return collie_options + i;
	}
	fprintf(stderr, "internal error\n");
	exit(EXIT_SYSFAIL);
}

static char *build_short_options(const char *opts)
{
	static char sopts[256], *p;
	const struct sd_option *sd_opt;
	int i, len = strlen(opts);

	p = sopts;
	for (i = 0; i < len; i++) {
		sd_opt = find_opt(opts[i]);
		*p++ = sd_opt->val;
		if (sd_opt->has_arg)
			*p++ = ':';
	}
	*p = '\0';

	return sopts;
}

static struct option *build_long_options(const char *opts)
{
	static struct option lopts[256], *p;
	const struct sd_option *sd_opt;
	int i, len = strlen(opts);

	p = lopts;
	for (i = 0; i < len; i++) {
		sd_opt = find_opt(opts[i]);
		p->name = sd_opt->name;
		p->has_arg = sd_opt->has_arg;
		p->flag = NULL;
		p->val = sd_opt->val;
		p++;
	}
	memset(p, 0, sizeof(struct option));

	return lopts;
}

static unsigned long setup_command(char *cmd, char *subcmd)
{
	int i, found = 0;
	struct subcommand *s;
	unsigned long flags = 0;

	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (!strcmp(commands[i].name, cmd)) {
			found = 1;
			if (commands[i].parser)
				command_parser = commands[i].parser;
			break;
		}
	}

	if (!found) {
		fprintf(stderr, "'%s' is not a valid command\n", cmd);
		usage(EXIT_USAGE);
	}

	for (s = commands[i].sub; s->name; s++) {
		if (!strcmp(s->name, subcmd)) {
			command_fn = s->fn;
			command_options = s->opts;
			command_arg = s->arg;
			command_desc = s->desc;
			flags = s->flags;
			break;
		}
	}

	if (!command_fn) {
		fprintf(stderr, "'%s' is not a valid subcommand\n", subcmd);
		fprintf(stderr, "'%s' supports the following subcommands:\n", cmd);
		for (s = commands[i].sub; s->name; s++)
			fprintf(stderr, "%s\n", s->name);
		exit(EXIT_USAGE);
	}

	return flags;
}

static void usage(int status)
{
	int i;
	struct subcommand *s;
	char name[64];

	if (status)
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	else {
		printf("Usage: %s <command> <subcommand> [options]\n", program_name);
		printf("Sheepdog Administrator Utilty\n");
		printf("\n");
		printf("Command syntax:\n");
		for (i = 0; i < ARRAY_SIZE(commands); i++) {
			for (s = commands[i].sub; s->name; s++) {
				sprintf(name, "%s %s", commands[i].name, s->name);
				printf("  %-24s%s\n", name, s->desc);
			}
		}
		printf("\n");
		printf("For more information, "
		       "type \"%s <command> <subcommand> --help\".\n", program_name);
	}
	exit(status);
}

static void subcommand_usage(char *cmd, char *subcmd, int status)
{
	int i, len = strlen(command_options);
	const struct sd_option *sd_opt;
	char name[64];

	printf("%s %s - %s\n", cmd, subcmd, command_desc);
	printf("\n");
	printf("Usage:\n");
	printf("  %s %s %s", program_name, cmd, subcmd);
	if (command_arg)
		printf(" %s", command_arg);

	for (i = 0; i < len; i++) {
		sd_opt = find_opt(command_options[i]);
		if (sd_opt->has_arg)
			printf(" [-%c %s]", sd_opt->val, sd_opt->name);
		else
			printf(" [-%c]", sd_opt->val);
	}
	printf("\n");
	printf("\n");

	printf("Command parameters:\n");
	for (i = 0; i < len; i++) {
		sd_opt = find_opt(command_options[i]);
		sprintf(name, "-%c, --%s", sd_opt->val, sd_opt->name);
		printf("  %-24s%s\n", name, sd_opt->desc);
	}

	exit(status);
}

int main(int argc, char **argv)
{
	int ch, longindex, ret;
	unsigned long flags;
	struct option *long_options;
	const char *short_options;

	if (argc < 3)
		usage(0);

	flags = setup_command(argv[1], argv[2]);

	optind = 3;

	long_options = build_long_options(command_options);
	short_options = build_short_options(command_options);

	while ((ch = getopt_long(argc, argv, short_options, long_options,
				&longindex)) >= 0) {

		switch (ch) {
		case 'a':
			sdhost = optarg;
			break;
		case 'p':
			sdport = atoi(optarg);
			break;
		case 'r':
			raw_output = 1;
			break;
		case 'h':
			subcommand_usage(argv[1], argv[2], EXIT_SUCCESS);
			break;
		case '?':
			usage(EXIT_USAGE);
			break;
		default:
			if (command_parser)
				command_parser(ch, optarg);
			else
				usage(EXIT_USAGE);
			break;
		}
	}

	if (!isatty(STDOUT_FILENO) || raw_output)
		highlight = 0;

	if (flags & SUBCMD_FLAG_NEED_NODELIST) {
		ret = update_node_list(SD_MAX_NODES, 0);
		if (ret < 0) {
			fprintf(stderr, "failed to get node list\n");
			exit(EXIT_SYSFAIL);
		}
	}

	if (flags & SUBCMD_FLAG_NEED_THIRD_ARG && argc == optind) {
		fprintf(stderr, "'%s %s' needs the third argument\n", argv[1], argv[2]);
		exit(EXIT_USAGE);
	}

	return command_fn(argc, argv);
}
