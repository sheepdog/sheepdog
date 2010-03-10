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
#include <term.h>
#include <curses.h>

#include "sheepdog_proto.h"
#include "meta.h"
#include "net.h"
#include "treeview.h"

static char program_name[] = "shepherd";
static int sdport = SD_LISTEN_PORT;

static struct option const long_options[] =
{
	{"port", required_argument, 0, 'p'},
	{"copies", required_argument, 0, 'c'},
	{"epoch", required_argument, 0, 'e'},
	{"index", required_argument, 0, 'i'},
	{"format", required_argument, 0, 'f'},
	{"type", required_argument, 0, 't'},
	{"highlight", required_argument, 0, 'H'},
	{"resident", required_argument, 0, 'R'},
	{"op", required_argument, 0, 'o'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

static char *short_options = "p:f:rR:t:H:o:i:e:h";

enum info_type {
	INFO_VDI,
	INFO_DOG,
	INFO_SHEEP,
	INFO_OBJ,
	INFO_VM,
	INFO_NONE,
};

enum format_type {
	FORMAT_LIST,
	FORMAT_TREE,
	FORMAT_GRAPH,
	FORMAT_NONE,
};

static void usage(int status)
{
	if (status)
		fprintf(stderr, "Try `%s --help' for more information.\n", program_name);
	else {
		printf("Usage: %s command [command options]\n", program_name);
		printf("Sheepdog Administrator Utilty\n\
\n\
Command syntax:\n\
  mkfs [--copies=N]\n\
  info -t (vdi|dog|sheep|obj) [-f (list|tree|graph)] [-H (on|off)] [-R (on|off)] [-i N] [-e N] [vdiname]\n\
  debug -o node_version\n\
  shutdown\n\
\n\
Command parameters:\n\
  -f, --format            specify the output format\n\
  -R, --resient           show in a dynamic real-time view\n\
  -t, --type              specify the type of information\n\
  -H, --highlight         highlight an important infomation\n\
  -h, --help              display this help and exit\n\
");
	}
	exit(status);
}

static uint64_t node_list_version;

static struct sheepdog_node_list_entry *node_list_entries;
static int nr_nodes;
static unsigned master_idx;

static char *size_to_str(uint64_t size, char *str, int str_size)
{
	char *units[] = {"MB", "GB", "TB", "PB", "EB", "ZB", "YB"};
	int i = 0, frac = 0;

	size /= 1024 * 1024;
	while (i < ARRAY_SIZE(units) && size >= 1024) {
		i++;

		frac = size % 1024;
		if (frac > 1000)
			frac -= 100;
		while (frac > 10)
			frac /= 10;

		size /= 1024;
	}

	if (size > 9)
		snprintf(str, str_size, "%" PRId64 " %s", size, units[i]);
	else
		snprintf(str, str_size, "%" PRId64 ".%d %s", size, frac, units[i]);

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

	fd = connect_to("localhost", sdport);
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

	switch (rsp->result) {
	case SD_RES_SUCCESS:
		break;
	case SD_RES_DIR_READ:
		fprintf(stderr, "cannot read directory object\n");
		ret = -1;
		goto out;
	case SD_RES_STARTUP:
		fprintf(stderr, "sheepdog is not ready\n");
		ret = -1;
		goto out;
	case SD_RES_SHUTDOWN:
		fprintf(stderr, "sheepdog is shutting down\n");
		ret = -1;
		goto out;
	case SD_RES_NO_EPOCH:
		fprintf(stderr, "requested epoch is not found\n");
		ret = -1;
		goto out;
	default:
		fprintf(stderr, "unknown error: %d\n", rsp->result);
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
	node_list_version = hdr.epoch;
	master_idx = rsp->master_idx;
out:
	if (buf)
		free(buf);
	if (fd >= 0)
		close(fd);

	return ret;
}

static int mkfs(int copies)
{
	int fd, ret;
	struct sd_so_req hdr;
	struct sd_so_rsp *rsp = (struct sd_so_rsp *)&hdr;
	unsigned rlen, wlen;
	struct timeval tv;

	fd = connect_to("localhost", sdport);
	if (fd < 0)
		return -1;

	gettimeofday(&tv, NULL);

	memset(&hdr, 0, sizeof(hdr));

	hdr.opcode = SD_OP_MAKE_FS;
	hdr.copies = copies;
	hdr.epoch = node_list_version;
	hdr.ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;

	rlen = 0;
	wlen = 0;
	ret = exec_req(fd, (struct sd_req *)&hdr, NULL, &wlen, &rlen);
	close(fd);

	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "failed to connect the dog\n");
		return ret;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		switch (rsp->result) {
		case SD_RES_STARTUP:
			fprintf(stderr, "the dog is not ready for the mkfs operation\n");
			break;
		case SD_RES_SHUTDOWN:
			fprintf(stderr, "the dog is shutting down\n");
			break;
		default:
			fprintf(stderr, "unknown error\n");
			break;
		}
	}

	return 0;
}

static int debug(char *op, char *arg)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int fd, ret;
	char name[128];
	unsigned rlen, wlen;
	unsigned opcode, flags;
	uint64_t oid = 0;

	if (!op)
		return 1;

	if (!strcasecmp(op, "node_version")) {
		rlen = 0;
		wlen = 0;
		opcode = SD_OP_DEBUG_INC_NVER;
		flags = 0;
	} else if (!strcasecmp(op, "node")) {
		if (!arg)
			return 1;
		rlen = 0;
		wlen = strlen(arg);
		opcode = SD_OP_DEBUG_SET_NODE;
		flags = SD_FLAG_CMD_WRITE;
	} else if (!strcasecmp(op, "lock_vdi")) {
		if (!arg)
			return 1;
		rlen = 0;
		wlen = strlen(arg) + 1;
		opcode = SD_OP_LOCK_VDI;
		flags = SD_FLAG_CMD_WRITE;
	} else if (!strcasecmp(op, "release_vdi")) {
		if (!arg)
			return 1;
		rlen = 0;
		wlen = strlen(arg) + 1;
		opcode = SD_OP_RELEASE_VDI;
		flags = SD_FLAG_CMD_WRITE;
	} else if (!strcasecmp(op, "vdi_info")) {
		if (!arg)
			return 1;
		rlen = 0;
		oid = strtoul(arg, NULL, 10);
		if (oid == 0) {
			wlen = strlen(arg) + 1;
			opcode = SD_OP_GET_VDI_INFO;
			flags = SD_FLAG_CMD_WRITE;
		} else {
			wlen = 0;
			opcode = SD_OP_GET_EPOCH;
			flags = 0;
		}
	} else
		return 1;

	strcpy(name, "localhost");
	fd = connect_to(name, sdport);
	if (fd < 0)
		return -1;

	memset(&hdr, 0, sizeof(hdr));

	hdr.opcode = opcode;
	hdr.data_length = wlen;
	hdr.flags = flags;
	hdr.epoch = node_list_version;
	if (oid > 0) {
		((struct sd_vdi_req *)&hdr)->base_oid = oid;
	}

	ret = exec_req(fd, &hdr, arg, &wlen, &rlen);
	close(fd);

	if (ret) {
		fprintf(stderr, "communication error\n");
		return ret;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		switch(rsp->result) {
		case SD_RES_VDI_LOCKED:
			fprintf(stderr, "%s is already locked\n", arg);
			break;
		case SD_RES_VDI_NOT_LOCKED:
			fprintf(stderr, "%s is not locked\n", arg);
			break;
		case SD_RES_NO_VDI:
			fprintf(stderr, "%s: no such vdi\n", arg);
			break;
		default:
			fprintf(stderr, "error %d\n", rsp->result);
			break;
		}
		return -1;
	}

	if (!strcasecmp(op, "vdi_info")) {
		struct sd_vdi_rsp *vdi_rsp = (struct sd_vdi_rsp *)rsp;
		printf("name = %s, oid = %"PRIu64", epoch = %d\n",
		       arg, vdi_rsp->oid, vdi_rsp->vdi_epoch);
	}
	return ret;
}

static int shutdown_sheepdog(void)
{
	int fd, ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	unsigned rlen, wlen;

	fd = connect_to("localhost", sdport);
	if (fd < 0)
		return -1;

	memset(&hdr, 0, sizeof(hdr));

	hdr.opcode = SD_OP_SHUTDOWN;
	hdr.epoch = node_list_version;

	rlen = 0;
	wlen = 0;
	ret = exec_req(fd, &hdr, NULL, &wlen, &rlen);
	close(fd);

	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "failed to connect the dog\n");
		return ret;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		switch (rsp->result) {
		case SD_RES_STARTUP:
			fprintf(stderr, "the dog is not ready for the mkfs operation\n");
			break;
		default:
			fprintf(stderr, "unknown error\n");
			break;
		}
	}

	return 0;
}

#define DIR_BUF_LEN (UINT64_C(1) << 20)

typedef void (*vdi_parser_func_t)(uint64_t oid, char *name, uint32_t tag, uint32_t flags,
				  struct sheepdog_inode *i, void *data);

/*
 * TODO: handle larger buffer
 */
int parse_vdi(vdi_parser_func_t func, void *data)
{
	struct sheepdog_vdi_info *ent;
	char *buf;
	int rest, ret;
	struct sheepdog_inode i;
	struct sd_so_req req;

	memset(&req, 0, sizeof(req));

	buf = zalloc(DIR_BUF_LEN);
	if (!buf)
		return 1;

	req.opcode = SD_OP_SO_READ_VDIS;

	ret = exec_reqs(node_list_entries, nr_nodes, node_list_version,
			SD_DIR_OID, (struct sd_req *)&req, buf, 0, DIR_BUF_LEN,
			nr_nodes, 1);

	if (ret < 0) {
		ret = 1;
		goto out;
	}

	ent = (struct sheepdog_vdi_info *)buf;
	rest = ret;
	while (rest > 0) {
		if (!ent->name_len)
			break;

		ret = read_object(node_list_entries, nr_nodes, node_list_version,
				  ent->oid, (void *)&i, sizeof(i), 0, nr_nodes);

		if (ret == sizeof(i))
			func(ent->oid, ent->name, ent->id, ent->flags, &i, data);

		ent++;
		rest -= sizeof(*ent);
	}

out:
	free(buf);

	return 0;
}

struct graph_info {
	int64_t root;
	char *name;
	int highlight;
};

static void print_graph_tree(uint64_t oid, char *name, uint32_t tag,
			     uint32_t flags, struct sheepdog_inode *i, void *data)
{
	struct graph_info *info = (struct graph_info *)data;
	time_t ti;
	struct tm tm;
	char date[128];
	char time[128];
	char size_str[8];

	if (info->name && strcmp(info->name, name) != 0)
		return;

	if (info->root < 0)
		info->root = i->parent_oid;

	ti = i->ctime >> 32;
	localtime_r(&ti, &tm);

	strftime(date, sizeof(date), "%y-%m-%d", &tm);
	strftime(time, sizeof(time), "%H:%M:%S", &tm);
	size_to_str(i->vdi_size, size_str, sizeof(size_str));

	printf("  \"%" PRIu64 "\" [shape = \"box\","
	       "fontname = \"Courier\","
	       "fontsize = \"12\","
	       "group = \"%s\","
	       "label = \"",
	       oid, name);
	printf("name: %8s\\n"
	       "tag : %8x\\n"
	       "size: %8s\\n"
	       "date: %8s\\n"
	       "time: %8s",
	       name, tag, size_str, date, time);

	if (info->highlight && (flags & FLAG_CURRENT))
		printf("\", color=\"red\"];\n");
	else
		printf("\"];\n");

	printf("  \"%" PRIu64 "\" -> \"%" PRIu64 "\";\n", i->parent_oid, oid);
}

static int graphview_vdi(char *vdiname, int highlight)
{
	struct graph_info i;

	i.name = vdiname;
	i.highlight = highlight;
	i.root = -1;

	/* print a header */
	printf("digraph G \{\n");

	parse_vdi(print_graph_tree, &i);

	if (i.root == 0)
		printf("  \"0\" [shape = \"ellipse\", label = \"root\"];\n");
	else if (i.root > 0)
		printf("  \"%" PRIu64 "\" [shape = \"ellipse\", label = \"%s\"];\n",
		       i.root, vdiname);

	/* print a footer */
	printf("}\n");

	return 0;
}

struct tree_info {
	int highlight;
	char *name;
};

static void print_vdi_tree(uint64_t oid, char *name, uint32_t tag,
			   uint32_t flags, struct sheepdog_inode *i, void *data)
{
	struct tree_info *info = (struct tree_info *)data;
	time_t ti;
	struct tm tm;
	char buf[128];

	if (info->name && strcmp(name, info->name))
		return;

	if (flags & FLAG_CURRENT) {
		strcpy(buf, "(You Are Here)");
	} else {
		ti = i->ctime >> 32;
		localtime_r(&ti, &tm);

		strftime(buf, sizeof(buf),
			 "[%y-%m-%d %H:%M]", &tm);
	}

	add_vdi_tree(name, buf, oid, i->parent_oid,
		 info->highlight && (flags & FLAG_CURRENT));
}

static int treeview_vdi(char *vdiname, int highlight)
{
	struct tree_info i;

	i.name = vdiname;
	i.highlight = highlight;

	init_tree();

	parse_vdi(print_vdi_tree, &i);

	dump_tree();

	return 0;
}

static void print_vdi_list(uint64_t oid, char *name, uint32_t tag,
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
		if (!i->data_oid[idx])
			continue;
		if (is_data_obj_writeable(i->data_oid[idx], oid))
			my_objs++;
		else
			cow_objs++;
	}

	size_to_str(i->vdi_size, vdi_size_str, sizeof(vdi_size_str));
	size_to_str(my_objs * SD_DATA_OBJ_SIZE, my_objs_str, sizeof(my_objs_str));
	size_to_str(cow_objs * SD_DATA_OBJ_SIZE, cow_objs_str, sizeof(cow_objs_str));

	if (!data || strcmp(name, data) == 0) {
		printf("%c %-8s %5d %7s %7s %7s %s  %9" PRIx64 "\n",
		       flags & FLAG_CURRENT ? ' ' : 's', name, tag,
		       vdi_size_str, my_objs_str, cow_objs_str, dbuf, oid);
	}
}

struct vm_list_info {
	struct sheepdog_vm_list_entry *vm_list_entries;
	int nr_vms;
	int highlight;
};

static void print_vm_list(uint64_t oid, char *name, uint32_t tag,
			  uint32_t flags, struct sheepdog_inode *inode, void *data)
{
	int i, j;
	uint64_t my_objs, cow_objs;
	struct vm_list_info *vli = (struct vm_list_info *)data;
	char vdi_size_str[8], my_objs_str[8], cow_objs_str[8];

	if (!(flags & FLAG_CURRENT))
		return;

	for (i = 0; i < vli->nr_vms; i++) {
		if (!strcmp((char *)vli->vm_list_entries[i].name, name))
			break;
	}

	my_objs = 0;
	cow_objs = 0;
	for (j = 0; j < MAX_DATA_OBJS; j++) {
		if (!inode->data_oid[j])
			continue;
		if (is_data_obj_writeable(inode->data_oid[j], oid))
			my_objs++;
		else
			cow_objs++;
	}

	size_to_str(inode->vdi_size, vdi_size_str, sizeof(vdi_size_str));
	size_to_str(my_objs * SD_DATA_OBJ_SIZE, my_objs_str, sizeof(my_objs_str));
	size_to_str(cow_objs * SD_DATA_OBJ_SIZE, cow_objs_str, sizeof(cow_objs_str));
	if (i < vli->nr_vms) {
		char *tmp;
		if (vli->highlight && (tmp = tgetstr("md", NULL)))
			tputs(tmp, 1, putchar);

		printf("%-16s|%9s|%9s|%9s| running on %d.%d.%d.%d", name,
		       vdi_size_str, my_objs_str, cow_objs_str,
		       vli->vm_list_entries[i].host_addr[12],
		       vli->vm_list_entries[i].host_addr[13],
		       vli->vm_list_entries[i].host_addr[14],
		       vli->vm_list_entries[i].host_addr[15]);
		if (vli->highlight && (tmp = tgetstr("me", NULL)))
			tputs(tmp, 1, putchar);
		printf("\n");
	} else
		printf("%-16s|%9s|%9s|%9s| not running\n", name,
		       vdi_size_str, my_objs_str, cow_objs_str);
}

static void cal_total_vdi_size(uint64_t oid, char *name, uint32_t tag,
			   uint32_t flags, struct sheepdog_inode *i, void *data)
{
	uint64_t *size = data;

	if (flags & FLAG_CURRENT)
		*size += i->vdi_size;
}

struct get_oid_info {
	char *name;
	uint64_t oid;
};

static void get_oid(uint64_t oid, char *name, uint32_t tag,
		    uint32_t flags, struct sheepdog_inode *i, void *data)
{
	struct get_oid_info *info = data;
	char *p;

	if (info->name) {
		p = strchr(info->name, ':');

		if (p) {
			if (!strncmp(name, info->name, p - info->name) &&
			    tag == strtoul(p + 1, NULL, 16))
				info->oid = oid;
		} else {
			if (!strcmp(name, info->name))
				info->oid = oid;
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
		printf("%s: has the version %u (should be %d copies)\n",
		       sheep, rsp->obj_ver, rsp->copies);
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
		info->data_oid = inode->data_oid[info->idx];
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

	for (i = 0; i < nr_nodes; i++) {
		char buf[sizeof(struct sheepdog_inode)];
		unsigned wlen = 0, rlen = sizeof(buf);
		struct sd_obj_req hdr;
		struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;

		addr_to_str(name, sizeof(name), node_list_entries[i].addr, 0);

		fd = connect_to(name, node_list_entries[i].port);
		if (fd < 0)
			break;

		memset(&hdr, 0, sizeof(hdr));

		hdr.opcode = SD_OP_READ_OBJ;
		hdr.data_length = rlen;
		hdr.flags = 0;
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
}

static void print_obj(char *vdiname, unsigned index)
{
	int ret;
	struct get_oid_info info;
	uint64_t oid;

	info.name = vdiname;
	info.oid = 0;

	ret = parse_vdi(get_oid, &info);

	oid = info.oid;
	if (oid == 0) {
		printf("No such vdi\n");
		return;
	}

	if (index == ~0) {
		printf("Looking for the inode object 0x%" PRIx64 " with %d nodes\n\n",
		       oid, nr_nodes);
		parse_objs(oid, do_print_obj, NULL);
	} else {
		struct get_data_oid_info info;

		info.success = 0;
		info.idx = index;

		if (index >= MAX_DATA_OBJS) {
			printf("The offset is too large!\n");
			exit(1);
		}

		parse_objs(oid, get_data_oid, &info);

		if (info.success) {
			if (info.data_oid) {
				printf("Looking for the object 0x%" PRIx64
				       " (the inode oid 0x%" PRIx64 " index %u) with %d nodes\n\n",
				       info.data_oid, oid, index, nr_nodes);

				parse_objs(info.data_oid, do_print_obj, NULL);
			} else
				printf("The inode object 0x%" PRIx64 " index %u is not allocated\n",
				       oid, index);
		} else
			printf("failed to read the inode object 0x%" PRIx64 "\n", oid);
	}
}

int info(enum info_type type, enum format_type format, char *name,
	 int highlight, int real_time, unsigned index)
{
	int i, ret = -1;
	uint64_t total_size = 0, total_avail = 0, total_vdi_size = 0;
	char total_str[8], avail_str[8], vdi_size_str[8];

	if (real_time) {
		setupterm(NULL, 1, (int *)0);
		fflush(stderr);
		fflush(stdout);
		clear();
	}
rerun:
	if (real_time) {
		if (clear_screen == NULL)
			return -2;
		putp(clear_screen);
	}

	switch (type) {
	case INFO_VDI:
		switch (format) {
		case FORMAT_LIST:
			printf("  name        id    size    used  shared    creation time  object id\n");
			printf("--------------------------------------------------------------------\n");
			ret = parse_vdi(print_vdi_list, name);
			break;
		case FORMAT_TREE:
			ret = treeview_vdi(name, highlight);
			break;
		case FORMAT_GRAPH:
			ret = graphview_vdi(name, highlight);
			break;
		default:
			ret = -1;
			break;
		}
		break;
	case INFO_DOG:
		printf("  Idx\tNode id (FNV-1a) - Host:Port\n");
		printf("------------------------------------------------\n");
		for (i = 0; i < nr_nodes; i++) {
			char data[128];

			print_node_list_entry(&node_list_entries[i], data, sizeof(data));

			if (i == master_idx) {
				const char *tmp;

				if (highlight && (tmp = tgetstr("md", NULL)))
					tputs(tmp, 1, putchar);
				printf("* %d\t%s\n", i, data);
				if (highlight && (tmp = tgetstr("me", NULL)))
					tputs(tmp, 1, putchar);
			} else
				printf("  %d\t%s\n", i, data);
		}
		ret = 0;
		break;
	case INFO_SHEEP:
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
				continue;

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
			if (!ret && rsp->result == SD_RES_SUCCESS)
				printf("%2d\t%s\t%s\t%3d%%\n", i, store_str, free_str,
				       (int)(((double)(rsp->store_size - rsp->store_free) / rsp->store_size) * 100));

			total_size += rsp->store_size;
			total_avail += rsp->store_free;
		}

		printf("\n");

		parse_vdi(cal_total_vdi_size, &total_vdi_size);

		size_to_str(total_size, total_str, sizeof(total_str));
		size_to_str(total_size - total_avail, avail_str, sizeof(avail_str));
		size_to_str(total_vdi_size, vdi_size_str, sizeof(vdi_size_str));
		printf("Total\t%s\t%s\t%3d%%, total virtual VDI Size\t%s\n",
		       total_str, avail_str,
		       (int)(((double)(total_size - total_avail) / total_size) * 100),
		       vdi_size_str);

		ret = 0;
		break;
	case INFO_OBJ:
		if (!name) {
			printf("Please specify the vdiname\n");
			break;
		}
		print_obj(name, index);
		ret = 0;
		break;
	case INFO_VM:
	{
		int fd;
		struct sd_req hdr;
		unsigned rlen, wlen;
		char *data;
		struct vm_list_info vli;

		fd = connect_to("localhost", sdport);
		if (fd < 0)
			break;

		memset(&hdr, 0, sizeof(hdr));

		hdr.opcode = SD_OP_GET_VM_LIST;
		hdr.data_length = sizeof(struct sheepdog_vm_list_entry) * SD_MAX_VMS;
		hdr.epoch = node_list_version;
		data = zalloc(hdr.data_length);

		rlen = hdr.data_length;
		wlen = 0;
		ret = exec_req(fd, &hdr, data, &wlen, &rlen);
		close(fd);

		if (ret != SD_RES_SUCCESS)
			break;
		vli.vm_list_entries = (struct sheepdog_vm_list_entry *)data;
		vli.nr_vms = rlen / sizeof(struct sheepdog_vm_list_entry);
		vli.highlight = highlight;

		printf("Name            |Vdi size |Allocated| Shared  | Status\n");
		printf("----------------+---------+---------+---------+------------\n");
		ret = parse_vdi(print_vm_list, &vli);
		break;
	}
	default:
		ret = -1;
		break;
	}

	if (real_time && ret == 0) {
		fflush(stdout);
		sleep(1);
		goto rerun;
	}
	return ret;
}

int main(int argc, char **argv)
{
	int ch, longindex;
	int ret = 0;
	char *command;
	enum info_type type = INFO_NONE;
	enum format_type format = FORMAT_LIST;
	int reboot = 0;
	int highlight = 1;
	char termcap_area[1024];
	int copies = DEAFAULT_NR_COPIES;
	char *op = NULL;
	unsigned index = ~0;
	int real_time = 0;
	int epoch = 0;

	if (getenv("TERM"))
		tgetent(termcap_area, getenv("TERM"));

	while ((ch = getopt_long(argc, argv, short_options, long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'p':
			sdport = atoi(optarg);
			break;
		case 'c':
			copies = atoi(optarg);
			break;
		case 'f':
			if (strcasecmp(optarg, "list") == 0)
				format = FORMAT_LIST;
			else if (strcasecmp(optarg, "tree") == 0)
				format = FORMAT_TREE;
			else if (strcasecmp(optarg, "graph") == 0)
				format = FORMAT_GRAPH;
			else
				usage(1);
			break;
		case 'H':
			if (strcasecmp(optarg, "on") == 0)
				highlight = 1;
			else if (strcasecmp(optarg, "off") == 0)
				highlight = 0;
			else
				usage(1);
			break;
		case 'R':
			if (strcasecmp(optarg, "on") == 0)
				real_time = 1;
			else if (strcasecmp(optarg, "off") == 0)
				real_time = 0;
			else
				usage(1);
			break;
		case 'h':
			usage(0);
		case 'r':
			reboot = 1;
			break;
		case 't':
			if (!strcasecmp(optarg, "vdi"))
				type = INFO_VDI;
			else if (!strcasecmp(optarg, "dog"))
				type = INFO_DOG;
			else if (!strcasecmp(optarg, "sheep"))
				type = INFO_SHEEP;
			else if (!strcasecmp(optarg, "obj"))
				type = INFO_OBJ;
			else if (!strcasecmp(optarg, "vm"))
				type = INFO_VM;
			else
				usage(1);
			break;
		case 'o':
			op = optarg;
			break;
		case 'i':
			index = strtoul(optarg, NULL, 10);
			break;
		case 'e':
			epoch = strtoul(optarg, NULL, 10);
			if (epoch <= 0) {
				fprintf(stderr, "epoch must be larger than 0\n");
				usage(1);
			}
			break;
		default:
			usage(1);
			break;
		}
	}
	if (optind >= argc)
		usage(0);


	node_list_entries = zalloc(SD_MAX_NODES * sizeof(struct sheepdog_node_list_entry));
	ret = update_node_list(SD_MAX_NODES, epoch);
	if (ret < 0)
		return 1;

	command = argv[optind++];

	if (!strcasecmp(command, "info")) {
		char *name = NULL;

		if (type == INFO_NONE)
			usage(0);
		if (optind != argc)
			name = argv[optind];

		info(type, format, name, highlight, real_time, index);
	} else if (!strcasecmp(command, "mkfs"))
		ret = mkfs(copies);
	else if (!strcasecmp(command, "debug"))
		ret = debug(op, argv[optind]);
	else if (!strcasecmp(command, "shutdown"))
		ret = shutdown_sheepdog();
	else {
		fprintf(stderr, "'%s' is not a valid command\n", command);
		usage(1);
	}

	return ret;
}
