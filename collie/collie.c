/*
 * Copyright (C) 2009-2010 Nippon Telegraph and Telephone Corporation.
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
#include "sheep.h"
#include "net.h"
#include "treeview.h"

static char program_name[] = "collie";
static int sdport = SD_LISTEN_PORT;
static int highlight = 1;

#define COMMON_LONG_OPTIONS				\
	{"port", required_argument, NULL, 'p'},		\
	{"help", no_argument, NULL, 'h'},		\

#define COMMON_SHORT_OPTIONS "p:h"

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
  vdi (list|delete|object|lock|release)\n\
  vm list\n\
\n\
Common parameters:\n\
  -p, --port              specify the daemon port\n\
  -h, --help              display this help and exit\n\
");
	}
	exit(status);
}

static uint64_t node_list_version;

static struct sheepdog_node_list_entry node_list_entries[SD_MAX_NODES];
static int nr_nodes;
static unsigned master_idx;

static int is_current(struct sheepdog_inode *i)
{
	return !i->snap_ctime;
}

static char *size_to_str(uint64_t _size, char *str, int str_size)
{
	char *units[] = {"MB", "GB", "TB", "PB", "EB", "ZB", "YB"};
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

static int cluster_format(int argc, char **argv)
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

typedef void (*vdi_parser_func_t)(uint32_t vid, char *name, uint32_t tag, uint32_t flags,
				  struct sheepdog_inode *i, void *data);

static int parse_vdi(vdi_parser_func_t func, void *data)
{
	int ret, fd;
	unsigned long nr;
	static struct sheepdog_inode i;
	struct sd_req req;
	static DECLARE_BITMAP(vdi_inuse, SD_NR_VDIS);
	unsigned int rlen, wlen = 0;

	fd = connect_to("localhost", sdport);
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

	for (nr = 0; nr < SD_NR_VDIS; nr++) {
		struct sd_obj_req hdr;
		struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;

		if (!test_bit(nr, vdi_inuse))
			continue;

		wlen = 0;
		rlen = sizeof(i);

		memset(&hdr, 0, sizeof(hdr));
		hdr.opcode = SD_OP_READ_OBJ;
		hdr.oid = vid_to_vdi_oid(nr);
		hdr.data_length = rlen;

		ret = exec_req(fd, (struct sd_req *)&hdr, &i, &wlen, &rlen);

		if (!ret && rsp->result == SD_RES_SUCCESS) {
			if (i.name[0] == '\0') /* deleted */
				continue;
			func(i.vdi_id, i.name, i.snap_id, 0, &i, data);
		} else
			printf("error %lu, %d\n", nr, ret);
	}

	close(fd);

	return 0;
}

static void print_vdi_list(uint32_t vid, char *name, uint32_t tag,
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
		       is_current(i) ? ' ' : 's', name, tag,
		       vdi_size_str, my_objs_str, cow_objs_str, dbuf, vid);
	}
}

struct vm_list_info {
	struct sheepdog_vm_list_entry *vm_list_entries;
	int nr_vms;
	int highlight;
};

static void print_vm_list(uint32_t vid, char *name, uint32_t tag,
			  uint32_t flags, struct sheepdog_inode *inode, void *data)
{
	int i, j;
	uint64_t my_objs, cow_objs;
	struct vm_list_info *vli = (struct vm_list_info *)data;
	char vdi_size_str[8], my_objs_str[8], cow_objs_str[8];

	if (!is_current(inode))
		return;

	for (i = 0; i < vli->nr_vms; i++) {
		if (!strcmp((char *)vli->vm_list_entries[i].name, name))
			break;
	}

	my_objs = 0;
	cow_objs = 0;
	for (j = 0; j < MAX_DATA_OBJS; j++) {
		if (!inode->data_vdi_id[j])
			continue;
		if (is_data_obj_writeable(inode, j))
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

static void cal_total_vdi_size(uint32_t vid, char *name, uint32_t tag,
			       uint32_t flags, struct sheepdog_inode *i, void *data)
{
	uint64_t *size = data;

	if (is_current(i))
		*size += i->vdi_size;
}

struct get_vid_info {
	char *name;
	uint32_t vid;
};

static void get_oid(uint32_t vid, char *name, uint32_t tag,
		    uint32_t flags, struct sheepdog_inode *i, void *data)
{
	struct get_vid_info *info = data;
	char *p;

	if (info->name) {
		p = strchr(info->name, ':');

		if (p) {
			if (!strncmp(name, info->name, p - info->name) &&
			    tag == strtoul(p + 1, NULL, 16))
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
		unsigned wlen = 0, rlen = sizeof(sizeof(struct sheepdog_inode));
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

	free(buf);
}

#define SUBCMD_FLAG_NEED_NOEDLIST (1 << 0)
#define SUBCMD_FLAG_NEED_THIRD_ARG (1 << 1)

struct subcommand {
	char *name;
	unsigned long flags;
	int (*fn)(int, char **);
};

static int node_list(int argc, char **argv)
{
	int i;

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

	parse_vdi(cal_total_vdi_size, &total_vdi_size);

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

static int vm_list(int argc, char **argv)
{
	int fd, ret;
	struct sd_req hdr;
	unsigned rlen, wlen;
	char *data;
	struct vm_list_info vli;

	fd = connect_to("localhost", sdport);
	if (fd < 0)
		return 1;

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
		return 1;
	vli.vm_list_entries = (struct sheepdog_vm_list_entry *)data;
	vli.nr_vms = rlen / sizeof(struct sheepdog_vm_list_entry);
	vli.highlight = highlight;

	printf("Name            |Vdi size |Allocated| Shared  | Status\n");
	printf("----------------+---------+---------+---------+------------\n");
	ret = parse_vdi(print_vm_list, &vli);

	return 0;
}

static struct subcommand vm_cmd[] = {
	{"list", SUBCMD_FLAG_NEED_NOEDLIST, vm_list},
	{NULL,},
};

static int vdi_list(int argc, char **argv)
{
	printf("  name        id    size    used  shared    creation time   vdi id\n");
	printf("------------------------------------------------------------------\n");

	parse_vdi(print_vdi_list, NULL);
	return 0;
}

static int vdi_delete(int argc, char **argv)
{
	char *data = argv[optind];
	int fd, ret;
	struct sd_vdi_req hdr;
	struct sd_vdi_rsp *rsp = (struct sd_vdi_rsp *)&hdr;
	unsigned rlen, wlen;
	char vdiname[SD_MAX_VDI_LEN];
	uint32_t id = ~0;

	fd = connect_to("localhost", sdport);
	if (fd < 0)
		return -1;

	memset(&hdr, 0, sizeof(hdr));

	rlen = 0;
	wlen = sizeof(vdiname);

	hdr.opcode = SD_OP_DEL_VDI;
	if (id != ~0)
		hdr.snapid = id;
	hdr.epoch = node_list_version;
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = wlen;
	strncpy(vdiname, data, sizeof(vdiname));

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
	unsigned index = ~0;
	int ret;
	struct get_vid_info info;
	uint32_t vid;

	info.name = vdiname;
	info.vid = 0;

	ret = parse_vdi(get_oid, &info);

	vid = info.vid;
	if (vid == 0) {
		printf("No such vdi\n");
		return 1;
	}

	if (index == ~0) {
		printf("Looking for the inode object 0x%" PRIx32 " with %d nodes\n\n",
		       vid, nr_nodes);
		parse_objs(vid_to_vdi_oid(vid), do_print_obj, NULL);
	} else {
		struct get_data_oid_info info;

		info.success = 0;
		info.idx = index;

		if (index >= MAX_DATA_OBJS) {
			printf("The offset is too large!\n");
			exit(1);
		}

		parse_objs(vid_to_vdi_oid(vid), get_data_oid, &info);

		if (info.success) {
			if (info.data_oid) {
				printf("Looking for the object 0x%" PRIx64
				       " (the inode vid 0x%" PRIx32 " index %u) with %d nodes\n\n",
				       info.data_oid, vid, index, nr_nodes);

				parse_objs(info.data_oid, do_print_obj, NULL);
			} else
				printf("The inode object 0x%" PRIx32 " index %u is not allocated\n",
				       vid, index);
		} else
			printf("failed to read the inode object 0x%" PRIx32 "\n", vid);
	}

	return 0;
}

static int vdi_lock(int argc, char **argv)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret;
	char vdiname[SD_MAX_VDI_LEN];
	unsigned rlen = 0, wlen = 0;
	unsigned opcode, flags;
	int fd;

	memset(vdiname, 0, sizeof(vdiname));

	strncpy(vdiname, argv[optind], sizeof(vdiname));
	wlen = sizeof(vdiname);
	opcode = SD_OP_LOCK_VDI;
	flags = SD_FLAG_CMD_WRITE;

	fd = connect_to("localhost", sdport);
	if (fd < 0)
		return 1;

	memset(&hdr, 0, sizeof(hdr));

	hdr.proto_ver = SD_PROTO_VER; /* version is checked when locking */
	hdr.opcode = opcode;
	hdr.data_length = wlen;
	hdr.flags = flags;
	hdr.epoch = node_list_version;

	ret = exec_req(fd, &hdr, vdiname, &wlen, &rlen);
	close(fd);

	if (ret) {
		fprintf(stderr, "communication error\n");
		return 1;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "%s: %s\n", vdiname, sd_strerror(rsp->result));
		return 1;
	}

	return 0;
}

static int vdi_release(int argc, char **argv)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret;
	char vdiname[SD_MAX_VDI_LEN];
	unsigned rlen = 0, wlen = 0;
	unsigned opcode, flags;
	int fd;
	char *data = NULL;

	memset(vdiname, 0, sizeof(vdiname));

	strncpy(vdiname, argv[optind], sizeof(vdiname));
	wlen = sizeof(vdiname);
	data = vdiname;
	opcode = SD_OP_RELEASE_VDI;
	flags = SD_FLAG_CMD_WRITE;

	fd = connect_to("localhost", sdport);
	if (fd < 0)
		return 1;

	memset(&hdr, 0, sizeof(hdr));

	hdr.opcode = opcode;
	hdr.data_length = wlen;
	hdr.flags = flags;
	hdr.epoch = node_list_version;

	ret = exec_req(fd, &hdr, data, &wlen, &rlen);
	close(fd);

	if (ret) {
		fprintf(stderr, "communication error\n");
		return 1;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "%s: %s\n", vdiname, sd_strerror(rsp->result));
		return 1;
	}

	return 0;
}

static struct subcommand vdi_cmd[] = {
	{"delete", SUBCMD_FLAG_NEED_NOEDLIST|SUBCMD_FLAG_NEED_THIRD_ARG, vdi_delete},
	{"list", SUBCMD_FLAG_NEED_NOEDLIST, vdi_list},
	{"object", SUBCMD_FLAG_NEED_NOEDLIST|SUBCMD_FLAG_NEED_THIRD_ARG, vdi_object},
	{"lock", SUBCMD_FLAG_NEED_THIRD_ARG, vdi_lock},
	{"release", SUBCMD_FLAG_NEED_THIRD_ARG, vdi_release},
	{NULL,},
};

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
	char time[128];

	fd = connect_to("localhost", sdport);
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
	printf("Ctime              Epoch Nodes\n");
	nr_logs = rsp->data_length / sizeof(struct epoch_log);
	for (i = 0; i < nr_logs; i++) {
		int j;
		char name[128];
		struct sheepdog_node_list_entry *entry;

		ti = logs[i].ctime >> 32;
		localtime_r(&ti, &tm);
		strftime(time, sizeof(time), "%y-%m-%d %H:%M:%S", &tm);

		printf("%s %6d", time, logs[i].epoch);
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
	char *name;
	struct subcommand *sub;
	struct option *lopts;
	char *sopts;
	int (*parser)(int, char *);
	void (*help)(void);
} commands[] = {
	{"vdi", vdi_cmd,},
	{"node", node_cmd,},
	{"vm", vm_cmd,},
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
static char *short_options = COMMON_SHORT_OPTIONS;
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
	char termcap_area[1024];
	unsigned long flags;

	if (getenv("TERM"))
		tgetent(termcap_area, getenv("TERM"));

	if (argc < 3)
		usage(0);

	flags = setup_command(argv[1], argv[2]);

	optind = 3;

	while ((ch = getopt_long(argc, argv, short_options, long_options,
				&longindex)) >= 0) {

		switch (ch) {
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
