/*
 * Copyright (C) 2012 Taobao Inc.
 *
 * Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <fuse.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <dirent.h>
#include <pthread.h>
#include <getopt.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdarg.h>

#include "strbuf.h"
#include "util.h"
#include "sheepfs.h"
#include "sheepdog_proto.h"

#define SH_OP_NAME   "user.sheepfs.opcode"
#define SH_OP_SIZE   sizeof(uint32_t)

char sheepfs_shadow[PATH_MAX];

static int sheepfs_debug;
static int sheepfs_fg;
int sheepfs_page_cache;
int sheepfs_object_cache = true;
char sdhost[32] = "127.0.0.1";
int sdport = SD_LISTEN_PORT;

static struct option const long_options[] = {
	{"address", required_argument, NULL, 'a'},
	{"debug", no_argument, NULL, 'd'},
	{"help", no_argument, NULL, 'h'},
	{"foreground", no_argument, NULL, 'f'},
	{"pagecache", no_argument, NULL, 'k'},
	{"noobjectcache", no_argument, NULL, 'n'},
	{"port", required_argument, NULL, 'p'},
	{NULL, 0, NULL, 0},
};

static const char *short_options = "a:dfhknp:";

static struct sheepfs_file_operation {
	int (*read)(const char *path, char *buf, size_t size, off_t);
	int (*write)(const char *path, const char *buf, size_t size, off_t);
	size_t (*get_size)(const char *path);
	int (*sync)(const char *path);
	int (*open)(const char *paht, struct fuse_file_info *);
} sheepfs_file_ops[] = {
	[OP_NULL]           = { NULL, NULL, NULL },
	[OP_CLUSTER_INFO]   = { cluster_info_read, NULL,
				cluster_info_get_size },
	[OP_VDI_LIST]       = { vdi_list_read, NULL, vdi_list_get_size },
	[OP_VDI_MOUNT]      = { NULL, vdi_mount_write },
	[OP_VDI_UNMOUNT]    = { NULL, vdi_unmount_write },
	[OP_NODE_INFO]      = { node_info_read, NULL, node_info_get_size },
	[OP_NODE_LIST]      = { node_list_read, NULL, node_list_get_size },
	[OP_CONFIG_PCACHE]  = { config_pcache_read, config_pcache_write,
				config_pcache_get_size },
	[OP_CONFIG_OCACHE]  = { config_ocache_read, config_ocache_write,
				config_ocache_get_size },
	[OP_CONFIG_SHEEP]   = { config_sheep_info_read,
				config_sheep_info_write,
				config_sheep_info_get_size },
	[OP_VOLUME]         = { volume_read, volume_write, volume_get_size,
				volume_sync, volume_open },
};

__printf(3, 4)
static void fg_printf(const char *func, int line, const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s(%d): ", func, line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

__printf(3, 4)
static void bg_printf(const char *func, int line, const char *fmt, ...)
{
	va_list ap;

	syslog(LOG_ERR, "%s(%d)", func, line);
	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);
}

printf_fn fs_printf = bg_printf;

int sheepfs_set_op(const char *path, unsigned opcode)
{
	if (shadow_file_setxattr(path, SH_OP_NAME, &opcode, SH_OP_SIZE) < 0) {
		shadow_file_delete(path);
		return -1;
	}
	return 0;
}

static unsigned sheepfs_get_op(const char *path)
{
	unsigned opcode = 0;

	/* If fail, we simply return 0 to run NULL operation */
	shadow_file_getxattr(path, SH_OP_NAME, &opcode, SH_OP_SIZE);

	return opcode;
}

static size_t sheepfs_get_size(const char *path)
{
	unsigned op = sheepfs_get_op(path);

	if (sheepfs_file_ops[op].get_size)
		return sheepfs_file_ops[op].get_size(path);

	return 0;
}

static int sheepfs_getattr(const char *path, struct stat *st)
{
	struct strbuf p = STRBUF_INIT;
	int ret;

	strbuf_addf(&p, "%s%s", sheepfs_shadow, path);
	ret = stat(p.buf, st);
	if (ret < 0) {
		ret = -errno;
		goto out;
	}
	if (S_ISREG(st->st_mode))
		st->st_size = sheepfs_get_size(path);
out:
	strbuf_release(&p);
	return ret;
}

static int sheepfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			   off_t offset, struct fuse_file_info *fi)
{
	DIR *dir;
	struct dirent *dentry;
	struct strbuf p = STRBUF_INIT;
	int ret = 0;

	strbuf_addf(&p, "%s%s", sheepfs_shadow, path);
	dir = opendir(p.buf);
	if (!dir) {
		ret = -errno;
		sheepfs_pr("%m\n");
		goto out;
	}

	while ((dentry = readdir(dir))) {
		if (filler(buf, dentry->d_name, NULL, 0) != 0) {
			sheepfs_pr("out of memory\n");
			ret = -ENOMEM;
			goto out;
		}
	}

out:
	strbuf_release(&p);
	return ret;
}

static int sheepfs_read(const char *path, char *buf, size_t size,
			off_t offset, struct fuse_file_info *fi)
{
	int ret = 0;
	unsigned op = sheepfs_get_op(path);

	if (sheepfs_file_ops[op].read)
		ret = sheepfs_file_ops[op].read(path, buf, size, offset);

	return ret;
}

static int sheepfs_write(const char *path, const char *buf, size_t size,
			 off_t offset, struct fuse_file_info *fi)
{
	int ret = 0;
	unsigned op = sheepfs_get_op(path);

	if (sheepfs_file_ops[op].write)
		ret = sheepfs_file_ops[op].write(path, buf, size, offset);

	return ret;
}

static int sheepfs_truncate(const char *path, off_t size)
{
	struct strbuf p = STRBUF_INIT;
	int ret = 0, fd;

	strbuf_addf(&p, "%s%s", sheepfs_shadow, path);
	fd = open(p.buf, O_RDWR);
	if (fd < 0)
		ret = -ENOENT;
	else
		close(fd);

	strbuf_release(&p);
	return ret;
}

static int sheepfs_fsync(const char *path, int datasync,
			 struct fuse_file_info *fi)
{
	int ret = 0;
	unsigned op = sheepfs_get_op(path);

	if (sheepfs_file_ops[op].sync)
		ret = sheepfs_file_ops[op].sync(path);

	return ret;
}

static int sheepfs_open(const char *path, struct fuse_file_info *fi)
{
	int ret = 0;
	unsigned op = sheepfs_get_op(path);

	if (sheepfs_file_ops[op].open)
		ret = sheepfs_file_ops[op].open(path, fi);

	return ret;
}

static struct fuse_operations sheepfs_ops =  {
	.getattr  = sheepfs_getattr,
	.readdir  = sheepfs_readdir,
	.truncate = sheepfs_truncate,
	.read     = sheepfs_read,
	.write    = sheepfs_write,
	.fsync    = sheepfs_fsync,
	.open     = sheepfs_open,
};

static int sheepfs_main_loop(char *mountpoint)
{
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	int ret = -1;

	fuse_opt_add_arg(&args, "sheepfs"); /* placeholder for argv[0] */
	fuse_opt_add_arg(&args, "-oallow_root");
	fuse_opt_add_arg(&args, "-obig_writes");
	fuse_opt_add_arg(&args, "-okernel_cache");
	fuse_opt_add_arg(&args, "-ofsname=sheepfs");
	fuse_opt_add_arg(&args, mountpoint);
	if (sheepfs_debug)
		fuse_opt_add_arg(&args, "-odebug");
	if (sheepfs_fg)
		fuse_opt_add_arg(&args, "-f");

	sheepfs_pr("sheepfs daemon started\n");
	ret = fuse_main(args.argc, args.argv, &sheepfs_ops, NULL);
	rmdir_r(sheepfs_shadow);
	sheepfs_pr("sheepfs daemon exited %d\n", ret);
	return ret;
}

static int create_sheepfs_layout(void)
{
	if (create_cluster_layout() < 0)
		return -1;
	if (create_vdi_layout() < 0)
		return -1;
	if (create_volume_layout() < 0)
		return -1;
	if (create_node_layout() < 0)
		return -1;
	if (create_config_layout() < 0)
		return -1;

	return 0;
}

static void usage(int inval)
{
	if (inval)
		fprintf(stderr, "Try 'sheepfs --help' for help.\n");
	else
		printf("\
Usage: sheepfs [OPTION]... MOUNTPOINT\n\
Options:\n\
  -a, --address           specify the sheep address (default: localhost)\n\
  -d, --debug             enable debug output (implies -f)\n\
  -f, --foreground        sheepfs run in the foreground\n\
  -k, --pagecache         use local kernel's page cache to access volume\n\
  -n, --noobjectcache     disable object cache of the attached volumes\n\
  -p, --port              specify the sheep port (default: 7000)\n\
  -h, --help              display this help and exit\n\
");
	exit(inval);
}

int main(int argc, char **argv)
{
	struct strbuf path = STRBUF_INIT;
	int ch, longindex;
	char *dir = NULL, *cwd;


	while ((ch = getopt_long(argc, argv, short_options, long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'a':
			memcpy(sdhost, optarg, strlen(optarg));
			break;
		case 'd':
			sheepfs_debug = true;
			break;
		case 'h':
			usage(0);
			break;
		case 'f':
			sheepfs_fg = true;
			fs_printf = fg_printf;
			break;
		case 'k':
			sheepfs_page_cache = true;
			break;
		case 'n':
			sheepfs_object_cache = false;
			break;
		case 'p':
			sdport = strtol(optarg, NULL, 10);
			if (sdport < 1 || sdport > UINT16_MAX) {
				fprintf(stderr,
					"Invalid port number '%s'\n", optarg);
				exit(1);
			}
			break;
		default:
			usage(1);
		}
	}

	if (optind != argc)
		dir = argv[optind];
	else
		usage(1);

	cwd = get_current_dir_name();
	if (!cwd) {
		fprintf(stderr, "%m\n");
		exit(1);
	}
	strbuf_addf(&path, "%s/%s", cwd, ".sheepfs");
	free(cwd);
	memcpy(sheepfs_shadow, path.buf, path.len);
	if (xmkdir(sheepfs_shadow, 0755) < 0) {
		fprintf(stderr, "%m\n");
		exit(1);
	}

	strbuf_release(&path);
	if (create_sheepfs_layout() < 0)
		fprintf(stderr, "failed to create sheepfs layout\n");

	if (!sheepfs_fg)
		openlog("sheepfs", LOG_CONS | LOG_PID, LOG_DAEMON);

	return sheepfs_main_loop(dir);
}

struct strbuf *sheepfs_run_cmd(const char *command)
{
	struct strbuf *buf = xmalloc(sizeof(*buf));
	FILE *f = popen(command, "re");

	if (!f) {
		sheepfs_pr("popen failed\n");
		goto err;
	}

	strbuf_init(buf, 4096);

	while (!feof(f))
		strbuf_fread(buf, 4096, f);

	pclose(f);
	return buf;
err:
	strbuf_release(buf);
	pclose(f);
	free(buf);
	return NULL;
}
