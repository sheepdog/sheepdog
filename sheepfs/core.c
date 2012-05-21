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
#include <attr/xattr.h>
#include <dirent.h>
#include <pthread.h>
#include <getopt.h>
#include <syslog.h>

#include "strbuf.h"
#include "util.h"
#include "sheepfs.h"

#define SH_OP_NAME   "user.sheepfs.opcode"
#define SH_OP_SIZE   sizeof(uint32_t)

char sheepfs_shadow[PATH_MAX];

static int sheepfs_debug;
static int sheepfs_fg;

static struct option const long_options[] = {
	{"debug", no_argument, NULL, 'd'},
	{"help", no_argument, NULL, 'h'},
	{"foreground", no_argument, NULL, 'f'},
	{NULL, 0, NULL, 0},
};

static const char *short_options = "dhf";

static struct sheepfs_file_operation {
	int (*read)(const char *path, char *buf, size_t size, off_t);
	int (*write)(const char *path, const char *buf, size_t size, off_t);
	size_t (*get_size)(const char *path);
	int (*sync)(const char *path);
} sheepfs_file_ops[] = {
	[OP_NULL]         = { NULL, NULL, NULL },
	[OP_CLUSTER_INFO] = { cluster_info_read, NULL, cluster_info_get_size },
	[OP_VDI_LIST]     = { vdi_list_read, NULL, vdi_list_get_size },
	[OP_VDI_MOUNT]    = { NULL, vdi_mount_write, NULL },
	[OP_VOLUME]       = { volume_read, volume_write, volume_get_size,
			      volume_sync },
};

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
		syslog(LOG_ERR, "[%s] %m\n", __func__);
		goto out;
	}

	while ((dentry = readdir(dir))) {
		if (filler(buf, dentry->d_name, NULL, 0) != 0) {
			syslog(LOG_ERR, "[%s] out of memory\n", __func__);
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

struct fuse_operations sheepfs_ops =  {
	.getattr  = sheepfs_getattr,
	.readdir  = sheepfs_readdir,
	.truncate = sheepfs_truncate,
	.read     = sheepfs_read,
	.write    = sheepfs_write,
	.fsync    = sheepfs_fsync,
};

static int sheepfs_main_loop(char *mountpoint)
{
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	int ret = -1;

	fuse_opt_add_arg(&args, "sheepfs"); /* placeholder for argv[0] */
	fuse_opt_add_arg(&args, "-oallow_root");
	fuse_opt_add_arg(&args, "-obig_writes");
	fuse_opt_add_arg(&args, "-ofsname=sheepfs");
	fuse_opt_add_arg(&args, mountpoint);
	if (sheepfs_debug)
		fuse_opt_add_arg(&args, "-odebug");
	if (sheepfs_fg)
		fuse_opt_add_arg(&args, "-f");

	syslog(LOG_INFO, "sheepfs daemon started\n");
	ret = fuse_main(args.argc, args.argv, &sheepfs_ops, NULL);
	rmdir_r(sheepfs_shadow);
	syslog(LOG_INFO, "sheepfs daemon exited %d\n", ret);
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
  -d, --debug             enable debug output (implies -f)\n\
  -f, --foreground        sheepfs run in the foreground\n\
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
		case 'd':
			sheepfs_debug = 1;
			break;
		case 'h':
			usage(0);
			break;
		case 'f':
			sheepfs_fg = 1;
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
	if (mkdir(sheepfs_shadow, 0755) < 0) {
		if (errno != EEXIST) {
			fprintf(stderr, "%m\n");
			exit(1);
		}
	}

	strbuf_release(&path);
	if (create_sheepfs_layout() < 0)
		fprintf(stderr, "failed to create sheepfs layout\n");

	openlog("sheepfs", LOG_CONS | LOG_PID, LOG_DAEMON);

	return sheepfs_main_loop(dir);
}

struct strbuf *sheepfs_run_cmd(const char *command)
{
	struct strbuf *buf = xmalloc(sizeof(*buf));
	FILE *f = popen(command, "re");

	if (!f) {
		syslog(LOG_ERR, "[%s] popen failed\n", __func__);
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
