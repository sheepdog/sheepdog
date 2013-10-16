/*
 * Copyright (C) 2013 Taobao Inc.
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

#include "sheep_priv.h"

#define MD_VDISK_SIZE ((uint64_t)1*1024*1024*1024) /* 1G */

#define NONE_EXIST_PATH "/all/disks/are/broken/,ps/əʌo7/!"

struct disk {
	struct rb_node rb;
	char path[PATH_MAX];
	uint64_t space;
};

struct vdisk {
	struct rb_node rb;
	struct disk *disk;
	uint64_t hash;
};

struct md {
	struct rb_root vroot;
	struct rb_root root;
	struct sd_lock lock;
	uint64_t space;
	uint32_t nr_disks;
};

static struct md md = {
	.vroot = RB_ROOT,
	.root = RB_ROOT,
	.lock = SD_LOCK_INITIALIZER,
};

static inline int nr_online_disks(void)
{
	int nr;

	sd_read_lock(&md.lock);
	nr = md.nr_disks;
	sd_unlock(&md.lock);

	return nr;
}

static inline int vdisk_number(const struct disk *disk)
{
	return DIV_ROUND_UP(disk->space, MD_VDISK_SIZE);
}

static int disk_cmp(const struct disk *d1, const struct disk *d2)
{
	return strcmp(d1->path, d2->path);
}

static int vdisk_cmp(const struct vdisk *d1, const struct vdisk *d2)
{
	return intcmp(d1->hash, d2->hash);
}

static struct vdisk *vdisk_insert(struct vdisk *new)
{
	return rb_insert(&md.vroot, new, rb, vdisk_cmp);
}

/* If v1_hash < hval <= v2_hash, then oid is resident in v2 */
static struct vdisk *hval_to_vdisk(uint64_t hval)
{
	struct vdisk dummy = { .hash = hval };

	return rb_nsearch(&md.vroot, &dummy, rb, vdisk_cmp);
}

static struct vdisk *oid_to_vdisk(uint64_t oid)
{
	return hval_to_vdisk(sd_hash_oid(oid));
}

static void create_vdisks(struct disk *disk)
{
	uint64_t hval = sd_hash(disk->path, strlen(disk->path));
	int nr = vdisk_number(disk);

	for (int i = 0; i < nr; i++) {
		struct vdisk *v = xmalloc(sizeof(*v));

		hval = sd_hash_next(hval);
		v->hash = hval;
		v->disk = disk;
		if (unlikely(vdisk_insert(v)))
			panic("vdisk hash collison");
	}
}

static inline void vdisk_free(struct vdisk *v)
{
	rb_erase(&v->rb, &md.vroot);
	free(v);
}

static void remove_vdisks(const struct disk *disk)
{
	uint64_t hval = sd_hash(disk->path, strlen(disk->path));
	int nr = vdisk_number(disk);

	for (int i = 0; i < nr; i++) {
		struct vdisk *v;

		hval = sd_hash_next(hval);
		v = hval_to_vdisk(hval);
		assert(v->hash == hval);

		vdisk_free(v);
	}
}

static inline void trim_last_slash(char *path)
{
	assert(path[0]);
	while (path[strlen(path) - 1] == '/')
		path[strlen(path) - 1] = '\0';
}

static struct disk *path_to_disk(const char *path)
{
	struct disk key = {};

	pstrcpy(key.path, sizeof(key.path), path);
	trim_last_slash(key.path);

	return rb_search(&md.root, &key, rb, disk_cmp);
}

static int get_total_object_size(uint64_t oid, const char *wd, uint32_t epoch,
				 void *total)
{
	uint64_t *t = total;
	struct stat s;
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "%s/%016" PRIx64, wd, oid);
	if (stat(path, &s) == 0)
		*t += s.st_blocks * SECTOR_SIZE;
	else
		*t += get_store_objsize(oid);

	return SD_RES_SUCCESS;
}

/* If cleanup is true, temporary objects will be removed */
static int for_each_object_in_path(const char *path,
				   int (*func)(uint64_t, const char *, uint32_t,
					       void *),
				   bool cleanup, void *arg)
{
	DIR *dir;
	struct dirent *d;
	uint64_t oid;
	int ret = SD_RES_SUCCESS;
	char p[PATH_MAX];

	dir = opendir(path);
	if (unlikely(!dir)) {
		sd_err("failed to open %s, %m", path);
		return SD_RES_EIO;
	}

	while ((d = readdir(dir))) {
		uint32_t epoch = 0;

		if (unlikely(!strncmp(d->d_name, ".", 1)))
			continue;

		oid = strtoull(d->d_name, NULL, 16);
		if (oid == 0 || oid == ULLONG_MAX)
			continue;

		/* don't call callback against temporary objects */
		if (strlen(d->d_name) == 20 &&
		    strcmp(d->d_name + 16, ".tmp") == 0) {
			if (cleanup) {
				snprintf(p, PATH_MAX, "%s/%016"PRIx64".tmp",
					 path, oid);
				sd_debug("remove tmp object %s", p);
				unlink(p);
			}
			continue;
		}

		if (strlen(d->d_name) > 17 && d->d_name[16] == '.')
			epoch = strtoul(d->d_name + 17, NULL, 10);

		ret = func(oid, path, epoch, arg);
		if (ret != SD_RES_SUCCESS)
			break;
	}
	closedir(dir);
	return ret;
}

static uint64_t get_path_free_size(const char *path, uint64_t *used)
{
	struct statvfs fs;
	uint64_t size;

	if (statvfs(path, &fs) < 0) {
		sd_err("get disk %s space failed %m", path);
		return 0;
	}
	size = (int64_t)fs.f_frsize * fs.f_bavail;

	if (!used)
		goto out;
	if (for_each_object_in_path(path, get_total_object_size, false, used)
	    != SD_RES_SUCCESS)
		return 0;
out:
	return size;
}

/*
 * If path is broken during initilization or not support xattr return 0. We can
 * safely use 0 to represent failure case  because 0 space path can be
 * considered as broken path.
 */
static uint64_t init_path_space(const char *path, bool purge)
{
	uint64_t size;
	char stale[PATH_MAX];

	if (!is_xattr_enabled(path)) {
		sd_info("multi-disk support need xattr feature");
		goto broken_path;
	}

	if (purge && purge_directory(path) < 0)
		sd_err("failed to purge %s", path);

	snprintf(stale, PATH_MAX, "%s/.stale", path);
	if (xmkdir(stale, sd_def_dmode) < 0) {
		sd_err("can't mkdir for %s, %m", stale);
		goto broken_path;
	}

#define MDNAME	"user.md.size"
#define MDSIZE	sizeof(uint64_t)
	if (getxattr(path, MDNAME, &size, MDSIZE) < 0) {
		if (errno == ENODATA) {
			goto create;
		} else {
			sd_err("%s, %m", path);
			goto broken_path;
		}
	}

	return size;
create:
	size = get_path_free_size(path, NULL);
	if (!size)
		goto broken_path;
	if (setxattr(path, MDNAME, &size, MDSIZE, 0) < 0) {
		sd_err("%s, %m", path);
		goto broken_path;
	}
	return size;
broken_path:
	return 0;
}

/* We don't need lock at init stage */
bool md_add_disk(const char *path, bool purge)
{
	struct disk *new;

	if (path_to_disk(path)) {
		sd_err("duplicate path %s", path);
		return false;
	}

	if (xmkdir(path, sd_def_dmode) < 0) {
		sd_err("can't mkdir for %s, %m", path);
		return false;
	}

	new = xmalloc(sizeof(*new));
	pstrcpy(new->path, PATH_MAX, path);
	new->space = init_path_space(new->path, purge);
	if (!new->space) {
		free(new);
		return false;
	}

	create_vdisks(new);
	rb_insert(&md.root, new, rb, disk_cmp);
	md.space += new->space;
	md.nr_disks++;

	sd_info("%s, vdisk nr %d, total disk %d", new->path, vdisk_number(new),
		md.nr_disks);
	return true;
}

static inline void md_remove_disk(struct disk *disk)
{
	sd_info("%s from multi-disk array", disk->path);
	rb_erase(&disk->rb, &md.root);
	md.nr_disks--;
	remove_vdisks(disk);
	free(disk);
}

uint64_t md_init_space(void)
{
	return md.space;
}

static const char *md_get_object_path_nolock(uint64_t oid)
{
	const struct vdisk *vd;

	if (unlikely(md.nr_disks == 0))
		return NONE_EXIST_PATH; /* To generate EIO */

	vd = oid_to_vdisk(oid);
	return vd->disk->path;
}

const char *md_get_object_path(uint64_t oid)
{
	const char *p;

	sd_read_lock(&md.lock);
	p = md_get_object_path_nolock(oid);
	sd_unlock(&md.lock);

	return p;
}

int for_each_object_in_wd(int (*func)(uint64_t oid, const char *path,
				      uint32_t epoch, void *arg),
			  bool cleanup, void *arg)
{
	int ret = SD_RES_SUCCESS;
	const struct disk *disk;

	sd_read_lock(&md.lock);
	rb_for_each_entry(disk, &md.root, rb) {
		ret = for_each_object_in_path(disk->path, func, cleanup, arg);
		if (ret != SD_RES_SUCCESS)
			break;
	}
	sd_unlock(&md.lock);
	return ret;
}

int for_each_object_in_stale(int (*func)(uint64_t oid, const char *path,
					 uint32_t epoch, void *arg),
			     void *arg)
{
	int ret = SD_RES_SUCCESS;
	char path[PATH_MAX];
	const struct disk *disk;

	sd_read_lock(&md.lock);
	rb_for_each_entry(disk, &md.root, rb) {
		snprintf(path, sizeof(path), "%s/.stale", disk->path);
		ret = for_each_object_in_path(path, func, false, arg);
		if (ret != SD_RES_SUCCESS)
			break;
	}
	sd_unlock(&md.lock);
	return ret;
}


int for_each_obj_path(int (*func)(const char *path))
{
	int ret = SD_RES_SUCCESS;
	const struct disk *disk;

	sd_read_lock(&md.lock);
	rb_for_each_entry(disk, &md.root, rb) {
		ret = func(disk->path);
		if (ret != SD_RES_SUCCESS)
			break;
	}
	sd_unlock(&md.lock);
	return ret;
}

struct md_work {
	struct work work;
	char path[PATH_MAX];
};

static inline void kick_recover(void)
{
	struct vnode_info *vinfo = get_vnode_info();

	start_recovery(vinfo, vinfo, false);
	put_vnode_info(vinfo);
}

static void md_do_recover(struct work *work)
{
	struct md_work *mw = container_of(work, struct md_work, work);
	struct disk *disk;
	int nr = 0;

	sd_write_lock(&md.lock);
	disk = path_to_disk(mw->path);
	if (!disk)
		/* Just ignore the duplicate EIO of the same path */
		goto out;
	md_remove_disk(disk);
	nr = md.nr_disks;
out:
	sd_unlock(&md.lock);

	if (nr > 0)
		kick_recover();

	free(mw);
}

int md_handle_eio(const char *fault_path)
{
	struct md_work *mw;

	if (nr_online_disks() == 0)
		return SD_RES_EIO;

	mw = xzalloc(sizeof(*mw));
	mw->work.done = md_do_recover;
	pstrcpy(mw->path, PATH_MAX, fault_path);
	queue_work(sys->md_wqueue, &mw->work);

	/* Fool the requester to retry */
	return SD_RES_NETWORK_ERROR;
}

static inline bool md_access(const char *path)
{
	if (access(path, R_OK | W_OK) < 0) {
		if (unlikely(errno != ENOENT))
			sd_err("failed to check %s, %m", path);
		return false;
	}

	return true;
}

static int get_old_new_path(uint64_t oid, uint32_t epoch, const char *path,
			    char *old, size_t old_size, char *new,
			    size_t new_size)
{
	if (!epoch) {
		snprintf(old, old_size, "%s/%016" PRIx64, path, oid);
		snprintf(new, new_size, "%s/%016" PRIx64,
			 md_get_object_path_nolock(oid), oid);
	} else {
		snprintf(old, old_size, "%s/.stale/%016"PRIx64".%"PRIu32, path,
			 oid, epoch);
		snprintf(new, new_size, "%s/.stale/%016"PRIx64".%"PRIu32,
			 md_get_object_path_nolock(oid), oid, epoch);
	}

	if (!md_access(old))
		return -1;

	return 0;
}

static int md_move_object(uint64_t oid, const char *old, const char *new)
{
	struct strbuf buf = STRBUF_INIT;
	int fd, ret = -1;
	size_t sz = get_store_objsize(oid);

	fd = open(old, O_RDONLY);
	if (fd < 0) {
		sd_err("failed to open %s", old);
		goto out;
	}

	ret = strbuf_read(&buf, fd, sz);
	if (ret != sz) {
		sd_err("failed to read %s, %d", old, ret);
		ret = -1;
		goto out_close;
	}

	if (atomic_create_and_write(new, buf.buf, buf.len, false) < 0) {
		sd_err("failed to create %s", new);
		ret = -1;
		goto out_close;
	}
	unlink(old);
	ret = 0;
out_close:
	close(fd);
out:
	strbuf_release(&buf);
	return ret;
}

static int md_check_and_move(uint64_t oid, uint32_t epoch, const char *path)
{
	char old[PATH_MAX], new[PATH_MAX];

	if (get_old_new_path(oid, epoch, path, old, sizeof(old), new,
			     sizeof(new)) < 0)
		return SD_RES_EIO;
	/*
	 * Recovery thread and main thread might try to recover the same object.
	 * Either one succeeds, the other will fail and proceed and end up
	 * trying to move the object to where it is already in place, in this
	 * case we simply return.
	 */
	if (!strcmp(old, new))
		return SD_RES_SUCCESS;

	/* We can't use rename(2) accross device */
	if (md_move_object(oid, old, new) < 0) {
		sd_err("move old %s to new %s failed", old, new);
		return SD_RES_EIO;
	}

	sd_debug("from %s to %s", old, new);
	return SD_RES_SUCCESS;
}

static int scan_wd(uint64_t oid, uint32_t epoch)
{
	int ret = SD_RES_EIO;
	const struct disk *disk;

	sd_read_lock(&md.lock);
	rb_for_each_entry(disk, &md.root, rb) {
		ret = md_check_and_move(oid, epoch, disk->path);
		if (ret == SD_RES_SUCCESS)
			break;
	}
	sd_unlock(&md.lock);
	return ret;
}

bool md_exist(uint64_t oid)
{
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "%s/%016" PRIx64, md_get_object_path(oid),
		 oid);
	if (md_access(path))
		return true;
	/*
	 * We have to iterate the WD because we don't have epoch-like history
	 * track to locate the objects for multiple disk failure. Simply do
	 * hard iteration simplify the code a lot.
	 */
	if (scan_wd(oid, 0) == SD_RES_SUCCESS)
		return true;

	return false;
}

int md_get_stale_path(uint64_t oid, uint32_t epoch, char *path, size_t size)
{
	snprintf(path, size, "%s/.stale/%016"PRIx64".%"PRIu32,
		 md_get_object_path(oid), oid, epoch);
	if (md_access(path))
		return SD_RES_SUCCESS;

	assert(epoch);
	if (scan_wd(oid, epoch) == SD_RES_SUCCESS)
		return SD_RES_SUCCESS;

	return SD_RES_NO_OBJ;
}

uint32_t md_get_info(struct sd_md_info *info)
{
	uint32_t ret = sizeof(*info);
	const struct disk *disk;
	int i = 0;

	memset(info, 0, ret);
	sd_read_lock(&md.lock);
	rb_for_each_entry(disk, &md.root, rb) {
		info->disk[i].idx = i;
		pstrcpy(info->disk[i].path, PATH_MAX, disk->path);
		/* FIXME: better handling failure case. */
		info->disk[i].free = get_path_free_size(info->disk[i].path,
							&info->disk[i].used);
		i++;
	}
	info->nr = md.nr_disks;
	sd_unlock(&md.lock);
	return ret;
}

static inline void md_del_disk(const char *path)
{
	struct disk *disk = path_to_disk(path);

	if (!disk) {
		sd_err("invalid path %s", path);
		return;
	}
	md_remove_disk(disk);
}

static int do_plug_unplug(char *disks, bool plug)
{
	const char *path;
	int old_nr, ret = SD_RES_UNKNOWN;

	sd_write_lock(&md.lock);
	old_nr = md.nr_disks;
	path = strtok(disks, ",");
	do {
		if (plug) {
			if (!md_add_disk(path, true))
				sd_err("failed to add %s", path);
		} else {
			md_del_disk(path);
		}
	} while ((path = strtok(NULL, ",")));

	/* If no disks change, bail out */
	if (old_nr == md.nr_disks)
		goto out;

	ret = SD_RES_SUCCESS;
out:
	sd_unlock(&md.lock);

	if (ret == SD_RES_SUCCESS)
		kick_recover();

	return ret;
}

int md_plug_disks(char *disks)
{
	return do_plug_unplug(disks, true);
}

int md_unplug_disks(char *disks)
{
	return do_plug_unplug(disks, false);
}

uint64_t md_get_size(uint64_t *used)
{
	uint64_t fsize = 0;
	const struct disk *disk;

	*used = 0;
	sd_read_lock(&md.lock);
	rb_for_each_entry(disk, &md.root, rb) {
		fsize += get_path_free_size(disk->path, used);
	}
	sd_unlock(&md.lock);

	return fsize + *used;
}
