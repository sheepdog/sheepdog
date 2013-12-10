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

#define MD_DEFAULT_VDISKS 128
#define MD_MAX_VDISK (MD_MAX_DISK * MD_DEFAULT_VDISKS)

struct disk {
	char path[PATH_MAX];
	uint16_t nr_vdisks;
	uint64_t space;
};

struct vdisk {
	uint16_t idx;
	uint64_t id;
};

static struct disk md_disks[MD_MAX_DISK];
static struct vdisk md_vds[MD_MAX_VDISK];

static struct sd_lock md_lock = SD_LOCK_INITIALIZER;
static int md_nr_disks; /* Protected by md_lock */
static int md_nr_vds;

static inline int nr_online_disks(void)
{
	int nr;

	sd_read_lock(&md_lock);
	nr = md_nr_disks;
	sd_unlock(&md_lock);

	return nr;
}

static struct vdisk *oid_to_vdisk_from(struct vdisk *vds, int nr, uint64_t oid)
{
	uint64_t id = fnv_64a_buf(&oid, sizeof(oid), FNV1A_64_INIT);
	int start, end, pos;

	start = 0;
	end = nr - 1;

	if (id > vds[end].id || id < vds[start].id)
		return &vds[start];

	for (;;) {
		pos = (end - start) / 2 + start;
		if (vds[pos].id < id) {
			if (vds[pos + 1].id >= id)
				return &vds[pos + 1];
			start = pos;
		} else
			end = pos;
	}
}

static int vdisk_cmp(const struct vdisk *d1, const struct vdisk *d2)
{
	return intcmp(d1->id, d2->id);
}

static inline int disks_to_vdisks(struct disk *ds, int nmds, struct vdisk *vds)
{
	struct disk *d_iter = ds;
	int i, j, nr_vdisks = 0;
	uint64_t hval;

	while (nmds--) {
		hval = FNV1A_64_INIT;

		for (i = 0; i < d_iter->nr_vdisks; i++) {
			hval = fnv_64a_buf(&nmds, sizeof(nmds), hval);
			for (j = strlen(d_iter->path) - 1; j >= 0; j--)
				hval = fnv_64a_buf(&d_iter->path[j], 1, hval);

			vds[nr_vdisks].id = hval;
			vds[nr_vdisks].idx = d_iter - ds;

			nr_vdisks++;
		}

		d_iter++;
	}
	xqsort(vds, nr_vdisks, vdisk_cmp);

	return nr_vdisks;
}

static inline struct vdisk *oid_to_vdisk(uint64_t oid)
{
	return oid_to_vdisk_from(md_vds, md_nr_vds, oid);
}

static inline void trim_last_slash(char *path)
{
	assert(path[0]);
	while (path[strlen(path) - 1] == '/')
		path[strlen(path) - 1] = '\0';
}

static int path_to_disk_idx(char *path)
{
	int i;

	trim_last_slash(path);
	for (i = 0; i < md_nr_disks; i++)
		if (strcmp(md_disks[i].path, path) == 0)
			return i;

	return -1;
}

bool md_add_disk(char *path)
{
	if (path_to_disk_idx(path) != -1) {
		sd_err("duplicate path %s", path);
		return false;
	}

	if (xmkdir(path, sd_def_dmode) < 0) {
		sd_err("can't mkdir for %s, %m", path);
		return false;
	}

	md_nr_disks++;

	pstrcpy(md_disks[md_nr_disks - 1].path, PATH_MAX, path);
	sd_info("%s, nr %d", md_disks[md_nr_disks - 1].path, md_nr_disks);
	return true;
}

static inline void calculate_vdisks(struct disk *disks, int nr_disks,
				    uint64_t total)
{
	uint64_t avg_size = total / nr_disks;
	float factor;
	int i;

	for (i = 0; i < nr_disks; i++) {
		factor = (float)disks[i].space / (float)avg_size;
		md_disks[i].nr_vdisks = rintf(MD_DEFAULT_VDISKS * factor);
		sd_debug("%s has %d vdisks, free space %" PRIu64,
			 md_disks[i].path, md_disks[i].nr_vdisks,
			 md_disks[i].space);
	}
}

#define MDNAME	"user.md.size"
#define MDSIZE	sizeof(uint64_t)

static int get_total_object_size(uint64_t oid, char *wd, uint32_t epoch,
				 void *total)
{
	uint64_t *t = total;
	struct stat s;
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "%s/%016" PRIx64, wd, oid);
	if (stat(path, &s) == 0)
		*t += s.st_blocks * SECTOR_SIZE;
	else
		*t += get_objsize(oid);

	return SD_RES_SUCCESS;
}

/* If cleanup is true, temporary objects will be removed */
static int for_each_object_in_path(char *path,
				   int (*func)(uint64_t, char *, uint32_t,
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

static uint64_t get_path_free_size(char *path, uint64_t *used)
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
static uint64_t init_path_space(char *path)
{
	uint64_t size;
	char stale[PATH_MAX];

	if (!is_xattr_enabled(path)) {
		sd_info("multi-disk support need xattr feature");
		goto broken_path;
	}

	snprintf(stale, PATH_MAX, "%s/.stale", path);
	if (xmkdir(stale, sd_def_dmode) < 0) {
		sd_err("can't mkdir for %s, %m", stale);
		goto broken_path;
	}

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

static inline void md_remove_disk(int idx)
{
	int i;

	sd_info("%s from multi-disk array", md_disks[idx].path);
	/*
	 * We need to keep last disk path to generate EIO when all disks are
	 * broken
	 */
	for (i = idx; i < md_nr_disks - 1; i++)
		md_disks[i] = md_disks[i + 1];

	md_nr_disks--;
}

uint64_t md_init_space(void)
{
	uint64_t total;
	int i;

reinit:
	if (!md_nr_disks)
		return 0;
	total = 0;

	for (i = 0; i < md_nr_disks; i++) {
		md_disks[i].space = init_path_space(md_disks[i].path);
		if (!md_disks[i].space) {
			md_remove_disk(i);
			goto reinit;
		}
		total += md_disks[i].space;
	}
	calculate_vdisks(md_disks, md_nr_disks, total);
	md_nr_vds = disks_to_vdisks(md_disks, md_nr_disks, md_vds);

	return total;
}

char *md_get_object_path(uint64_t oid)
{
	struct vdisk *vd;
	char *p;

	sd_read_lock(&md_lock);
	vd = oid_to_vdisk(oid);
	p = md_disks[vd->idx].path;
	sd_unlock(&md_lock);
	sd_debug("%d, %s", vd->idx, p);

	return p;
}

static char *md_get_object_path_nolock(uint64_t oid)
{
	struct vdisk *vd;

	vd = oid_to_vdisk(oid);
	return md_disks[vd->idx].path;
}

int for_each_object_in_wd(int (*func)(uint64_t oid, char *path, uint32_t epoch,
				      void *arg),
			  bool cleanup, void *arg)
{
	int i, ret = SD_RES_SUCCESS;

	sd_read_lock(&md_lock);
	for (i = 0; i < md_nr_disks; i++) {
		ret = for_each_object_in_path(md_disks[i].path, func,
					      cleanup, arg);
		if (ret != SD_RES_SUCCESS)
			break;
	}
	sd_unlock(&md_lock);
	return ret;
}

int for_each_object_in_stale(int (*func)(uint64_t oid, char *path,
					 uint32_t epoch, void *arg),
			     void *arg)
{
	int i, ret = SD_RES_SUCCESS;
	char path[PATH_MAX];

	sd_read_lock(&md_lock);
	for (i = 0; i < md_nr_disks; i++) {
		snprintf(path, sizeof(path), "%s/.stale", md_disks[i].path);
		ret = for_each_object_in_path(path, func, false, arg);
		if (ret != SD_RES_SUCCESS)
			break;
	}
	sd_unlock(&md_lock);
	return ret;
}


int for_each_obj_path(int (*func)(char *path))
{
	int i, ret = SD_RES_SUCCESS;

	sd_read_lock(&md_lock);
	for (i = 0; i < md_nr_disks; i++) {
		ret = func(md_disks[i].path);
		if (ret != SD_RES_SUCCESS)
			break;
	}
	sd_unlock(&md_lock);
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
	int idx, nr = 0;

	sd_write_lock(&md_lock);
	idx = path_to_disk_idx(mw->path);
	if (idx < 0)
		/* Just ignore the duplicate EIO of the same path */
		goto out;
	md_remove_disk(idx);
	md_init_space();
	nr = md_nr_disks;
out:
	sd_unlock(&md_lock);

	if (nr > 0)
		kick_recover();

	free(mw);
}

int md_handle_eio(char *fault_path)
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

static inline bool md_access(char *path)
{
	if (access(path, R_OK | W_OK) < 0) {
		if (unlikely(errno != ENOENT))
			sd_err("failed to check %s, %m", path);
		return false;
	}

	return true;
}

static int get_old_new_path(uint64_t oid, uint32_t epoch, char *path,
			    char *old, char *new)
{
	if (!epoch) {
		snprintf(old, PATH_MAX, "%s/%016" PRIx64, path, oid);
		snprintf(new, PATH_MAX, "%s/%016" PRIx64,
			 md_get_object_path_nolock(oid), oid);
	} else {
		snprintf(old, PATH_MAX, "%s/.stale/%016"PRIx64".%"PRIu32, path,
			 oid, epoch);
		snprintf(new, PATH_MAX, "%s/.stale/%016"PRIx64".%"PRIu32,
			 md_get_object_path_nolock(oid), oid, epoch);
	}

	if (!md_access(old))
		return -1;

	return 0;
}

static int md_move_object(uint64_t oid, char *old, char *new)
{
	struct strbuf buf = STRBUF_INIT;
	int fd, ret = -1;
	size_t sz = get_objsize(oid);

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

static int md_check_and_move(uint64_t oid, uint32_t epoch, char *path)
{
	char old[PATH_MAX], new[PATH_MAX];

	if (get_old_new_path(oid, epoch, path, old, new) < 0)
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
	int i, ret = SD_RES_EIO;

	sd_read_lock(&md_lock);
	for (i = 0; i < md_nr_disks; i++) {
		ret = md_check_and_move(oid, epoch, md_disks[i].path);
		if (ret == SD_RES_SUCCESS)
			break;
	}
	sd_unlock(&md_lock);
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

int md_get_stale_path(uint64_t oid, uint32_t epoch, char *path)
{
	snprintf(path, PATH_MAX, "%s/.stale/%016"PRIx64".%"PRIu32,
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
	int i;

	memset(info, 0, ret);
	sd_read_lock(&md_lock);
	for (i = 0; i < md_nr_disks; i++) {
		info->disk[i].idx = i;
		pstrcpy(info->disk[i].path, PATH_MAX, md_disks[i].path);
		/* FIXME: better handling failure case. */
		info->disk[i].free = get_path_free_size(info->disk[i].path,
							&info->disk[i].used);
	}
	info->nr = md_nr_disks;
	sd_unlock(&md_lock);
	return ret;
}

static inline void md_del_disk(char *path)
{
	int idx = path_to_disk_idx(path);

	if (idx < 0) {
		sd_err("invalid path %s", path);
		return;
	}
	md_remove_disk(idx);
}

static int do_plug_unplug(char *disks, bool plug)
{
	char *path;
	int old_nr, cur_nr = 0, ret = SD_RES_UNKNOWN;

	sd_write_lock(&md_lock);
	old_nr = md_nr_disks;
	path = strtok(disks, ",");
	do {
		if (plug) {
			if (md_add_disk(path) && purge_directory(path) < 0)
				md_del_disk(path);
		} else {
			md_del_disk(path);
		}
	} while ((path = strtok(NULL, ",")));

	/* If no disks change, bail out */
	if (old_nr == md_nr_disks)
		goto out;

	md_init_space();
	cur_nr = md_nr_disks;

	ret = SD_RES_SUCCESS;
out:
	sd_unlock(&md_lock);

	/*
	 * We have to kick recover aggressively because there is possibility
	 * that nr of disks are removed during md_init_space() happens to equal
	 * nr of disks we added.
	 */
	if (cur_nr > 0 && ret == SD_RES_SUCCESS)
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
	*used = 0;

	sd_read_lock(&md_lock);
	for (int i = 0; i < md_nr_disks; i++)
		fsize += get_path_free_size(md_disks[i].path, used);
	sd_unlock(&md_lock);

	return fsize + *used;
}
