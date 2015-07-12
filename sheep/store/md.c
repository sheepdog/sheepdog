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

struct md md = {
	.vroot = RB_ROOT,
	.root = RB_ROOT,
	.lock = SD_RW_LOCK_INITIALIZER,
};

static inline uint32_t nr_online_disks(void)
{
	uint32_t nr;

	sd_read_lock(&md.lock);
	nr = md.nr_disks;
	sd_rw_unlock(&md.lock);

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

static void create_vdisks(const struct disk *disk)
{
	uint64_t hval = sd_hash(disk->path, strlen(disk->path));
	const struct sd_node *n = &sys->this_node;
	uint64_t node_hval;
	int nr;

	if (is_cluster_diskmode(&sys->cinfo)) {
		node_hval = sd_hash(&n->nid, offsetof(typeof(n->nid), io_addr));
		hval = fnv_64a_64(node_hval, hval);
		nr = DIV_ROUND_UP(disk->space, WEIGHT_MIN);
		if (0 == n->nid.port)
			return;
	} else
		nr = vdisk_number(disk);

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
	const struct sd_node *n = &sys->this_node;
	uint64_t node_hval;
	int nr;

	if (is_cluster_diskmode(&sys->cinfo)) {
		node_hval = sd_hash(&n->nid, offsetof(typeof(n->nid), io_addr));
		hval = fnv_64a_64(node_hval, hval);
		nr = DIV_ROUND_UP(disk->space, WEIGHT_MIN);
	} else
		nr = vdisk_number(disk);

	for (int i = 0; i < nr; i++) {
		struct vdisk *v;

		hval = sd_hash_next(hval);
		v = hval_to_vdisk(hval);
		sd_assert(v->hash == hval);

		vdisk_free(v);
	}
}

static inline void trim_last_slash(char *path)
{
	sd_assert(path[0]);
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

size_t get_store_objsize(uint64_t oid)
{
	if (is_erasure_oid(oid)) {
		uint8_t policy = get_vdi_copy_policy(oid_to_vid(oid));
		int d;
		ec_policy_to_dp(policy, &d, NULL);
		return get_vdi_object_size(oid_to_vid(oid)) / d;
	}
	return get_objsize(oid, get_vdi_object_size(oid_to_vid(oid)));
}

static int get_total_object_size(uint64_t oid, const char *wd, uint32_t epoch,
				 uint8_t ec_index, struct vnode_info *vinfo,
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

static int64_t find_string_integer(const char *str, const char *delimiter)
{
	char *pos = strstr(str, delimiter), *p;
	int64_t ret;

	ret = strtoll(pos + 1, &p, 10);
	if (ret == LLONG_MAX || p == pos + 1) {
		sd_err("%s strtoul failed, delimiter %s, %m", str, delimiter);
		return -1;
	}

	return ret;
}

/* If cleanup is true, temporary objects will be removed */
static int for_each_object_in_path(const char *path,
				   int (*func)(uint64_t, const char *, uint32_t,
					       uint8_t, struct vnode_info *,
					       void *),
				   bool cleanup, struct vnode_info *vinfo,
				   void *arg)
{
	DIR *dir;
	struct dirent *d;
	uint64_t oid;
	int ret = SD_RES_SUCCESS;
	char file_name[PATH_MAX];

	dir = opendir(path);
	if (unlikely(!dir)) {
		sd_err("failed to open %s, %m", path);
		return SD_RES_EIO;
	}

	while ((d = readdir(dir))) {
		uint32_t epoch = 0;
		uint8_t ec_index = SD_MAX_COPIES;

		/* skip ".", ".." and ".stale" */
		if (unlikely(!strncmp(d->d_name, ".", 1)))
			continue;

		/* recursive call for tree store driver sub directories*/
		if (store_id_match(TREE_STORE)) {
			struct stat s;

			snprintf(file_name, sizeof(file_name),
				 "%s/%s", path, d->d_name);
			stat(file_name, &s);
			if (S_ISDIR(s.st_mode)) {
				ret = for_each_object_in_path(file_name,
					func, cleanup, vinfo, arg);
				continue;
			}
		}

		sd_debug("%s, %s", path, d->d_name);
		oid = strtoull(d->d_name, NULL, 16);
		if (oid == 0 || oid == ULLONG_MAX)
			continue;

		/* don't call callback against temporary objects */
		if (is_tmp_dentry(d->d_name)) {
			if (cleanup) {
				snprintf(file_name, sizeof(file_name),
						"%s/%s", path, d->d_name);
				sd_debug("remove tmp object %s", file_name);
				if (unlink(file_name) < 0)
					sd_err("failed to unlink %s: %m",
							file_name);
			}
			continue;
		}

		if (is_stale_dentry(d->d_name)) {
			epoch = find_string_integer(d->d_name, ".");
			if (epoch < 0)
				continue;
		}

		if (is_ec_dentry(d->d_name)) {
			ec_index = find_string_integer(d->d_name, "_");
			if (ec_index < 0)
				continue;
		}

		ret = func(oid, path, epoch, ec_index, vinfo, arg);
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
	if (for_each_object_in_path(path, get_total_object_size, false,
				    NULL, used)
	    != SD_RES_SUCCESS)
		return 0;
out:
	return size;
}

/*
 * If path is broken during initialization or not support xattr return 0. We can
 * safely use 0 to represent failure case  because 0 space path can be
 * considered as broken path.
 */
static uint64_t init_path_space(const char *path, bool purge)
{
	uint64_t size;
	char stale[PATH_MAX];

	if (!is_xattr_enabled(path)) {
		sd_warn("multi-disk support need xattr feature for path: %s",
			path);
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
	trim_last_slash(new->path);
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

static const char *md_get_object_dir_nolock(uint64_t oid)
{
	const struct vdisk *vd;

	if (unlikely(md.nr_disks == 0))
		return NONE_EXIST_PATH; /* To generate EIO */

	vd = oid_to_vdisk(oid);
	return vd->disk->path;
}

const char *md_get_object_dir(uint64_t oid)
{
	const char *p;

	sd_read_lock(&md.lock);
	p = md_get_object_dir_nolock(oid);
	sd_rw_unlock(&md.lock);

	return p;
}

struct process_path_arg {
	const char *path;
	struct vnode_info *vinfo;
	int (*func)(uint64_t oid, const char *, uint32_t, uint8_t,
		    struct vnode_info *, void *arg);
	bool cleanup;
	void *opaque;
	int result;
};

static void *thread_process_path(void *arg)
{
	int ret;
	struct process_path_arg *parg = (struct process_path_arg *)arg;

	ret = for_each_object_in_path(parg->path, parg->func, parg->cleanup,
				      parg->vinfo, parg->opaque);
	if (ret != SD_RES_SUCCESS)
		parg->result = ret;

	return arg;
}

main_fn int for_each_object_in_wd(int (*func)(uint64_t oid, const char *path,
				      uint32_t epoch, uint8_t ec_index,
				      struct vnode_info *vinfo, void *arg),
				  bool cleanup, void *arg)
{
	int ret = SD_RES_SUCCESS;
	const struct disk *disk;
	struct process_path_arg *thread_args, *path_arg;
	struct vnode_info *vinfo;
	void *ret_arg;
	sd_thread_t *thread_array;
	int nr_thread = 0, idx = 0;

	sd_read_lock(&md.lock);

	rb_for_each_entry(disk, &md.root, rb) {
		nr_thread++;
	}

	thread_args = xmalloc(nr_thread * sizeof(struct process_path_arg));
	thread_array = xmalloc(nr_thread * sizeof(sd_thread_t));

	vinfo = get_vnode_info();

	rb_for_each_entry(disk, &md.root, rb) {
		thread_args[idx].path = disk->path;
		thread_args[idx].vinfo = vinfo;
		thread_args[idx].func = func;
		thread_args[idx].cleanup = cleanup;
		thread_args[idx].opaque = arg;
		thread_args[idx].result = SD_RES_SUCCESS;
		ret = sd_thread_create_with_idx("foreach wd",
						thread_array + idx,
						thread_process_path,
						(void *)(thread_args + idx));
		if (ret) {
			/*
			 * If we can't create enough threads to process
			 * files, the data-consistent will be broken if
			 * we continued.
			 */
			panic("Failed to create thread for path %s",
			      disk->path);
		}
		idx++;
	}

	sd_debug("Create %d threads for all path", nr_thread);
	/* wait for all threads to exit */
	for (idx = 0; idx < nr_thread; idx++) {
		ret = sd_thread_join(thread_array[idx], &ret_arg);
		if (ret)
			sd_err("Failed to join thread");
		if (ret_arg) {
			path_arg = (struct process_path_arg *)ret_arg;
			if (path_arg->result != SD_RES_SUCCESS)
				sd_err("%s, %s", path_arg->path,
				       sd_strerror(path_arg->result));
		}
	}

	put_vnode_info(vinfo);
	sd_rw_unlock(&md.lock);

	free(thread_args);
	free(thread_array);
	return ret;
}

int for_each_object_in_stale(int (*func)(uint64_t oid, const char *path,
					 uint32_t epoch, uint8_t,
					 struct vnode_info *, void *arg),
			     void *arg)
{
	int ret = SD_RES_SUCCESS;
	char path[PATH_MAX];
	const struct disk *disk;

	sd_read_lock(&md.lock);
	rb_for_each_entry(disk, &md.root, rb) {
		snprintf(path, sizeof(path), "%s/.stale", disk->path);
		ret = for_each_object_in_path(path, func, false, NULL, arg);
		if (ret != SD_RES_SUCCESS)
			break;
	}
	sd_rw_unlock(&md.lock);
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
	sd_rw_unlock(&md.lock);
	return ret;
}

struct md_work {
	struct work work;
	char path[PATH_MAX];
};

static inline void kick_recover(void)
{
	struct vnode_info *vinfo = get_vnode_info();

	if (is_cluster_diskmode(&sys->cinfo))
		sys->cdrv->update_node(&sys->this_node);
	else {
		start_recovery(vinfo, vinfo, false, false);
		put_vnode_info(vinfo);
	}
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
	sd_rw_unlock(&md.lock);

	if (disk) {
		if (nr > 0) {
			update_node_disks();
			kick_recover();
		} else {
			leave_cluster();
		}
	}

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

static int get_old_new_path(uint64_t oid, uint32_t epoch, uint8_t ec_index,
			    const char *path, char *old, char *new)
{
	if (!epoch) {
		if (!is_erasure_oid(oid)) {
			snprintf(old, PATH_MAX, "%s/%016" PRIx64, path, oid);
			snprintf(new, PATH_MAX, "%s/%016" PRIx64,
				 md_get_object_dir_nolock(oid), oid);
		} else {
			snprintf(old, PATH_MAX, "%s/%016" PRIx64"_%d", path,
				 oid, ec_index);
			snprintf(new, PATH_MAX, "%s/%016" PRIx64"_%d",
				 md_get_object_dir_nolock(oid), oid, ec_index);
		}
	} else {
		if (!is_erasure_oid(oid)) {
			snprintf(old, PATH_MAX,
				 "%s/.stale/%016"PRIx64".%"PRIu32, path,
				 oid, epoch);
			snprintf(new, PATH_MAX,
				 "%s/.stale/%016"PRIx64".%"PRIu32,
				 md_get_object_dir_nolock(oid), oid, epoch);
		} else {
			snprintf(old, PATH_MAX,
				 "%s/.stale/%016"PRIx64"_%d.%"PRIu32, path,
				 oid, ec_index, epoch);
			snprintf(new, PATH_MAX,
				 "%s/.stale/%016"PRIx64"_%d.%"PRIu32,
				 md_get_object_dir_nolock(oid),
				 oid, ec_index, epoch);
		}
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
		sd_err("failed to read %s, size %zu, %d, %m", old, sz, ret);
		ret = -1;
		goto out_close;
	}

	if (atomic_create_and_write(new, buf.buf, buf.len, false) < 0) {
		if (errno != EEXIST) {
			sd_err("failed to create %s", new);
			ret = -1;
			goto out_close;
		}
	}
	unlink(old);
	ret = 0;
out_close:
	close(fd);
out:
	strbuf_release(&buf);
	return ret;
}

static int md_check_and_move(uint64_t oid, uint32_t epoch, uint8_t ec_index,
			     const char *path)
{
	char old[PATH_MAX], new[PATH_MAX];

	if (get_old_new_path(oid, epoch, ec_index, path, old, new) < 0)
		return SD_RES_EIO;
	/*
	 * Recovery thread and main thread might try to recover the same object.
	 * Either one succeeds, the other will fail and proceed and end up
	 * trying to move the object to where it is already in place, in this
	 * case we simply return.
	 */
	if (!strcmp(old, new))
		return SD_RES_SUCCESS;

	/* We can't use rename(2) across device */
	if (md_move_object(oid, old, new) < 0) {
		sd_err("move old %s to new %s failed", old, new);
		return SD_RES_EIO;
	}

	sd_debug("from %s to %s", old, new);
	return SD_RES_SUCCESS;
}

static int scan_wd(uint64_t oid, uint32_t epoch, uint8_t ec_index)
{
	int ret = SD_RES_EIO;
	const struct disk *disk;

	sd_read_lock(&md.lock);
	rb_for_each_entry(disk, &md.root, rb) {
		ret = md_check_and_move(oid, epoch, ec_index, disk->path);
		if (ret == SD_RES_SUCCESS)
			break;
	}
	sd_rw_unlock(&md.lock);
	return ret;
}

bool md_exist(uint64_t oid, uint8_t ec_index, char *path)
{
	if (md_access(path))
		return true;
	/*
	 * We have to iterate the WD because we don't have epoch-like history
	 * track to locate the objects for multiple disk failure. Simply do
	 * hard iteration simplify the code a lot.
	 */
	if (scan_wd(oid, 0, ec_index) == SD_RES_SUCCESS)
		return true;

	return false;
}

int md_get_stale_path(uint64_t oid, uint32_t epoch, uint8_t ec_index,
		      char *path)
{
	if (unlikely(!epoch))
		panic("invalid 0 epoch");

	if (is_erasure_oid(oid)) {
		if (unlikely(ec_index >= SD_MAX_COPIES))
			panic("invalid ec index %d", ec_index);

		snprintf(path, PATH_MAX, "%s/.stale/%016"PRIx64"_%d.%"PRIu32,
			 md_get_object_dir(oid), oid, ec_index, epoch);
	} else
		snprintf(path, PATH_MAX, "%s/.stale/%016"PRIx64".%"PRIu32,
			 md_get_object_dir(oid), oid, epoch);

	if (md_access(path))
		return SD_RES_SUCCESS;

	if (scan_wd(oid, epoch, ec_index) == SD_RES_SUCCESS)
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
	sd_rw_unlock(&md.lock);
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

#ifdef HAVE_DISKVNODES
void update_node_disks(void)
{
	const struct disk *disk;
	int i = 0;
	bool rb_empty = false;

	if (!sys)
		return;

	memset(sys->this_node.disks, 0, sizeof(struct disk_info) * DISK_MAX);
	sd_read_lock(&md.lock);
	rb_for_each_entry(disk, &md.root, rb) {
		sys->this_node.disks[i].disk_id =
			sd_hash(disk->path, strlen(disk->path));
		sys->this_node.disks[i].disk_space = disk->space;
		i++;
	}
	sd_rw_unlock(&md.lock);

	if (RB_EMPTY_ROOT(&md.vroot))
		rb_empty = true;
	sd_write_lock(&md.lock);
	rb_for_each_entry(disk, &md.root, rb) {
		if (!rb_empty)
			remove_vdisks(disk);
		create_vdisks(disk);
	}
	sd_rw_unlock(&md.lock);
}
#else
void update_node_disks(void)
{
}
#endif

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
	sd_rw_unlock(&md.lock);

	if (ret == SD_RES_SUCCESS) {
		update_node_disks();
		kick_recover();
	}

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
	sd_rw_unlock(&md.lock);

	return fsize + *used;
}

uint32_t md_nr_disks(void)
{
	return nr_online_disks();
}
