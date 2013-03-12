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
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <sys/xattr.h>

#include "sheep_priv.h"

#define MD_DEFAULT_VDISKS 128
#define MD_MAX_DISK 64 /* FIXME remove roof and make it dynamic */
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

static int md_nr_disks;
static int md_nr_vds;

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

static int vdisk_cmp(const void *a, const void *b)
{
	const struct vdisk *d1 = a;
	const struct vdisk *d2 = b;

	if (d1->id < d2->id)
		return -1;
	if (d1->id > d2->id)
		return 1;
	return 0;
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
	qsort(vds, nr_vdisks, sizeof(*vds), vdisk_cmp);

	return nr_vdisks;
}

static inline struct vdisk *oid_to_vdisk(uint64_t oid)
{
	return oid_to_vdisk_from(md_vds, md_nr_vds, oid);
}

int md_init_disk(char *path)
{
	md_nr_disks++;

	if (mkdir(path, def_dmode) < 0)
		if (errno != EEXIST)
			panic("%s, %m", path);
	pstrcpy(md_disks[md_nr_disks - 1].path, PATH_MAX, path);
	sd_iprintf("%s added to md, nr %d", md_disks[md_nr_disks - 1].path,
		   md_nr_disks);
	return 0;
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
		sd_dprintf("%s has %d vdisks, free space %" PRIu64,
			   md_disks[i].path, md_disks[i].nr_vdisks,
			   md_disks[i].space);
	}
}

#define MDNAME	"user.md.size"
#define MDSIZE	sizeof(uint64_t)

static uint64_t init_path_space(char *path)
{
	struct statvfs fs;
	uint64_t size;

	if (getxattr(path, MDNAME, &size, MDSIZE) < 0) {
		if (errno == ENODATA)
			goto create;
		else
			panic("%s, %m", path);
	}

	return size;
create:
	if (statvfs(path, &fs) < 0)
		panic("get disk %s space failed %m", path);
	size = (int64_t)fs.f_frsize * fs.f_bfree;
	if (setxattr(path, MDNAME, &size, MDSIZE, 0) < 0)
		panic("%s, %m", path);
	return size;
}

uint64_t md_init_space(void)
{
	uint64_t total = 0;
	int i;

	if (!md_nr_disks)
		return 0;

	for (i = 0; i < md_nr_disks; i++) {
		if (!is_xattr_enabled(md_disks[i].path))
			panic("multi-disk support need xattr feature");
		md_disks[i].space = init_path_space(md_disks[i].path);
		total += md_disks[i].space;
	}
	calculate_vdisks(md_disks, md_nr_disks, total);
	md_nr_vds = disks_to_vdisks(md_disks, md_nr_disks, md_vds);

	return total;
}
