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
#include "http.h"

/*
 * Meta Object tracks the free information of data vdi for the object allocation
 * in a free list. Free list is a redundant structure for bitmap for faster
 * allocation.
 *
 *            +-------------------------------+
 *            |                               |
 *            |  sorted list               v------v
 * +--------------------------------+-----------------------+     +--------+
 * | Header | fd1 | fd2 | ... | fdN | .... object data .... | <-- | bitmap |
 * +--------------------------------+-----------------------+     +---------
 * |<--           4M             -->|
 *
 * Best-fit algorithm for allocation and merge and sort the free list at
 * deallocation. One simple sorted list is efficient enough for extent based
 * invariable user object.
 *
 * XXX: Add allocation group for scalability and solve the meta size limitation
 */

struct header {
	uint64_t used;
	uint64_t nr_free;
};

struct free_desc {
	uint64_t start;
	uint64_t count;
};

static inline uint32_t oalloc_meta_length(struct header *hd)
{
	return sizeof(struct header) + sizeof(struct free_desc) * hd->nr_free;
}

#define HEADER_TO_FREE_DESC(hd) ((struct free_desc *) \
				 ((char *)hd + sizeof(struct header)))

#define MAX_FREE_DESC ((SD_DATA_OBJ_SIZE - sizeof(struct header)) / \
		       sizeof(struct free_desc))

/*
 * Initialize the data vdi
 *
 * @vid: the vdi where the allocator resides
 */
int oalloc_init(uint32_t vid)
{
	struct strbuf buf = STRBUF_INIT;
	struct sd_inode *inode = xmalloc(sizeof(struct sd_inode));
	struct header hd = {
		.nr_free = 1,
	};
	struct free_desc fd = {
		.start = 1, /* Use first object as the meta object */
		.count = MAX_DATA_OBJS - 1,
	};
	int ret;

	strbuf_add(&buf, &hd, sizeof(hd));
	strbuf_add(&buf, &fd, sizeof(fd));

	ret = sd_read_object(vid_to_vdi_oid(vid), (char *)inode,
			     sizeof(*inode), 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to read inode, %" PRIx32", %s", vid,
		       sd_strerror(ret));
		goto out;
	}
	ret = sd_write_object(vid_to_data_oid(vid, 0), buf.buf,
			      buf.len, 0, true);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to create meta object for %" PRIx32", %s", vid,
		       sd_strerror(ret));
		goto out;
	}
	sd_inode_set_vid(inode, 0, vid);
	ret = sd_inode_write_vid(inode, 0, vid, vid, 0, false, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update inode, %" PRIx32", %s", vid,
		       sd_strerror(ret));
		goto out;
	}
out:
	strbuf_release(&buf);
	free(inode);
	return ret;
}

/*
 * Allocate the objects and update the free list.
 *
 * Callers are expected to call oalloc_new_finish() to update the inode bitmap
 * after filling up the data.
 *
 * @vid: the vdi where the allocator resides
 * @start: start index of the objects to allocate
 * @count: number of the objects to allocate
 */
int oalloc_new_prepare(uint32_t vid, uint64_t *start, uint64_t count)
{
	char *meta = xvalloc(SD_DATA_OBJ_SIZE);
	struct header *hd;
	struct free_desc *fd;
	uint64_t oid = vid_to_data_oid(vid, 0), i;
	int ret;

	ret = sd_read_object(oid, meta, SD_DATA_OBJ_SIZE, 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to read meta %016" PRIx64 ", %s", oid,
		       sd_strerror(ret));
		goto out;
	}

	hd = (struct header *)meta;
	fd = (struct free_desc *)(meta + oalloc_meta_length(hd)) - 1;
	sd_debug("used %"PRIu64", nr_free %"PRIu64, hd->used, hd->nr_free);
	for (i = 0; i < hd->nr_free; i++, fd--) {
		sd_debug("start %"PRIu64", count %"PRIu64, fd->start,
			 fd->count);
		if (fd->count > count)
			break;
	}
	if (i == hd->nr_free) {
		ret = SD_RES_NO_SPACE;
		goto out;
	}

	*start = fd->start;
	fd->start += count;
	fd->count -= count;
	hd->used += count;

	/* Update the meta object */
	ret = sd_write_object(oid, meta, oalloc_meta_length(hd), 0, false);
	if (ret != SD_RES_SUCCESS)
		sd_err("failed to update meta %016"PRIx64 ", %s", oid,
		       sd_strerror(ret));
out:
	free(meta);
	return ret;
}

/*
 * Update the inode map of the vid
 *
 * @vid: the vdi where the allocator resides
 * @start: start index of the objects to update
 * @count: number of the objects to update
 */
int oalloc_new_finish(uint32_t vid, uint64_t start, uint64_t count)
{
	struct sd_inode *inode = xmalloc(sizeof(struct sd_inode));
	int ret;

	ret = sd_read_object(vid_to_vdi_oid(vid), (char *)inode,
			     sizeof(*inode), 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to read inode, %016" PRIx64 ", %s",
		       vid_to_vdi_oid(vid), sd_strerror(ret));
		goto out;
	}

	sd_debug("start %"PRIu64" end %"PRIu64, start, start + count - 1);
	sd_inode_set_vid_range(inode, start, (start + count - 1), vid);

	ret = sd_inode_write(inode, 0, false, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update inode, %016" PRIx64", %s",
		       vid_to_vdi_oid(vid), sd_strerror(ret));
		goto out;
	}
out:
	free(inode);
	return ret;
}

static int free_desc_cmp(struct free_desc *a, struct free_desc *b)
{
	return -intcmp(a->start, b->start);
}

static inline int update_and_merge_free_desc(char *meta, uint64_t start,
					     uint64_t count, uint32_t vid)
{
	struct header *hd = (struct header *)meta;
	struct free_desc *tail, *fd = HEADER_TO_FREE_DESC(hd);
	uint64_t i, j;

	/* Try our best to merge it in place, or append it to tail */
	for (i = 0; i < hd->nr_free; i++) {
		if (start + count == fd->start) {
			fd->start = start;
			fd->count += count;
			break;
		} else if(fd->start + fd->count == start) {
			fd->count +=count;
			break;
		}
		fd++;
	}

	if (i == hd->nr_free) {
		if (hd->nr_free >= MAX_FREE_DESC)
			return SD_RES_NO_SPACE;

		tail = (struct free_desc *)(meta + oalloc_meta_length(hd));
		tail->start = start;
		tail->count = count;
		hd->nr_free++;
	}

	hd->used -= count;
	xqsort(HEADER_TO_FREE_DESC(hd), hd->nr_free, free_desc_cmp);

	/* Merge as hard as we can */
	j = hd->nr_free - 1;
	tail = (struct free_desc *)(meta + oalloc_meta_length(hd)) - 1;
	for (i = 0; i < j; i++, tail--) {
		struct free_desc *front = tail - 1;

		sd_debug("start %"PRIu64", count %"PRIu64, tail->start,
			 tail->count);
		if (tail->start + tail->count > front->start)
			sd_emerg("bad free descriptor found at %"PRIx32, vid);
		if (tail->start + tail->count == front->start) {
			front->start = tail->start;
			front->count += tail->count;
			memmove(tail, tail + 1, sizeof(*tail) * i);
			hd->nr_free--;
		}
	}

	return SD_RES_SUCCESS;
}

/*
 * Discard the allocated objects and update the free list of the allocator
 *
 * Caller should check the return value since it might fail.
 *
 * @vid: the vdi where the allocator resides
 * @start: start index of the objects to free
 * @count: number of the objects to free
 */
int oalloc_free(uint32_t vid, uint64_t start, uint64_t count)
{
	char *meta = xvalloc(SD_DATA_OBJ_SIZE);
	struct header *hd;
	uint64_t oid = vid_to_data_oid(vid, 0), i;
	struct sd_inode *inode = xmalloc(sizeof(struct sd_inode));
	int ret;

	ret = sd_read_object(vid_to_vdi_oid(vid), (char *)inode,
			     sizeof(*inode), 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to read inode, %016" PRIx64 ", %s",
		       vid_to_vdi_oid(vid), sd_strerror(ret));
		goto out;
	}

	sd_debug("discard start %"PRIu64" end %"PRIu64, start,
		 start + count - 1);
	sd_inode_set_vid_range(inode, start, (start + count - 1), 0);

	ret = sd_inode_write(inode, 0, false, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update inode, %016" PRIx64", %s",
		       vid_to_vdi_oid(vid), sd_strerror(ret));
		goto out;
	}

	ret = sd_read_object(oid, meta, SD_DATA_OBJ_SIZE, 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to read meta %016" PRIx64 ", %s", oid,
		       sd_strerror(ret));
		goto out;
	}

	ret = update_and_merge_free_desc(meta, start, count, vid);
	if (ret != SD_RES_SUCCESS)
		goto out;

	/* XXX use aio to speed up remove of objects */
	for (i = 0; i < count; i++) {
		struct sd_req hdr;
		int res;

		sd_init_req(&hdr, SD_OP_REMOVE_OBJ);
		hdr.obj.oid = vid_to_data_oid(vid, start + i);
		res = exec_local_req(&hdr, NULL);
		/*
		 * return the error code if it does not
		 * success or can't find obj.
		 */
		if (res != SD_RES_SUCCESS && res != SD_RES_NO_OBJ)
			ret = res;
	}

	hd = (struct header *)meta;
	ret = sd_write_object(oid, meta, oalloc_meta_length(hd), 0, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update meta %016"PRIx64 ", %s", oid,
		       sd_strerror(ret));
		goto out;
	}
	sd_debug("used %"PRIu64", nr_free %"PRIu64, hd->used, hd->nr_free);
out:
	free(meta);
	free(inode);
	return ret;
}
