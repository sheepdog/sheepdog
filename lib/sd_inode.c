/*
 * Copyright (C) 2014 Taobao Inc.
 *
 * Robin Dong <sanbai@taobao.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * B-tree is a tree data structure that keeps data sorted and allows searches,
 * sequential access, insertions, and deletions in logarithmic time.
 * The B-tree is a generalization of a binary search tree in that a node can
 * have more than two children. (Comer 1979, p. 123) Unlike self-balancing
 * binary search trees, the B-tree is optimized for systems that read and
 * write large blocks of data. (ref: http://en.wikipedia.org/wiki/B-tree)
 *
 * In sheepdog, we use space in inode->data_vdi_id[] to store leaf-node at
 * beginning and store root-node of B-tree when it reach depths of two.
 *
 * At beginning, the inode->data_vdi_id[] is storing leaf-node which point
 * to data-obj directly:
 *
 *  R: root index node
 *  I: Indirect index node
 *  D: data node that hold user data
 *                                                             Depth:
 *     +------------------+-----------+-----------+--------+
 *  R: | sd_index_header  | sd_index | sd_index   | ...... |    1
 *     +------------------+-----------+-----------+--------+
 *                             v            v
 *                          +-------+    +-------+
 *  D:                      | data1 |    | data2 |              0
 *                          +-------+    +-------+
 *
 * After adding more oid into it, the leaf-node will be full of struct sd_index
 * and should be split to two leaf-nodes, after it, the inode->data_vdi_id[]
 * should become root-node which store sd_indirect_idx and point to the two
 * leaf-nodes:
 *
 *  root split:
 *
 *     +------------------+-----------------+-----------------+
 *  R: | sd_index_header  | sd_indirect_idx | sd_indirect_idx |           2
 *     +------------------+-----------------+-----------------+
 *                          |                      |
 *                          v                      v
 *     +--------+-------+------+      +--------+-------+-------+------+
 *  I: | header | index | .... |      | header | index | index | .... |   1
 *     +--------+-------+------+      +--------+-------+-------+------+
 *                 v                              v        v
 *              +-----+                        +-------+ +-------+
 *  D:          |data1|  ....                  |data511| |data512| ....   0
 *              +-----+                        +-------+ +-------+
 *
 * When a leaf-node is full, we could add a new leaf-node and add a
 * new sd_indirect_idx in root-node to point to it:
 *
 *     +-----------------+------------+------------+----------+
 *  R: | sd_index_header |  indirect  |  indirect  | indirect |           2
 *     +-----------------+------------+------------+----------+
 *                              |          |           |
 *                              v          v           v NEW
 *                         +-------+    +-------+    +-------+
 *  I:                     | index |    | index |    | index |            1
 *                         +-------+    +-------+    +-------+
 *
 *
 * We now only support two levels, which support up to:
 *
 *  (nr of sd_indirect_idx in root node) * (nr of sd_index in indirect node)
 *
 * which is 349524 * 524287 = 183250889388 data object, about 680 PB if object
 * size is 4MB.
 *
 */
#include <string.h>

#include "util.h"
#include "internal_proto.h"
#include "sheep.h"

#define PAYLOAD_SIZE (SD_INODE_DATA_INDEX_SIZE - \
		sizeof(struct sd_index_header))
#define MAX_INDEX (PAYLOAD_SIZE / sizeof(struct sd_index))
#define EXT_IDX_MAX_ENTRIES (PAYLOAD_SIZE / sizeof(struct sd_indirect_idx))

#define INDEX_HEADER(data) ((struct sd_index_header *)(data))
#define FIRST_INDEX(data)  ((struct sd_index *)((char *)(data) + \
			sizeof(struct sd_index_header)))
#define LAST_INDEX(data)   (FIRST_INDEX(data) + INDEX_HEADER(data)->entries)
#define OFFSET_EXT(data, n) ((char *)(data) + sizeof(struct sd_index_header) \
			+ n * sizeof(struct sd_index))

#define MAX_INDIRECT_IDX (PAYLOAD_SIZE / sizeof(struct sd_indirect_idx))
#define FIRST_INDIRECT_IDX(data)  ((struct sd_indirect_idx *)((char *)(data) + \
			sizeof(struct sd_index_header)))
#define LAST_INDRECT_IDX(data)   (FIRST_INDIRECT_IDX(data) + \
				  INDEX_HEADER(data)->entries)

struct find_path {
	struct sd_indirect_idx *p_indirect_idx;
	struct sd_index *p_index;
	struct sd_index_header *p_index_header;
	int depth;
};

struct sd_inode_actor {
	write_node_fn writer;
	read_node_fn reader;
};

static struct sd_inode_actor inode_actor;

static int index_compare(struct sd_index *a, struct sd_index *b)
{
	return intcmp(a->idx, b->idx);
}

static int indirect_idx_compare(struct sd_indirect_idx *a,
				struct sd_indirect_idx *b)
{
	return intcmp(a->idx, b->idx);
}

typedef void (*btree_cb_fn)(void *data, void *arg, int type);

/*
 * Traverse the whole btree that include all header, indirect_idx and index.
 * @interest specify which objects user wants to run @fn against.
 *
 * If error happens when reading btree internal nodes, we simply continue to
 * process next candidate.
 */
static void traverse_btree(const struct sd_inode *inode, btree_cb_fn fn,
			   void *arg, int interest)
{
	struct sd_index_header *header = INDEX_HEADER(inode->data_vdi_id);
	struct sd_index_header *leaf_node = NULL;
	struct sd_index *last, *iter;
	struct sd_indirect_idx *last_idx, *iter_idx;
	void *tmp;
	int ret;

	if (interest & BTREE_HEAD)
		fn(header, arg, BTREE_HEAD);
	if (header->depth == 1) {
		last = LAST_INDEX(inode->data_vdi_id);
		iter = FIRST_INDEX(inode->data_vdi_id);

		if (interest & BTREE_INDEX)
			while (iter != last) {
				fn(iter, arg, BTREE_INDEX);
				iter++;
			}
	} else if (header->depth == 2) {
		last_idx = LAST_INDRECT_IDX(inode->data_vdi_id);
		iter_idx = FIRST_INDIRECT_IDX(inode->data_vdi_id);
		leaf_node = xvalloc(SD_INODE_DATA_INDEX_SIZE);
		tmp = (void *)leaf_node;

		while (iter_idx != last_idx) {
			ret = inode_actor.reader(iter_idx->oid, &tmp,
						 SD_INODE_DATA_INDEX_SIZE, 0);
			if (ret != SD_RES_SUCCESS) {
				sd_err("failed to read %016"PRIx64, iter_idx->oid);
				iter_idx++;
				continue;
			}

			if (interest & BTREE_INDIRECT_IDX)
				fn(iter_idx, arg, BTREE_INDIRECT_IDX);
			if (interest & BTREE_HEAD)
				fn(leaf_node, arg, BTREE_HEAD);
			last = LAST_INDEX(leaf_node);
			iter = FIRST_INDEX(leaf_node);
			if (interest & BTREE_INDEX)
				while (iter != last) {
					fn(iter, arg, BTREE_INDEX);
					iter++;
				}
			iter_idx++;
		}

		free(leaf_node);
	} else
		panic("This B-tree not support depth %u", header->depth);
}

/* Walk the sd_inode's vdi index array and call func against each sd_index */
void sd_inode_index_walk(const struct sd_inode *inode, index_cb_fn func,
			 void *arg)
{
	traverse_btree(inode, (btree_cb_fn)func, arg, BTREE_INDEX);
}

#ifdef DEBUG
static void dump_cb(void *data, void *arg, int type)
{
	struct sd_index_header *header;
	struct sd_index *ext;
	struct sd_indirect_idx *idx;

	switch (type) {
	case BTREE_HEAD:
		header = (struct sd_index_header *)data;
		sd_info("btree> HEAD: magic %u entries %u depth %u",
			header->magic, header->entries, header->depth);
		break;
	case BTREE_INDEX:
		ext = (struct sd_index *)data;
		sd_info("btree> EXT: idx %u vdi_id %u", ext->idx, ext->vdi_id);
		break;
	case BTREE_INDIRECT_IDX:
		idx = (struct sd_indirect_idx *)data;
		sd_info("btree> IDX: idx %u oid %lu", idx->idx, idx->oid);
		break;
	}
}
#endif

/* dump the information of B-tree */
static void dump_btree(struct sd_inode *inode)
{
#ifdef DEBUG
	sd_info("btree> BEGIN");
	traverse_btree(inode, dump_cb, NULL,
		       BTREE_INDEX | BTREE_HEAD | BTREE_INDIRECT_IDX);
	sd_info("btree> END");
#endif
}

/*
 * This is the cache for inode and ext-node (B-tree), so we name it 'icache'.
 * Cache of the same inode and ext-node dose not support concurrent operations
 * so it could only be used in sd_inode_set_vid() which will be protected by
 * distributed lock and should be released in the end of sd_inode_set_vid().
 */

/* no rationale */
#define NUMBER_OF_CACHE	4

struct inode_cache {
	uint64_t oid;
	unsigned char mem[SD_INODE_DATA_INDEX_SIZE];
} cache_array[NUMBER_OF_CACHE];
static int cache_idx;

static void icache_writeout(int copies, int policy)
{
	int i;
	for (i = 0; i < cache_idx; i++) {
		inode_actor.writer(cache_array[i].oid, cache_array[i].mem,
				   SD_INODE_DATA_INDEX_SIZE, 0, 0, copies,
				   policy, false, false);
	}
}

static void icache_release(int copies, int policy)
{
	icache_writeout(copies, policy);
	cache_idx = 0; /* reset icache */
}

static void icache_insert(int copies, int policy,
			  uint64_t oid, void *mem)
{
	int i;
	for (i = 0; i < cache_idx; i++) {
		if (oid == cache_array[i].oid) {
			memcpy(cache_array[i].mem, mem,
			       SD_INODE_DATA_INDEX_SIZE);
			return;
		}
	}

	if (cache_idx == (NUMBER_OF_CACHE - 1)) {
		sd_debug("cache for B-tree is full, so write all out");
		icache_release(copies, policy);
	}

	/* insert new cache */
	cache_array[cache_idx].oid = oid;
	memcpy(cache_array[cache_idx].mem, mem, SD_INODE_DATA_INDEX_SIZE);
	cache_idx++;
}

static void *icache_find(uint64_t oid)
{
	int i;
	for (i = 0; i < cache_idx; i++) {
		if (cache_array[i].oid == oid)
			return cache_array[i].mem;
	}
	return NULL;
}

static int icache_writer(uint64_t id, void *mem, unsigned int len,
			 uint64_t offset, uint32_t flags, int copies,
			 int copy_policy, bool create, bool direct)
{
	/* Only try to cache entire ext-node */
	if (!offset && !create && !direct && len == SD_INODE_DATA_INDEX_SIZE) {
		icache_insert(copies, copy_policy, id, mem);
		return SD_RES_SUCCESS;
	}
	return inode_actor.writer(id, mem, len, offset, flags, copies,
				  copy_policy, create, direct);
}

static int icache_reader(uint64_t id, void **mem, unsigned int len,
			 uint64_t offset)
{
	void *data;

	if (!offset && len == SD_INODE_DATA_INDEX_SIZE) {
		data = icache_find(id);
		if (data) {
			memcpy(*mem, data, len);
			return SD_RES_SUCCESS;
		}
	}
	return inode_actor.reader(id, mem, len, offset);
}

void sd_inode_init(void *data, int depth)
{
	struct sd_index_header *header = INDEX_HEADER(data);
	header->magic = INODE_BTREE_MAGIC;
	header->depth = depth;
	header->entries = 0;
}

static bool index_in_range(struct sd_index_header *header, struct sd_index *ext)
{
	struct sd_index *last = LAST_INDEX(header);
	if (last - ext > 0)
		return true;
	return false;
}

static bool indirect_in_range(struct sd_index_header *header,
			      struct sd_indirect_idx *idx)
{
	struct sd_indirect_idx *last = LAST_INDRECT_IDX(header);
	if (last - idx > 0)
		return true;
	return false;
}

static struct sd_index *search_index_entry(struct sd_index_header *header,
					   uint32_t idx)
{
	struct sd_index tmp;
	tmp.idx = idx;
	return nbsearch(&tmp, FIRST_INDEX(header), header->entries,
			index_compare);
}

static struct
sd_indirect_idx *search_indirect_entry(struct sd_index_header *header,
				       uint32_t idx)
{
	struct sd_indirect_idx tmp;
	tmp.idx = idx;
	return nbsearch(&tmp, FIRST_INDIRECT_IDX(header), header->entries,
			indirect_idx_compare);
}

static void insert_index_nosearch(struct sd_index_header *header,
				      struct sd_index *ext, uint32_t idx,
				      uint32_t vdi_id)
{
	struct sd_index *last = LAST_INDEX(header);

	memmove(ext + 1, ext, (last - ext) * sizeof(struct sd_index));
	ext->idx = idx;
	ext->vdi_id = vdi_id;
	header->entries++;
}

static void insert_indirect_nosearch(struct sd_index_header *header,
				     struct sd_indirect_idx *idx_ext,
				     uint32_t idx, uint64_t oid)
{
	struct sd_indirect_idx *last = LAST_INDRECT_IDX(header);
	memmove(idx_ext + 1, idx_ext,
		(last - idx_ext) * sizeof(struct sd_indirect_idx));
	idx_ext->idx = idx;
	idx_ext->oid = oid;
	header->entries++;
}

static void insert_idx_entry(struct sd_index_header *header,
			     uint32_t idx, uint64_t oid)
{
	struct sd_indirect_idx *found;

	if (header->entries >= MAX_INDIRECT_IDX)
		goto out;

	if (!header->entries) {
		FIRST_INDIRECT_IDX(header)->idx = idx;
		FIRST_INDIRECT_IDX(header)->oid = oid;
		header->entries++;
		goto out;
	}

	found = search_indirect_entry(header, idx);
	insert_indirect_nosearch(header, found, idx, oid);
out:
	return;
}

static void split_to_nodes(struct sd_index_header *src,
			   struct sd_index_header *left,
			   struct sd_index_header *right, int num)
{
	memcpy(left, src, sizeof(struct sd_index_header) +
	       num * sizeof(struct sd_index));
	left->entries = num;

	mempcpy(right, src, sizeof(struct sd_index_header));
	mempcpy(FIRST_INDEX(right), OFFSET_EXT(src, num),
		(src->entries - num) * sizeof(struct sd_index));
	right->entries = src->entries - num;
}

/*
 * The meta-data in inode is leaf-node at beginning, but after inserting too
 * much sd_index it will be full. When sd_indexs is full, we need to create
 * two new nodes, move sd_indexs from inode to them and finally, let inode
 * point to them.
 */
static void transfer_to_idx_root(write_node_fn writer, struct sd_inode *inode)
{
	struct sd_index_header *left;
	struct sd_index_header *right;
	struct sd_index_header *root = INDEX_HEADER(inode->data_vdi_id);
	uint64_t left_oid, right_oid;
	uint32_t num = root->entries / 2;

	/* create two leaf-node and copy the entries from root-node */
	left = xvalloc(SD_INODE_DATA_INDEX_SIZE);
	right = xvalloc(SD_INODE_DATA_INDEX_SIZE);

	split_to_nodes(root, left, right, num);

	/* write two nodes back */
	left_oid = vid_to_btree_oid(inode->vdi_id, inode->btree_counter++);
	right_oid = vid_to_btree_oid(inode->vdi_id, inode->btree_counter++);

	writer(left_oid, left, SD_INODE_DATA_INDEX_SIZE, 0, 0,
	       inode->nr_copies, inode->copy_policy, true, false);
	writer(right_oid, right, SD_INODE_DATA_INDEX_SIZE, 0, 0,
	       inode->nr_copies, inode->copy_policy, true, false);

	/* change root from ext-node to idx-node */
	root->entries = 0;
	root->depth = 2;
	insert_idx_entry(root, (LAST_INDEX(left) - 1)->idx, left_oid);
	insert_idx_entry(root, (LAST_INDEX(right) - 1)->idx, right_oid);

	free(left);
	free(right);
}

/*
 * Search whole btree for 'idx'.
 * Return available position (could insert new sd_index) if can't find 'idx'.
 */
static int search_whole_btree(read_node_fn reader, const struct sd_inode *inode,
			      uint32_t idx, struct find_path *path)
{
	struct sd_index_header *header, *leaf_node;
	void *tmp;
	uint64_t oid;
	int ret = SD_RES_NOT_FOUND;

	header = INDEX_HEADER(inode->data_vdi_id);

	/* root is idx-node */
	if (header->depth == 2) {
		path->depth = 2;
		path->p_indirect_idx = search_indirect_entry(header, idx);
		leaf_node = xvalloc(SD_INODE_DATA_INDEX_SIZE);
		tmp = (void *)leaf_node;

		if (indirect_in_range(header, path->p_indirect_idx)) {
			oid = path->p_indirect_idx->oid;
			ret = reader(oid, &tmp, SD_INODE_DATA_INDEX_SIZE, 0);
			if (ret != SD_RES_SUCCESS) {
				sd_err("read oid %"PRIu64" fail", oid);
				goto out;
			}
			path->p_index = search_index_entry(leaf_node, idx);
			path->p_index_header = leaf_node;
			if (index_in_range(leaf_node, path->p_index) &&
			    path->p_index->idx == idx)
				ret = SD_RES_SUCCESS;
			else
				ret = SD_RES_NOT_FOUND;
		} else {
			/* check if last ext-node has space */
			oid = (path->p_indirect_idx - 1)->oid;
			ret = reader(oid, &tmp, SD_INODE_DATA_INDEX_SIZE, 0);
			if (ret != SD_RES_SUCCESS) {
				sd_err("read oid %"PRIu64" fail", oid);
				goto out;
			}
			if (leaf_node->entries < MAX_INDEX) {
				path->p_index = search_index_entry(leaf_node,
								 idx);
				path->p_index_header = leaf_node;
			} else {
				sd_debug("last ext-node is full (oid: %016"
					 PRIx64")", oid);
				free(leaf_node);
			}
			ret = SD_RES_NOT_FOUND;
		}
	} else if (header->depth == 1) {
		path->depth = 1;
		path->p_index = search_index_entry(header, idx);
		if (index_in_range(header, path->p_index) &&
		    path->p_index->idx == idx)
			ret = SD_RES_SUCCESS;
		else
			ret = SD_RES_NOT_FOUND;
	}
out:
	return ret;
}

uint32_t sd_inode_get_vid(const struct sd_inode *inode, uint32_t idx)
{
	struct find_path path;
	int ret;

	if (inode->store_policy == 0)
		return inode->data_vdi_id[idx];
	else {
		/* btree is not init, so vdi is 0 */
		if (inode->data_vdi_id[0] == 0)
			return 0;

		memset(&path, 0, sizeof(path));
		ret = search_whole_btree(inode_actor.reader, inode, idx, &path);
		if (ret == SD_RES_SUCCESS)
			return path.p_index->vdi_id;
		if (path.p_index_header)
			free(path.p_index_header);
	}

	return 0;
}

/*
 * When the leaf-node is full, we need to create a new node and
 * move half of the data into new one.
 */
static void split_index_node(write_node_fn writer, struct sd_inode *inode,
			     struct find_path *path)
{
	struct sd_index_header *old = path->p_index_header, *new_ext;
	uint32_t num = old->entries / 2;
	uint64_t new_oid;

	new_ext = xvalloc(SD_INODE_DATA_INDEX_SIZE);

	split_to_nodes(old, new_ext, old, num);

	new_oid = vid_to_btree_oid(inode->vdi_id, inode->btree_counter++);
	writer(new_oid, new_ext, SD_INODE_DATA_INDEX_SIZE, 0, 0,
	       inode->nr_copies, inode->copy_policy, true, false);
	writer(path->p_indirect_idx->oid, old, SD_INODE_DATA_INDEX_SIZE, 0, 0,
	       inode->nr_copies, inode->copy_policy, false, false);

	/* write new index */
	insert_idx_entry(INDEX_HEADER(inode->data_vdi_id),
			 LAST_INDEX(new_ext)->idx, new_oid);

	free(new_ext);
}

/*
 * Add new 'idx' and 'vdi_id' pair into leaf-node if depth equal 1 and
 * add new leaf-node if there is no room for new 'idx' and 'vdi_id' pair.
 */
static int insert_new_node(write_node_fn writer, read_node_fn reader,
			   struct sd_inode *inode, struct find_path *path,
			   uint32_t idx, uint32_t vdi_id)
{
	struct sd_index_header *header = INDEX_HEADER(inode->data_vdi_id);
	struct sd_index_header *leaf_node = NULL;
	uint64_t oid;
	int ret = SD_RES_SUCCESS;

	if (path->depth == 1) {
		if (header->entries >= MAX_INDEX) {
			transfer_to_idx_root(writer, inode);
			ret = SD_RES_AGAIN;
			goto out;
		}
		insert_index_nosearch(header, path->p_index, idx, vdi_id);
	} else if (path->depth == 2) {
		if (indirect_in_range(header, path->p_indirect_idx)) {
			if (!path->p_index_header) {
				ret = SD_RES_NOT_FOUND;
				goto out;
			}
			if (path->p_index_header->entries >= MAX_INDEX) {
				split_index_node(writer, inode, path);
				ret = SD_RES_AGAIN;
				goto out;
			}
			insert_index_nosearch(path->p_index_header,
					      path->p_index, idx, vdi_id);
			writer(path->p_indirect_idx->oid, path->p_index_header,
			       SD_INODE_DATA_INDEX_SIZE, 0, 0, inode->nr_copies,
			       inode->copy_policy, false, false);
		} else if (path->p_index_header) {
			/* the last idx-node */
			insert_index_nosearch(path->p_index_header,
					      path->p_index, idx, vdi_id);
			path->p_indirect_idx--;
			path->p_indirect_idx->idx =
				(LAST_INDEX(path->p_index_header) - 1)->idx;
			writer(path->p_indirect_idx->oid, path->p_index_header,
			       SD_INODE_DATA_INDEX_SIZE, 0, 0, inode->nr_copies,
			       inode->copy_policy, false, false);
		} else {
			/* if btree is full, then panic */
			if (header->entries >= EXT_IDX_MAX_ENTRIES)
				panic("%s() B-tree is full!", __func__);
			/* create a new ext-node */
			leaf_node = xvalloc(SD_INODE_DATA_INDEX_SIZE);
			sd_inode_init(leaf_node, 1);
			oid = vid_to_btree_oid(inode->vdi_id,
					       inode->btree_counter++);
			insert_index_nosearch(leaf_node,
					      FIRST_INDEX(leaf_node), idx,
					      vdi_id);
			writer(oid, leaf_node, SD_INODE_DATA_INDEX_SIZE,
			       0, 0, inode->nr_copies,
			       inode->copy_policy, true, false);
			insert_indirect_nosearch(header, path->p_indirect_idx,
						 idx, oid);
		}
	}
out:
	if (leaf_node)
		free(leaf_node);
	return ret;
}

static void set_vid_for_btree(write_node_fn writer, read_node_fn reader,
			      struct sd_inode *inode, uint32_t idx,
			      uint32_t vdi_id)
{
	struct find_path path;
	uint64_t offset;
	int ret;

	path.p_index_header = NULL;

	while (1) {
		memset(&path, 0, sizeof(path));
		ret = search_whole_btree(reader, inode, idx, &path);
		if (ret == SD_RES_SUCCESS) {
			path.p_index->vdi_id = vdi_id;
			/*
			 * Only write the vdi_id in sd_index for
			 * second level leaf-node.
			 */
			if (!path.p_index_header)
				goto out;
			offset = (unsigned char *)(path.p_index) -
				(unsigned char *)(path.p_index_header) +
				offsetof(struct sd_index, vdi_id);
			writer(path.p_indirect_idx->oid, &vdi_id,
			       sizeof(vdi_id), offset, 0, inode->nr_copies,
			       inode->copy_policy, false, false);
			goto out;
		} else if (ret == SD_RES_NOT_FOUND) {
			ret = insert_new_node(writer, reader, inode,
					      &path, idx, vdi_id);
			if (SD_RES_AGAIN == ret) {
				if (path.p_index_header)
					free(path.p_index_header);
				continue;
			} else
				goto out;
		} else
			panic("ret: %d", ret);
	}
out:
	if (path.p_index_header)
		free(path.p_index_header);
}

int sd_inode_set_vid_range(struct sd_inode *inode, uint32_t idx_start,
			   uint32_t idx_end, uint32_t vdi_id)
{
	struct sd_index_header *header;
	int idx;

	for (idx = idx_start; idx <= idx_end; idx++) {
		if (inode->store_policy == 0)
			inode->data_vdi_id[idx] = vdi_id;
		else {
			if (inode->data_vdi_id[0] == 0)
				sd_inode_init(inode->data_vdi_id, 1);
			header = INDEX_HEADER(inode->data_vdi_id);
			if (header->magic != INODE_BTREE_MAGIC)
				panic("%s() B-tree in inode is corrupt!",
				      __func__);
			/*
			 * use icache(write buffer) to accelerate batch set
			 * operation. icache will be released after this
			 * transaction to assure consistency.
			 */
			set_vid_for_btree(icache_writer, icache_reader, inode,
					  idx, vdi_id);
		}
	}
	if (inode->store_policy != 0)
		dump_btree(inode);

	icache_release(inode->nr_copies, inode->copy_policy);
	/* XXX: return error code */
	return 0;
}

int sd_inode_set_vid(struct sd_inode *inode, uint32_t idx, uint32_t vdi_id)
{
	return sd_inode_set_vid_range(inode, idx, idx, vdi_id);
}

/*
 * Return the size of meta-data in inode->data_vdi_id. When leaf-node of B-tree
 * is not full, we don't need to read out all sizeof(sd_inode).
 * The argument of 'size' is just for compatibility of parse_vdi().
 */
uint32_t sd_inode_get_meta_size(struct sd_inode *inode, size_t size)
{
	struct sd_index_header *header;
	uint32_t len;

	if (inode->store_policy == 0) {
		len = count_data_objs(inode) * sizeof(inode->data_vdi_id[0]);
		if (len > size - SD_INODE_HEADER_SIZE - sizeof(uint32_t))
			len = size - SD_INODE_HEADER_SIZE - sizeof(uint32_t);
	} else {
		header = INDEX_HEADER(inode->data_vdi_id);
		len = sizeof(struct sd_index_header);
		if (header->depth == 1)
			len += sizeof(struct sd_index) * header->entries;
		else if (header->depth == 2)
			len += sizeof(struct sd_indirect_idx) * header->entries;
		else
			panic("Depth of B-tree is out of range(depth: %u)",
			      header->depth);
	}
	return len;
}

/* Write the whole meta-data of inode out */
int sd_inode_write(struct sd_inode *inode, int flags, bool create, bool direct)
{
	uint32_t len;
	int ret;

	if (inode->store_policy == 0)
		ret = inode_actor.writer(vid_to_vdi_oid(inode->vdi_id), inode,
					 SD_INODE_HEADER_SIZE, 0,
					 flags, inode->nr_copies,
					 inode->copy_policy,
					 create, direct);
	else {
		len = SD_INODE_HEADER_SIZE + sd_inode_get_meta_size(inode, 0);
		ret = inode_actor.writer(vid_to_vdi_oid(inode->vdi_id), inode,
					 len, 0, flags, inode->nr_copies,
					 inode->copy_policy, create, false);
		if (ret != SD_RES_SUCCESS)
			goto out;
		ret = inode_actor.writer(vid_to_vdi_oid(inode->vdi_id),
					 &(inode->btree_counter),
					 sizeof(uint32_t),
					 offsetof(struct sd_inode,
						  btree_counter),
					 flags,
					 inode->nr_copies, inode->copy_policy,
					 create, false);
	}
out:
	return ret;
}

/* Write the meta-data of inode out */
int sd_inode_write_vid(struct sd_inode *inode,
		       uint32_t idx, uint32_t vid, uint32_t value,
		       int flags, bool create, bool direct)
{
	int ret = SD_RES_SUCCESS;

	if (inode->store_policy == 0)
		ret = inode_actor.writer(vid_to_vdi_oid(vid), &value,
					 sizeof(value),
				SD_INODE_HEADER_SIZE + sizeof(value) * idx,
					 flags, inode->nr_copies,
					 inode->copy_policy,
					 create, direct);
	else {
		/*
		 * For btree type sd_inode, we only have to write all
		 * meta-data of sd_inode out.
		 */
		ret = sd_inode_write(inode, flags, create, direct);
	}
	return ret;
}

void sd_inode_copy_vdis(write_node_fn writer, read_node_fn reader,
			uint32_t *data_vdi_id, uint8_t store_policy,
			uint8_t nr_copies, uint8_t copy_policy,
			struct sd_inode *newi)
{
	struct sd_index_header *header = INDEX_HEADER(data_vdi_id);
	struct sd_index_header *leaf_node;
	struct sd_indirect_idx *last_idx, *old_iter_idx, *new_iter_idx;
	uint64_t oid;
	void *tmp;

	memcpy(newi->data_vdi_id, data_vdi_id, sizeof(newi->data_vdi_id));

	if (store_policy == 1 && header->depth > 1) {
		/* for B-tree (> 1 level), it needs to copy all leaf-node */
		last_idx = LAST_INDRECT_IDX(data_vdi_id);
		old_iter_idx = FIRST_INDIRECT_IDX(data_vdi_id);
		new_iter_idx = FIRST_INDIRECT_IDX(newi->data_vdi_id);
		leaf_node = xvalloc(SD_INODE_DATA_INDEX_SIZE);
		tmp = (void *)leaf_node;
		while (old_iter_idx != last_idx) {
			reader(old_iter_idx->oid, &tmp,
			       SD_INODE_DATA_INDEX_SIZE, 0);
			oid = vid_to_btree_oid(newi->vdi_id,
					       newi->btree_counter++);
			writer(oid, leaf_node, SD_INODE_DATA_INDEX_SIZE, 0, 0,
			       nr_copies, copy_policy, true, false);
			new_iter_idx->oid = oid;
			old_iter_idx++;
			new_iter_idx++;
		}
		free(leaf_node);
	}
}

struct stat_arg {
	uint64_t *my;
	uint64_t *cow;
	uint32_t vid;
};

static void stat_cb(struct sd_index *idx, void *arg,
		    int ignore)
{
	struct stat_arg *sarg = arg;
	uint64_t *my = sarg->my;
	uint64_t *cow = sarg->cow;

	if (idx->vdi_id == sarg->vid)
		(*my)++;
	else if (idx->vdi_id != 0)
		(*cow)++;
}

static void hypver_volume_stat(const struct sd_inode *inode,
			       uint64_t *my_objs, uint64_t *cow_objs)
{
	struct stat_arg arg = {my_objs, cow_objs, inode->vdi_id};
	sd_inode_index_walk(inode, stat_cb, &arg);
}

static void volume_stat(const struct sd_inode *inode, uint64_t *my_objs,
			uint64_t *cow_objs)
{
	int nr;
	uint64_t my, cow, *p;
	uint32_t vid = inode->vdi_id;

	my = 0;
	cow = 0;
	nr = count_data_objs(inode);

	if (nr % 2 != 0) {
		if (inode->data_vdi_id[0] == inode->vdi_id)
			my++;
		else if (inode->data_vdi_id[0] != 0)
			cow++;
		p = (uint64_t *)(inode->data_vdi_id + 1);
	} else
		p = (uint64_t *)inode->data_vdi_id;

	/*
	 * To boost performance, this function checks data_vdi_id for each 64
	 * bit integer.
	 */
	nr /= 2;
	for (int i = 0; i < nr; i++) {
		if (p[i] == 0)
			continue;
		if (p[i] == (((uint64_t)vid << 32) | vid)) {
			my += 2;
			continue;
		}

		/* Check the higher 32 bit */
		if (p[i] >> 32 == vid)
			my++;
		else if ((p[i] & 0xFFFFFFFF00000000) != 0)
			cow++;

		/* Check the lower 32 bit */
		if ((p[i] & 0xFFFFFFFF) == vid)
			my++;
		else if ((p[i] & 0xFFFFFFFF) != 0)
			cow++;
	}

	*my_objs = my;
	*cow_objs = cow;
}

/*
 * Get the number of objects.
 *
 * 'my_objs' means the number objects which belongs to this vdi.  'cow_objs'
 * means the number of the other objects.
 */
void sd_inode_stat(const struct sd_inode *inode, uint64_t *my_objs,
		   uint64_t *cow_objs)
{
	if (inode->store_policy == 0)
		volume_stat(inode, my_objs, cow_objs);
	else
		hypver_volume_stat(inode, my_objs, cow_objs);
}

int sd_inode_actor_init(write_node_fn writer, read_node_fn reader)
{
	if (!writer || !reader) {
		sd_err("failed to init sd inode actor");
		return -1;
	}
	inode_actor.writer = writer;
	inode_actor.reader = reader;
	return 0;
}
