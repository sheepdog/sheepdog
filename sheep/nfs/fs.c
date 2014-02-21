/*
 * Copyright (C) 2014 Taobao Inc.
 *
 * Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <nfs://www.gnu.org/licenses/>.
 */

#include "nfs.h"

#define ROOT_IDX (sd_hash("/", 1) % MAX_DATA_OBJS)

struct inode_data {
	struct sd_inode *sd_inode;
	struct inode *inode;
	const char *name;
	uint32_t vid;
	uint32_t idx;
	bool create;
};

static struct inode_data *prepare_inode_data(struct inode *inode, uint32_t vid,
					     const char *name)
{
	struct inode_data *id = xzalloc(sizeof(*id));

	id->sd_inode = xmalloc(sizeof(struct sd_inode));
	id->inode = inode;
	id->vid = vid;
	id->name = name;

	return id;
}

static void finish_inode_data(struct inode_data *id)
{
	free(id->sd_inode);
	free(id);
}

static int inode_do_create(struct inode_data *id)
{
	struct sd_inode *sd_inode = id->sd_inode;
	struct inode *inode = id->inode;
	uint32_t idx = id->idx;
	uint32_t vid = sd_inode->vdi_id;
	uint64_t oid = vid_to_data_oid(vid, idx);
	bool create = id->create;
	int ret;

	inode->ino = oid;
	ret = sd_write_object(oid, (char *)inode, INODE_META_SIZE + inode->size,
			      0, create);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to create object, %" PRIx64, oid);
		goto out;
	}
	if (!create)
		goto out;

	sd_inode_set_vid(sd_inode, idx, vid);
	ret = sd_inode_write_vid(sd_inode, idx, vid, vid, 0, false, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update sd inode, %" PRIx64,
		       vid_to_vdi_oid(vid));
		goto out;
	}
out:
	return ret;
}

static int inode_lookup(struct inode_data *idata)
{
	struct sd_inode *sd_inode = idata->sd_inode;
	uint32_t tmp_vid, idx, vid = idata->vid;
	uint64_t hval, i;
	bool create = true;
	const char *name = idata->name;
	int ret;

	ret = sd_read_object(vid_to_vdi_oid(vid), (char *)sd_inode,
			     sizeof(*sd_inode), 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to read %" PRIx32 " %s", vid,
		       sd_strerror(ret));
		goto err;
	}

	hval = sd_hash(name, strlen(name));
	for (i = 0; i < MAX_DATA_OBJS; i++) {
		idx = (hval + i) % MAX_DATA_OBJS;
		tmp_vid = sd_inode_get_vid(sd_inode, idx);
		if (tmp_vid) {
			uint64_t oid = vid_to_data_oid(vid, idx);
			uint64_t block;

			ret = sd_read_object(oid, (char *)&block, sizeof(block),
					     0);
			if (ret != SD_RES_SUCCESS)
				goto err;
			if (block == 0) {
				create = false;
				goto out;
			}
		} else
			break;
	}
	if (i == MAX_DATA_OBJS) {
		ret = SD_RES_NO_SPACE;
		goto err;
	}
out:
	idata->create = create;
	idata->idx = idx;
	return SD_RES_SUCCESS;
err:
	return ret;
}

static inline int inode_create(struct inode *inode, uint32_t vid,
			       const char *name)
{
	struct inode_data *id = prepare_inode_data(inode, vid, name);
	int ret;

	sys->cdrv->lock(vid);
	ret = inode_lookup(id);
	if (ret == SD_RES_SUCCESS)
		ret = inode_do_create(id);
	else
		sd_err("failed to lookup %s", name);
	sys->cdrv->unlock(vid);
	finish_inode_data(id);
	return ret;
}

static void dentry_add(struct inode *parent, struct dentry *dentry)
{
	uint8_t *tail = parent->data + parent->size;

	parent->nlink++;
	memcpy(tail, dentry, sizeof(*dentry));
	parent->size += sizeof(*dentry);
}

int fs_create_dir(struct inode *inode, const char *name, struct inode *parent)
{
	uint64_t myino, pino = parent->ino;
	uint32_t vid = oid_to_vid(pino);
	struct inode_data *id = prepare_inode_data(inode, vid, name);
	struct dentry *entry;
	int ret;

	sys->cdrv->lock(vid);
	ret = inode_lookup(id);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to lookup %s", name);
		goto out;
	}

	myino = vid_to_data_oid(id->vid, id->idx);

	inode->nlink = 2; /* '.' and 'name' */
	inode->size = 2 * sizeof(struct dentry);
	inode->used = INODE_DATA_SIZE;
	entry = (struct dentry *)inode->data;
	entry->ino = myino;
	entry->nlen = 1;
	entry->name[0] = '.';
	entry++;
	entry->ino = pino;
	entry->nlen = 2;
	entry->name[0] = '.';
	entry->name[1] = '.';

	if (unlikely(inode == parent))
		inode->nlink++; /* I'm root */
	else {
		struct dentry new = {
			.ino = myino,
			.nlen = strlen(name),
		};
		pstrcpy(new.name, NFS_MAXNAMLEN, name);
		dentry_add(parent, &new);
	}

	ret = inode_do_create(id);
	if (ret != SD_RES_SUCCESS)
		goto out;
	ret = fs_write_inode_full(parent);
out:
	sys->cdrv->unlock(vid);
	finish_inode_data(id);
	return ret;
}

int fs_make_root(uint32_t vid)
{
	struct inode *root = xzalloc(sizeof(*root));
	int ret;

	root->mode = S_IFDIR | sd_def_dmode;
	root->uid = 0;
	root->gid = 0;
	root->atime = root->mtime = root->ctime = time(NULL);
	root->ino = fs_root_ino(vid);

	ret = fs_create_dir(root, "/", root);
	free(root);
	return ret;
}

uint64_t fs_root_ino(uint32_t vid)
{
	return vid_to_data_oid(vid, ROOT_IDX);
}

static struct inode *inode_read(uint64_t ino, uint64_t size)
{
	struct inode *inode = xmalloc(size);
	long ret;

	ret = sd_read_object(ino, (char *)inode, size, 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to read %" PRIx64 " %s", ino, sd_strerror(ret));
		free(inode);
		inode = (struct inode *)-ret;
	}
	return inode;
}

struct inode *fs_read_inode_hdr(uint64_t ino)
{
	return inode_read(ino, INODE_HDR_SIZE);
}

struct inode *fs_read_inode_full(uint64_t ino)
{
	return inode_read(ino, sizeof(struct inode));
}

static int inode_write(struct inode *inode, uint64_t size)
{
	uint64_t oid = inode->ino;
	int ret;

	ret = sd_write_object(oid, (char *)inode, size, 0, 0);
	if (ret != SD_RES_SUCCESS)
		sd_err("failed to write %" PRIx64" %s", oid, sd_strerror(ret));

	return ret;
}

int fs_write_inode_hdr(struct inode *inode)
{
	return inode_write(inode, INODE_HDR_SIZE);
}

int fs_write_inode_full(struct inode *inode)
{
	return inode_write(inode, sizeof(*inode));
}

int fs_read_dir(struct inode *inode, uint64_t offset,
		int (*dentry_reader)(struct inode *, struct dentry *, void *),
		void *data)
{
	struct dentry *entry = (struct dentry *)(inode->data + offset);
	int ret = SD_RES_SUCCESS;
	uint64_t dentry_count = inode->size / sizeof(struct dentry);
	uint64_t i;

	sd_debug("%"PRIu64", %"PRIu64, offset, inode->size);

	for (i = offset / sizeof(*entry); i < dentry_count; i++) {
		ret = dentry_reader(inode, entry + i, data);
		if (ret != SD_RES_SUCCESS)
			break;
	}
	return ret;
}

static int dentry_compare(struct dentry *a, struct dentry *b)
{
	return strcmp(a->name, b->name);
}

struct dentry *fs_lookup_dir(struct inode *inode, const char *name)
{
	struct dentry *tmp, *base = (struct dentry *)inode->data;
	struct dentry *key = xmalloc(sizeof(*key));
	uint64_t dentry_count = inode->size / sizeof(struct dentry);

	sd_debug("%"PRIx64", %s", inode->ino, name);

	pstrcpy(key->name, NFS_MAXNAMLEN, name);

	tmp = xlfind(key, base, dentry_count, dentry_compare);
	if (tmp)
		*key = *tmp;
	else {
		free(key);
		key = (struct dentry *)-SD_RES_NOT_FOUND;
	}

	return key;
}

int fs_create_file(uint64_t pino, struct inode *new, const char *name)
{
	uint32_t vid = oid_to_vid(pino);
	struct inode *inode;
	struct dentry *dentry;
	int ret;

	ret = inode_create(new, vid, name);
	if (ret != SD_RES_SUCCESS)
		return ret;

	inode = fs_read_inode_full(pino);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	dentry = (struct dentry *)(inode->data + inode->size);
	pstrcpy(dentry->name, NFS_MAXNAMLEN, name);
	dentry->ino = new->ino;
	inode->size += sizeof(*dentry);

	ret = fs_write_inode_full(inode);
	free(inode);
	return ret;
}

/* TODO: support extent */
int64_t fs_read(struct inode *inode, void *buffer, uint64_t count,
		uint64_t offset)
{
	uint8_t *start = inode->data + offset;
	int64_t done = count;

	if (offset >= inode->size || count == 0)
		return 0;

	if (offset + count > inode->size)
		done = inode->size - offset;

	memcpy(buffer, start, done);

	return done;
}

int64_t fs_write(struct inode *inode, void *buffer, uint64_t count,
		 uint64_t offset)
{
	uint8_t *start = inode->data + offset;
	int64_t done = count;
	int ret;

	if (count == 0)
		return 0;

	memcpy(start, buffer, done);

	/* TODO: lock inode */
	if ((offset + done) > inode->size)
		inode->size = offset + done;

	inode->mtime = time(NULL);
	ret = fs_write_inode_full(inode);
	if (ret != SD_RES_SUCCESS)
		done = -1;
	return done;
}
