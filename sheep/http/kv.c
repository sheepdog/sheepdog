/*
 * Copyright (C) 2013 MORITA Kazutaka <morita.kazutaka@gmail.com>
 * Copyright (C) 2013 Robin Dong <sanbai@taobao.com>
 * Copyright (C) 2013 Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/* This file implements backend kv functions for object storage. */

#include "sheep_priv.h"
#include "http.h"

uint64_t kv_rw_buffer = DEFAULT_KV_RW_BUFFER;

struct kv_bnode {
	char name[SD_MAX_BUCKET_NAME];
	uint64_t object_count;
	uint64_t bytes_used;
	uint64_t oid;
};

struct onode_extent {
	uint64_t start;
	uint64_t count;
};

struct kv_onode {
	union {
		struct {
			char name[SD_MAX_OBJECT_NAME];
			/* a hash value for etag */
			uint8_t sha1[round_up(SHA1_DIGEST_SIZE, 8)];
			uint64_t size;
			uint64_t mtime;
			uint32_t data_vid;
			uint32_t nr_extent;
			uint64_t oid;
			uint8_t inlined;
		};

		uint8_t pad[BLOCK_SIZE];
	};
	union {
		uint8_t data[SD_DATA_OBJ_SIZE - BLOCK_SIZE];
		struct onode_extent o_extent[0];
	};
};

typedef void (*bucket_iter_cb)(const char *bucket, void *opaque);

struct bucket_iterater_arg {
	void *opaque;
	bucket_iter_cb cb;
	uint64_t bucket_count;
	uint64_t object_count;
	uint64_t bytes_used;
};

/* Account operations */

/*
 * Account can have unlimited buckets, each of which can contain unlimited user
 * KV objects.
 *
 * For a URI such as /$account/$bucket/$object:
 *
 *      kv_bnode helps us find the desired bucket by $bucket
 *             |
 *             V
 *   $account --> [bucket1, bucket2, bucket3, ...]
 *                    |
 *                    | kv_onode helps us find the desired object by $object
 *                    V
 *                  [object1, object2, ...]
 *
 * We assign a hyper volume for each account to hold the kv_bnodes(bucket index
 * node), each of which point to a bucket(also a hyper volume), into which we
 * store kv_onodes, that maps to user kv data objects.
 */

int kv_create_account(const char *account)
{
	uint32_t vdi_id;
	return sd_create_hyper_volume(account, &vdi_id);
}

static void bucket_iterater(void *data, enum btree_node_type type, void *arg)
{
	struct sd_index *ext;
	struct bucket_iterater_arg *biarg = arg;
	struct kv_bnode bnode;
	uint64_t oid;
	int ret;

	if (type == BTREE_INDEX) {
		ext = (struct sd_index *)data;
		if (!ext->vdi_id)
			return;

		oid = vid_to_data_oid(ext->vdi_id, ext->idx);
		ret = sd_read_object(oid, (char *)&bnode, sizeof(bnode), 0);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to read data object %"PRIx64, oid);
			return;
		}

		if (bnode.name[0] == 0)
			return;
		if (biarg->cb)
			biarg->cb(bnode.name, biarg->opaque);
		biarg->bucket_count++;
		biarg->object_count += bnode.object_count;
		biarg->bytes_used += bnode.bytes_used;
	}
}

static int read_account_meta(const char *account, uint64_t *bucket_count,
			     uint64_t *object_count, uint64_t *used)
{
	struct sd_inode *inode = NULL;
	struct bucket_iterater_arg arg = {};
	uint32_t account_vid;
	uint64_t oid;
	int ret;

	ret = sd_lookup_vdi(account, &account_vid);
	if (ret != SD_RES_SUCCESS)
		goto out;

	oid = vid_to_vdi_oid(account_vid);
	inode = xmalloc(sizeof(*inode));
	ret = sd_read_object(oid, (char *)inode, sizeof(struct sd_inode), 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to read inode header %"PRIx64, oid);
		goto out;
	}

	traverse_btree(inode, bucket_iterater, &arg);
	*object_count = arg.object_count;
	*bucket_count = arg.bucket_count;
	*used = arg.bytes_used;
out:
	free(inode);
	return ret;
}

int kv_read_account_meta(struct http_request *req, const char *account)
{
	uint64_t bcount, ocount, used;
	int ret;

	ret = read_account_meta(account, &bcount, &ocount, &used);
	if (ret != SD_RES_SUCCESS)
		return ret;

	http_request_writef(req, "X-Account-Container-Count: %"PRIu64"\n",
			    bcount);
	http_request_writef(req, "X-Account-Object-Count: %"PRIu64"\n", ocount);
	http_request_writef(req, "X-Account-Bytes-Used: %"PRIu64"\n", used);
	return ret;
}

int kv_update_account(const char *account)
{
	/* TODO: update metadata of the account */
	return -1;
}

int kv_delete_account(struct http_request *req, const char *account)
{
	uint64_t bcount, ocount, used;
	int ret;

	ret = read_account_meta(account, &bcount, &ocount, &used);
	if (ret != SD_RES_SUCCESS)
		return ret;

	if (bcount)
		return SD_RES_VDI_NOT_EMPTY;

	ret = sd_delete_vdi(account);
	if (ret != SD_RES_SUCCESS)
		sd_err("Failed to delete vdi %s", account);
	return ret;
}

/* Bucket operations */

/*
 * We use two VDIs to implement bucket abstraction: one stores 'struct kv_onode'
 * which is an index node for user data and the other actually stores kv data,
 * which use oalloc.c to manage free space.
 *
 * The first vdi is named as "$account/$bucket" and the second vdi as
 * "$account/$bucket/allocator".
 *
 * For example: bucket "fruit" with account 'coly' has two objects "banana"
 *              and "apple"
 *
 * Account: coly
 * +-----------------------+
 * | kv_bnode: fruit | ... |    <--- account_vid
 * +-----------------------+
 *         |            +--------------------- kv_onode ---------------------+
 *         |            |                                                    |
 *          \           v                                                    v
 *	     \       +---------------------------------------------------------+
 * bucket_vdi  \---> |coly/fruit | ... | kv_onode: banana | kv_onode: apple    |
 *                   +---------------------------------------------------------+
 *                                                    |             |
 *      oalloc.c manages allocation and deallocation  |             |
 *		                                      v             v
 *                   +---------------------------+---+-----------------+
 * data_vid          |coly/fruit/allocator       |...|       data      |
 *                   +---------------------------+---+-----------------+
 */

static int bnode_do_create(struct kv_bnode *bnode, struct sd_inode *inode,
			   uint32_t idx)
{
	uint32_t vid = inode->vdi_id;
	uint64_t oid = vid_to_data_oid(vid, idx);
	int ret;

	bnode->oid = oid;
	ret = sd_write_object(oid, (char *)bnode, sizeof(*bnode), 0, true);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to create object, %" PRIx64, oid);
		goto out;
	}
	sd_inode_set_vid(inode, idx, vid);
	ret = sd_inode_write_vid(inode, idx, vid, vid, 0, false, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update inode, %" PRIx64,
		       vid_to_vdi_oid(vid));
		goto out;
	}
out:
	return ret;
}

static int bnode_create(struct kv_bnode *bnode, uint32_t account_vid)
{
	struct sd_inode *inode = xmalloc(sizeof(struct sd_inode));
	uint32_t tmp_vid, idx;
	uint64_t hval, i;
	int ret;

	ret = sd_read_object(vid_to_vdi_oid(account_vid), (char *)inode,
			       sizeof(*inode), 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to read %" PRIx32 " %s", account_vid,
		       sd_strerror(ret));
		goto out;
	}

	hval = sd_hash(bnode->name, strlen(bnode->name));
	for (i = 0; i < MAX_DATA_OBJS; i++) {
		idx = (hval + i) % MAX_DATA_OBJS;
		tmp_vid = sd_inode_get_vid(inode, idx);
		if (tmp_vid)
			continue;
		else
			break;
	}
	if (i == MAX_DATA_OBJS) {
		ret = SD_RES_NO_SPACE;
		goto out;
	}
	ret = bnode_do_create(bnode, inode, idx);
out:
	free(inode);
	return ret;
}

static int bucket_create(const char *account, uint32_t account_vid,
			 const char *bucket)
{
	char onode_name[SD_MAX_VDI_LEN];
	char alloc_name[SD_MAX_VDI_LEN];
	struct kv_bnode bnode;
	uint32_t vid;
	int ret;

	snprintf(onode_name, SD_MAX_VDI_LEN, "%s/%s", account, bucket);
	ret = sd_create_hyper_volume(onode_name, &vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to create bucket %s onode vid", bucket);
		return ret;
	}
	snprintf(alloc_name, SD_MAX_VDI_LEN, "%s/%s/allocator", account,
		 bucket);
	ret = sd_create_hyper_volume(alloc_name, &vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to create bucket %s data vid", bucket);
		sd_delete_vdi(onode_name);
		return ret;
	}
	ret = oalloc_init(vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to init allocator for bucket %s", bucket);
		goto err;
	}

	pstrcpy(bnode.name, sizeof(bnode.name), bucket);
	bnode.bytes_used = 0;
	bnode.object_count = 0;
	ret = bnode_create(&bnode, account_vid);
	if (ret != SD_RES_SUCCESS)
		goto err;

	return SD_RES_SUCCESS;
err:
	sd_delete_vdi(onode_name);
	sd_delete_vdi(alloc_name);
	return ret;
}

static int bnode_lookup(struct kv_bnode *bnode, uint32_t vid, const char *name)
{
	uint64_t hval, i;
	int ret;

	hval = sd_hash(name, strlen(name));
	for (i = 0; i < MAX_DATA_OBJS; i++) {
		uint32_t idx = (hval + i) % MAX_DATA_OBJS;
		uint64_t oid = vid_to_data_oid(vid, idx);

		ret = sd_read_object(oid, (char *)bnode, sizeof(*bnode), 0);
		if (ret != SD_RES_SUCCESS)
			goto out;
		if (strcmp(bnode->name, name) == 0)
			break;
	}

	if (i == MAX_DATA_OBJS)
		ret = SD_RES_NO_OBJ;
out:
	return ret;
}

/*
 * For object create/delete, we can't easily maintain the bnode consistent by
 * playing around the operations order.
 *
 * We should inform the user the deletion failure if bnode_update() fails even
 * though we might delete the onode successfully. Then subsequent 'delete' for
 * the same object won't skew up the bnode metadata.
 * The true fix for the inconsistency (for whatever reaons it happens), is a
 * check request that does a server side consistency check. This is left for a
 * future patch.
 *
 * Alternative fix is that we drop the redundant data about bytes_used,
 * object_counts from bnode, and so for "HEAD" operation, we just iterate all
 * the objects. This can't scale if we have huge objects.
 */
static int bnode_update(const char *account, const char *bucket, uint64_t used,
			bool create)
{
	uint32_t account_vid;
	struct kv_bnode bnode;
	int ret;

	ret = sd_lookup_vdi(account, &account_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to find account %s", account);
		return ret;
	}

	ret = bnode_lookup(&bnode, account_vid, bucket);
	if (ret != SD_RES_SUCCESS)
		return ret;

	if (create) {
		bnode.object_count++;
		bnode.bytes_used += used;
	} else {
		bnode.object_count--;
		bnode.bytes_used -= used;
	}

	ret = sd_write_object(bnode.oid, (char *)&bnode, sizeof(bnode), 0, 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update bnode for %s", bucket);
		return ret;
	}
	return SD_RES_SUCCESS;
}

static int bucket_delete(const char *account, uint32_t avid, const char *bucket)
{
	struct kv_bnode bnode;
	char onode_name[SD_MAX_VDI_LEN];
	char alloc_name[SD_MAX_VDI_LEN];
	int ret;

	snprintf(onode_name, SD_MAX_VDI_LEN, "%s/%s", account, bucket);
	snprintf(alloc_name, SD_MAX_VDI_LEN, "%s/%s/allocator", account,
		 bucket);

	ret = bnode_lookup(&bnode, avid, bucket);
	if (ret != SD_RES_SUCCESS)
		return ret;

	if (bnode.object_count > 0)
		return SD_RES_VDI_NOT_EMPTY;

	ret = sd_discard_object(bnode.oid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to discard bnode for %s", bucket);
		return ret;
	}
	sd_delete_vdi(onode_name);
	sd_delete_vdi(alloc_name);

	return SD_RES_SUCCESS;
}

typedef void (*object_iter_cb)(const char *object, void *opaque);

struct object_iterater_arg {
	void *opaque;
	object_iter_cb cb;
	uint32_t count;
};

static void object_iterater(void *data, enum btree_node_type type, void *arg)
{
	struct sd_index *ext;
	struct object_iterater_arg *oiarg = arg;
	struct kv_onode *onode = NULL;
	uint64_t oid;
	int ret;

	if (type == BTREE_INDEX) {
		ext = (struct sd_index *)data;
		if (!ext->vdi_id)
			goto out;

		onode = xmalloc(SD_DATA_OBJ_SIZE);
		oid = vid_to_data_oid(ext->vdi_id, ext->idx);
		ret = sd_read_object(oid, (char *)onode, SD_DATA_OBJ_SIZE, 0);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to read data object %"PRIx64, oid);
			goto out;
		}

		if (onode->name[0] == '\0')
			goto out;
		if (oiarg->cb)
			oiarg->cb(onode->name, oiarg->opaque);
		oiarg->count++;
	}
out:
	free(onode);
}

static int bucket_iterate_object(uint32_t bucket_vid, object_iter_cb cb,
				 void *opaque)
{
	struct object_iterater_arg arg = {opaque, cb, 0};
	struct sd_inode *inode;
	int ret;

	inode = xmalloc(sizeof(*inode));
	ret = sd_read_object(vid_to_vdi_oid(bucket_vid), (char *)inode,
			     sizeof(struct sd_inode), 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to read inode %s", sd_strerror(ret));
		goto out;
	}

	traverse_btree(inode, object_iterater, &arg);
out:
	free(inode);
	return ret;
}

int kv_create_bucket(const char *account, const char *bucket)
{
	uint32_t account_vid, vid;
	char vdi_name[SD_MAX_VDI_LEN];
	int ret;

	ret = sd_lookup_vdi(account, &account_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to find account %s", account);
		return ret;
	}

	sys->cdrv->lock(account_vid);
	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s", account, bucket);
	ret = sd_lookup_vdi(vdi_name, &vid);
	if (ret == SD_RES_SUCCESS) {
		sd_err("bucket %s is exists.", bucket);
		ret = SD_RES_VDI_EXIST;
		goto out;
	}
	if (ret != SD_RES_NO_VDI)
		goto out;

	ret = bucket_create(account, account_vid, bucket);
out:
	sys->cdrv->unlock(account_vid);
	return ret;
}

int kv_read_bucket(struct http_request *req, const char *account,
		   const char *bucket)
{
	uint32_t account_vid;
	struct kv_bnode bnode;
	int ret;

	ret = sd_lookup_vdi(account, &account_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to find account %s", account);
		return ret;
	}

	ret = bnode_lookup(&bnode, account_vid, bucket);
	if (ret != SD_RES_SUCCESS)
		goto out;
	http_request_writef(req, "X-Container-Object-Count: %"PRIu64"\n",
			    bnode.object_count);

	http_request_writef(req, "X-Container-Bytes-Used: %"PRIu64"\n",
			    bnode.bytes_used);
out:
	return ret;
}

int kv_update_bucket(const char *account, const char *bucket)
{
	/* TODO: update metadata of the bucket */
	return -1;
}

/* return SD_RES_NO_VDI if bucket is not existss */
int kv_delete_bucket(const char *account, const char *bucket)
{
	uint32_t account_vid, vid;
	char vdi_name[SD_MAX_VDI_LEN];
	int ret;

	ret = sd_lookup_vdi(account, &account_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to find account %s", account);
		return ret;
	}

	sys->cdrv->lock(account_vid);
	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s", account, bucket);

	ret = sd_lookup_vdi(vdi_name, &vid);
	if (ret != SD_RES_SUCCESS)
		goto out;
	ret = bucket_delete(account, account_vid, bucket);
out:
	sys->cdrv->unlock(account_vid);
	return ret;
}

int kv_iterate_bucket(const char *account, bucket_iter_cb cb, void *opaque)
{
	struct sd_inode account_inode;
	struct bucket_iterater_arg arg = {opaque, cb, 0, 0, 0};
	uint32_t account_vid;
	uint64_t oid;
	int ret;

	ret = sd_lookup_vdi(account, &account_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to find account %s", account);
		return ret;
	}

	oid = vid_to_vdi_oid(account_vid);
	sys->cdrv->lock(account_vid);
	ret = sd_read_object(oid, (char *)&account_inode,
			     sizeof(struct sd_inode), 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to read account inode header %s", account);
		goto out;
	}

	traverse_btree(&account_inode, bucket_iterater, &arg);
out:
	sys->cdrv->unlock(account_vid);
	return ret;
}

/* Object operations */

#define KV_ONODE_INLINE_SIZE (SD_DATA_OBJ_SIZE - BLOCK_SIZE)

static int vdi_read_write(uint32_t vid, char *data, size_t length,
			  off_t offset, bool is_read)
{
	struct sd_req hdr;
	uint32_t idx = offset / SD_DATA_OBJ_SIZE;
	uint64_t done = 0;
	struct request_iocb *iocb;
	int ret;

	iocb = local_req_init();
	if (!iocb)
		return SD_RES_SYSTEM_ERROR;

	offset %= SD_DATA_OBJ_SIZE;
	while (done < length) {
		size_t len = min(length - done, SD_DATA_OBJ_SIZE - offset);

		if (is_read) {
			sd_init_req(&hdr, SD_OP_READ_OBJ);
		} else {
			sd_init_req(&hdr, SD_OP_CREATE_AND_WRITE_OBJ);
			hdr.flags = SD_FLAG_CMD_WRITE;
		}
		hdr.data_length = len;
		hdr.obj.oid = vid_to_data_oid(vid, idx);
		hdr.obj.offset = offset;

		ret = exec_local_req_async(&hdr, data, iocb);
		if (ret != SD_RES_SUCCESS)
			sd_err("failed to write object %" PRIx64 ", %s",
			       hdr.obj.oid, sd_strerror(ret));

		offset += len;
		if (offset == SD_DATA_OBJ_SIZE) {
			offset = 0;
			idx++;
		}
		done += len;
		data += len;
	}

	return local_req_wait(iocb);
}

static int onode_populate_extents(struct kv_onode *onode,
				  struct http_request *req)
{
	ssize_t size;
	uint64_t start = 0, count, done = 0, total, offset;
	int ret;
	char *data_buf = NULL;
	uint32_t data_vid = onode->data_vid;
	uint64_t write_buffer_size = MIN(kv_rw_buffer, req->data_length);

	count = DIV_ROUND_UP(req->data_length, SD_DATA_OBJ_SIZE);
	sys->cdrv->lock(data_vid);
	ret = oalloc_new_prepare(data_vid, &start, count);
	sys->cdrv->unlock(data_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("oalloc_new_prepare failed for %s, %s", onode->name,
		       sd_strerror(ret));
		goto out;
	}

	data_buf = xmalloc(write_buffer_size);
	offset = start * SD_DATA_OBJ_SIZE;
	total = req->data_length;
	while (done < total) {
		size = http_request_read(req, data_buf, write_buffer_size);
		if (size <= 0) {
			sd_err("Failed to read http request: %ld", size);
			sys->cdrv->lock(data_vid);
			oalloc_free(data_vid, start, count);
			sys->cdrv->unlock(data_vid);
			ret = SD_RES_EIO;
			goto out;
		}
		ret = vdi_read_write(data_vid, data_buf, size, offset, false);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to write data object for %s, %s",
			       onode->name, sd_strerror(ret));
			sys->cdrv->lock(data_vid);
			oalloc_free(data_vid, start, count);
			sys->cdrv->unlock(data_vid);
			goto out;
		}
		done += size;
		offset += size;
	}

	sys->cdrv->lock(data_vid);
	ret = oalloc_new_finish(data_vid, start, count);
	sys->cdrv->unlock(data_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("oalloc_new_finish failed for %s, %s", onode->name,
		       sd_strerror(ret));
		goto out;
	}

	onode->o_extent[0].start = start;
	onode->o_extent[0].count = count;
	onode->nr_extent = 1;
out:
	free(data_buf);
	return ret;
}

static uint64_t get_seconds(void)
{
	struct timeval tv;
	uint64_t seconds;

	gettimeofday(&tv, NULL);
	seconds = (uint64_t)tv.tv_sec;
	return seconds;
}

static int onode_populate_data(struct kv_onode *onode, struct http_request *req)
{
	ssize_t size;
	int ret = SD_RES_SUCCESS;

	if (req->data_length <= KV_ONODE_INLINE_SIZE) {
		onode->inlined = 1;
		size = http_request_read(req, onode->data, sizeof(onode->data));
		if (size < 0 || req->data_length != size) {
			sd_err("Failed to read from web server for %s",
			       onode->name);
			ret = SD_RES_SYSTEM_ERROR;
			goto out;
		}
	} else {
		ret = onode_populate_extents(onode, req);
		if (ret != SD_RES_SUCCESS)
			goto out;
	}

	onode->mtime = get_seconds();
	onode->size = req->data_length;
out:
	return ret;
}

static int onode_do_create(struct kv_onode *onode, struct sd_inode *inode,
			   uint32_t idx, bool create)
{
	uint32_t vid = inode->vdi_id;
	uint64_t oid = vid_to_data_oid(vid, idx), len;
	int ret;

	onode->oid = oid;
	if (onode->inlined)
		len = onode->size;
	else
		len = sizeof(struct onode_extent) * onode->nr_extent;

	ret = sd_write_object(oid, (char *)onode, BLOCK_SIZE + len,
			      0, create);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to create object, %" PRIx64, oid);
		goto out;
	}
	if (!create)
		goto out;

	sd_inode_set_vid(inode, idx, vid);
	ret = sd_inode_write_vid(inode, idx, vid, vid, 0, false, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update inode, %" PRIx64,
		       vid_to_vdi_oid(vid));
		goto out;
	}
out:
	return ret;
}

static int onode_create(struct kv_onode *onode, uint32_t bucket_vid)
{
	struct sd_inode *inode = xmalloc(sizeof(struct sd_inode));
	uint32_t tmp_vid, idx;
	uint64_t hval, i;
	int ret;
	bool create = true;

	sys->cdrv->lock(bucket_vid);
	ret = sd_read_object(vid_to_vdi_oid(bucket_vid), (char *)inode,
			       sizeof(*inode), 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to read %" PRIx32 " %s", bucket_vid,
		       sd_strerror(ret));
		goto out;
	}

	hval = sd_hash(onode->name, strlen(onode->name));
	for (i = 0; i < MAX_DATA_OBJS; i++) {
		idx = (hval + i) % MAX_DATA_OBJS;
		tmp_vid = sd_inode_get_vid(inode, idx);
		if (tmp_vid) {
			uint64_t oid = vid_to_data_oid(bucket_vid, idx);
			char name[SD_MAX_OBJECT_NAME] = { };

			ret = sd_read_object(oid, name, sizeof(name), 0);
			if (ret != SD_RES_SUCCESS)
				goto out;
			if (name[0] == 0) {
				create = false;
				goto create;
			}
		} else
			break;
	}
	if (i == MAX_DATA_OBJS) {
		ret = SD_RES_NO_SPACE;
		goto out;
	}
create:
	ret = onode_do_create(onode, inode, idx, create);
out:
	free(inode);
	sys->cdrv->unlock(bucket_vid);
	return ret;
}

static int onode_free_data(struct kv_onode *onode)
{
	uint32_t data_vid = onode->data_vid;
	int ret = SD_RES_SUCCESS;

	/* it don't need to free data for inlined onode */
	if (!onode->inlined) {
		sys->cdrv->lock(data_vid);
		ret = oalloc_free(data_vid, onode->o_extent[0].start,
				  onode->o_extent[0].count);
		sys->cdrv->unlock(data_vid);
		if (ret != SD_RES_SUCCESS)
			sd_err("failed to free %s", onode->name);
	}
	return ret;
}

static int onode_read_extents(struct kv_onode *onode, struct http_request *req)
{
	struct onode_extent *ext;
	uint64_t size, total, total_size, offset, done = 0, i, ext_len;
	uint64_t off = req->offset, len = req->data_length;
	int ret;
	char *data_buf = NULL;
	uint64_t read_buffer_size = MIN(kv_rw_buffer, onode->size);

	data_buf = xmalloc(read_buffer_size);
	total_size = len;
	for (i = 0; i < onode->nr_extent; i++) {
		ext = onode->o_extent + i;
		ext_len = ext->count * SD_DATA_OBJ_SIZE;
		if (off >= ext_len) {
			off -= ext_len;
			continue;
		}
		total = min(ext_len - off, total_size);
		offset = ext->start * SD_DATA_OBJ_SIZE + off;
		off = 0;
		done = 0;
		while (done < total) {
			size = MIN(total - done, read_buffer_size);
			ret = vdi_read_write(onode->data_vid, data_buf,
					     size, offset, true);
			sd_debug("vdi_read_write size: %"PRIx64", offset: %"
				 PRIx64, size, offset);
			if (ret != SD_RES_SUCCESS) {
				sd_err("Failed to read for vid %"PRIx32,
				       onode->data_vid);
				goto out;
			}
			http_request_write(req, data_buf, size);
			done += size;
			offset += size;
			total_size -= size;
		}
	}
out:
	free(data_buf);
	return ret;
}

/*
 * Check if object by name exists in a bucket and init 'onode' if it exists.
 *
 * Return SD_RES_SUCCESS if found, SD_RES_NO_OBJ if not found.
 *
 * We check adjacent objects one by one once we get a start index by hashing
 * name. Unallocated slot marks the end of the check window.
 *
 * For e.g, if we are going to check if fish in the following bucket, assume
 * fish hashes to 'sheep', so we compare the name one by one from 'sheep' to
 * 'fish'. '\0' indicates that object was deleted before checking.
 *
 * [ sheep, dog, wolve, '\0', fish, {unallocated}, tiger, ]
 */
static int onode_lookup(struct kv_onode *onode, uint32_t ovid, const char *name)
{
	struct sd_inode *inode = xmalloc(sizeof(struct sd_inode));
	uint32_t tmp_vid, idx;
	uint64_t hval, i;
	int ret;

	sys->cdrv->lock(ovid);
	ret = sd_read_object(vid_to_vdi_oid(ovid), (char *)inode,
			     sizeof(*inode), 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to read %" PRIx32 " %s", ovid,
		       sd_strerror(ret));
		goto out;
	}

	hval = sd_hash(name, strlen(name));
	for (i = 0; i < MAX_DATA_OBJS; i++) {
		idx = (hval + i) % MAX_DATA_OBJS;
		tmp_vid = sd_inode_get_vid(inode, idx);
		if (tmp_vid) {
			uint64_t oid = vid_to_data_oid(ovid, idx);

			ret = sd_read_object(oid, (char *)onode,
					     sizeof(*onode), 0);
			if (ret != SD_RES_SUCCESS)
				goto out;
			if (strcmp(onode->name, name) == 0)
				break;
		} else {
			ret = SD_RES_NO_OBJ;
			break;
		}
	}
	if (i == MAX_DATA_OBJS) {
		ret = SD_RES_NO_OBJ;
		goto out;
	}
out:
	free(inode);
	sys->cdrv->unlock(ovid);
	return ret;
}

static int onode_read_data(struct kv_onode *onode, struct http_request *req)
{
	int ret;
	uint64_t off = 0, len = onode->size;

	if (req->offset || req->data_length) {
		off = req->offset;
		len = req->data_length;
		if ((off + len - 1) > onode->size) {
			if (onode->size > off)
				len = onode->size - off;
			else
				len = 0;
		}
	}

	req->data_length = len;
	if (!len)
		return SD_RES_INVALID_PARMS;

	http_response_header(req, OK);

	if (!onode->inlined)
		return onode_read_extents(onode, req);

	ret = http_request_write(req, onode->data + off, len);
	if (ret != len)
		return SD_RES_SYSTEM_ERROR;

	return SD_RES_SUCCESS;
}

/*
 * We free the data and meta data in following sequence:
 *
 * 1. zero onode
 *  - we can't discard it because onode_lookup() need it to find if some object
 *    exists or not by checking adjacent objects
 * 2. discard data
 *
 * If (1) success, we consdier it a successful deletion of user object. If (2)
 * fails, data objects become orphan(s).
 *
 * XXX: GC the orphans
 */
static int onode_delete(struct kv_onode *onode)
{
	char name[SD_MAX_OBJECT_NAME] = {};
	int ret;

	ret = sd_write_object(onode->oid, name, sizeof(name), 0, 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to zero onode for %s", onode->name);
		return ret;
	}

	ret = onode_free_data(onode);
	if (ret != SD_RES_SUCCESS)
		sd_err("failed to free data for %s", onode->name);

	return SD_RES_SUCCESS;
}

/*
 * user object name -> struct kv_onode -> sheepdog objects -> user data
 *
 * onode is a index node that maps name to sheepdog objects which hold the user
 * data, similar to UNIX inode. We use simple hashing for [name, onode] mapping.
 */
int kv_create_object(struct http_request *req, const char *account,
		     const char *bucket, const char *name)
{
	char vdi_name[SD_MAX_VDI_LEN];
	struct kv_onode *onode;
	uint32_t bucket_vid, data_vid;
	int ret;

	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s", account, bucket);
	ret = sd_lookup_vdi(vdi_name, &bucket_vid);
	if (ret != SD_RES_SUCCESS)
		return ret;

	onode = xzalloc(sizeof(*onode));
	ret = onode_lookup(onode, bucket_vid, name);
	if (ret == SD_RES_SUCCESS) {
		/* For overwrite, we delete old object and then create */
		ret = kv_delete_object(account, bucket, name);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to delete exists object %s", name);
			goto out;
		}
	} else if (ret != SD_RES_NO_OBJ)
		goto out;

	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s/allocator", account, bucket);
	ret = sd_lookup_vdi(vdi_name, &data_vid);
	if (ret != SD_RES_SUCCESS)
		goto out;

	memset(onode, 0, sizeof(*onode));
	pstrcpy(onode->name, sizeof(onode->name), name);
	onode->data_vid = data_vid;

	ret = onode_populate_data(onode, req);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to write data for %s", name);
		goto out;
	}

	ret = onode_create(onode, bucket_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to create onode for %s", name);
		onode_free_data(onode);
		goto out;
	}

	ret = bnode_update(account, bucket, req->data_length, true);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update bucket for %s", name);
		onode_delete(onode);
		goto out;
	}
out:
	free(onode);
	return ret;
}

int kv_read_object(struct http_request *req, const char *account,
		   const char *bucket, const char *name)
{
	struct kv_onode *onode = NULL;
	char vdi_name[SD_MAX_VDI_LEN];
	uint32_t bucket_vid;
	int ret;

	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s", account, bucket);
	ret = sd_lookup_vdi(vdi_name, &bucket_vid);
	if (ret != SD_RES_SUCCESS)
		return ret;

	onode = xzalloc(sizeof(*onode));
	ret = onode_lookup(onode, bucket_vid, name);
	if (ret != SD_RES_SUCCESS)
		goto out;

	ret = onode_read_data(onode, req);
	if (ret != SD_RES_SUCCESS)
		sd_err("failed to read data for %s", name);
out:
	free(onode);
	return ret;
}

int kv_delete_object(const char *account, const char *bucket, const char *name)
{
	char vdi_name[SD_MAX_VDI_LEN];
	uint32_t bucket_vid;
	struct kv_onode *onode = NULL;
	int ret;

	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s", account, bucket);
	ret = sd_lookup_vdi(vdi_name, &bucket_vid);
	if (ret != SD_RES_SUCCESS)
		return ret;

	onode = xzalloc(sizeof(*onode));
	ret = onode_lookup(onode, bucket_vid, name);
	if (ret != SD_RES_SUCCESS)
		goto out;

	ret = onode_delete(onode);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to delete bnode for %s", name);
		goto out;
	}
	ret = bnode_update(account, bucket, onode->size, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update bnode for %s", name);
		goto out;
	}
out:
	free(onode);
	return ret;
}

int kv_iterate_object(const char *account, const char *bucket,
		      object_iter_cb cb, void *opaque)
{
	char vdi_name[SD_MAX_VDI_LEN];
	uint32_t bucket_vid;
	int ret;

	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s", account, bucket);
	ret = sd_lookup_vdi(vdi_name, &bucket_vid);
	if (ret != SD_RES_SUCCESS)
		return ret;

	sys->cdrv->lock(bucket_vid);
	ret = bucket_iterate_object(bucket_vid, cb, opaque);
	sys->cdrv->unlock(bucket_vid);

	return ret;
}

static char *http_time(uint64_t time_sec)
{
	static __thread char time_str[128];

	strftime(time_str, sizeof(time_str), "%a, %d %b %Y %H:%M:%S GMT",
		 gmtime((time_t *)&time_sec));
	return time_str;
}

int kv_read_object_meta(struct http_request *req, const char *account,
			const char *bucket, const char *name)
{
	struct kv_onode *onode = NULL;
	char vdi_name[SD_MAX_VDI_LEN];
	uint32_t bucket_vid;
	int ret;

	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s", account, bucket);
	ret = sd_lookup_vdi(vdi_name, &bucket_vid);
	if (ret != SD_RES_SUCCESS)
		return ret;

	onode = xzalloc(sizeof(*onode));
	ret = onode_lookup(onode, bucket_vid, name);
	if (ret != SD_RES_SUCCESS)
		goto out;

	req->data_length = onode->size;
	http_request_writef(req, "Last-Modified: %s\n",
			    http_time(onode->mtime));
out:
	free(onode);
	return ret;
}
