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
	uint64_t data_len;
};

/*
 * The processes of creating object is:
 *
 *   1. lock container
 *   2. check whether the onode is exists.
 *   3. allocate data space for object, and create onode, then write it done
 *   4. unlock container
 *   5. upload object
 *
 * This routine will avoid uploading duplicated objects but have  an exception:
 * if the client halt the uploading progress, we will have a
 * "uploading incompleted" onode.
 *
 * The solution is: we can add code for onode to identify its status.
 * A new onode will be set to "ONODE_INIT", and after uploading completed, the
 * onode will be set to  "ONODE_COMPLETE". So, when users try to use swift
 * interface to GET a "incompleted" object, sheep will find out the onode is
 * "ONODE_INIT" which means "not completed", so sheep will return
 * "partial content" for http request, and user could remove the object and
 * upload it again.
 */
#define ONODE_INIT	1	/* created and allocated space, but no data */
#define ONODE_COMPLETE	2	/* data upload complete */

#define ONODE_HDR_SIZE  BLOCK_SIZE

struct kv_onode {
	union {
		struct {
			char name[SD_MAX_OBJECT_NAME];
			/* a hash value for etag */
			uint8_t sha1[round_up(SHA1_DIGEST_SIZE, 8)];
			uint64_t size;
			uint64_t ctime;
			uint64_t mtime;
			uint32_t data_vid;
			uint32_t nr_extent;
			uint64_t oid;
			uint8_t inlined;
			uint8_t flags;
		};

		uint8_t pad[ONODE_HDR_SIZE];
	};
	union {
		uint8_t data[SD_DATA_OBJ_SIZE - ONODE_HDR_SIZE];
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

static void bucket_iterater(struct sd_index *idx, void *arg, int ignore)
{
	struct bucket_iterater_arg *biarg = arg;
	struct kv_bnode bnode;
	uint64_t oid;
	int ret;

	if (!idx->vdi_id)
		return;

	oid = vid_to_data_oid(idx->vdi_id, idx->idx);
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

	sd_inode_index_walk(inode, bucket_iterater, &arg);
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
			   uint32_t idx, bool create)
{
	uint32_t vid = inode->vdi_id;
	uint64_t oid = vid_to_data_oid(vid, idx);
	int ret;

	bnode->oid = oid;
	ret = sd_write_object(oid, (char *)bnode, sizeof(*bnode), 0, create);
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

static int bnode_create(struct kv_bnode *bnode, uint32_t account_vid)
{
	struct sd_inode *inode = xmalloc(sizeof(struct sd_inode));
	uint32_t tmp_vid, idx;
	uint64_t hval, i;
	int ret;
	bool create = true;

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
		if (tmp_vid) {
			uint64_t oid = vid_to_data_oid(account_vid, idx);
			char name[SD_MAX_BUCKET_NAME] = { };

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
	ret = bnode_do_create(bnode, inode, idx, create);
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
	struct sd_inode *inode = xmalloc(sizeof(struct sd_inode));
	uint32_t tmp_vid, idx;
	uint64_t hval, i;
	int ret;

	ret = sd_read_object(vid_to_vdi_oid(vid), (char *)inode,
			     sizeof(*inode), 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to read %" PRIx32 " %s", vid,
		       sd_strerror(ret));
		goto out;
	}

	hval = sd_hash(name, strlen(name));
	for (i = 0; i < MAX_DATA_OBJS; i++) {
		idx = (hval + i) % MAX_DATA_OBJS;
		tmp_vid = sd_inode_get_vid(inode, idx);
		if (tmp_vid) {
			uint64_t oid = vid_to_data_oid(vid, idx);
			ret = sd_read_object(oid, (char *)bnode,
							sizeof(*bnode), 0);
			if (ret != SD_RES_SUCCESS)
				goto out;
			if (strcmp(bnode->name, name) == 0)
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
	return ret;
}

/*
 * For object create/delete, we can't easily maintain the bnode consistent by
 * playing around the operations order.
 *
 * We should inform the user the deletion failure if bnode_update() fails even
 * though we might delete the onode successfully. Then subsequent 'delete' for
 * the same object won't skew up the bnode metadata.
 * The true fix for the inconsistency (for whatever reason it happens), is a
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
	char name[SD_MAX_BUCKET_NAME] = {};
	int ret;

	snprintf(onode_name, SD_MAX_VDI_LEN, "%s/%s", account, bucket);
	snprintf(alloc_name, SD_MAX_VDI_LEN, "%s/%s/allocator", account,
		 bucket);

	ret = bnode_lookup(&bnode, avid, bucket);
	if (ret != SD_RES_SUCCESS)
		return ret;

	if (bnode.object_count > 0)
		return SD_RES_VDI_NOT_EMPTY;

	/*
	 * We can't discard bnode because bnode_lookup() need it to find
	 * if some bucket exists or not by checking adjacent bnodes.
	 * So we just zero bnode.name to indicate a deleted bucket.
	 */
	ret = sd_write_object(bnode.oid, name, sizeof(name), 0, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to zero bnode for %s", bucket);
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

static void object_iterater(struct sd_index *idx, void *arg, int ignore)
{
	struct object_iterater_arg *oiarg = arg;
	struct kv_onode *onode = NULL;
	uint64_t oid, read_size;
	int ret;

	if (!idx->vdi_id)
		goto out;

	read_size = offsetof(struct kv_onode, name) + sizeof(onode->name);
	onode = xmalloc(read_size);
	oid = vid_to_data_oid(idx->vdi_id, idx->idx);
	ret = sd_read_object(oid, (char *)onode, read_size, 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to read data object %"PRIx64, oid);
		goto out;
	}

	if (onode->name[0] == '\0')
		goto out;
	if (oiarg->cb)
		oiarg->cb(onode->name, oiarg->opaque);
	oiarg->count++;
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

	sd_inode_index_walk(inode, object_iterater, &arg);
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

/* return SD_RES_NO_VDI if bucket is not existed */
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
	struct sd_inode *account_inode;
	struct bucket_iterater_arg arg = {opaque, cb, 0, 0, 0};
	uint32_t account_vid;
	uint64_t oid;
	int ret;

	ret = sd_lookup_vdi(account, &account_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to find account %s", account);
		return ret;
	}

	account_inode = xmalloc(sizeof(*account_inode));
	oid = vid_to_vdi_oid(account_vid);
	sys->cdrv->lock(account_vid);
	ret = sd_read_object(oid, (char *)account_inode,
			     sizeof(struct sd_inode), 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to read account inode header %s", account);
		goto out;
	}

	sd_inode_index_walk(account_inode, bucket_iterater, &arg);
out:
	sys->cdrv->unlock(account_vid);
	free(account_inode);
	return ret;
}

/* Object operations */

#define KV_ONODE_INLINE_SIZE (SD_DATA_OBJ_SIZE - ONODE_HDR_SIZE)

static int vdi_read_write(uint32_t vid, char *data, size_t length,
			  off_t offset, bool is_read, bool create)
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
			if (create)
				sd_init_req(&hdr, SD_OP_CREATE_AND_WRITE_OBJ);
			else
				sd_init_req(&hdr, SD_OP_WRITE_OBJ);
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
		create = true;
	}

	return local_req_wait(iocb);
}

static int onode_allocate_extents(struct kv_onode *onode,
				  struct http_request *req)
{
	uint64_t start = 0, count, reserv_len = 0;
	int ret = SD_RES_SUCCESS;
	uint32_t data_vid = onode->data_vid, idx = onode->nr_extent;

	/* if the previous o_extent[] has some extra space, use it */
	if (idx) {
		reserv_len = onode->o_extent[idx - 1].count * SD_DATA_OBJ_SIZE -
			     onode->o_extent[idx - 1].data_len;
		/*
		 * if we can put whole request data into extra space of last
		 * o_extent, it don't need to allocate new extent.
		 */
		if (req->data_length <= reserv_len) {
			onode->o_extent[idx - 1].data_len += req->data_length;
			goto out;
		} else
			onode->o_extent[idx - 1].data_len += reserv_len;
	}
	count = DIV_ROUND_UP((req->data_length - reserv_len), SD_DATA_OBJ_SIZE);
	sys->cdrv->lock(data_vid);
	ret = oalloc_new_prepare(data_vid, &start, count);
	sys->cdrv->unlock(data_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("oalloc_new_prepare failed for %s, %s", onode->name,
		       sd_strerror(ret));
		goto out;
	}

	sys->cdrv->lock(data_vid);
	ret = oalloc_new_finish(data_vid, start, count);
	sys->cdrv->unlock(data_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("oalloc_new_finish failed for %s, %s", onode->name,
		       sd_strerror(ret));
		goto out;
	}

	onode->o_extent[idx].start = start;
	onode->o_extent[idx].count = count;
	onode->o_extent[idx].data_len = req->data_length - reserv_len;
	onode->nr_extent++;
out:
	return ret;
}

static int do_vdi_write(struct http_request *req, uint32_t data_vid,
			uint64_t offset, uint64_t total, char *data_buf,
			bool create)
{
	uint64_t done = 0, size;
	int ret = SD_RES_SUCCESS;

	while (done < total) {
		size = http_request_read(req, data_buf,
					 MIN(kv_rw_buffer, total - done));
		if (size <= 0) {
			sd_err("Failed to read http request: %ld", size);
			ret = SD_RES_EIO;
			goto out;
		}
		ret = vdi_read_write(data_vid, data_buf, size, offset,
				     false, create);
		sd_debug("vdi_write offset: %"PRIu64", size: %" PRIu64
			 ", for %" PRIx32 "ret: %d", offset, size,
			 data_vid, ret);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to write data object for %" PRIx32
			       ", %s", data_vid, sd_strerror(ret));
			goto out;
		}
		done += size;
		offset += size;
	}
out:
	return ret;
}

static int onode_populate_extents(struct kv_onode *onode,
				  struct http_request *req)
{
	struct onode_extent *ext;
	struct onode_extent *last_ext = onode->o_extent + onode->nr_extent - 1;
	uint64_t total, offset = 0, reserv_len;
	uint64_t write_buffer_size = MIN(kv_rw_buffer, req->data_length);
	int ret = SD_RES_SUCCESS;
	char *data_buf = NULL;
	uint32_t data_vid = onode->data_vid;
	bool create = true;

	data_buf = xmalloc(write_buffer_size);

	if (last_ext->data_len < req->data_length) {
		ext = last_ext - 1;
		reserv_len = (req->data_length - last_ext->data_len);
		offset = (ext->start + ext->count) * SD_DATA_OBJ_SIZE -
			 reserv_len;
		ret = do_vdi_write(req, data_vid, offset, reserv_len,
				   data_buf, false);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to do_vdi_write data_vid: %" PRIx32
			       ", offset: %" PRIx64 ", total: %" PRIx64
			       ", ret: %s", data_vid, offset, reserv_len,
			       sd_strerror(ret));
			goto out;
		}
		offset = last_ext->start * SD_DATA_OBJ_SIZE;
		total = last_ext->data_len;
	} else {
		reserv_len = (last_ext->data_len - req->data_length);
		offset = last_ext->start * SD_DATA_OBJ_SIZE + reserv_len;
		total = req->data_length;
		if (last_ext->data_len > req->data_length)
			create = false;
	}

	ret = do_vdi_write(req, data_vid, offset, total, data_buf, create);
	if (ret != SD_RES_SUCCESS)
		sd_err("Failed to do_vdi_write data_vid: %" PRIx32
		       ", offset: %" PRIx64 ", total: %" PRIx64
		       ", ret: %s", data_vid, offset, total,
		       sd_strerror(ret));
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

static int onode_allocate_data(struct kv_onode *onode, struct http_request *req)
{
	int ret = SD_RES_SUCCESS;

	if (req->data_length <= KV_ONODE_INLINE_SIZE)
		onode->inlined = 1;
	else {
		ret = onode_allocate_extents(onode, req);
		if (ret != SD_RES_SUCCESS)
			goto out;
	}

	onode->ctime = get_seconds();
	onode->size += req->data_length;
out:
	return ret;
}

static int onode_append_data(struct kv_onode *onode, struct http_request *req)
{
	int ret;

	ret = onode_allocate_extents(onode, req);
	if (ret != SD_RES_SUCCESS)
		goto out;

	onode->size += req->data_length;
out:
	return ret;
}

static int onode_do_update(struct kv_onode *onode)
{
	uint64_t len;
	int ret;

	if (onode->inlined)
		len = onode->size;
	else
		len = sizeof(struct onode_extent) * onode->nr_extent;

	ret = sd_write_object(onode->oid, (char *)onode, ONODE_HDR_SIZE + len,
			      0, false);
	if (ret != SD_RES_SUCCESS)
		sd_err("Failed to update object, %" PRIx64, onode->oid);
	return ret;
}

static int onode_populate_data(struct kv_onode *onode, struct http_request *req)
{
	ssize_t size;
	int ret = SD_RES_SUCCESS;

	onode->mtime = get_seconds();
	onode->flags = ONODE_COMPLETE;

	if (req->data_length <= KV_ONODE_INLINE_SIZE) {
		size = http_request_read(req, onode->data, sizeof(onode->data));
		if (size < 0 || req->data_length != size) {
			sd_err("Failed to read from web server for %s",
			       onode->name);
			ret = SD_RES_SYSTEM_ERROR;
			goto out;
		}
		ret = sd_write_object(onode->oid, (char *)onode,
				      ONODE_HDR_SIZE + size, 0, false);
		if (ret != SD_RES_SUCCESS)
			goto out;
	} else {
		ret = onode_populate_extents(onode, req);
		if (ret != SD_RES_SUCCESS)
			goto out;
		/* write mtime and flag ONODE_COMPLETE to onode */
		ret = onode_do_update(onode);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to write mtime and flags of onode %s",
			       onode->name);
			goto out;
		}
	}
out:
	return ret;
}

static int onode_populate_append_data(struct kv_onode *onode,
				      struct http_request *req)
{
	int ret;

	onode->mtime = get_seconds();

	ret = onode_populate_extents(onode, req);
	if (ret != SD_RES_SUCCESS)
		goto out;
	ret = onode_do_update(onode);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to write mtime of onode %s", onode->name);
		goto out;
	}
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

	ret = sd_write_object(oid, (char *)onode, ONODE_HDR_SIZE + len,
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
	return ret;
}

static int onode_free_data(struct kv_onode *onode)
{
	uint32_t data_vid = onode->data_vid;
	int ret = SD_RES_SUCCESS, i;

	/* it don't need to free data for inlined onode */
	if (!onode->inlined) {
		sys->cdrv->lock(data_vid);
		for (i = 0; i < onode->nr_extent; i++) {
			ret = oalloc_free(data_vid, onode->o_extent[i].start,
					  onode->o_extent[i].count);
			if (ret != SD_RES_SUCCESS)
				sd_err("failed to free start: %"PRIu64
				       ", count: %"PRIu64", for %s",
				       onode->o_extent[i].start,
				       onode->o_extent[i].count,
				       onode->name);
		}
		sys->cdrv->unlock(data_vid);
	}
	return ret;
}

static int onode_read_extents(struct kv_onode *onode, struct http_request *req)
{
	struct onode_extent *ext;
	uint64_t size, total, total_size, offset, done = 0, i, ext_len;
	uint64_t off = req->offset, len = req->data_length;
	int ret = SD_RES_SUCCESS;
	char *data_buf = NULL;
	uint64_t read_buffer_size = MIN(kv_rw_buffer, onode->size);

	data_buf = xmalloc(read_buffer_size);
	total_size = len;
	for (i = 0; i < onode->nr_extent; i++) {
		ext = onode->o_extent + i;
		ext_len = ext->data_len;
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
					     size, offset, true, false);
			sd_debug("vdi_read size: %"PRIu64", offset: %"
				 PRIu64", ret:%d", size, offset, ret);
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
static int onode_lookup_nolock(struct kv_onode *onode, uint32_t ovid,
			       const char *name)
{
	struct sd_inode *inode = xmalloc(sizeof(struct sd_inode));
	uint32_t tmp_vid, idx;
	uint64_t hval, i;
	int ret;

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
	return ret;
}

static int onode_lookup(struct kv_onode *onode, uint32_t ovid, const char *name)
{
	int ret;

	sys->cdrv->lock(ovid);
	ret = onode_lookup_nolock(onode, ovid, name);
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
 * If (1) success, we consider it a successful deletion of user object. If (2)
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

static int
onode_create_and_update_bnode(struct http_request *req, const char *account,
			      uint32_t bucket_vid, const char *bucket,
			      uint32_t data_vid, struct kv_onode *onode)
{
	int ret;

	ret = onode_create(onode, bucket_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to create onode for %s", onode->name);
		onode_delete(onode);
		goto out;
	}

	ret = bnode_update(account, bucket, req->data_length, true);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update bucket for %s", onode->name);
		onode_delete(onode);
		goto out;
	}
out:
	return ret;
}

/* Create onode and allocate space for it */
static int onode_allocate_space(struct http_request *req, const char *account,
				uint32_t bucket_vid, const char *bucket,
				const char *name, struct kv_onode *onode)
{
	char vdi_name[SD_MAX_VDI_LEN];
	uint32_t data_vid;
	int ret;

	sys->cdrv->lock(bucket_vid);
	ret = onode_lookup_nolock(onode, bucket_vid, name);
	if (ret == SD_RES_SUCCESS) {
		/* if the exists onode has not been uploaded complete */
		if (onode->flags != ONODE_COMPLETE) {
			ret = SD_RES_INCOMPLETE;
			sd_err("The exists onode %s is incomplete", name);
			goto out;
		}
		/* For overwrite, we delete old object and then create */
		ret = onode_delete(onode);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to delete exists object %s", name);
			goto out;
		}
		ret = bnode_update(account, bucket, onode->size, false);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to update bnode for %s", name);
			goto out;
		}
	} else if (ret != SD_RES_NO_OBJ) {
		sd_err("Failed to lookup onode %s %s", name, sd_strerror(ret));
		goto out;
	}

	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s/allocator", account, bucket);
	ret = sd_lookup_vdi(vdi_name, &data_vid);
	if (ret != SD_RES_SUCCESS)
		goto out;

	memset(onode, 0, sizeof(*onode));
	pstrcpy(onode->name, sizeof(onode->name), name);
	onode->data_vid = data_vid;
	onode->flags = ONODE_INIT;

	ret = onode_allocate_data(onode, req);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to write data for %s", name);
		goto out;
	}

	ret = onode_create_and_update_bnode(req, account, bucket_vid, bucket,
					    data_vid, onode);
out:
	sys->cdrv->unlock(bucket_vid);
	return ret;
}

static int onode_append_space(struct http_request *req, const char *account,
			      uint32_t bucket_vid, const char *bucket,
			      const char *name, struct kv_onode *onode)
{
	char vdi_name[SD_MAX_VDI_LEN];
	uint32_t data_vid;
	uint64_t len;
	int ret;
	bool object_exists = false;

	sys->cdrv->lock(bucket_vid);
	ret = onode_lookup_nolock(onode, bucket_vid, name);

	if (ret == SD_RES_SUCCESS) {
		object_exists = true;
		if (onode->flags == ONODE_COMPLETE) {
			/* Not allowed "append" to a COMPLETED onode */
			sd_err("Failed to append data to the object %s, which"
			       " is marked COMPLETE", onode->name);
			goto out;
		}
	}

	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s/allocator", account, bucket);
	ret = sd_lookup_vdi(vdi_name, &data_vid);
	if (ret != SD_RES_SUCCESS)
		goto out;

	if (!object_exists) {
		memset(onode, 0, sizeof(*onode));
		pstrcpy(onode->name, sizeof(onode->name), name);
		onode->data_vid = data_vid;
		onode->flags = ONODE_INIT;
	}

	ret = onode_append_data(onode, req);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to write data for %s", name);
		goto out;
	}

	if (!object_exists)
		ret = onode_create_and_update_bnode(req, account, bucket_vid,
						    bucket, data_vid, onode);
	else {
		/* update new appended o_extent[] */
		len = sizeof(struct onode_extent) * onode->nr_extent;
		ret = sd_write_object(onode->oid, (char *)onode,
				      ONODE_HDR_SIZE + len, 0, 0);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to write o_extent[] for %s %s",
			       onode->name, sd_strerror(ret));
			goto out;
		}
	}
out:
	sys->cdrv->unlock(bucket_vid);
	return ret;
}

int kv_complete_object(struct http_request *req, const char *account,
		       const char *bucket, const char *object)
{
	char vdi_name[SD_MAX_VDI_LEN];
	struct kv_onode *onode = NULL;
	uint32_t bucket_vid;
	int ret;

	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s", account, bucket);
	ret = sd_lookup_vdi(vdi_name, &bucket_vid);
	if (ret != SD_RES_SUCCESS)
		goto out;

	onode = xzalloc(sizeof(*onode));

	sys->cdrv->lock(bucket_vid);
	ret = onode_lookup_nolock(onode, bucket_vid, object);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to lookup onode %s (%s)", object,
		       sd_strerror(ret));
		goto out;
	}

	/* update flag of onode */
	onode->flags = ONODE_COMPLETE;
	ret = sd_write_object(onode->oid, (char *)onode, ONODE_HDR_SIZE, 0,
			      false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to update onode %s to COMPLETE (%s)",
		       onode->name, sd_strerror(ret));
		goto out;
	}
out:
	sys->cdrv->unlock(bucket_vid);
	return ret;
}

/*
 * user object name -> struct kv_onode -> sheepdog objects -> user data
 *
 * onode is a index node that maps name to sheepdog objects which hold the user
 * data, similar to UNIX inode. We use simple hashing for [name, onode] mapping.
 *
 * At before, the implementation of swift interface for creating object in
 * sheepdog is:
 *     1. lock container
 *     2. check whether the onode with same object name is exists.
 *     3. unlock container
 *     4. upload object
 *     5. create onode
 * this sequence have a problem: if two clients uploading same objects
 * concurrently, it will create two objects with same names in container.
 * To avoid duplicated names, we must put "create onode" operation in container
 * lock regions.
 *
 * Therefore we need to change the processes of creating object to:
 *     1. lock container
 *     2. check whether the onode is exists.
 *     3. allocate data space for object, and create onode, then write it done
 *     4. unlock container
 *     5. upload object
 * this routine will avoid uploading duplicated objects.
 *
 * Cases:
 * 1. create objects with same name simultaneously,
 *    only one object will be create.
 * 2. create object and delete object simultaneously,
 *    return FAIL for "delete object" request if "create object" is running.
 * 3. kill client if it is uploading object,
 *    the object is "INCOMPLETED", it will return "PARTIAL_CONTENT" when
 *    client GET or HEAD object.
 */
int kv_create_object(struct http_request *req, const char *account,
		     const char *bucket, const char *name)
{
	char vdi_name[SD_MAX_VDI_LEN];
	struct kv_onode *onode = NULL;
	uint32_t bucket_vid;
	int ret;

	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s", account, bucket);
	ret = sd_lookup_vdi(vdi_name, &bucket_vid);
	if (ret != SD_RES_SUCCESS)
		goto out;

	onode = xzalloc(sizeof(*onode));
	ret = onode_allocate_space(req, account, bucket_vid, bucket,
				   name, onode);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to create onode and allocate space %s", name);
		goto out;
	}

	ret = onode_populate_data(onode, req);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to write data to onode %s", name);
		goto out;
	}
out:
	free(onode);
	return ret;
}

/*
 * We allow append write for PUT operation. When 'FLAG: append' is specified
 * in the http PUT request header, we append the new data at the tail of the
 * existing object instead of a 'delete-then-create' semantic.
 * When we append objects, we mark them as ONODE_INIT. When all the append
 * operations are done, we specify 'FLAG: eof' in the PUT request header to
 * finalize the whole transaction, which mark the
 * objects as ONODE_COMPLETE.
 */
int kv_append_object(struct http_request *req, const char *account,
		     const char *bucket, const char *name)
{
	char vdi_name[SD_MAX_VDI_LEN];
	struct kv_onode *onode = NULL;
	uint32_t bucket_vid;
	int ret;

	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s", account, bucket);
	ret = sd_lookup_vdi(vdi_name, &bucket_vid);
	if (ret != SD_RES_SUCCESS)
		goto out;

	onode = xzalloc(sizeof(*onode));
	ret = onode_append_space(req, account, bucket_vid, bucket, name, onode);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to create onode and allocate space %s", name);
		goto out;
	}

	ret = onode_populate_append_data(onode, req);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to write data to onode %s", name);
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

	/* this object has not been uploaded complete */
	if (onode->flags != ONODE_COMPLETE) {
		ret = SD_RES_EIO;
		goto out;
	}

	ret = onode_read_data(onode, req);
	if (ret != SD_RES_SUCCESS)
		sd_err("failed to read data for %s ret %d", name, ret);
out:
	free(onode);
	return ret;
}

/*
 * Imaging a scenario:
 *
 * 1. Client A is uploading a large object which names 'elephant', it
 *    only allocate meta-data in oalloc and is creating SD_OBJ_DATA files.
 * 2. Client B send a DELETE request to remove object 'elephant', it
 *    will remove all the backend files for 'elephant'.
 *    At the same time, Client A doesn't know what happened because uploading
 *    progress don't need to lock any vdi.
 * 3. Client A return Create-object-success, but the real data have all been
 *    removed.
 *
 * To avoid this scenario, we let DELETE operation do nothing but only return
 * 'CONFLICT' when the object is 'incompleted'. And, users can send the DELETE
 * request with a new header 'Force: true' which will remove 'incompleted'
 * object forcely when users make sure that there isn't any uploading progress
 * for this object.
 */
int kv_delete_object(const char *account, const char *bucket, const char *name,
		     bool force)
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

	/* this object has not been uploaded complete */
	if (!force && onode->flags != ONODE_COMPLETE) {
		ret = SD_RES_INCOMPLETE;
		goto out;
	}

	ret = onode_delete(onode);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to delete onode for %s", name);
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
	http_request_writef(req, "Created: %s\n",
			    http_time(onode->ctime));
	http_request_writef(req, "Last-Modified: %s\n",
			    http_time(onode->mtime));

	/* this object has not been uploaded complete */
	if (onode->flags != ONODE_COMPLETE) {
		ret = SD_RES_INCOMPLETE;
		goto out;
	}
out:
	free(onode);
	return ret;
}
