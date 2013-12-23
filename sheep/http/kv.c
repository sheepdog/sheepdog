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

struct kv_bnode {
	char name[SD_MAX_BUCKET_NAME];
	uint64_t obj_count;
	uint64_t bytes_used;
	uint64_t oid;
};

static int kv_create_hyper_volume(const char *name, uint32_t *vdi_id)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret;
	char buf[SD_MAX_VDI_LEN] = {0};

	pstrcpy(buf, SD_MAX_VDI_LEN, name);

	sd_init_req(&hdr, SD_OP_NEW_VDI);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = SD_MAX_VDI_LEN;

	hdr.vdi.vdi_size = SD_MAX_VDI_SIZE;
	hdr.vdi.copies = sys->cinfo.nr_copies;
	hdr.vdi.copy_policy = sys->cinfo.copy_policy;
	hdr.vdi.store_policy = 1;

	ret = exec_local_req(&hdr, buf);
	if (rsp->result != SD_RES_SUCCESS)
		sd_err("Failed to create VDI %s: %s", name,
		       sd_strerror(rsp->result));

	if (vdi_id)
		*vdi_id = rsp->vdi.vdi_id;

	return ret;
}

static int discard_data_obj(uint64_t oid)
{
	int ret;
	struct sd_req hdr;

	sd_init_req(&hdr, SD_OP_DISCARD_OBJ);
	hdr.obj.oid = oid;

	ret = exec_local_req(&hdr, NULL);
	if (ret != SD_RES_SUCCESS)
		sd_err("Failed to discard data obj %lu %s", oid,
		       sd_strerror(ret));

	return ret;
}

static int kv_lookup_vdi(const char *name, uint32_t *vid)
{
	int ret;
	struct vdi_info info = {};
	struct vdi_iocb iocb = {
		.name = name,
		.data_len = strlen(name),
	};

	ret = vdi_lookup(&iocb, &info);
	switch (ret) {
	case SD_RES_SUCCESS:
		*vid = info.vid;
		break;
	case SD_RES_NO_VDI:
		break;
	default:
		sd_err("Failed to lookup name %s, %s", name, sd_strerror(ret));
	}

	return ret;
}

static int kv_delete_vdi(const char *name)
{
	struct sd_req hdr;
	char data[SD_MAX_VDI_LEN] = {0};
	int ret;

	sd_init_req(&hdr, SD_OP_DEL_VDI);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = sizeof(data);
	pstrcpy(data, SD_MAX_VDI_LEN, name);

	ret = exec_local_req(&hdr, data);
	if (ret != SD_RES_SUCCESS)
		sd_err("Failed to delete vdi %s %s", name, sd_strerror(ret));

	return ret;
}

/*
 * Find an free object index by hash of name in the vid and create an object
 * that holds the kv node{kv_bnode, kv_onode}.
 */
#define kv_generic_object_create(node, vid, node_do_create)		\
({									\
	struct sd_inode *__inode = xmalloc(sizeof(struct sd_inode));	\
	uint32_t __tmp_vid, __idx, __i;					\
	uint64_t __hval;						\
	int __ret;							\
									\
	__ret = sd_read_object(vid_to_vdi_oid(vid), (char *)__inode,	\
			       sizeof(*__inode), 0);			\
	if (__ret != SD_RES_SUCCESS) {					\
		sd_err("failed to read %" PRIx32 " %s", vid,		\
		       sd_strerror(__ret));				\
		goto out;						\
	}								\
									\
	__hval = sd_hash(node->name, strlen(node->name));		\
	for (__i = 0; __i < MAX_DATA_OBJS; __i++) {			\
		__idx = (__hval + __i) % MAX_DATA_OBJS;			\
		__tmp_vid = INODE_GET_VID(__inode, __idx);		\
		if (__tmp_vid)						\
			continue;					\
		else							\
			break;						\
	}								\
	if (__i == MAX_DATA_OBJS) {					\
		__ret = SD_RES_NO_SPACE;				\
		goto out;						\
	}								\
	__ret = node_do_create(node, __inode, __idx);			\
out:									\
	free(__inode);							\
	__ret;								\
})

/* Find the object in the vid which holds the 'node' that matches 'name' */
#define kv_generic_object_lookup(node, vid, name)			\
({									\
	uint64_t __hval;						\
	uint32_t __i;							\
	int __ret;							\
									\
	__hval = sd_hash(name, strlen(name));				\
	for (__i = 0; __i < MAX_DATA_OBJS; __i++) {			\
		uint32_t __idx = (__hval + __i) % MAX_DATA_OBJS;	\
		uint64_t __oid = vid_to_data_oid(vid, __idx);		\
									\
		__ret = sd_read_object(__oid, (char *)node, sizeof(*node), 0); \
		if (__ret != SD_RES_SUCCESS)				\
			goto out;					\
		if (strcmp(node->name, name) == 0)			\
			break;						\
	}								\
									\
	if (__i == MAX_DATA_OBJS)					\
		__ret = SD_RES_NO_OBJ;					\
out:									\
	__ret;								\
})

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
	return kv_create_hyper_volume(account, &vdi_id);
}

typedef void (*list_bucket_cb)(struct http_request *req, const char *bucket,
			       void *opaque);

struct list_buckets_arg {
	struct http_request *req;
	void *opaque;
	list_bucket_cb cb;
	uint32_t bucket_counter;
};

static void list_buckets_cb(void *data, enum btree_node_type type, void *arg)
{
	struct sd_extent *ext;
	struct list_buckets_arg *lbarg = arg;
	struct kv_bnode bnode;
	uint64_t oid;
	int ret;

	if (type == BTREE_EXT) {
		ext = (struct sd_extent *)data;
		if (!ext->vdi_id)
			return;

		oid = vid_to_data_oid(ext->vdi_id, ext->idx);
		ret = sd_read_object(oid, (char *)&bnode, sizeof(bnode), 0);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to read data object %lx", oid);
			return;
		}

		if (bnode.name[0] == 0)
			return;
		if (lbarg->cb)
			lbarg->cb(lbarg->req, bnode.name, lbarg->opaque);
		lbarg->bucket_counter++;
	}
}

/* get number of buckets in this account */
static int kv_get_account(const char *account, uint32_t *nr_buckets)
{
	struct sd_inode inode;
	uint64_t oid;
	uint32_t account_vid;
	struct list_buckets_arg arg = {NULL, NULL, NULL, 0};
	int ret;

	ret = kv_lookup_vdi(account, &account_vid);
	if (ret != SD_RES_SUCCESS)
		goto out;

	/* read account vdi out */
	oid = vid_to_vdi_oid(account_vid);
	ret = sd_read_object(oid, (char *)&inode, sizeof(struct sd_inode), 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to read inode header %lx", oid);
		goto out;
	}

	traverse_btree(sheep_bnode_reader, &inode, list_buckets_cb, &arg);
	if (nr_buckets)
		*nr_buckets = arg.bucket_counter;
out:
	return ret;
}

int kv_read_account(const char *account, uint32_t *nr_buckets)
{
	int ret;

	ret = kv_get_account(account, nr_buckets);
	if (ret != SD_RES_SUCCESS)
		sd_err("Failed to get number of buckets in %s", account);
	return ret;
}

int kv_update_account(const char *account)
{
	/* TODO: update metadata of the account */
	return -1;
}

int kv_delete_account(const char *account)
{
	int ret;

	ret = kv_delete_vdi(account);
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
 * onode_vdi  \----> |coly/fruit | ... | kv_onode: banana | kv_onode: apple    |
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
	INODE_SET_VID(inode, idx, vid);
	ret = sd_inode_write_vid(sheep_bnode_writer, inode, idx,
				 vid, vid, 0, false, false);
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
	return kv_generic_object_create(bnode, account_vid, bnode_do_create);
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
	ret = kv_create_hyper_volume(onode_name, &vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to create bucket %s onode vid", bucket);
		return ret;
	}
	snprintf(alloc_name, SD_MAX_VDI_LEN, "%s/%s/allocator", account,
		 bucket);
	ret = kv_create_hyper_volume(alloc_name, &vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to create bucket %s data vid", bucket);
		kv_delete_vdi(onode_name);
		return ret;
	}
	ret = oalloc_init(vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to init allocator for bucket %s", bucket);
		goto err;
	}

	pstrcpy(bnode.name, sizeof(bnode.name), bucket);
	bnode.bytes_used = 0;
	bnode.obj_count = 0;
	ret = bnode_create(&bnode, account_vid);
	if (ret != SD_RES_SUCCESS)
		goto err;

	return SD_RES_SUCCESS;
err:
	kv_delete_vdi(onode_name);
	kv_delete_vdi(alloc_name);
	return ret;
}

static int bucket_lookup(struct kv_bnode *bnode, uint32_t vid, const char *name)
{
	return kv_generic_object_lookup(bnode, vid, name);
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

	ret = bucket_lookup(&bnode, avid, bucket);
	if (ret != SD_RES_SUCCESS)
		return ret;

	ret = discard_data_obj(bnode.oid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to discard bnode for %s", bucket);
		return ret;
	}
	kv_delete_vdi(onode_name);
	kv_delete_vdi(alloc_name);

	return SD_RES_SUCCESS;
}

int kv_create_bucket(const char *account, const char *bucket)
{
	uint32_t account_vid, vid;
	char vdi_name[SD_MAX_VDI_LEN];
	int ret;

	ret = kv_lookup_vdi(account, &account_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to find account %s", account);
		return ret;
	}

	sys->cdrv->lock(account_vid);
	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s", account, bucket);
	ret = kv_lookup_vdi(vdi_name, &vid);
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

int kv_read_bucket(const char *account, const char *bucket)
{
	/* TODO: read metadata of the bucket */
	return -1;
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

	ret = kv_lookup_vdi(account, &account_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to find account %s", account);
		return ret;
	}

	sys->cdrv->lock(account_vid);
	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s", account, bucket);

	ret = kv_lookup_vdi(vdi_name, &vid);
	if (ret != SD_RES_SUCCESS)
		goto out;
	ret = bucket_delete(account, account_vid, bucket);
out:
	sys->cdrv->unlock(account_vid);
	return ret;
}

int kv_list_buckets(struct http_request *req, const char *account,
		    list_bucket_cb cb, void *opaque)
{
	struct sd_inode account_inode;
	struct list_buckets_arg arg = {req, opaque, cb, 0};
	uint32_t account_vid;
	uint64_t oid;
	int ret;

	ret = kv_lookup_vdi(account, &account_vid);
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

	traverse_btree(sheep_bnode_reader, &account_inode,
		       list_buckets_cb, &arg);
out:
	sys->cdrv->unlock(account_vid);
	return ret;
}

/* Object operations */

/* 4 KB header of kv object index node */
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
			uint64_t ctime;
			uint64_t mtime;
			uint32_t data_vid;
			uint32_t nr_extent;
			uint64_t oid;
			uint8_t inlined;
		};

		uint8_t __pad[BLOCK_SIZE];
	};
	union {
		uint8_t data[SD_DATA_OBJ_SIZE - BLOCK_SIZE];
		struct onode_extent o_extent[0];
	};
};

typedef void (*list_object_cb)(struct http_request *req, const char *bucket,
			       const char *object, void *opaque);

struct list_objects_arg {
	struct http_request *req;
	void *opaque;
	const char *bucket;
	list_object_cb cb;
	uint32_t object_counter;
};

static void list_objects_cb(void *data, enum btree_node_type type, void *arg)
{
	struct sd_extent *ext;
	struct list_objects_arg *loarg = arg;
	struct kv_onode *onode = NULL;
	uint64_t oid;
	int ret;

	if (type == BTREE_EXT) {
		ext = (struct sd_extent *)data;
		if (!ext->vdi_id)
			goto out;

		onode = xmalloc(SD_DATA_OBJ_SIZE);

		oid = vid_to_data_oid(ext->vdi_id, ext->idx);
		ret = sd_read_object(oid, (char *)onode, SD_DATA_OBJ_SIZE, 0);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to read data object %lx", oid);
			goto out;
		}

		if (onode->name[0] == '\0')
			goto out;
		if (loarg->cb)
			loarg->cb(loarg->req, loarg->bucket, onode->name,
				  loarg->opaque);
		loarg->object_counter++;
	}
out:
	free(onode);
}

struct find_object_arg {
	bool found;
	const char *object_name;
};

static void find_object_cb(struct http_request *req, const char *bucket,
			   const char *name, void *opaque)
{
	struct find_object_arg *foarg = (struct find_object_arg *)opaque;

	if (!strncmp(foarg->object_name, name, SD_MAX_OBJECT_NAME))
		foarg->found = true;
}

static bool kv_find_object(struct http_request *req, const char *account,
			   const char *bucket, const char *name)
{
	struct find_object_arg arg = {false, name};
	kv_list_objects(req, account, bucket, find_object_cb, &arg);
	return arg.found;
}

#define KV_ONODE_INLINE_SIZE (SD_DATA_OBJ_SIZE - BLOCK_SIZE)

static int vdi_read_write(uint32_t vid, char *data, size_t length,
			  off_t offset, bool read)
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

		if (read) {
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

#define READ_WRITE_BUFFER (SD_DATA_OBJ_SIZE * 25) /* no rationale */

static int onode_populate_extents(struct kv_onode *onode,
				  struct http_request *req)
{
	ssize_t size;
	uint64_t start = 0, count, done = 0, total, offset;
	int ret;
	char *data_buf = NULL;
	uint32_t data_vid = onode->data_vid;

	count = DIV_ROUND_UP(req->data_length, SD_DATA_OBJ_SIZE);
	sys->cdrv->lock(data_vid);
	ret = oalloc_new_prepare(data_vid, &start, count);
	sys->cdrv->unlock(data_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("oalloc_new_prepare failed for %s, %s", onode->name,
		       sd_strerror(ret));
		goto out;
	}

	data_buf = xmalloc(READ_WRITE_BUFFER);
	offset = start * SD_DATA_OBJ_SIZE;
	total = req->data_length;
	while (done < total) {
		size = http_request_read(req, data_buf, READ_WRITE_BUFFER);
		ret = vdi_read_write(data_vid, data_buf, size, offset, false);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to write data object for %s, %s",
			       onode->name, sd_strerror(ret));
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

static int onode_populate_data(struct kv_onode *onode, struct http_request *req)
{
	ssize_t size;
	struct timeval tv;
	int ret;

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

	gettimeofday(&tv, NULL);
	onode->ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;
	onode->mtime = onode->ctime;
	onode->size = req->data_length;
out:
	return ret;
}

static int get_onode_data_vid(const char *account, const char *bucket,
			      uint32_t *onode_vid, uint32_t *data_vid)
{
	char vdi_name[SD_MAX_VDI_LEN];
	int ret;

	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s", account, bucket);
	ret = kv_lookup_vdi(vdi_name, onode_vid);
	if (ret != SD_RES_SUCCESS)
		return ret;

	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s/allocator", account, bucket);
	ret = kv_lookup_vdi(vdi_name, data_vid);
	if (ret != SD_RES_SUCCESS)
		return ret;

	return SD_RES_SUCCESS;
}

static int onode_do_create(struct kv_onode *onode, struct sd_inode *inode,
			   uint32_t idx)
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
			      0, true);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to create object, %" PRIx64, oid);
		goto out;
	}
	INODE_SET_VID(inode, idx, vid);
	ret = sd_inode_write_vid(sheep_bnode_writer, inode, idx,
				 vid, vid, 0, false, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update inode, %" PRIx64,
		       vid_to_vdi_oid(vid));
		goto out;
	}
out:
	return ret;
}

static int onode_create(struct kv_onode *onode, uint32_t onode_vid)
{
	int ret;

	sys->cdrv->lock(onode_vid);
	ret = kv_generic_object_create(onode, onode_vid, onode_do_create);
	sys->cdrv->unlock(onode_vid);

	return ret;
}

static int onode_free_data(struct kv_onode *onode)
{
	uint32_t data_vid = onode->data_vid;
	int ret;

	sys->cdrv->lock(data_vid);
	ret = oalloc_free(data_vid, onode->o_extent[0].start,
			  onode->o_extent[0].count);
	sys->cdrv->unlock(data_vid);
	if (ret != SD_RES_SUCCESS)
		sd_err("failed to free %s", onode->name);
	return ret;
}

static int onode_read_extents(struct kv_onode *onode, struct http_request *req)
{
	struct onode_extent *ext;
	uint64_t size, total, total_size, offset, done = 0;
	uint32_t i;
	int ret;
	char *data_buf = NULL;

	data_buf = xmalloc(READ_WRITE_BUFFER);
	total_size = onode->size;
	for (i = 0; i < onode->nr_extent; i++) {
		ext = onode->o_extent + i;
		total = min(ext->count * SD_DATA_OBJ_SIZE, total_size);
		offset = ext->start * SD_DATA_OBJ_SIZE;
		while (done < total) {
			size = MIN(total - done, READ_WRITE_BUFFER);
			ret = vdi_read_write(onode->data_vid, data_buf,
					     size, offset, true);
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

static int onode_lookup(struct kv_onode *onode, uint32_t ovid, const char *name)
{
	int ret;

	sys->cdrv->lock(ovid);
	ret = kv_generic_object_lookup(onode, ovid, name);
	sys->cdrv->unlock(ovid);
	return ret;
}

static int onode_read_data(struct kv_onode *onode, struct http_request *req)
{
	int ret;

	if (!onode->inlined)
		return onode_read_extents(onode, req);

	ret = http_request_write(req, onode->data, onode->size);
	if (ret != onode->size)
		return SD_RES_SYSTEM_ERROR;

	return SD_RES_SUCCESS;
}

/*
 * We free the data and meta data in following sequence:
 *
 * 1. discard onode
 * 2. discard data
 *
 * If (1) success, we consdier it a successful deletion of user object. If (2)
 * fails, data objects become orphan(s).
 *
 * XXX: GC the orphans
 */
static int onode_delete(struct kv_onode *onode)
{
	int ret;

	ret = discard_data_obj(onode->oid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to discard onode for %s", onode->name);
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
	struct kv_onode *onode;
	uint32_t onode_vid, data_vid;
	int ret;

	if (kv_find_object(req, account, bucket, name)) {
		/* For overwrite, we delete old object and then create */
		ret = kv_delete_object(req, account, bucket, name);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to delete exists object %s", name);
			return ret;
		}
	}

	ret = get_onode_data_vid(account, bucket, &onode_vid, &data_vid);
	if (ret != SD_RES_SUCCESS)
		return ret;

	onode = xzalloc(sizeof(*onode));
	pstrcpy(onode->name, sizeof(onode->name), name);
	onode->data_vid = data_vid;

	ret = onode_populate_data(onode, req);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to write data for %s", name);
		goto out;
	}

	ret = onode_create(onode, onode_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to create onode for %s", name);
		onode_free_data(onode);
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
	uint32_t onode_vid;
	int ret;

	if (!kv_find_object(req, account, bucket, name))
		return SD_RES_NO_OBJ;

	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s", account, bucket);
	ret = kv_lookup_vdi(vdi_name, &onode_vid);
	if (ret != SD_RES_SUCCESS)
		return ret;

	onode = xzalloc(sizeof(*onode));
	ret = onode_lookup(onode, onode_vid, name);
	if (ret != SD_RES_SUCCESS)
		goto out;

	req->data_length = onode->size;
	http_response_header(req, OK);
	ret = onode_read_data(onode, req);
	if (ret != SD_RES_SUCCESS)
		sd_err("failed to read data for %s", name);
out:
	free(onode);
	return ret;
}

int kv_delete_object(struct http_request *req, const char *account,
		     const char *bucket, const char *name)
{
	char vdi_name[SD_MAX_VDI_LEN];
	uint32_t onode_vid;
	struct kv_onode *onode = NULL;
	int ret;

	if (!kv_find_object(req, account, bucket, name))
		return SD_RES_NO_OBJ;

	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s", account, bucket);
	ret = kv_lookup_vdi(vdi_name, &onode_vid);
	if (ret != SD_RES_SUCCESS)
		return ret;

	onode = xzalloc(sizeof(*onode));
	ret = onode_lookup(onode, onode_vid, name);
	if (ret != SD_RES_SUCCESS)
		goto out;

	ret = onode_delete(onode);
out:
	free(onode);
	return ret;
}

int kv_list_objects(struct http_request *req, const char *account,
		    const char *bucket, list_object_cb cb, void *opaque)
{
	int ret;
	uint32_t vid;
	struct sd_inode *inode = NULL;
	char vdi_name[SD_MAX_VDI_LEN];

	snprintf(vdi_name, SD_MAX_VDI_LEN, "%s/%s", account, bucket);
	ret = kv_lookup_vdi(vdi_name, &vid);
	if (ret != SD_RES_SUCCESS)
		goto out;

	inode = xmalloc(sizeof(*inode));
	ret = sd_read_object(vid_to_vdi_oid(vid), (char *)inode,
			     sizeof(struct sd_inode), 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("%s: bucket %s", sd_strerror(ret), bucket);
		http_response_header(req, INTERNAL_SERVER_ERROR);
		goto out;
	}

	struct list_objects_arg arg = {req, opaque, bucket, cb, 0};
	traverse_btree(sheep_bnode_reader, inode, list_objects_cb, &arg);
out:
	free(inode);
	return ret;
}
