/*
 * Copyright (C) 2013 MORITA Kazutaka <morita.kazutaka@gmail.com>
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
#include "kv.h"

#define FOR_EACH_VDI(nr, vdis) FOR_EACH_BIT(nr, vdis, SD_NR_VDIS)

static int lookup_bucket(struct http_request *req, const char *bucket,
			 uint32_t *vid)
{
	int ret;
	struct vdi_info info = {};
	struct vdi_iocb iocb = {
		.name = bucket,
		.data_len = strlen(bucket),
	};

	ret = vdi_lookup(&iocb, &info);
	switch (ret) {
	case SD_RES_SUCCESS:
		*vid = info.vid;
		break;
	case SD_RES_NO_VDI:
		sd_info("no such bucket %s", bucket);
		http_response_header(req, NOT_FOUND);
		return -1;
	default:
		sd_err("%s: bucket %s", sd_strerror(ret), bucket);
		http_response_header(req, INTERNAL_SERVER_ERROR);
		return -1;
	}

	return 0;
}

/* Bucket operations */

int kv_create_bucket(struct http_request *req, const char *bucket)
{
	struct sd_req hdr;
	int ret;
	char buf[SD_MAX_VDI_LEN] = {0};

	pstrcpy(buf, SD_MAX_VDI_LEN, bucket);

	sd_init_req(&hdr, SD_OP_NEW_VDI);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = SD_MAX_VDI_LEN;

	hdr.vdi.vdi_size = SD_MAX_VDI_SIZE;
	hdr.vdi.copies = sys->cinfo.nr_copies;
	hdr.vdi.copy_policy = sys->cinfo.copy_policy;
	hdr.vdi.store_policy = 1;

	ret = exec_local_req(&hdr, buf);
	switch (ret) {
	case SD_RES_SUCCESS:
		http_response_header(req, CREATED);
		break;
	case SD_RES_VDI_EXIST:
		http_response_header(req, ACCEPTED);
		break;
	default:
		sd_err("%s: bucket %s", sd_strerror(ret), bucket);
		http_response_header(req, INTERNAL_SERVER_ERROR);
		return -1;
	}

	return 0;
}

int kv_read_bucket(struct http_request *req, const char *bucket)
{
	/* TODO: read metadata of the bucket */
	return -1;
}

int kv_update_bucket(struct http_request *req, const char *bucket)
{
	/* TODO: update metadata of the bucket */
	return -1;
}

/* TODO: return HTTP_CONFLICT when the bucket is not empty */
int kv_delete_bucket(struct http_request *req, const char *bucket)
{
	int ret;
	struct sd_req hdr;
	char data[SD_MAX_VDI_LEN] = {0};
	uint32_t vid;

	ret = lookup_bucket(req, bucket, &vid);
	if (ret < 0)
		return ret;

	sd_init_req(&hdr, SD_OP_DELETE_CACHE);
	hdr.obj.oid = vid_to_vdi_oid(vid);

	ret = exec_local_req(&hdr, NULL);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to execute request");
		http_response_header(req, INTERNAL_SERVER_ERROR);
		return -1;
	}

	sd_init_req(&hdr, SD_OP_DEL_VDI);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = sizeof(data);
	pstrcpy(data, SD_MAX_VDI_LEN, bucket);

	ret = exec_local_req(&hdr, data);
	if (ret == SD_RES_SUCCESS) {
		http_response_header(req, NO_CONTENT);
		return 0;
	} else {
		sd_err("%s: bucket %s", sd_strerror(ret), bucket);
		http_response_header(req, INTERNAL_SERVER_ERROR);
		return -1;
	}
}

int kv_list_buckets(struct http_request *req,
		    void (*cb)(struct http_request *req, const char *bucket,
			       void *opaque),
		    void *opaque)
{
	char buf[SD_INODE_HEADER_SIZE];
	struct sd_inode *inode = (struct sd_inode *)buf;
	unsigned long nr;

	http_response_header(req, OK);

	FOR_EACH_VDI(nr, sys->vdi_inuse) {
		uint64_t oid;
		int ret;

		oid = vid_to_vdi_oid(nr);

		ret = read_object(oid, (char *)inode, SD_INODE_HEADER_SIZE, 0);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to read inode header");
			continue;
		}

		if (inode->name[0] == '\0') /* this VDI has been deleted */
			continue;

		if (!vdi_is_snapshot(inode))
			cb(req, inode->name, opaque);
	}

	return 0;
}

/* Object operations */

/* 4 KB header of kv object */
struct kv_object_hdr {
	union {
		struct {
			char name[SD_MAX_OBJECT_NAME];
			uint64_t size;
			uint64_t ctime;
			uint64_t mtime;

			/* the index of the multi parted object */
			uint64_t segment;

			/* a hash value for etag */
			uint8_t sha1[round_up(SHA1_DIGEST_SIZE, 8)];
		};

		uint8_t __pad[BLOCK_SIZE];
	};
};

struct kv_object {
	struct kv_object_hdr hdr;
	uint8_t data[SD_DATA_OBJ_SIZE - sizeof(struct kv_object_hdr)];
};

/*
 * Create the object if the index isn't taken. Overwrite the object if it exists
 * Return 0 if the index is taken by other object.
 */
static int do_kv_create_object(struct http_request *req, const char *obj_name,
			       struct kv_object *obj, uint32_t vid,
			       uint32_t idx)
{
	uint64_t oid = vid_to_data_oid(vid, idx);
	uint32_t tmp_vid;
	struct kv_object_hdr hdr;
	struct sd_inode *inode = xmalloc(sizeof(struct sd_inode));
	int ret;

	ret = read_object(vid_to_vdi_oid(vid), (char *)inode,
			  sizeof(*inode), 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to read inode, %" PRIx64,
		       vid_to_vdi_oid(vid));
		goto err;
	}
	tmp_vid = INODE_GET_VID(inode, idx);
	if (tmp_vid) {
		ret = read_object(oid, (char *)&hdr, sizeof(hdr), 0);
		if (ret != SD_RES_SUCCESS) {
			sd_err("failed to read object, %" PRIx64, oid);
			goto err;
		}

		if (hdr.name[0] != '\0' &&
		    strcmp(hdr.name, obj->hdr.name) != 0){
			sd_debug("index %d is already used", idx);
			goto out;
		}
		sd_info("overwrite object %s", obj_name);
		ret = write_object(oid, (char *)obj,
				   sizeof(obj->hdr) + obj->hdr.size,
				   0, false);
		if (ret != SD_RES_SUCCESS) {
			sd_err("failed to write object, %" PRIx64, oid);
			goto err;
		}
	} else {
		ret = write_object(oid, (char *)obj,
				   sizeof(obj->hdr) + obj->hdr.size,
				   0, true);
		if (ret != SD_RES_SUCCESS) {
			sd_err("failed to create object, %" PRIx64, oid);
			goto err;
		}
		INODE_SET_VID(inode, idx, vid);
		ret = sd_inode_write_vid(sheep_bnode_writer, inode, idx,
					 vid, vid, 0, false, false);
		if (ret != SD_RES_SUCCESS) {
			sd_err("failed to update inode, %" PRIx64,
			       vid_to_vdi_oid(vid));
			goto err;
		}
	}
	http_response_header(req, CREATED);
out:
	free(inode);
	return 0;
err:
	http_response_header(req, INTERNAL_SERVER_ERROR);
	free(inode);
	return -1;
}

int kv_create_object(struct http_request *req, const char *bucket,
		     const char *object)
{
	struct kv_object *obj;
	ssize_t size;
	int ret;
	uint64_t hval;
	uint32_t vid;
	struct timeval tv;

	ret = lookup_bucket(req, bucket, &vid);
	if (ret < 0)
		return ret;

	obj = xzalloc(sizeof(*obj));

	gettimeofday(&tv, NULL);
	pstrcpy(obj->hdr.name, sizeof(obj->hdr.name), object);
	obj->hdr.ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;
	obj->hdr.mtime = obj->hdr.ctime;

	/* TODO: support multi parted object for large object */
	size = http_request_read(req, obj->data, sizeof(obj->data));
	if (size < 0) {
		sd_err("%s: bucket %s, object %s", sd_strerror(ret),
		       bucket, object);
		http_response_header(req, INTERNAL_SERVER_ERROR);
		return -1;
	}

	obj->hdr.size = size;

	hval = sd_hash(object, strlen(object));
	for (int i = 0; i < MAX_DATA_OBJS; i++) {
		uint32_t idx = (hval + i) % MAX_DATA_OBJS;

		do_kv_create_object(req, object, obj, vid, idx);
		if (req->status != UNKNOWN) {
			free(obj);
			return 0;
		}
	}

	free(obj);

	/* no free space to create a object */
	http_response_header(req, SERVICE_UNAVAILABLE);
	return -1;
}

static int do_kv_read_object(struct http_request *req, const char *obj_name,
			     struct kv_object *obj, uint32_t vid, uint32_t idx)
{
	uint64_t oid = vid_to_data_oid(vid, idx);
	int ret;

	ret = read_object(oid, (char *)obj, sizeof(*obj), 0);
	switch (ret) {
	case SD_RES_SUCCESS:
		break;
	case SD_RES_NO_OBJ:
		sd_info("object %s doesn't exist", obj_name);
		http_response_header(req, NOT_FOUND);
		return -1;
	default:
		sd_err("failed to read %s, %s", req->uri, sd_strerror(ret));
		http_response_header(req, INTERNAL_SERVER_ERROR);
		return -1;
	}

	if (strcmp(obj->hdr.name, obj_name) == 0) {
		http_response_header(req, OK);

		/* TODO: support multi parted object for large object */
		http_request_write(req, obj->data, obj->hdr.size);
	}

	return 0;
}

int kv_read_object(struct http_request *req, const char *bucket,
		   const char *object)
{
	struct kv_object *obj;
	int ret;
	uint64_t hval;
	uint32_t vid;

	ret = lookup_bucket(req, bucket, &vid);
	if (ret < 0)
		return ret;

	obj = xzalloc(sizeof(*obj));

	hval = sd_hash(object, strlen(object));
	for (int i = 0; i < MAX_DATA_OBJS; i++) {
		uint32_t idx = (hval + i) % MAX_DATA_OBJS;

		do_kv_read_object(req, object, obj, vid, idx);
		if (req->status != UNKNOWN) {
			free(obj);
			return 0;
		}
	}

	free(obj);

	http_response_header(req, NOT_FOUND);
	return -1;
}

static int do_kv_update_object(struct http_request *req, const char *obj_name,
			       struct kv_object *obj, uint32_t vid,
			       uint32_t idx, size_t size)
{
	uint64_t oid = vid_to_data_oid(vid, idx);
	int ret;

	ret = read_object(oid, (char *)&obj->hdr, sizeof(obj->hdr), 0);
	switch (ret) {
	case SD_RES_SUCCESS:
		break;
	case SD_RES_NO_VDI:
		sd_info("object %s doesn't exist", obj_name);
		http_response_header(req, NOT_FOUND);
		return -1;
	default:
		sd_err("failed to read %s, %s", req->uri, sd_strerror(ret));
		http_response_header(req, INTERNAL_SERVER_ERROR);
		return -1;
	}

	if (strcmp(obj->hdr.name, obj_name) == 0) {
		struct timeval tv;

		gettimeofday(&tv, NULL);
		obj->hdr.mtime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;
		obj->hdr.size = size;

		ret = write_object(oid, (char *)obj,
				   sizeof(obj->hdr) + obj->hdr.size, 0, false);
		if (ret == SD_RES_SUCCESS)
			http_response_header(req, ACCEPTED);
		else {
			sd_err("failed to update object, %" PRIx64, oid);
			http_response_header(req, INTERNAL_SERVER_ERROR);
			return -1;
		}
	}

	return 0;
}

int kv_update_object(struct http_request *req, const char *bucket,
		     const char *object)
{
	struct kv_object *obj;
	int ret;
	uint64_t hval;
	uint32_t vid;
	ssize_t size;

	ret = lookup_bucket(req, bucket, &vid);
	if (ret < 0)
		return ret;

	obj = xzalloc(sizeof(*obj));

	/* TODO: support multi parted object for large object */
	size = http_request_read(req, obj->data, sizeof(obj->data));
	if (size < 0) {
		sd_err("%s: bucket %s, object %s", sd_strerror(ret),
		       bucket, object);
		http_response_header(req, INTERNAL_SERVER_ERROR);
		return -1;
	}

	hval = sd_hash(object, strlen(object));
	for (int i = 0; i < MAX_DATA_OBJS; i++) {
		uint32_t idx = (hval + i) % MAX_DATA_OBJS;

		do_kv_update_object(req, object, obj, vid, idx, size);
		if (req->status != UNKNOWN) {
			free(obj);
			return 0;
		}
	}

	free(obj);

	http_response_header(req, NOT_FOUND);
	return -1;
}

static int do_kv_delete_object(struct http_request *req, const char *obj_name,
			       uint32_t vid, uint32_t idx)
{
	uint64_t oid = vid_to_data_oid(vid, idx);
	char name[SD_MAX_OBJECT_NAME];
	int ret;

	ret = read_object(oid, name, sizeof(name), 0);
	switch (ret) {
	case SD_RES_SUCCESS:
		break;
	case SD_RES_NO_OBJ:
		sd_info("object %s doesn't exist", obj_name);
		http_response_header(req, NOT_FOUND);
		return -1;
	default:
		sd_err("failed to read %s, %s", req->uri, sd_strerror(ret));
		http_response_header(req, INTERNAL_SERVER_ERROR);
		return -1;
	}

	if (strcmp(name, obj_name) == 0) {
		memset(name, 0, sizeof(name));
		ret = write_object(oid, name, sizeof(name), 0, false);
		if (ret == SD_RES_SUCCESS)
			http_response_header(req, NO_CONTENT);
		else {
			sd_err("failed to update object, %" PRIx64,
			       oid);
			http_response_header(req, INTERNAL_SERVER_ERROR);
			return -1;
		}
	}

	return 0;
}

int kv_delete_object(struct http_request *req, const char *bucket,
		     const char *object)
{
	int ret;
	uint64_t hval;
	uint32_t vid;

	ret = lookup_bucket(req, bucket, &vid);
	if (ret < 0)
		return ret;

	hval = sd_hash(object, strlen(object));
	for (int i = 0; i < MAX_DATA_OBJS; i++) {
		uint32_t idx = (hval + i) % MAX_DATA_OBJS;

		do_kv_delete_object(req, object, vid, idx);
		if (req->status != UNKNOWN)
			return 0;
	}

	http_response_header(req, NOT_FOUND);
	return -1;
}

int kv_list_objects(struct http_request *req, const char *bucket,
		    void (*cb)(struct http_request *req, const char *bucket,
			       const char *object, void *opaque),
		    void *opaque)
{
	int ret;
	uint32_t vid;
	struct sd_inode *inode;

	ret = lookup_bucket(req, bucket, &vid);
	if (ret < 0)
		return ret;

	inode = xzalloc(sizeof(*inode));
	ret = read_object(vid_to_vdi_oid(vid), (char *)inode->data_vdi_id,
			  sizeof(inode->data_vdi_id),
			  offsetof(typeof(*inode), data_vdi_id));
	if (ret != SD_RES_SUCCESS) {
		sd_err("%s: bucket %s", sd_strerror(ret), bucket);
		http_response_header(req, INTERNAL_SERVER_ERROR);
		return -1;
	}

	http_response_header(req, OK);

	for (uint32_t idx = 0; idx < MAX_DATA_OBJS; idx++) {
		uint64_t oid;
		char name[SD_MAX_OBJECT_NAME];

		if (inode->data_vdi_id[idx] == 0)
			continue;

		oid = vid_to_data_oid(vid, idx);

		ret = read_object(oid, name, sizeof(name), 0);
		switch (ret) {
		case SD_RES_SUCCESS:
			if (name[0] != '\0')
				cb(req, bucket, name, opaque);
			break;
		default:
			sd_err("%s: bucket %s", sd_strerror(ret), bucket);
			break;
		}
	}

	free(inode);

	return 0;
}
