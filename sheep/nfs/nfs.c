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

#include "sheep_priv.h"
#include "nfs.h"

/*
 * Comment from Linux kernel nfsd for RPC payload size
 *
 * Maximum payload size supported by a kernel RPC server.
 * This is use to determine the max number of pages nfsd is
 * willing to return in a single READ operation.
 *
 * These happen to all be powers of 2, which is not strictly
 * necessary but helps enforce the real limitation, which is
 * that they should be multiples of PAGE_CACHE_SIZE.
 *
 * For UDP transports, a block plus NFS,RPC, and UDP headers
 * has to fit into the IP datagram limit of 64K.  The largest
 * feasible number for all known page sizes is probably 48K,
 * but we choose 32K here.  This is the same as the historical
 * Linux limit; someone who cares more about NFS/UDP performance
 * can test a larger number.
 *
 * For TCP transports we have more freedom.  A size of 1MB is
 * chosen to match the client limit.  Other OSes are known to
 * have larger limits, but those numbers are probably beyond
 * the point of diminishing returns.
 */
#define RPCSVC_MAXPAYLOAD	(1*1024*1024u)
#define RPCSVC_MAXPAYLOAD_TCP	RPCSVC_MAXPAYLOAD
#define RPCSVC_MAXPAYLOAD_UDP	(32*1024u)

static inline struct svc_fh *get_svc_fh(struct nfs_arg *argp)
{
	struct nfs_fh3 *nfh = (struct nfs_fh3 *)argp;

	if (unlikely(nfh->data.data_len != sizeof(struct svc_fh)))
		panic("invalid nfs file handle len %u", nfh->data.data_len);

	return (struct svc_fh *)(nfh->data.data_val);
}

static inline void set_svc_fh(struct nfs_fh3 *nfh, struct svc_fh *sfh)
{
	nfh->data.data_len = sizeof(struct svc_fh);
	nfh->data.data_val = (char *)sfh;
}

static void update_post_attr(struct inode *inode, fattr3 *post)
{
	post->type = S_ISDIR(inode->mode) ? NF3DIR : NF3REG;
	post->mode = inode->mode;
	post->nlink = inode->nlink;
	post->uid = inode->uid;
	post->gid = inode->gid;
	post->size = inode->size;
	post->used = inode->used;
	post->fsid = oid_to_vid(inode->ino);
	post->fileid = inode->ino;
	post->atime.seconds = inode->atime;
	post->mtime.seconds = inode->mtime;
	post->ctime.seconds = inode->ctime;
}

void *nfs3_null(struct svc_req *req, struct nfs_arg *argp)
{
	static void *result;

	return &result;
}

void *nfs3_getattr(struct svc_req *req, struct nfs_arg *argp)
{
	static GETATTR3res result;
	struct svc_fh *fh = get_svc_fh(argp);
	struct fattr3 *post = &result.GETATTR3res_u.resok.obj_attributes;
	struct inode *inode;

	inode = fs_read_inode_hdr(fh->ino);
	if (IS_ERR(inode)) {
		switch (PTR_ERR(inode)) {
		case SD_RES_NO_OBJ:
			result.status = NFS3ERR_NOENT;
			goto out;
		default:
			result.status = NFS3ERR_IO;
			goto out;
		}
	}

	update_post_attr(inode, post);
	result.status = NFS3_OK;

	free(inode);
out:
	return &result;
}

/* FIXME: Add nanotime support */
void *nfs3_setattr(struct svc_req *req, struct nfs_arg *argp)
{
	static SETATTR3res result;
	SETATTR3args *arg = &argp->setattr;
	struct svc_fh *fh = get_svc_fh(argp);
	struct sattr3 *sattr = &arg->new_attributes;
	struct post_op_attr *poa = &result.SETATTR3res_u.resok.obj_wcc.after;
	struct fattr3 *post = &poa->post_op_attr_u.attributes;
	struct inode *inode;
	int ret;

	sd_debug("%"PRIx64, fh->ino);

	inode = fs_read_inode_hdr(fh->ino);
	if (IS_ERR(inode)) {
		switch (PTR_ERR(inode)) {
		case SD_RES_NO_OBJ:
			result.status = NFS3ERR_NOENT;
			goto out;
		default:
			result.status = NFS3ERR_IO;
			goto out;
		}
	}

	if (sattr->mode.set_it)
		inode->mode = sattr->mode.mode;
	if (sattr->uid.set_it)
		inode->uid = sattr->uid.uid;
	if (sattr->gid.set_it)
		inode->gid = sattr->gid.gid;
	if (sattr->size.set_it)
		inode->size = sattr->size.size;

	ret = fs_write_inode_hdr(inode);
	if (ret != SD_RES_SUCCESS)
		result.status = NFS3ERR_IO;
	else
		result.status = NFS3_OK;

	poa->attributes_follow = true;
	update_post_attr(inode, post);
	free(inode);
out:
	return &result;
}

void *nfs3_lookup(struct svc_req *req, struct nfs_arg *argp)
{
	static LOOKUP3res result;
	static struct svc_fh den_fh;
	LOOKUP3args *arg = &argp->lookup;
	struct svc_fh *fh = get_svc_fh(argp);
	struct inode *inode;
	struct dentry *dentry;
	char *name = arg->what.name;

	sd_debug("%"PRIx64" %s", fh->ino, name);

	inode = fs_read_inode_full(fh->ino);
	if (IS_ERR(inode)) {
		switch (PTR_ERR(inode)) {
		case SD_RES_NO_OBJ:
			result.status = NFS3ERR_NOENT;
			goto out;
		default:
			result.status = NFS3ERR_IO;
			goto out;
		}
	}

	if (!S_ISDIR(inode->mode)) {
		result.status = NFS3ERR_NOTDIR;
		goto out_free;
	}

	dentry = fs_lookup_dir(inode, name);
	if (IS_ERR(dentry)) {
		switch (PTR_ERR(dentry)) {
		case SD_RES_NOT_FOUND:
			result.status = NFS3ERR_NOENT;
			goto out_free;
		default:
			result.status = NFS3ERR_IO;
			goto out_free;
		}
	}

	result.status = NFS3_OK;
	den_fh.ino = dentry->ino;
	set_svc_fh(&result.LOOKUP3res_u.resok.object, &den_fh);
out_free:
	free(inode);
out:
	return &result;
}

/* FIXME: implement UNIX ACL */
void *nfs3_access(struct svc_req *req, struct nfs_arg *argp)
{
	static ACCESS3res result;
	ACCESS3args *arg = &argp->access;
	struct svc_fh *fh = get_svc_fh(argp);
	struct post_op_attr *poa = &result.ACCESS3res_u.resok.obj_attributes;
	struct fattr3 *post = &poa->post_op_attr_u.attributes;
	uint32_t access;
	struct inode *inode;

	inode = fs_read_inode_hdr(fh->ino);
	if (IS_ERR(inode)) {
		switch (PTR_ERR(inode)) {
		case SD_RES_NO_OBJ:
			result.status = NFS3ERR_NOENT;
			goto out;
		default:
			result.status = NFS3ERR_IO;
			goto out;
		}
	}

	poa->attributes_follow = true;
	update_post_attr(inode, post);
	access = ACCESS3_READ | ACCESS3_MODIFY | ACCESS3_EXTEND |
		 ACCESS3_EXECUTE;
	if (post->type == NF3DIR) {
		access |= ACCESS3_LOOKUP | ACCESS3_DELETE;
		access &= ~ACCESS3_EXECUTE;
	}

	result.status = NFS3_OK;
	result.ACCESS3res_u.resok.access = access & arg->access;

	free(inode);
out:
	return &result;
}

void *nfs3_readlink(struct svc_req *req, struct nfs_arg *argp)
{
	return NULL;
}

static char nfs_read_buffer[RPCSVC_MAXPAYLOAD];

void *nfs3_read(struct svc_req *req, struct nfs_arg *argp)
{
	static READ3res result;
	READ3args *arg = &argp->read;
	struct svc_fh *fh = get_svc_fh(argp);
	uint64_t offset = arg->offset, count = arg->count;
	struct post_op_attr *poa =
		&result.READ3res_u.resok.file_attributes;
	struct fattr3 *post = &poa->post_op_attr_u.attributes;
	struct inode *inode;
	int ret;

	sd_debug("%"PRIx64"count %"PRIu64" offset %"PRIu64, fh->ino,
		 count, offset);

	inode = fs_read_inode_full(fh->ino);
	if (IS_ERR(inode)) {
		switch (PTR_ERR(inode)) {
		case SD_RES_NO_OBJ:
			result.status = NFS3ERR_NOENT;
			goto out;
		default:
			result.status = NFS3ERR_IO;
			goto out;
		}
	}

	ret = fs_read(inode, nfs_read_buffer, count, offset);
	if (ret < 0) {
		result.status = NFS3ERR_IO;
		goto out_free;
	}
	result.status = NFS3_OK;
	result.READ3res_u.resok.count = ret;
	result.READ3res_u.resok.eof = ret < count;
	result.READ3res_u.resok.data.data_val = nfs_read_buffer;
	result.READ3res_u.resok.data.data_len = ret;
	poa->attributes_follow = true;
	update_post_attr(inode, post);
out_free:
	free(inode);
out:
	return &result;
}

void *nfs3_write(struct svc_req *req, struct nfs_arg *argp)
{
	static WRITE3res result;
	WRITE3args *arg = &argp->write;
	struct svc_fh *fh = get_svc_fh(argp);
	uint64_t offset = arg->offset, count = arg->count;
	struct post_op_attr *poa =
		&result.WRITE3res_u.resok.file_wcc.after;
	struct fattr3 *post = &poa->post_op_attr_u.attributes;
	struct inode *inode;
	int64_t done;
	void *buffer = arg->data.data_val;

	sd_debug("%"PRIx64" count %"PRIu64" offset %"PRIu64" stable %d",
		 fh->ino, count, offset, arg->stable);

	inode = fs_read_inode_full(fh->ino);
	if (IS_ERR(inode)) {
		switch (PTR_ERR(inode)) {
		case SD_RES_NO_OBJ:
			result.status = NFS3ERR_NOENT;
			goto out;
		default:
			result.status = NFS3ERR_IO;
			goto out;
		}
	}

	done = fs_write(inode, buffer, count, offset);
	if (done < 0) {
		result.status = NFS3ERR_IO;
		goto out_free;
	}
	result.status = NFS3_OK;
	result.WRITE3res_u.resok.count = done;
	result.WRITE3res_u.resok.committed = FILE_SYNC;
	memcpy(&result.WRITE3res_u.resok.verf, &nfs_boot_time,
	       sizeof(nfs_boot_time));
	poa->attributes_follow = true;
	update_post_attr(inode, post);
out_free:
	free(inode);
out:
	return &result;
}

/* FIXME: support GUARDED and EXCLUSIVE */
void *nfs3_create(struct svc_req *req, struct nfs_arg *argp)
{
	static CREATE3res result;
	static struct svc_fh file_fh;
	CREATE3args *arg = &argp->create;
	struct svc_fh *fh = get_svc_fh(argp);
	struct sattr3 *sattr = &arg->how.createhow3_u.obj_attributes;
	struct post_op_attr *poa =
		&result.CREATE3res_u.resok.obj_attributes;
	struct fattr3 *post = &poa->post_op_attr_u.attributes;
	struct inode *new = xzalloc(sizeof(*new));
	char *name = arg->where.name;
	int mode = arg->how.mode, ret;

	sd_debug("%"PRIx64" %s, mode %d, size %"PRIu64, fh->ino, name, mode,
		 sattr->size.size);

	new->mode = S_IFREG | sd_def_fmode;
	new->uid = 0;
	new->gid = 0;
	new->size = 0;
	new->used = INODE_DATA_SIZE;
	new->ctime = new->atime = new->mtime = time(NULL);

	ret = fs_create_file(fh->ino, new, name);
	if (ret != SD_RES_SUCCESS) {
		result.status = NFS3ERR_IO;
		goto out;
	}

	file_fh.ino = new->ino;

	result.status = NFS3_OK;
	result.CREATE3res_u.resok.obj.handle_follows = true;
	set_svc_fh(&result.CREATE3res_u.resok.obj.post_op_fh3_u.handle,
		   &file_fh);
	poa->attributes_follow = true;
	update_post_attr(new, post);
out:
	return &result;
}

void *nfs3_mkdir(struct svc_req *req, struct nfs_arg *argp)
{
	static MKDIR3res result;
	static struct svc_fh file_fh;
	MKDIR3args *arg = &argp->mkdir;
	struct svc_fh *fh = get_svc_fh(argp);
	struct post_op_attr *poa =
		&result.MKDIR3res_u.resok.obj_attributes;
	struct fattr3 *post = &poa->post_op_attr_u.attributes;
	struct inode *new = xzalloc(sizeof(*new)), *parent;
	char *name = arg->where.name;
	int ret;

	sd_debug("%"PRIx64" %s", fh->ino, name);

	parent = fs_read_inode_full(fh->ino);
	if (IS_ERR(parent)) {
		switch (PTR_ERR(parent)) {
		case SD_RES_NO_OBJ:
			result.status = NFS3ERR_NOENT;
			goto out;
		default:
			result.status = NFS3ERR_IO;
			goto out;
		}
	}

	if (!S_ISDIR(parent->mode)) {
		result.status = NFS3ERR_NOTDIR;
		goto out_free_parent;
	}

	new->mode = S_IFDIR | sd_def_dmode;
	new->uid = 0;
	new->gid = 0;
	new->size = 0;
	new->used = INODE_DATA_SIZE;
	new->ctime = new->atime = new->mtime = time(NULL);

	ret = fs_create_dir(new, name, parent);
	if (ret != SD_RES_SUCCESS) {
		result.status = NFS3ERR_IO;
		goto out_free_parent;
	}

	file_fh.ino = new->ino;
	result.status = NFS3_OK;
	result.MKDIR3res_u.resok.obj.handle_follows = true;
	set_svc_fh(&result.MKDIR3res_u.resok.obj.post_op_fh3_u.handle,
		   &file_fh);
	poa->attributes_follow = true;
	update_post_attr(new, post);

out_free_parent:
	free(parent);
out:
	free(new);
	return &result;
}

void *nfs3_symlink(struct svc_req *req, struct nfs_arg *argp)
{
	return NULL;
}

void *nfs3_mknod(struct svc_req *req, struct nfs_arg *argp)
{
	static MKNOD3res result;

	result.status = NFS3ERR_NOTSUPP;

	return &result;
}

/* TODO: implement btree or hash based kv store to manage dentries */
void *nfs3_remove(struct svc_req *req, struct nfs_arg *argp)
{
	static REMOVE3res result;

	result.status = NFS3ERR_NOTSUPP;

	return &result;
}

void *nfs3_rmdir(struct svc_req *req, struct nfs_arg *argp)
{
	static RMDIR3res result;

	result.status = NFS3ERR_NOTSUPP;

	return &result;
}

void *nfs3_rename(struct svc_req *req, struct nfs_arg *argp)
{
	static RENAME3res result;

	result.status = NFS3ERR_NOTSUPP;

	return &result;
}

void *nfs3_link(struct svc_req *req, struct nfs_arg *argp)
{
	return NULL;
}

/* Linux NFS client will issue at most 32k count for readdir on my test */
#define ENTRY3_MAX_LEN (32*1024)

static char entry3_buffer[ENTRY3_MAX_LEN];
static char entry3_name[ENTRY3_MAX_LEN];

/*
 * static READDIR3resok size with XDR overhead
 *
 * 88 bytes attributes, 8 bytes verifier, 4 bytes value_follows for
 * first entry, 4 bytes eof flag
 */
#define RESOK_SIZE 104

/*
 * static entry3 size with XDR overhead
 *
 * 8 bytes fileid, 4 bytes name length, 8 bytes cookie, 4 byte value_follows
 */
#define ENTRY_SIZE 24

/*
 * size of a name with XDR overhead
 *
 * XDR pads to multiple of 4 bytes
 */
#define NAME_SIZE(x) (((strlen((x))+3)/4)*4)

struct dir_reader_d {
	uint32_t count;
	uint32_t used;
	entry3 *entries;
	uint32_t iter;
};

static int nfs_dentry_reader(struct inode *inode, struct dentry *dentry,
			     void *data)
{
	struct dir_reader_d *d = data;
	uint32_t iter = d->iter;
	uint64_t offset = (uint8_t *)(dentry + 1) - inode->data;

	/* If we have enough room for next dentry */
	d->used += ENTRY_SIZE + NAME_SIZE(dentry->name);
	if (d->used > d->count)
		return SD_RES_AGAIN;

	d->entries[iter].fileid = dentry->ino;
	strcpy(&entry3_name[iter * NFS_MAXNAMLEN], dentry->name);
	d->entries[iter].name = &entry3_name[iter * NFS_MAXNAMLEN];
	d->entries[iter].cookie = offset;
	d->entries[iter].nextentry = NULL;
	if (iter > 0)
		d->entries[iter - 1].nextentry = d->entries + iter;
	sd_debug("%s, %"PRIu64, d->entries[iter].name, offset);
	d->iter++;

	return SD_RES_SUCCESS;
}

void *nfs3_readdir(struct svc_req *req, struct nfs_arg *argp)
{
	static READDIR3res result;
	READDIR3args *arg = &argp->readdir;
	struct svc_fh *fh = get_svc_fh(argp);
	struct post_op_attr *poa =
		&result.READDIR3res_u.resok.dir_attributes;
	struct fattr3 *post = &poa->post_op_attr_u.attributes;
	struct inode *inode;
	struct dir_reader_d wd;
	int ret;

	sd_debug("%"PRIx64" count %"PRIu32", at %"PRIu64, fh->ino,
		 (uint32_t)arg->count, arg->cookie);

	inode = fs_read_inode_full(fh->ino);
	if (IS_ERR(inode)) {
		switch (PTR_ERR(inode)) {
		case SD_RES_NO_OBJ:
			result.status = NFS3ERR_NOENT;
			goto out;
		default:
			result.status = NFS3ERR_IO;
			goto out;
		}
	}

	if (!S_ISDIR(inode->mode)) {
		result.status = NFS3ERR_NOTDIR;
		goto out_free;
	}

	wd.count = arg->count;
	wd.entries = (entry3 *)entry3_buffer;
	wd.iter = 0;
	wd.used = RESOK_SIZE;
	ret = fs_read_dir(inode, arg->cookie, nfs_dentry_reader, &wd);
	switch (ret) {
	case SD_RES_SUCCESS:
		result.status = NFS3_OK;
		result.READDIR3res_u.resok.reply.eof = true;
		break;
	case SD_RES_AGAIN:
		result.status = NFS3_OK;
		break;
	default:
		result.status = NFS3ERR_IO;
		goto out_free;
	}

	result.READDIR3res_u.resok.reply.entries = wd.entries;
	poa->attributes_follow = true;
	update_post_attr(inode, post);
out_free:
	free(inode);
out:
	return &result;
}

void *nfs3_readdirplus(struct svc_req *req, struct nfs_arg *argp)
{
	static READDIRPLUS3res result;

	result.status = NFS3ERR_NOTSUPP;

	return &result;
}

void *nfs3_fsstat(struct svc_req *req, struct nfs_arg *argp)
{
	static FSSTAT3res result;
	struct svc_fh *fh = get_svc_fh(argp);
	struct sd_inode *sd_inode = xmalloc(sizeof(*sd_inode));
	uint32_t vid = oid_to_vid(fh->ino);
	uint64_t my = 0 , cow = 0;
	int ret;

	ret = sd_read_object(vid_to_vdi_oid(vid), (char *)sd_inode,
			     sizeof(*sd_inode), 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to read %" PRIx32 " %s", vid,
		       sd_strerror(ret));
		result.status = NFS3ERR_IO;
		goto out;
	}

	sd_inode_stat(sd_inode, &my, &cow);

	sd_debug("%"PRIx32" contains %lu objects", vid, my);

	result.status = NFS3_OK;
	result.FSSTAT3res_u.resok.tbytes = SD_MAX_VDI_SIZE;
	result.FSSTAT3res_u.resok.fbytes = SD_MAX_VDI_SIZE -
					my * SD_DATA_OBJ_SIZE;
	result.FSSTAT3res_u.resok.abytes = SD_MAX_VDI_SIZE -
					my * SD_DATA_OBJ_SIZE;
	result.FSSTAT3res_u.resok.tfiles = MAX_DATA_OBJS;
	result.FSSTAT3res_u.resok.ffiles = MAX_DATA_OBJS - my;
	result.FSSTAT3res_u.resok.afiles = MAX_DATA_OBJS - my;
out:
	free(sd_inode);
	return &result;
}

static uint32_t get_max_size(struct svc_req *req)
{
	int v, ret;
	socklen_t l;

	l = sizeof(v);
	ret = getsockopt(req->rq_xprt->xp_sock, SOL_SOCKET, SO_TYPE, &v, &l);
	if (ret < 0) {
		sd_info("unable to determine socket type, use udp size");
		goto out;
	}
	if (ret == SOCK_STREAM)
		return RPCSVC_MAXPAYLOAD_TCP;
out:
	/* UDP is a safe value for all the transport */
	return RPCSVC_MAXPAYLOAD_UDP;
}

void *nfs3_fsinfo(struct svc_req *req, struct nfs_arg *argp)
{
	static FSINFO3res result;
	uint32_t maxsize = get_max_size(req);

	result.status = NFS3_OK;
	result.FSINFO3res_u.resok.obj_attributes.attributes_follow = false;
	result.FSINFO3res_u.resok.rtmax = maxsize;
	result.FSINFO3res_u.resok.rtpref = maxsize;
	result.FSINFO3res_u.resok.rtmult = BLOCK_SIZE;
	result.FSINFO3res_u.resok.wtmax = maxsize;
	result.FSINFO3res_u.resok.wtpref = maxsize;
	result.FSINFO3res_u.resok.wtmult = BLOCK_SIZE;
	result.FSINFO3res_u.resok.dtpref = BLOCK_SIZE;
	result.FSINFO3res_u.resok.maxfilesize = SD_MAX_VDI_SIZE;
	result.FSINFO3res_u.resok.time_delta.seconds = 1;
	result.FSINFO3res_u.resok.time_delta.nseconds = 0;
	result.FSINFO3res_u.resok.properties = FSF3_HOMOGENEOUS;

	return &result;
}

void *nfs3_pathconf(struct svc_req *req, struct nfs_arg *argp)
{
	static PATHCONF3res result;

	result.status = NFS3_OK;
	result.PATHCONF3res_u.resok.obj_attributes.attributes_follow = false;
	result.PATHCONF3res_u.resok.linkmax = UINT32_MAX;
	result.PATHCONF3res_u.resok.name_max = NFS_MAXNAMLEN;
	result.PATHCONF3res_u.resok.no_trunc = true;
	result.PATHCONF3res_u.resok.chown_restricted = false;
	result.PATHCONF3res_u.resok.case_insensitive = false;
	result.PATHCONF3res_u.resok.case_preserving = true;

	return &result;
}

void *nfs3_commit(struct svc_req *req, struct nfs_arg *argp)
{
	static COMMIT3res result;

	result.status = NFS3ERR_NOTSUPP;

	return &result;
}
