#include "nfs.h"

bool_t
xdr_uint64(XDR *xdrs, uint64 *objp)
{
	if (!xdr_u_quad_t(xdrs, objp))
		return FALSE;
	return TRUE;
}

bool_t
xdr_int64(XDR *xdrs, int64 *objp)
{
	if (!xdr_quad_t(xdrs, objp))
		return FALSE;
	return TRUE;
}

bool_t
xdr_uint32(XDR *xdrs, uint32 *objp)
{
	if (!xdr_u_long(xdrs, objp))
		return FALSE;
	return TRUE;
}

bool_t
xdr_int32(XDR *xdrs, int32 *objp)
{
	if (!xdr_long(xdrs, objp))
		return FALSE;
	return TRUE;
}

bool_t
xdr_filename3(XDR *xdrs, filename3 *objp)
{
	if (!xdr_string(xdrs, objp, ~0))
		return FALSE;
	return TRUE;
}

bool_t
xdr_nfspath3(XDR *xdrs, nfspath3 *objp)
{
	if (!xdr_string(xdrs, objp, ~0))
		return FALSE;
	return TRUE;
}

bool_t
xdr_fileid3(XDR *xdrs, fileid3 *objp)
{
	if (!xdr_uint64(xdrs, objp))
		return FALSE;
	return TRUE;
}

bool_t
xdr_cookie3(XDR *xdrs, cookie3 *objp)
{
	if (!xdr_uint64(xdrs, objp))
		return FALSE;
	return TRUE;
}

bool_t
xdr_cookieverf3(XDR *xdrs, cookieverf3 objp)
{
	if (!xdr_opaque(xdrs, objp, NFS3_COOKIEVERFSIZE))
		return FALSE;
	return TRUE;
}

bool_t
xdr_createverf3(XDR *xdrs, createverf3 objp)
{
	if (!xdr_opaque(xdrs, objp, NFS3_CREATEVERFSIZE))
		return FALSE;
	return TRUE;
}

bool_t
xdr_writeverf3(XDR *xdrs, writeverf3 objp)
{
	if (!xdr_opaque(xdrs, objp, NFS3_WRITEVERFSIZE))
		return FALSE;
	return TRUE;
}

bool_t
xdr_uid3(XDR *xdrs, uid3 *objp)
{
	if (!xdr_uint32(xdrs, objp))
		return FALSE;
	return TRUE;
}

bool_t
xdr_gid3(XDR *xdrs, gid3 *objp)
{
	if (!xdr_uint32(xdrs, objp))
		return FALSE;
	return TRUE;
}

bool_t
xdr_size3(XDR *xdrs, size3 *objp)
{
	if (!xdr_uint64(xdrs, objp))
		return FALSE;
	return TRUE;
}

bool_t
xdr_offset3(XDR *xdrs, offset3 *objp)
{
	if (!xdr_uint64(xdrs, objp))
		return FALSE;
	return TRUE;
}

bool_t
xdr_mode3(XDR *xdrs, mode3 *objp)
{
	if (!xdr_uint32(xdrs, objp))
		return FALSE;
	return TRUE;
}

bool_t
xdr_count3(XDR *xdrs, count3 *objp)
{
	if (!xdr_uint32(xdrs, objp))
		return FALSE;
	return TRUE;
}

bool_t
xdr_nfsstat3(XDR *xdrs, nfsstat3 *objp)
{
	if (!xdr_enum(xdrs, (enum_t *) objp))
		return FALSE;
	return TRUE;
}

bool_t
xdr_ftype3(XDR *xdrs, ftype3 *objp)
{
	if (!xdr_enum(xdrs, (enum_t *) objp))
		return FALSE;
	return TRUE;
}

bool_t
xdr_specdata3(XDR *xdrs, specdata3 *objp)
{
	if (!xdr_uint32(xdrs, &objp->specdata1))
		return FALSE;
	if (!xdr_uint32(xdrs, &objp->specdata2))
		return FALSE;
	return TRUE;
}

bool_t
xdr_nfs_fh3(XDR *xdrs, nfs_fh3 *objp)
{
	if (!xdr_bytes(xdrs, (char **)&objp->data.data_val,
		       (u_int *)&objp->data.data_len, NFS3_FHSIZE))
		return FALSE;
	return TRUE;
}

bool_t
xdr_nfstime3(XDR *xdrs, nfstime3 *objp)
{
	if (!xdr_uint32(xdrs, &objp->seconds))
		return FALSE;
	if (!xdr_uint32(xdrs, &objp->nseconds))
		return FALSE;
	return TRUE;
}

bool_t
xdr_fattr3(XDR *xdrs, fattr3 *objp)
{
	if (!xdr_ftype3(xdrs, &objp->type))
		return FALSE;
	if (!xdr_mode3(xdrs, &objp->mode))
		return FALSE;
	if (!xdr_uint32(xdrs, &objp->nlink))
		return FALSE;
	if (!xdr_uid3(xdrs, &objp->uid))
		return FALSE;
	if (!xdr_gid3(xdrs, &objp->gid))
		return FALSE;
	if (!xdr_size3(xdrs, &objp->size))
		return FALSE;
	if (!xdr_size3(xdrs, &objp->used))
		return FALSE;
	if (!xdr_specdata3(xdrs, &objp->rdev))
		return FALSE;
	if (!xdr_uint64(xdrs, &objp->fsid))
		return FALSE;
	if (!xdr_fileid3(xdrs, &objp->fileid))
		return FALSE;
	if (!xdr_nfstime3(xdrs, &objp->atime))
		return FALSE;
	if (!xdr_nfstime3(xdrs, &objp->mtime))
		return FALSE;
	if (!xdr_nfstime3(xdrs, &objp->ctime))
		return FALSE;
	return TRUE;
}

bool_t
xdr_post_op_attr(XDR *xdrs, post_op_attr *objp)
{
	if (!xdr_bool(xdrs, &objp->attributes_follow))
		return FALSE;
	switch (objp->attributes_follow) {
	case TRUE:
		if (!xdr_fattr3(xdrs, &objp->post_op_attr_u.attributes))
			return FALSE;
		break;
	case FALSE:
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

bool_t
xdr_wcc_attr(XDR *xdrs, wcc_attr *objp)
{
	if (!xdr_size3(xdrs, &objp->size))
		return FALSE;
	if (!xdr_nfstime3(xdrs, &objp->mtime))
		return FALSE;
	if (!xdr_nfstime3(xdrs, &objp->ctime))
		return FALSE;
	return TRUE;
}

bool_t
xdr_pre_op_attr(XDR *xdrs, pre_op_attr *objp)
{
	if (!xdr_bool(xdrs, &objp->attributes_follow))
		return FALSE;
	switch (objp->attributes_follow) {
	case TRUE:
		if (!xdr_wcc_attr(xdrs, &objp->pre_op_attr_u.attributes))
			return FALSE;
		break;
	case FALSE:
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

bool_t
xdr_wcc_data(XDR *xdrs, wcc_data *objp)
{
	if (!xdr_pre_op_attr(xdrs, &objp->before))
		return FALSE;
	if (!xdr_post_op_attr(xdrs, &objp->after))
		return FALSE;
	return TRUE;
}

bool_t
xdr_post_op_fh3(XDR *xdrs, post_op_fh3 *objp)
{
	if (!xdr_bool(xdrs, &objp->handle_follows))
		return FALSE;
	switch (objp->handle_follows) {
	case TRUE:
		if (!xdr_nfs_fh3(xdrs, &objp->post_op_fh3_u.handle))
			return FALSE;
		break;
	case FALSE:
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

bool_t
xdr_time_how(XDR *xdrs, time_how *objp)
{
	if (!xdr_enum(xdrs, (enum_t *) objp))
		return FALSE;
	return TRUE;
}

bool_t
xdr_set_mode3(XDR *xdrs, set_mode3 *objp)
{
	if (!xdr_bool(xdrs, &objp->set_it))
		return FALSE;
	switch (objp->set_it) {
	case TRUE:
		if (!xdr_mode3(xdrs, &objp->set_mode3_u.mode))
			return FALSE;
		break;
	default:
		break;
	}
	return TRUE;
}

bool_t
xdr_set_uid3(XDR *xdrs, set_uid3 *objp)
{
	if (!xdr_bool(xdrs, &objp->set_it))
		return FALSE;
	switch (objp->set_it) {
	case TRUE:
		if (!xdr_uid3(xdrs, &objp->set_uid3_u.uid))
			return FALSE;
		break;
	default:
		break;
	}
	return TRUE;
}

bool_t
xdr_set_gid3(XDR *xdrs, set_gid3 *objp)
{
	if (!xdr_bool(xdrs, &objp->set_it))
		return FALSE;
	switch (objp->set_it) {
	case TRUE:
		if (!xdr_gid3(xdrs, &objp->set_gid3_u.gid))
			return FALSE;
		break;
	default:
		break;
	}
	return TRUE;
}

bool_t
xdr_set_size3(XDR *xdrs, set_size3 *objp)
{
	if (!xdr_bool(xdrs, &objp->set_it))
		return FALSE;
	switch (objp->set_it) {
	case TRUE:
		if (!xdr_size3(xdrs, &objp->set_size3_u.size))
			return FALSE;
		break;
	default:
		break;
	}
	return TRUE;
}

bool_t
xdr_set_atime(XDR *xdrs, set_atime *objp)
{
	if (!xdr_time_how(xdrs, &objp->set_it))
		return FALSE;
	switch (objp->set_it) {
	case SET_TO_CLIENT_TIME:
		if (!xdr_nfstime3(xdrs, &objp->set_atime_u.atime))
			return FALSE;
		break;
	default:
		break;
	}
	return TRUE;
}

bool_t
xdr_set_mtime(XDR *xdrs, set_mtime *objp)
{
	if (!xdr_time_how(xdrs, &objp->set_it))
		return FALSE;
	switch (objp->set_it) {
	case SET_TO_CLIENT_TIME:
		if (!xdr_nfstime3(xdrs, &objp->set_mtime_u.mtime))
			return FALSE;
		break;
	default:
		break;
	}
	return TRUE;
}

bool_t
xdr_sattr3(XDR *xdrs, sattr3 *objp)
{
	if (!xdr_set_mode3(xdrs, &objp->mode))
		return FALSE;
	if (!xdr_set_uid3(xdrs, &objp->uid))
		return FALSE;
	if (!xdr_set_gid3(xdrs, &objp->gid))
		return FALSE;
	if (!xdr_set_size3(xdrs, &objp->size))
		return FALSE;
	if (!xdr_set_atime(xdrs, &objp->atime))
		return FALSE;
	if (!xdr_set_mtime(xdrs, &objp->mtime))
		return FALSE;
	return TRUE;
}

bool_t
xdr_diropargs3(XDR *xdrs, diropargs3 *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->dir))
		return FALSE;
	if (!xdr_filename3(xdrs, &objp->name))
		return FALSE;
	return TRUE;
}

bool_t
xdr_getattr_args(XDR *xdrs, GETATTR3args *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->object))
		return FALSE;
	return TRUE;
}

bool_t
xdr_getattr_resok(XDR *xdrs, GETATTR3resok *objp)
{
	if (!xdr_fattr3(xdrs, &objp->obj_attributes))
		return FALSE;
	return TRUE;
}

bool_t
xdr_getattr_res(XDR *xdrs, GETATTR3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_getattr_resok(xdrs, &objp->GETATTR3res_u.resok))
			return FALSE;
		break;
	default:
		break;
	}
	return TRUE;
}

bool_t
xdr_sattrguard3(XDR *xdrs, sattrguard3 *objp)
{
	if (!xdr_bool(xdrs, &objp->check))
		return FALSE;
	switch (objp->check) {
	case TRUE:
		if (!xdr_nfstime3(xdrs, &objp->sattrguard3_u.obj_ctime))
			return FALSE;
		break;
	case FALSE:
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

bool_t
xdr_setattr_args(XDR *xdrs, SETATTR3args *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->object))
		return FALSE;
	if (!xdr_sattr3(xdrs, &objp->new_attributes))
		return FALSE;
	if (!xdr_sattrguard3(xdrs, &objp->guard))
		return FALSE;
	return TRUE;
}

bool_t
xdr_setattr_resok(XDR *xdrs, SETATTR3resok *objp)
{
	if (!xdr_wcc_data(xdrs, &objp->obj_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_setattr_resfail(XDR *xdrs, SETATTR3resfail *objp)
{
	if (!xdr_wcc_data(xdrs, &objp->obj_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_setattr_res(XDR *xdrs, SETATTR3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_setattr_resok(xdrs, &objp->SETATTR3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_setattr_resfail(xdrs, &objp->SETATTR3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_lookup_args(XDR *xdrs, LOOKUP3args *objp)
{
	if (!xdr_diropargs3(xdrs, &objp->what))
		return FALSE;
	return TRUE;
}

bool_t
xdr_lookup_resok(XDR *xdrs, LOOKUP3resok *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->object))
		return FALSE;
	if (!xdr_post_op_attr(xdrs, &objp->obj_attributes))
		return FALSE;
	if (!xdr_post_op_attr(xdrs, &objp->dir_attributes))
		return FALSE;
	return TRUE;
}

bool_t
xdr_lookup_resfail(XDR *xdrs, LOOKUP3resfail *objp)
{
	if (!xdr_post_op_attr(xdrs, &objp->dir_attributes))
		return FALSE;
	return TRUE;
}

bool_t
xdr_lookup_res(XDR *xdrs, LOOKUP3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_lookup_resok(xdrs, &objp->LOOKUP3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_lookup_resfail(xdrs, &objp->LOOKUP3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_access_args(XDR *xdrs, ACCESS3args *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->object))
		return FALSE;
	if (!xdr_uint32(xdrs, &objp->access))
		return FALSE;
	return TRUE;
}

bool_t
xdr_access_resok(XDR *xdrs, ACCESS3resok *objp)
{
	if (!xdr_post_op_attr(xdrs, &objp->obj_attributes))
		return FALSE;
	if (!xdr_uint32(xdrs, &objp->access))
		return FALSE;
	return TRUE;
}

bool_t
xdr_access_resfail(XDR *xdrs, ACCESS3resfail *objp)
{
	if (!xdr_post_op_attr(xdrs, &objp->obj_attributes))
		return FALSE;
	return TRUE;
}

bool_t
xdr_access_res(XDR *xdrs, ACCESS3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_access_resok(xdrs, &objp->ACCESS3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_access_resfail(xdrs, &objp->ACCESS3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_readlink_args(XDR *xdrs, READLINK3args *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->symlink))
		return FALSE;
	return TRUE;
}

bool_t
xdr_readlink_resok(XDR *xdrs, READLINK3resok *objp)
{
	if (!xdr_post_op_attr(xdrs, &objp->symlink_attributes))
		return FALSE;
	if (!xdr_nfspath3(xdrs, &objp->data))
		return FALSE;
	return TRUE;
}

bool_t
xdr_readlink_resfail(XDR *xdrs, READLINK3resfail *objp)
{
	if (!xdr_post_op_attr(xdrs, &objp->symlink_attributes))
		return FALSE;
	return TRUE;
}

bool_t
xdr_readlink_res(XDR *xdrs, READLINK3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_readlink_resok(xdrs, &objp->READLINK3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_readlink_resfail(xdrs, &objp->READLINK3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_read_args(XDR *xdrs, READ3args *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->file))
		return FALSE;
	if (!xdr_offset3(xdrs, &objp->offset))
		return FALSE;
	if (!xdr_count3(xdrs, &objp->count))
		return FALSE;
	return TRUE;
}

bool_t
xdr_read_resok(XDR *xdrs, READ3resok *objp)
{
	if (!xdr_post_op_attr(xdrs, &objp->file_attributes))
		return FALSE;
	if (!xdr_count3(xdrs, &objp->count))
		return FALSE;
	if (!xdr_bool(xdrs, &objp->eof))
		return FALSE;
	if (!xdr_bytes(xdrs, (char **)&objp->data.data_val,
		       (u_int *)&objp->data.data_len, ~0))
		return FALSE;
	return TRUE;
}

bool_t
xdr_read_resfail(XDR *xdrs, READ3resfail *objp)
{
	if (!xdr_post_op_attr(xdrs, &objp->file_attributes))
		return FALSE;
	return TRUE;
}

bool_t
xdr_read_res(XDR *xdrs, READ3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_read_resok(xdrs, &objp->READ3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_read_resfail(xdrs, &objp->READ3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_stable_how(XDR *xdrs, stable_how *objp)
{
	if (!xdr_enum(xdrs, (enum_t *) objp))
		return FALSE;
	return TRUE;
}

bool_t
xdr_write_args(XDR *xdrs, WRITE3args *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->file))
		return FALSE;
	if (!xdr_offset3(xdrs, &objp->offset))
		return FALSE;
	if (!xdr_count3(xdrs, &objp->count))
		return FALSE;
	if (!xdr_stable_how(xdrs, &objp->stable))
		return FALSE;
	if (!xdr_bytes(xdrs, (char **)&objp->data.data_val,
		       (u_int *)&objp->data.data_len, ~0))
		return FALSE;
	return TRUE;
}

bool_t
xdr_write_resok(XDR *xdrs, WRITE3resok *objp)
{
	if (!xdr_wcc_data(xdrs, &objp->file_wcc))
		return FALSE;
	if (!xdr_count3(xdrs, &objp->count))
		return FALSE;
	if (!xdr_stable_how(xdrs, &objp->committed))
		return FALSE;
	if (!xdr_writeverf3(xdrs, objp->verf))
		return FALSE;
	return TRUE;
}

bool_t
xdr_write_resfail(XDR *xdrs, WRITE3resfail *objp)
{
	if (!xdr_wcc_data(xdrs, &objp->file_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_write_res(XDR *xdrs, WRITE3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_write_resok(xdrs, &objp->WRITE3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_write_resfail(xdrs, &objp->WRITE3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_createmode3(XDR *xdrs, createmode3 *objp)
{
	if (!xdr_enum(xdrs, (enum_t *) objp))
		return FALSE;
	return TRUE;
}

bool_t
xdr_createhow3(XDR *xdrs, createhow3 *objp)
{
	if (!xdr_createmode3(xdrs, &objp->mode))
		return FALSE;
	switch (objp->mode) {
	case UNCHECKED:
	case GUARDED:
		if (!xdr_sattr3(xdrs, &objp->createhow3_u.obj_attributes))
			return FALSE;
		break;
	case EXCLUSIVE:
		if (!xdr_createverf3(xdrs, objp->createhow3_u.verf))
			return FALSE;
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

bool_t
xdr_create_args(XDR *xdrs, CREATE3args *objp)
{
	if (!xdr_diropargs3(xdrs, &objp->where))
		return FALSE;
	if (!xdr_createhow3(xdrs, &objp->how))
		return FALSE;
	return TRUE;
}

bool_t
xdr_create_resok(XDR *xdrs, CREATE3resok *objp)
{
	if (!xdr_post_op_fh3(xdrs, &objp->obj))
		return FALSE;
	if (!xdr_post_op_attr(xdrs, &objp->obj_attributes))
		return FALSE;
	if (!xdr_wcc_data(xdrs, &objp->dir_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_create_resfail(XDR *xdrs, CREATE3resfail *objp)
{
	if (!xdr_wcc_data(xdrs, &objp->dir_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_create_res(XDR *xdrs, CREATE3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_create_resok(xdrs, &objp->CREATE3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_create_resfail(xdrs, &objp->CREATE3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_mkdir_args(XDR *xdrs, MKDIR3args *objp)
{
	if (!xdr_diropargs3(xdrs, &objp->where))
		return FALSE;
	if (!xdr_sattr3(xdrs, &objp->attributes))
		return FALSE;
	return TRUE;
}

bool_t
xdr_mkdir_resok(XDR *xdrs, MKDIR3resok *objp)
{
	if (!xdr_post_op_fh3(xdrs, &objp->obj))
		return FALSE;
	if (!xdr_post_op_attr(xdrs, &objp->obj_attributes))
		return FALSE;
	if (!xdr_wcc_data(xdrs, &objp->dir_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_mkdir_resfail(XDR *xdrs, MKDIR3resfail *objp)
{
	if (!xdr_wcc_data(xdrs, &objp->dir_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_mkdir_res(XDR *xdrs, MKDIR3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_mkdir_resok(xdrs, &objp->MKDIR3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_mkdir_resfail(xdrs, &objp->MKDIR3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_symlinkdata3(XDR *xdrs, symlinkdata3 *objp)
{
	if (!xdr_sattr3(xdrs, &objp->symlink_attributes))
		return FALSE;
	if (!xdr_nfspath3(xdrs, &objp->symlink_data))
		return FALSE;
	return TRUE;
}

bool_t
xdr_symlink_args(XDR *xdrs, SYMLINK3args *objp)
{
	if (!xdr_diropargs3(xdrs, &objp->where))
		return FALSE;
	if (!xdr_symlinkdata3(xdrs, &objp->symlink))
		return FALSE;
	return TRUE;
}

bool_t
xdr_symlink_resok(XDR *xdrs, SYMLINK3resok *objp)
{
	if (!xdr_post_op_fh3(xdrs, &objp->obj))
		return FALSE;
	if (!xdr_post_op_attr(xdrs, &objp->obj_attributes))
		return FALSE;
	if (!xdr_wcc_data(xdrs, &objp->dir_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_symlink_resfail(XDR *xdrs, SYMLINK3resfail *objp)
{
	if (!xdr_wcc_data(xdrs, &objp->dir_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_symlink_res(XDR *xdrs, SYMLINK3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_symlink_resok(xdrs, &objp->SYMLINK3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_symlink_resfail(xdrs, &objp->SYMLINK3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_devicedata3(XDR *xdrs, devicedata3 *objp)
{
	if (!xdr_sattr3(xdrs, &objp->dev_attributes))
		return FALSE;
	if (!xdr_specdata3(xdrs, &objp->spec))
		return FALSE;
	return TRUE;
}

bool_t
xdr_mknoddata3(XDR *xdrs, mknoddata3 *objp)
{
	if (!xdr_ftype3(xdrs, &objp->type))
		return FALSE;
	switch (objp->type) {
	case NF3CHR:
	case NF3BLK:
		if (!xdr_devicedata3(xdrs, &objp->mknoddata3_u.device))
			return FALSE;
		break;
	case NF3SOCK:
	case NF3FIFO:
		if (!xdr_sattr3(xdrs, &objp->mknoddata3_u.pipe_attributes))
			return FALSE;
		break;
	default:
		break;
	}
	return TRUE;
}

bool_t
xdr_mknod_args(XDR *xdrs, MKNOD3args *objp)
{
	if (!xdr_diropargs3(xdrs, &objp->where))
		return FALSE;
	if (!xdr_mknoddata3(xdrs, &objp->what))
		return FALSE;
	return TRUE;
}

bool_t
xdr_mknod_resok(XDR *xdrs, MKNOD3resok *objp)
{
	if (!xdr_post_op_fh3(xdrs, &objp->obj))
		return FALSE;
	if (!xdr_post_op_attr(xdrs, &objp->obj_attributes))
		return FALSE;
	if (!xdr_wcc_data(xdrs, &objp->dir_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_mknod_resfail(XDR *xdrs, MKNOD3resfail *objp)
{
	if (!xdr_wcc_data(xdrs, &objp->dir_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_mknod_res(XDR *xdrs, MKNOD3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_mknod_resok(xdrs, &objp->MKNOD3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_mknod_resfail(xdrs, &objp->MKNOD3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_remove_args(XDR *xdrs, REMOVE3args *objp)
{
	if (!xdr_diropargs3(xdrs, &objp->object))
		return FALSE;
	return TRUE;
}

bool_t
xdr_remove_resok(XDR *xdrs, REMOVE3resok *objp)
{
	if (!xdr_wcc_data(xdrs, &objp->dir_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_remove_resfail(XDR *xdrs, REMOVE3resfail *objp)
{
	if (!xdr_wcc_data(xdrs, &objp->dir_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_remove_res(XDR *xdrs, REMOVE3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_remove_resok(xdrs, &objp->REMOVE3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_remove_resfail(xdrs, &objp->REMOVE3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_rmdir_args(XDR *xdrs, RMDIR3args *objp)
{
	if (!xdr_diropargs3(xdrs, &objp->object))
		return FALSE;
	return TRUE;
}

bool_t
xdr_rmdir_resok(XDR *xdrs, RMDIR3resok *objp)
{
	if (!xdr_wcc_data(xdrs, &objp->dir_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_rmdir_resfail(XDR *xdrs, RMDIR3resfail *objp)
{
	if (!xdr_wcc_data(xdrs, &objp->dir_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_rmdir_res(XDR *xdrs, RMDIR3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_rmdir_resok(xdrs, &objp->RMDIR3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_rmdir_resfail(xdrs, &objp->RMDIR3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_rename_args(XDR *xdrs, RENAME3args *objp)
{
	if (!xdr_diropargs3(xdrs, &objp->from))
		return FALSE;
	if (!xdr_diropargs3(xdrs, &objp->to))
		return FALSE;
	return TRUE;
}

bool_t
xdr_rename_resok(XDR *xdrs, RENAME3resok *objp)
{
	if (!xdr_wcc_data(xdrs, &objp->fromdir_wcc))
		return FALSE;
	if (!xdr_wcc_data(xdrs, &objp->todir_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_rename_resfail(XDR *xdrs, RENAME3resfail *objp)
{
	if (!xdr_wcc_data(xdrs, &objp->fromdir_wcc))
		return FALSE;
	if (!xdr_wcc_data(xdrs, &objp->todir_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_rename_res(XDR *xdrs, RENAME3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_rename_resok(xdrs, &objp->RENAME3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_rename_resfail(xdrs, &objp->RENAME3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_link_args(XDR *xdrs, LINK3args *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->file))
		return FALSE;
	if (!xdr_diropargs3(xdrs, &objp->link))
		return FALSE;
	return TRUE;
}

bool_t
xdr_link_resok(XDR *xdrs, LINK3resok *objp)
{
	if (!xdr_post_op_attr(xdrs, &objp->file_attributes))
		return FALSE;
	if (!xdr_wcc_data(xdrs, &objp->linkdir_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_link_resfail(XDR *xdrs, LINK3resfail *objp)
{
	if (!xdr_post_op_attr(xdrs, &objp->file_attributes))
		return FALSE;
	if (!xdr_wcc_data(xdrs, &objp->linkdir_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_link_res(XDR *xdrs, LINK3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_link_resok(xdrs, &objp->LINK3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_link_resfail(xdrs, &objp->LINK3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_readdir_args(XDR *xdrs, READDIR3args *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->dir))
		return FALSE;
	if (!xdr_cookie3(xdrs, &objp->cookie))
		return FALSE;
	if (!xdr_cookieverf3(xdrs, objp->cookieverf))
		return FALSE;
	if (!xdr_count3(xdrs, &objp->count))
		return FALSE;
	return TRUE;
}

bool_t
xdr_entry3(XDR *xdrs, entry3 *objp)
{
	if (!xdr_fileid3(xdrs, &objp->fileid))
		return FALSE;
	if (!xdr_filename3(xdrs, &objp->name))
		return FALSE;
	if (!xdr_cookie3(xdrs, &objp->cookie))
		return FALSE;
	if (!xdr_pointer(xdrs, (char **)&objp->nextentry, sizeof(entry3),
			 (xdrproc_t)xdr_entry3))
		return FALSE;
	return TRUE;
}

bool_t
xdr_dirlist3(XDR *xdrs, dirlist3 *objp)
{
	if (!xdr_pointer(xdrs, (char **)&objp->entries, sizeof(entry3),
			 (xdrproc_t)xdr_entry3))
		return FALSE;
	if (!xdr_bool(xdrs, &objp->eof))
		return FALSE;
	return TRUE;
}

bool_t
xdr_readdir_resok(XDR *xdrs, READDIR3resok *objp)
{
	if (!xdr_post_op_attr(xdrs, &objp->dir_attributes))
		return FALSE;
	if (!xdr_cookieverf3(xdrs, objp->cookieverf))
		return FALSE;
	if (!xdr_dirlist3(xdrs, &objp->reply))
		return FALSE;
	return TRUE;
}

bool_t
xdr_readdir_resfail(XDR *xdrs, READDIR3resfail *objp)
{
	if (!xdr_post_op_attr(xdrs, &objp->dir_attributes))
		return FALSE;
	return TRUE;
}

bool_t
xdr_readdir_res(XDR *xdrs, READDIR3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_readdir_resok(xdrs, &objp->READDIR3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_readdir_resfail(xdrs, &objp->READDIR3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_readdirplus_args(XDR *xdrs, READDIRPLUS3args *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->dir))
		return FALSE;
	if (!xdr_cookie3(xdrs, &objp->cookie))
		return FALSE;
	if (!xdr_cookieverf3(xdrs, objp->cookieverf))
		return FALSE;
	if (!xdr_count3(xdrs, &objp->dircount))
		return FALSE;
	if (!xdr_count3(xdrs, &objp->maxcount))
		return FALSE;
	return TRUE;
}

bool_t
xdr_entryplus3(XDR *xdrs, entryplus3 *objp)
{
	if (!xdr_fileid3(xdrs, &objp->fileid))
		return FALSE;
	if (!xdr_filename3(xdrs, &objp->name))
		return FALSE;
	if (!xdr_cookie3(xdrs, &objp->cookie))
		return FALSE;
	if (!xdr_post_op_attr(xdrs, &objp->name_attributes))
		return FALSE;
	if (!xdr_post_op_fh3(xdrs, &objp->name_handle))
		return FALSE;
	if (!xdr_pointer(xdrs, (char **)&objp->nextentry, sizeof(entryplus3),
			 (xdrproc_t) xdr_entryplus3))
		return FALSE;
	return TRUE;
}

bool_t
xdr_dirlistplus3(XDR *xdrs, dirlistplus3 *objp)
{
	if (!xdr_pointer(xdrs, (char **)&objp->entries, sizeof(entryplus3),
			 (xdrproc_t) xdr_entryplus3))
		return FALSE;
	if (!xdr_bool(xdrs, &objp->eof))
		return FALSE;
	return TRUE;
}

bool_t
xdr_readdirplus_resok(XDR *xdrs, READDIRPLUS3resok *objp)
{
	if (!xdr_post_op_attr(xdrs, &objp->dir_attributes))
		return FALSE;
	if (!xdr_cookieverf3(xdrs, objp->cookieverf))
		return FALSE;
	if (!xdr_dirlistplus3(xdrs, &objp->reply))
		return FALSE;
	return TRUE;
}

bool_t
xdr_readdirplus_resfail(XDR *xdrs, READDIRPLUS3resfail *objp)
{
	if (!xdr_post_op_attr(xdrs, &objp->dir_attributes))
		return FALSE;
	return TRUE;
}

bool_t
xdr_readdirplus_res(XDR *xdrs, READDIRPLUS3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_readdirplus_resok(xdrs,
					   &objp->READDIRPLUS3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_readdirplus_resfail(xdrs,
					     &objp->READDIRPLUS3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_fsstat_args(XDR *xdrs, FSSTAT3args *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->fsroot))
		return FALSE;
	return TRUE;
}

bool_t
xdr_fsstat_resok(XDR *xdrs, FSSTAT3resok *objp)
{
	if (!xdr_post_op_attr(xdrs, &objp->obj_attributes))
		return FALSE;
	if (!xdr_size3(xdrs, &objp->tbytes))
		return FALSE;
	if (!xdr_size3(xdrs, &objp->fbytes))
		return FALSE;
	if (!xdr_size3(xdrs, &objp->abytes))
		return FALSE;
	if (!xdr_size3(xdrs, &objp->tfiles))
		return FALSE;
	if (!xdr_size3(xdrs, &objp->ffiles))
		return FALSE;
	if (!xdr_size3(xdrs, &objp->afiles))
		return FALSE;
	if (!xdr_uint32(xdrs, &objp->invarsec))
		return FALSE;
	return TRUE;
}

bool_t
xdr_fsstat_resfail(XDR *xdrs, FSSTAT3resfail *objp)
{
	if (!xdr_post_op_attr(xdrs, &objp->obj_attributes))
		return FALSE;
	return TRUE;
}

bool_t
xdr_fsstat_res(XDR *xdrs, FSSTAT3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_fsstat_resok(xdrs, &objp->FSSTAT3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_fsstat_resfail(xdrs, &objp->FSSTAT3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_fsinfo_args(XDR *xdrs, FSINFO3args *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->fsroot))
		return FALSE;
	return TRUE;
}

bool_t
xdr_fsinfo_resok(XDR *xdrs, FSINFO3resok *objp)
{
	if (!xdr_post_op_attr(xdrs, &objp->obj_attributes))
		return FALSE;
	if (!xdr_uint32(xdrs, &objp->rtmax))
		return FALSE;
	if (!xdr_uint32(xdrs, &objp->rtpref))
		return FALSE;
	if (!xdr_uint32(xdrs, &objp->rtmult))
		return FALSE;
	if (!xdr_uint32(xdrs, &objp->wtmax))
		return FALSE;
	if (!xdr_uint32(xdrs, &objp->wtpref))
		return FALSE;
	if (!xdr_uint32(xdrs, &objp->wtmult))
		return FALSE;
	if (!xdr_uint32(xdrs, &objp->dtpref))
		return FALSE;
	if (!xdr_size3(xdrs, &objp->maxfilesize))
		return FALSE;
	if (!xdr_nfstime3(xdrs, &objp->time_delta))
		return FALSE;
	if (!xdr_uint32(xdrs, &objp->properties))
		return FALSE;
	return TRUE;
}

bool_t
xdr_fsinfo_resfail(XDR *xdrs, FSINFO3resfail *objp)
{
	if (!xdr_post_op_attr(xdrs, &objp->obj_attributes))
		return FALSE;
	return TRUE;
}

bool_t
xdr_fsinfo_res(XDR *xdrs, FSINFO3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_fsinfo_resok(xdrs, &objp->FSINFO3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_fsinfo_resfail(xdrs, &objp->FSINFO3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_pathconf_args(XDR *xdrs, PATHCONF3args *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->object))
		return FALSE;
	return TRUE;
}

bool_t
xdr_pathconf_resok(XDR *xdrs, PATHCONF3resok *objp)
{
	int32_t *buf;

	if (xdrs->x_op == XDR_ENCODE) {
		if (!xdr_post_op_attr(xdrs, &objp->obj_attributes))
			return FALSE;
		if (!xdr_uint32(xdrs, &objp->linkmax))
			return FALSE;
		if (!xdr_uint32(xdrs, &objp->name_max))
			return FALSE;
		buf = XDR_INLINE(xdrs, 4 * BYTES_PER_XDR_UNIT);
		if (buf == NULL) {
			if (!xdr_bool(xdrs, &objp->no_trunc))
				return FALSE;
			if (!xdr_bool(xdrs, &objp->chown_restricted))
				return FALSE;
			if (!xdr_bool(xdrs, &objp->case_insensitive))
				return FALSE;
			if (!xdr_bool(xdrs, &objp->case_preserving))
				return FALSE;
		} else {
			IXDR_PUT_BOOL(buf, objp->no_trunc);
			IXDR_PUT_BOOL(buf, objp->chown_restricted);
			IXDR_PUT_BOOL(buf, objp->case_insensitive);
			IXDR_PUT_BOOL(buf, objp->case_preserving);
		}
		return TRUE;
	} else if (xdrs->x_op == XDR_DECODE) {
		if (!xdr_post_op_attr(xdrs, &objp->obj_attributes))
			return FALSE;
		if (!xdr_uint32(xdrs, &objp->linkmax))
			return FALSE;
		if (!xdr_uint32(xdrs, &objp->name_max))
			return FALSE;
		buf = XDR_INLINE(xdrs, 4 * BYTES_PER_XDR_UNIT);
		if (buf == NULL) {
			if (!xdr_bool(xdrs, &objp->no_trunc))
				return FALSE;
			if (!xdr_bool(xdrs, &objp->chown_restricted))
				return FALSE;
			if (!xdr_bool(xdrs, &objp->case_insensitive))
				return FALSE;
			if (!xdr_bool(xdrs, &objp->case_preserving))
				return FALSE;
		} else {
			objp->no_trunc = IXDR_GET_BOOL(buf);
			objp->chown_restricted = IXDR_GET_BOOL(buf);
			objp->case_insensitive = IXDR_GET_BOOL(buf);
			objp->case_preserving = IXDR_GET_BOOL(buf);
		}
		return TRUE;
	}

	if (!xdr_post_op_attr(xdrs, &objp->obj_attributes))
		return FALSE;
	if (!xdr_uint32(xdrs, &objp->linkmax))
		return FALSE;
	if (!xdr_uint32(xdrs, &objp->name_max))
		return FALSE;
	if (!xdr_bool(xdrs, &objp->no_trunc))
		return FALSE;
	if (!xdr_bool(xdrs, &objp->chown_restricted))
		return FALSE;
	if (!xdr_bool(xdrs, &objp->case_insensitive))
		return FALSE;
	if (!xdr_bool(xdrs, &objp->case_preserving))
		return FALSE;
	return TRUE;
}

bool_t
xdr_pathconf_resfail(XDR *xdrs, PATHCONF3resfail *objp)
{
	if (!xdr_post_op_attr(xdrs, &objp->obj_attributes))
		return FALSE;
	return TRUE;
}

bool_t
xdr_pathconf_res(XDR *xdrs, PATHCONF3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_pathconf_resok(xdrs, &objp->PATHCONF3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_pathconf_resfail(xdrs, &objp->PATHCONF3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_commit_args(XDR *xdrs, COMMIT3args *objp)
{
	if (!xdr_nfs_fh3(xdrs, &objp->file))
		return FALSE;
	if (!xdr_offset3(xdrs, &objp->offset))
		return FALSE;
	if (!xdr_count3(xdrs, &objp->count))
		return FALSE;
	return TRUE;
}

bool_t
xdr_commit_resok(XDR *xdrs, COMMIT3resok *objp)
{
	if (!xdr_wcc_data(xdrs, &objp->file_wcc))
		return FALSE;
	if (!xdr_writeverf3(xdrs, objp->verf))
		return FALSE;
	return TRUE;
}

bool_t
xdr_commit_resfail(XDR *xdrs, COMMIT3resfail *objp)
{
	if (!xdr_wcc_data(xdrs, &objp->file_wcc))
		return FALSE;
	return TRUE;
}

bool_t
xdr_commit_res(XDR *xdrs, COMMIT3res *objp)
{
	if (!xdr_nfsstat3(xdrs, &objp->status))
		return FALSE;
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_commit_resok(xdrs, &objp->COMMIT3res_u.resok))
			return FALSE;
		break;
	default:
		if (!xdr_commit_resfail(xdrs, &objp->COMMIT3res_u.resfail))
			return FALSE;
		break;
	}
	return TRUE;
}

bool_t xdr_null_args(XDR *xdrs, void *ignore)
{
	return xdr_void();
}

bool_t xdr_null_res(XDR *xdrs, void *ignore)
{
	return xdr_void();
}
