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

void *mount3_null(struct svc_req *req, struct nfs_arg *arg)
{
	static void *result;

	return &result;
}

void *mount3_mnt(struct svc_req *req, struct nfs_arg *arg)
{
	static mountres3 result;
	static int auth = AUTH_UNIX; /* FIXME: add auth support */
	static struct svc_fh fh;
	char *p = arg->mnt;
	uint32_t vid;
	int ret;

	sd_debug("%s", p);

	ret = sd_lookup_vdi(p, &vid);
	switch (ret) {
	case SD_RES_SUCCESS:
		fh.ino = fs_root_ino(vid);
		result.fhs_status = MNT3_OK;
		break;
	case SD_RES_NO_VDI:
		result.fhs_status = MNT3ERR_NOENT;
		goto out;
	default:
		result.fhs_status = MNT3ERR_SERVERFAULT;
		goto out;
	}

	result.mountres3_u.mountinfo.fhandle.fhandle3_len = sizeof(fh);
	result.mountres3_u.mountinfo.fhandle.fhandle3_val = (char *)&fh;
	result.mountres3_u.mountinfo.auth_flavors.auth_flavors_len = 1;
	result.mountres3_u.mountinfo.auth_flavors.auth_flavors_val = &auth;
out:
	return &result;
}

void *mount3_dump(struct svc_req *req, struct nfs_arg *arg)
{
	return NULL;
}

void *mount3_umnt(struct svc_req *req, struct nfs_arg *arg)
{
	static void *result;
	char *p = arg->umnt;

	sd_debug("%s", p);

	return &result;
}

void *mount3_umntall(struct svc_req *req, struct nfs_arg *arg)
{
	return NULL;
}

void *mount3_export(struct svc_req *req, struct nfs_arg *arg)
{
	return NULL;
}
