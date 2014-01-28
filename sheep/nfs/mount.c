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
	return NULL;
}

void *mount3_mnt(struct svc_req *req, struct nfs_arg *arg)
{
	return NULL;
}

void *mount3_dump(struct svc_req *req, struct nfs_arg *arg)
{
	return NULL;
}
void *mount3_umnt(struct svc_req *req, struct nfs_arg *arg)
{
	return NULL;
}
void *mount3_umntall(struct svc_req *req, struct nfs_arg *arg)
{
	return NULL;
}
void *mount3_export(struct svc_req *req, struct nfs_arg *arg)
{
	return NULL;
}
