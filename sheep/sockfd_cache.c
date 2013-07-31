/*
 * Copyright (C) 2012-2013 Taobao Inc.
 *
 * Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "sheep_priv.h"

int sheep_exec_req(const struct node_id *nid, struct sd_req *hdr, void *buf)
{
	struct sd_rsp *rsp = (struct sd_rsp *)hdr;
	struct sockfd *sfd;
	int ret;

	assert(is_worker_thread());

	sfd = sockfd_cache_get(nid);
	if (!sfd)
		return SD_RES_NETWORK_ERROR;

	ret = exec_req(sfd->fd, hdr, buf, sheep_need_retry, hdr->epoch,
		       MAX_RETRY_COUNT);
	if (ret) {
		sd_dprintf("remote node might have gone away");
		sockfd_cache_del(nid, sfd);
		return SD_RES_NETWORK_ERROR;
	}
	ret = rsp->result;
	if (ret != SD_RES_SUCCESS)
		sd_eprintf("failed %s", sd_strerror(ret));

	sockfd_cache_put(nid, sfd);
	return ret;
}

bool sheep_need_retry(uint32_t epoch)
{
	return sys_epoch() == epoch;
}
