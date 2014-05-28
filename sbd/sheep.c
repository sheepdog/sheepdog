/*
 * Copyright (C) 2014 Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "sbd.h"

static DEFINE_MUTEX(socket_mutex);
static struct kmem_cache *sheep_aiocb_pool;
static struct kmem_cache *sheep_request_pool;

void socket_shutdown(struct socket *sock)
{
	if (sock)
		kernel_sock_shutdown(sock, SHUT_RDWR);
}

static struct sbd_device *sheep_request_to_device(struct sheep_request *req)
{
	return req->aiocb->request->q->queuedata;
}

static struct sbd_device *sheep_aiocb_to_device(struct sheep_aiocb *aiocb)
{
	return aiocb->request->q->queuedata;
}

static int socket_create(struct socket **sock, const char *ip_addr, int port)
{
	struct sockaddr_in addr;
	mm_segment_t oldmm = get_fs();
	struct linger linger_opt = {1, 0};
	int ret, nodelay = 1;

	ret = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, sock);
	if (ret < 0) {
		pr_err("fail to create socket\n");
		return ret;
	}

	set_fs(KERNEL_DS);
	ret = sock_setsockopt(*sock, SOL_SOCKET, SO_LINGER,
			      (char *)&linger_opt, sizeof(linger_opt));
	set_fs(oldmm);
	if (ret != 0) {
		pr_err("Can't set SO_LINGER: %d\n", ret);
		goto shutdown;
	}

	set_fs(KERNEL_DS);
	ret = sock_setsockopt(*sock, SOL_TCP, TCP_NODELAY,
			      (char *)&nodelay, sizeof(nodelay));
	set_fs(oldmm);
	if (ret != 0) {
		pr_err("Can't set nodelay: %d\n", ret);
		goto shutdown;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = in_aton(ip_addr);
	ret = (*sock)->ops->connect(*sock, (struct sockaddr *)&addr,
				    sizeof(addr), 0);
	if (ret < 0) {
		pr_err("failed connect to %s:%d\n", ip_addr, port);
		goto shutdown;
	}

	(*sock)->sk->sk_allocation = SBD_GFP_FLAGS;

	return ret;
shutdown:
	socket_shutdown(*sock);
	*sock = NULL;
	return ret;
}

static int socket_xmit(struct socket *sock, void *buf, int size, bool send,
		       int msg_flags)
{
	int result;
	struct msghdr msg;
	struct kvec iov;
	sigset_t blocked, oldset;

	if (unlikely(!sock))
		return -EINVAL;

	/* Don't allow signals to interrupt the transmission */
	siginitsetinv(&blocked, 0);
	sigprocmask(SIG_SETMASK, &blocked, &oldset);

	do {
		iov.iov_base = buf;
		iov.iov_len = size;
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = msg_flags | MSG_NOSIGNAL;

		if (send)
			result = kernel_sendmsg(sock, &msg, &iov, 1, size);
		else
			result = kernel_recvmsg(sock, &msg, &iov, 1, size,
						msg.msg_flags);

		if (result <= 0) {
			if (result == 0)
				result = -EPIPE; /* short read */
			break;
		}
		size -= result;
		buf += result;
	} while (size > 0);

	sigprocmask(SIG_SETMASK, &oldset, NULL);

	return result;
}

static int socket_read(struct socket *sock, char *buf, int length)
{
	return socket_xmit(sock, buf, length, false, 0);
}

static int socket_write(struct socket *sock, void *buf, int len)
{
	return socket_xmit(sock, buf, len, true, 0);
}

static int sheep_submit_sdreq(struct socket *sock, struct sd_req *hdr,
			      void *data, unsigned int wlen)
{
	int ret;

	/* Make sheep_submit_sdreq thread safe */
	mutex_lock(&socket_mutex);

	ret = socket_write(sock, hdr, sizeof(*hdr));
	if (ret < 0)
		goto out;

	if (wlen)
		ret = socket_write(sock, data, wlen);
out:
	mutex_unlock(&socket_mutex);
	return ret;
}

/* Run the request synchronously */
static int sheep_run_sdreq(struct socket *sock, struct sd_req *hdr,
			   void *data)
{
	struct sd_rsp *rsp = (struct sd_rsp *)hdr;
	unsigned int wlen, rlen;
	int ret;

	if (hdr->flags & SD_FLAG_CMD_WRITE) {
		wlen = hdr->data_length;
		rlen = 0;
	} else {
		wlen = 0;
		rlen = hdr->data_length;
	}

	ret = sheep_submit_sdreq(sock, hdr, data, wlen);
	if (ret < 0) {
		pr_err("failed to sbumit the request\n");
		return ret;
	}

	ret = socket_read(sock, (char *)rsp, sizeof(*rsp));
	if (ret < 0) {
		pr_err("failed to read a response hdr\n");
		return ret;
	}

	if (rlen > rsp->data_length)
		rlen = rsp->data_length;

	if (rlen) {
		ret = socket_read(sock, data, rlen);
		if (ret < 0) {
			pr_err("failed to read the response data\n");
			return ret;
		}
	}

	switch (rsp->result) {
	case SD_RES_SUCCESS:
		break;
	case SD_RES_NO_OBJ:
	case SD_RES_NO_VDI:
		return -ENOENT;
	default:
		return -EIO;
	}

	return 0;
}

static int lookup_sheep_vdi(struct sbd_device *dev)
{
	struct sd_req hdr = {};
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret;

	hdr.opcode = SD_OP_LOCK_VDI;
	hdr.data_length = SD_MAX_VDI_LEN;
	hdr.flags = SD_FLAG_CMD_WRITE;
	ret = sheep_run_sdreq(dev->sock, &hdr, dev->vdi.name);
	if (ret < 0)
		return ret;

	dev->vdi.vid = rsp->vdi.vdi_id;

	return 0;
}

int sheep_setup_vdi(struct sbd_device *dev)
{
	struct sd_req hdr = {};
	struct sd_inode *inode;
	int ret;

	inode = vmalloc(sizeof(*inode));
	if (!inode)
		return -ENOMEM;
	memset(inode, 0 , sizeof(*inode));

	ret = socket_create(&dev->sock, dev->vdi.ip, dev->vdi.port);
	if (ret < 0)
		goto out;

	ret = lookup_sheep_vdi(dev);
	if (ret < 0) {
		pr_err("Cannot get VDI for %s, %d\n", dev->vdi.name, ret);
		goto out_release;
	}

	hdr.opcode = SD_OP_READ_OBJ;
	hdr.data_length = SD_INODE_SIZE;
	hdr.obj.oid = vid_to_vdi_oid(dev->vdi.vid);
	hdr.obj.offset = 0;
	ret = sheep_run_sdreq(dev->sock, &hdr, inode);
	if (ret < 0) {
		pr_err("Cannot read inode for %s, %d\n", dev->vdi.name, ret);
		goto out_release;
	}

	if (vdi_is_snapshot(inode)) {
		pr_err("%s: don't support to add snapshot %s\n", DRV_NAME,
		       dev->vdi.name);
		ret = -EINVAL;
		goto out_release;
	}

	dev->vdi.inode = inode;
	pr_info("%s: Associated to %s\n", DRV_NAME, inode->name);
	return 0;
out_release:
	socket_shutdown(dev->sock);
	dev->sock = NULL;
out:
	vfree(inode);
	return ret;
}

/* FIXME: handle submit failure */
static int submit_sheep_request(struct sheep_request *req)
{
	struct sd_req hdr = {};
	struct sbd_device *dev = sheep_request_to_device(req);
	int ret;

	hdr.id = req->seq_num;
	hdr.data_length = req->length;
	hdr.obj.oid = req->oid;
	hdr.obj.cow_oid = req->cow_oid;
	hdr.obj.offset = req->offset;

	write_lock(&dev->inflight_lock);
	BUG_ON(!list_empty(&req->list));
	list_add_tail(&req->list, &dev->inflight_head);
	write_unlock(&dev->inflight_lock);

	switch (req->type) {
	case SHEEP_CREATE:
	case SHEEP_WRITE:
		if (req->type == SHEEP_CREATE)
			hdr.opcode = SD_OP_CREATE_AND_WRITE_OBJ;
		else
			hdr.opcode = SD_OP_WRITE_OBJ;
		hdr.flags = SD_FLAG_CMD_WRITE | SD_FLAG_CMD_DIRECT;
		if (req->cow_oid)
			hdr.flags |= SD_FLAG_CMD_COW;
		ret = sheep_submit_sdreq(dev->sock, &hdr, req->buf,
					 req->length);
		if (ret < 0)
			goto err;
		break;
	case SHEEP_READ:
		hdr.opcode = SD_OP_READ_OBJ;
		ret = sheep_submit_sdreq(dev->sock, &hdr, NULL, 0);
		if (ret < 0)
			goto err;
		break;
	}
	sbd_debug("add oid %llx off %d, len %d, seq %u, type %d\n", req->oid,
		  req->offset, req->length, req->seq_num, req->type);
	wake_up(&dev->reaper_wq);
	return 0;
err:
	return ret;
}

static inline void free_sheep_aiocb(struct sheep_aiocb *aiocb)
{
	vfree(aiocb->buf);
	kmem_cache_free(sheep_aiocb_pool, aiocb);
}

static void aio_write_done(struct sheep_aiocb *aiocb)
{
	sbd_debug("wdone off %llu, len %llu\n", aiocb->offset, aiocb->length);

	blk_end_request_all(aiocb->request, aiocb->ret);
	free_sheep_aiocb(aiocb);
}

static void aio_read_done(struct sheep_aiocb *aiocb)
{
	struct req_iterator iter;
	struct bio_vec *bvec;
	struct request *req = aiocb->request;
	int len = 0;

	sbd_debug("rdone off %llu, len %llu\n", aiocb->offset, aiocb->length);

	rq_for_each_segment(bvec, req, iter) {
		unsigned long flags;
		void *addr = bvec_kmap_irq(bvec, &flags);

		memcpy(addr, aiocb->buf + len, bvec->bv_len);
		flush_dcache_page(bvec->bv_page);
		bvec_kunmap_irq(addr, &flags);

		len += bvec->bv_len;
	}

	blk_end_request_all(aiocb->request, aiocb->ret);
	free_sheep_aiocb(aiocb);
}

struct sheep_aiocb *sheep_aiocb_setup(struct request *req)
{
	struct sheep_aiocb *aiocb = kmem_cache_alloc(sheep_aiocb_pool,
						     SBD_GFP_FLAGS);
	struct req_iterator iter;
	struct bio_vec *bvec;
	int len = 0;

	if (!aiocb)
		return ERR_PTR(-ENOMEM);

	aiocb->offset = blk_rq_pos(req) * SECTOR_SIZE;
	aiocb->length = blk_rq_bytes(req);
	aiocb->ret = 0;
	aiocb->buf_iter = 0;
	aiocb->request = req;
	aiocb->buf = vzalloc(aiocb->length);
	atomic_set(&aiocb->nr_requests, 0);

	if (!aiocb->buf) {
		kmem_cache_free(sheep_aiocb_pool, aiocb);
		return ERR_PTR(-ENOMEM);
	}

	switch (rq_data_dir(req)) {
	case WRITE:
		rq_for_each_segment(bvec, req, iter) {
			unsigned long flags;
			void *addr = bvec_kmap_irq(bvec, &flags);

			memcpy(aiocb->buf + len, addr, bvec->bv_len);
			flush_dcache_page(bvec->bv_page);
			bvec_kunmap_irq(addr, &flags);

			len += bvec->bv_len;
		}
		aiocb->aio_done_func = aio_write_done;
		break;
	case READ:
		aiocb->aio_done_func = aio_read_done;
		break;
	default:
		/* impossible case */
		WARN_ON(1);
		free_sheep_aiocb(aiocb);
		return ERR_PTR(-EINVAL);
	}

	return aiocb;
}

static inline bool aiocb_is_write(struct sheep_aiocb *aiocb)
{
	return aiocb->aio_done_func == aio_write_done;
}

static struct sheep_request *alloc_sheep_request(struct sheep_aiocb *aiocb,
						 u64 oid, u64 cow_oid, int len,
						 int offset)
{
	struct sheep_request *req = kmem_cache_alloc(sheep_request_pool,
						     SBD_GFP_FLAGS);
	struct sbd_device *dev = sheep_aiocb_to_device(aiocb);

	if (!req)
		return ERR_PTR(-ENOMEM);

	req->offset = offset;
	req->length = len;
	req->oid = oid;
	req->cow_oid = cow_oid;
	req->aiocb = aiocb;
	req->buf = aiocb->buf + aiocb->buf_iter;
	req->seq_num = atomic_inc_return(&dev->seq_num);
	INIT_LIST_HEAD(&req->list);
	if (aiocb_is_write(aiocb))
		req->type = SHEEP_WRITE;
	else
		req->type = SHEEP_READ;

	aiocb->buf_iter += len;
	atomic_inc(&aiocb->nr_requests);

	return req;
}

static void end_sheep_request(struct sheep_request *req)
{
	struct sheep_aiocb *aiocb = req->aiocb;

	sbd_debug("end oid %llx off %d, len %d, seq %u\n", req->oid,
		  req->offset, req->length, req->seq_num);

	if (atomic_dec_return(&aiocb->nr_requests) <= 0)
		aiocb->aio_done_func(aiocb);
	BUG_ON(!list_empty(&req->list));
	kmem_cache_free(sheep_request_pool, req);
}

static struct sheep_request *find_inflight_request_oid(struct sbd_device *dev,
						       uint64_t oid)
{
	struct sheep_request *req;

	read_lock(&dev->inflight_lock);
	list_for_each_entry(req, &dev->inflight_head, list) {
		if (req->oid == oid) {
			read_unlock(&dev->inflight_lock);
			return req;
		}
	}
	read_unlock(&dev->inflight_lock);
	return NULL;
}

static uint32_t sheep_inode_get_idx(struct sbd_device *dev, u32 idx)
{
	uint32_t vid;

	spin_lock(&dev->vdi_lock);
	vid = dev->vdi.inode->data_vdi_id[idx];
	spin_unlock(&dev->vdi_lock);

	return vid;
}

int sheep_aiocb_submit(struct sheep_aiocb *aiocb)
{
	struct sbd_device *dev = sheep_aiocb_to_device(aiocb);
	u64 offset = aiocb->offset;
	u64 total = aiocb->length;
	u64 start = offset % SD_DATA_OBJ_SIZE;
	u32 idx = offset / SD_DATA_OBJ_SIZE;
	int len = SD_DATA_OBJ_SIZE - start;

	if (total < len)
		len = total;

	sbd_debug("submit off %llu, len %llu\n", offset, total);
	/*
	 * Make sure we don't free the aiocb before we are done with all
	 * requests.This additional reference is dropped at the end of this
	 * function.
	 */
	atomic_inc(&aiocb->nr_requests);

	do {
		struct sheep_request *req;
		u64 oid = vid_to_data_oid(dev->vdi.vid, idx), cow_oid = 0;
		uint32_t vid = sheep_inode_get_idx(dev, idx);

		/*
		 * For read, either read cow object or end the request.
		 * For write, copy-on-write cow object
		 */
		if (vid && vid != dev->vdi.vid) {
			if (aiocb_is_write(aiocb))
				cow_oid = vid_to_data_oid(vid, idx);
			else
				oid = vid_to_data_oid(vid, idx);
		}

		req = alloc_sheep_request(aiocb, oid, cow_oid, len, start);
		if (IS_ERR(req))
			return PTR_ERR(req);

		if (likely(vid && !cow_oid))
			goto submit;

		switch (req->type) {
		case SHEEP_WRITE:
			/*
			 * Sheepdog can't handle concurrent creation on the same
			 * object. We send one create req first and then send
			 * write reqs in next.
			 */
			if (find_inflight_request_oid(dev, oid)) {
				uint32_t tmp_vid;

				write_lock(&dev->blocking_lock);
				/*
				 * There are slim chance object was created
				 * before we grab blocking_lock
				 */
				tmp_vid = sheep_inode_get_idx(dev, idx);
				if (unlikely(tmp_vid && tmp_vid ==
					     dev->vdi.vid)) {
					write_unlock(&dev->blocking_lock);
					goto submit;
				}
				list_add_tail(&req->list, &dev->blocking_head);
				sbd_debug("block oid %llx off %d, len %d,"
					  " seq %u\n", req->oid, req->offset,
					  req->length, req->seq_num);
				write_unlock(&dev->blocking_lock);
				goto done;
			}
			req->type = SHEEP_CREATE;
			break;
		case SHEEP_READ:
			end_sheep_request(req);
			goto done;
		}
submit:
		submit_sheep_request(req);
done:
		idx++;
		total -= len;
		start = (start + len) % SD_DATA_OBJ_SIZE;
		len = total > SD_DATA_OBJ_SIZE ? SD_DATA_OBJ_SIZE : total;
	} while (total > 0);

	if (atomic_dec_return(&aiocb->nr_requests) <= 0)
		aiocb->aio_done_func(aiocb);

	return 0;
}

static struct sheep_request *fetch_inflight_request(struct sbd_device *dev,
						    u32 seq_num)
{
	struct sheep_request *req, *t;

	write_lock(&dev->inflight_lock);
	list_for_each_entry_safe(req, t, &dev->inflight_head, list) {
		if (req->seq_num == seq_num) {
			list_del_init(&req->list);
			goto out;
		}
	}
	req = NULL;
out:
	write_unlock(&dev->inflight_lock);
	return req;
}

static void submit_blocking_sheep_request(struct sbd_device *dev, uint64_t oid)
{
	struct sheep_request *req, *t;

	write_lock(&dev->blocking_lock);
	list_for_each_entry_safe(req, t, &dev->blocking_head, list) {
		if (req->oid != oid)
			continue;
		list_del_init(&req->list);
		submit_sheep_request(req);
	}
	write_unlock(&dev->blocking_lock);
}

/* FIXME: add auto-reconnect support */
int sheep_handle_reply(struct sbd_device *dev)
{
	struct sd_rsp rsp = {};
	struct sheep_request *req, *new;
	uint32_t vid, idx;
	uint64_t oid;
	int ret;

	ret = socket_read(dev->sock, (char *)&rsp, sizeof(rsp));
	if (ret < 0) {
		pr_err("failed to read reply header %d\n", ret);
		goto err;
	}

	req = fetch_inflight_request(dev, rsp.id);
	if (!req) {
		pr_err("failed to find req %u\n", rsp.id);
		return 0;
	}
	if (rsp.data_length > 0) {
		ret = socket_read(dev->sock, req->buf, req->length);
		if (ret < 0) {
			pr_err("failed to read reply payload %d\n", ret);
			req->aiocb->ret = EIO;
			goto end_request;
		}
	}

	switch (req->type) {
	case SHEEP_CREATE:
		/* We need to update inode for create */
		new = kmem_cache_alloc(sheep_request_pool, SBD_GFP_FLAGS);
		if (!new) {
			ret = -ENOMEM;
			req->aiocb->ret = EIO;
			goto end_request;
		}

		vid = dev->vdi.vid;
		oid = vid_to_vdi_oid(vid);
		idx = data_oid_to_idx(req->oid);
		new->offset = SD_INODE_HEADER_SIZE + sizeof(vid) * idx;
		new->length = sizeof(vid);
		new->oid = oid;
		new->cow_oid = 0;
		new->aiocb = req->aiocb;
		new->buf = (char *)&vid;
		new->seq_num = atomic_inc_return(&dev->seq_num);
		new->type = SHEEP_WRITE;
		atomic_inc(&req->aiocb->nr_requests);
		INIT_LIST_HEAD(&new->list);

		/* Make sure no request is queued while we update inode */
		spin_lock(&dev->vdi_lock);
		dev->vdi.inode->data_vdi_id[idx] = vid;
		spin_unlock(&dev->vdi_lock);

		submit_sheep_request(new);
		submit_blocking_sheep_request(dev, req->oid);
		/* fall thru */
	case SHEEP_WRITE:
	case SHEEP_READ:
		break;
	}
end_request:
	end_sheep_request(req);
err:
	return ret;
}

int sheep_slab_create(void)
{
	sheep_aiocb_pool = KMEM_CACHE(sheep_aiocb, 0);
	if (!sheep_aiocb_pool)
		return -ENOMEM;

	sheep_request_pool = KMEM_CACHE(sheep_request, 0);
	if (!sheep_request_pool) {
		kmem_cache_destroy(sheep_aiocb_pool);
		return -ENOMEM;
	}
	return 0;
}

void sheep_slab_destroy(void)
{
	kmem_cache_destroy(sheep_aiocb_pool);
	kmem_cache_destroy(sheep_request_pool);
}
