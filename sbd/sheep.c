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

void socket_shutdown(struct socket *sock)
{
	if (sock)
		kernel_sock_shutdown(sock, SHUT_RDWR);
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
		pr_err("Can't set SO_LINGER: %d\n", ret);
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
		sock->sk->sk_allocation = GFP_NOIO;
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
	int ret = socket_write(sock, hdr, sizeof(*hdr));

	if (ret < 0)
		return ret;

	if (wlen)
		return socket_write(sock, data, wlen);
	return 0;
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

	/* XXX switch case */
	if (rsp->result != SD_RES_SUCCESS) {
		sbd_debug("Cannot get VDI info for %s\n", dev->vdi.name);
		return -EIO;
	}

	dev->vdi.vid = rsp->vdi.vdi_id;

	return 0;
}

int sheep_setup_vdi(struct sbd_device *dev)
{
	struct sd_req hdr = {};
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
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
	if (ret < 0)
		goto out_release;

	hdr.opcode = SD_OP_READ_OBJ;
	hdr.data_length = SD_INODE_SIZE;
	hdr.obj.oid = vid_to_vdi_oid(dev->vdi.vid);
	hdr.obj.offset = 0;
	ret = sheep_run_sdreq(dev->sock, &hdr, inode);
	if (ret < 0)
		goto out_release;

	/* XXX switch case */
	if (rsp->result != SD_RES_SUCCESS) {
		ret = -EIO;
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

static void submit_sheep_request(struct sheep_request *req)
{
}

static inline void free_sheep_aiocb(struct sheep_aiocb *aiocb)
{
	kfree(aiocb->buf);
	kfree(aiocb);
}

static void aio_write_done(struct sheep_aiocb *aiocb, bool locked)
{
	sbd_debug("off %llu, len %llu\n", aiocb->offset, aiocb->length);

	if (locked)
		__blk_end_request_all(aiocb->request, aiocb->ret);
	else
		blk_end_request_all(aiocb->request, aiocb->ret);
	free_sheep_aiocb(aiocb);
}

static void aio_read_done(struct sheep_aiocb *aiocb, bool locked)
{
	sbd_debug("off %llu, len %llu\n", aiocb->offset, aiocb->length);

	if (locked)
		__blk_end_request_all(aiocb->request, aiocb->ret);
	else
		blk_end_request_all(aiocb->request, aiocb->ret);
	free_sheep_aiocb(aiocb);
}

struct sheep_aiocb *sheep_aiocb_setup(struct request *req)
{
	struct sheep_aiocb *aiocb = kmalloc(sizeof(*aiocb), GFP_KERNEL);
	struct req_iterator iter;
	struct bio_vec *bvec;
	int len = 0;

	if (!aiocb)
		return ERR_PTR(-ENOMEM);

	aiocb->offset = blk_rq_pos(req) * SECTOR_SIZE;
	aiocb->length = blk_rq_bytes(req);
	aiocb->nr_requests = 0;
	aiocb->ret = 0;
	aiocb->buf_iter = 0;
	aiocb->request = req;
	aiocb->buf = kzalloc(aiocb->length, GFP_KERNEL);

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

static struct sheep_request *alloc_sheep_request(struct sheep_aiocb *aiocb,
						 u64 oid, int len,
						 int offset)
{
	struct sheep_request *req = kmalloc(sizeof(*req), GFP_KERNEL);
	struct sbd_device *dev = sheep_aiocb_to_device(aiocb);

	if (!req)
		return ERR_PTR(-ENOMEM);

	req->offset = offset;
	req->length = len;
	req->oid = oid;
	req->aiocb = aiocb;
	req->buf = aiocb->buf + aiocb->buf_iter;
	req->seq_num = atomic_inc_return(&dev->seq_num);

	switch (rq_data_dir(aiocb->request)) {
	case WRITE:
		req->type = SHEEP_WRITE;
		break;
	case READ:
		req->type = SHEEP_READ;
		break;
	default:
		/* impossible case */
		WARN_ON(1);
		kfree(req);
		return ERR_PTR(-EINVAL);
	}

	aiocb->buf_iter += len;
	aiocb->nr_requests++;

	return req;
}

static void end_sheep_request(struct sheep_request *req, bool queue_locked)
{
	struct sheep_aiocb *aiocb = req->aiocb;

	if (--aiocb->nr_requests == 0)
		aiocb->aio_done_func(aiocb, queue_locked);

	sbd_debug("end oid %llx off %d, len %d, seq %u\n", req->oid,
		  req->offset, req->length, req->seq_num);
	kfree(req);
}

int sheep_aiocb_submit(struct sheep_aiocb *aiocb)
{
	struct sbd_device *dev = sheep_aiocb_to_device(aiocb);
	u64 offset = aiocb->offset;
	u64 total = aiocb->length;
	u64 start = offset % SD_DATA_OBJ_SIZE;
	u32 vid = dev->vdi.vid;
	u64 oid = vid_to_data_oid(vid, offset / SD_DATA_OBJ_SIZE);
	u32 idx = data_oid_to_idx(oid);
	int len = SD_DATA_OBJ_SIZE - start;

	if (total < len)
		len = total;

	sbd_debug("submit oid %llx off %llu, len %llu\n", oid, offset, total);
	/*
	 * Make sure we don't free the aiocb before we are done with all
	 * requests.This additional reference is dropped at the end of this
	 * function.
	 */
	aiocb->nr_requests++;

	do {
		struct sheep_request *req;

		req = alloc_sheep_request(aiocb, oid, len, start);
		if (IS_ERR(req))
			return PTR_ERR(req);

		if (likely(dev->vdi.inode->data_vdi_id[idx]))
			goto submit;

		/* Object is not created yet... */
		switch (req->type) {
		case SHEEP_WRITE:
		case SHEEP_READ:
			end_sheep_request(req, true);
			goto done;
		}
submit:
		submit_sheep_request(req);
done:
		oid++;
		total -= len;
		start = (start + len) % SD_DATA_OBJ_SIZE;
		len = total > SD_DATA_OBJ_SIZE ? SD_DATA_OBJ_SIZE : total;
	} while (total > 0);

	if (--aiocb->nr_requests == 0)
		aiocb->aio_done_func(aiocb, true);

	return 0;
}

int sheep_handle_reply(struct sbd_device *dev)
{
	return 0;
}
