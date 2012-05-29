/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include "sheep_priv.h"
#include "strbuf.h"


enum rw_state {
	RW_INIT,
	RW_RUN,
};

struct recovery_work {
	enum rw_state state;

	uint32_t epoch;
	uint32_t done;

	int stop;
	struct work work;

	int nr_blocking;
	int count;
	uint64_t *oids;

	struct vnode_info *old_vnodes;
	struct vnode_info *cur_vnodes;
};

static struct recovery_work *next_rw;
static struct recovery_work *recovering_work;

static int obj_cmp(const void *oid1, const void *oid2)
{
	const uint64_t hval1 = fnv_64a_buf((void *)oid1, sizeof(uint64_t), FNV1A_64_INIT);
	const uint64_t hval2 = fnv_64a_buf((void *)oid2, sizeof(uint64_t), FNV1A_64_INIT);

	if (hval1 < hval2)
		return -1;
	if (hval1 > hval2)
		return 1;
	return 0;
}

static struct vnode_info *get_vnodes_from_epoch(uint32_t epoch)
{
	struct sd_node nodes[SD_MAX_NODES];
	int nr_nodes;

	nr_nodes = epoch_log_read_nr(epoch, (void *)nodes, sizeof(nodes));
	if (nr_nodes < 0) {
		nr_nodes = epoch_log_read_remote(epoch, (void *)nodes,
						 sizeof(nodes));
		if (nr_nodes == 0)
			return NULL;
		nr_nodes /= sizeof(nodes[0]);
	}

	return alloc_vnode_info(nodes, nr_nodes);
}

static int recover_object_from_replica(uint64_t oid,
				       struct sd_vnode *entry,
				       uint32_t epoch, uint32_t tgt_epoch)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	char name[128];
	unsigned wlen = 0, rlen;
	int fd, ret = -1;
	void *buf;
	struct siocb iocb = { 0 };

	if (is_vdi_obj(oid))
		rlen = SD_INODE_SIZE;
	else if (is_vdi_attr_obj(oid))
		rlen = SD_ATTR_OBJ_SIZE;
	else
		rlen = SD_DATA_OBJ_SIZE;

	buf = valloc(rlen);
	if (!buf) {
		eprintf("%m\n");
		goto out;
	}

	if (vnode_is_local(entry)) {
		iocb.epoch = epoch;
		iocb.length = rlen;
		ret = sd_store->link(oid, &iocb, tgt_epoch);
		if (ret == SD_RES_SUCCESS) {
			ret = 0;
			goto done;
		} else {
			ret = -1;
			goto out;
		}
	}

	addr_to_str(name, sizeof(name), entry->addr, 0);
	fd = connect_to(name, entry->port);
	dprintf("%s, %d\n", name, entry->port);
	if (fd < 0) {
		eprintf("failed to connect to %s:%"PRIu32"\n", name, entry->port);
		ret = -1;
		goto out;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = SD_OP_READ_OBJ;
	hdr.epoch = epoch;
	hdr.flags = SD_FLAG_CMD_RECOVERY | SD_FLAG_CMD_IO_LOCAL;
	hdr.data_length = rlen;

	hdr.obj.oid = oid;
	hdr.obj.tgt_epoch = tgt_epoch;

	ret = exec_req(fd, &hdr, buf, &wlen, &rlen);

	close(fd);

	if (ret != 0) {
		eprintf("res: %"PRIx32"\n", rsp->result);
		ret = -1;
		goto out;
	}

	rsp = (struct sd_rsp *)&hdr;

	if (rsp->result == SD_RES_SUCCESS) {
		iocb.epoch = epoch;
		iocb.length = rlen;
		iocb.buf = buf;
		ret = sd_store->atomic_put(oid, &iocb);
		if (ret != SD_RES_SUCCESS) {
			ret = -1;
			goto out;
		}
	} else {
		eprintf("failed, res: %"PRIx32"\n", rsp->result);
		ret = rsp->result;
		goto out;
	}
done:
	dprintf("recovered oid %"PRIx64" from %d to epoch %d\n", oid, tgt_epoch, epoch);
out:
	if (ret == SD_RES_SUCCESS)
		objlist_cache_insert(oid);
	free(buf);
	return ret;
}

/*
 * A virtual node that does not match any node in current node list
 * means the node has left the cluster, then it's an invalid virtual node.
 */
static int is_invalid_vnode(struct sd_vnode *entry, struct sd_node *nodes,
				int nr_nodes)
{
	if (bsearch(entry, nodes, nr_nodes, sizeof(struct sd_node),
		    vnode_node_cmp))
		return 0;
	return 1;
}

/*
 * Recover the object from its track in epoch history. That is,
 * the routine will try to recovery it from the nodes it has stayed,
 * at least, *theoretically* on consistent hash ring.
 */
static int do_recover_object(struct recovery_work *rw)
{
	struct vnode_info *old;
	uint64_t oid = rw->oids[rw->done];
	uint32_t epoch = rw->epoch, tgt_epoch = rw->epoch - 1;
	int nr_copies, ret, i;

	old = grab_vnode_info(rw->old_vnodes);

again:
	dprintf("try recover object %"PRIx64" from epoch %"PRIu32"\n",
		oid, tgt_epoch);

	/* Let's do a breadth-first search */
	nr_copies = get_nr_copies(old);
	for (i = 0; i < nr_copies; i++) {
		struct sd_vnode *tgt_vnode = oid_to_vnode(old, oid, i);

		if (is_invalid_vnode(tgt_vnode, rw->cur_vnodes->nodes,
				     rw->cur_vnodes->nr_nodes))
			continue;
		ret = recover_object_from_replica(oid, tgt_vnode,
						  epoch, tgt_epoch);
		if (ret == 0) {
			/* Succeed */
			break;
		} else if (SD_RES_OLD_NODE_VER == ret) {
			rw->stop = 1;
			goto err;
		} else
			ret = -1;
	}

	/* No luck, roll back to an older configuration and try again */
	if (ret < 0) {
		struct vnode_info *new_old;

		tgt_epoch--;
		if (tgt_epoch < 1) {
			eprintf("can not recover oid %"PRIx64"\n", oid);
			ret = -1;
			goto err;
		}

		new_old = get_vnodes_from_epoch(tgt_epoch);
		if (!new_old) {
			ret = -1;
			goto err;
		}

		put_vnode_info(old);
		old = new_old;
		goto again;
	}
err:
	put_vnode_info(old);
	return ret;
}

static void recover_object(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	uint64_t oid = rw->oids[rw->done];
	int ret;

	if (!sys->nr_copies)
		return;

	eprintf("done:%"PRIu32" count:%"PRIu32", oid:%"PRIx64"\n",
		rw->done, rw->count, oid);

	if (sd_store->exist(oid)) {
		dprintf("the object is already recovered\n");
		return;
	}

	ret = do_recover_object(rw);
	if (ret < 0)
		eprintf("failed to recover object %"PRIx64"\n", oid);
}

static struct recovery_work *suspended_recovery_work;

void resume_recovery_work(void)
{
	struct recovery_work *rw;
	uint64_t oid;

	if (!suspended_recovery_work)
		return;

	rw = suspended_recovery_work;

	oid =  rw->oids[rw->done];
	if (is_access_to_busy_objects(oid))
		return;

	suspended_recovery_work = NULL;
	queue_work(sys->recovery_wqueue, &rw->work);
}

int node_in_recovery(void)
{
	return !!recovering_work;
}

int is_recovery_init(void)
{
	struct recovery_work *rw = recovering_work;

	return rw->state == RW_INIT;
}

int is_recoverying_oid(uint64_t oid)
{
	uint64_t hval = fnv_64a_buf(&oid, sizeof(uint64_t), FNV1A_64_INIT);
	uint64_t min_hval;
	struct recovery_work *rw = recovering_work;
	int i;

	if (oid == 0)
		return 0;

	if (!rw)
		return 0; /* there is no thread working for object recovery */

	min_hval = fnv_64a_buf(&rw->oids[rw->done + rw->nr_blocking], sizeof(uint64_t), FNV1A_64_INIT);

	if (before(rw->epoch, sys->epoch))
		return 1;

	if (sd_store->exist(oid)) {
		dprintf("the object %" PRIx64 " is already recoverd\n", oid);
		return 0;
	}

	if (rw->state == RW_INIT)
		return 1;

	/* the first 'rw->nr_blocking' objects were already scheduled to be done earlier */
	for (i = 0; i < rw->nr_blocking; i++)
		if (rw->oids[rw->done + i] == oid)
			return 1;

	if (min_hval <= hval) {
		uint64_t *p;
		p = bsearch(&oid, rw->oids + rw->done + rw->nr_blocking,
			    rw->count - rw->done - rw->nr_blocking, sizeof(oid), obj_cmp);
		if (p) {
			dprintf("recover the object %" PRIx64 " first\n", oid);
			if (rw->nr_blocking == 0)
				rw->nr_blocking = 1; /* the first oid may be processed now */
			if (p > rw->oids + rw->done + rw->nr_blocking) {
				/* this object should be recovered earlier */
				memmove(rw->oids + rw->done + rw->nr_blocking + 1,
					rw->oids + rw->done + rw->nr_blocking,
					sizeof(uint64_t) * (p - (rw->oids + rw->done + rw->nr_blocking)));
				rw->oids[rw->done + rw->nr_blocking] = oid;
				rw->nr_blocking++;
			}
			return 1;
		}
	}

	dprintf("the object %" PRIx64 " is not found\n", oid);
	return 0;
}

static void free_recovery_work(struct recovery_work *rw)
{
	put_vnode_info(rw->cur_vnodes);
	put_vnode_info(rw->old_vnodes);
	free(rw->oids);
	free(rw);
}

static void do_recover_main(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work, work);
	uint64_t oid, recovered_oid = rw->oids[rw->done];

	if (rw->state == RW_INIT) {
		rw->state = RW_RUN;
		recovered_oid = 0;
		resume_wait_recovery_requests();
	} else if (!rw->stop){
		rw->done++;
		if (rw->nr_blocking > 0)
			rw->nr_blocking--;
	}

	oid = rw->oids[rw->done];

	if (recovered_oid)
		resume_wait_obj_requests(recovered_oid);

	if (rw->done < rw->count && !next_rw) {
		rw->work.fn = recover_object;

		if (rw->stop) {
			flush_wait_obj_requests();
			return;
		}

		if (is_access_to_busy_objects(oid)) {
			suspended_recovery_work = rw;
			return;
		}
		resume_pending_requests();
		queue_work(sys->recovery_wqueue, &rw->work);
		return;
	}

	dprintf("recovery complete: new epoch %"PRIu32"\n", rw->epoch);
	recovering_work = NULL;

	sys->recovered_epoch = rw->epoch;
	free_recovery_work(rw);

	if (next_rw) {
		rw = next_rw;
		next_rw = NULL;

		flush_wait_obj_requests();

		recovering_work = rw;

		queue_work(sys->recovery_wqueue, &rw->work);
	} else {
		if (sd_store->end_recover) {
			struct siocb iocb = { 0 };
			iocb.epoch = sys->epoch;
			sd_store->end_recover(&iocb);
		}
	}

	resume_pending_requests();
}

static int request_obj_list(struct sd_node *e, uint32_t epoch,
			   uint8_t *buf, size_t buf_size)
{
	int fd, ret;
	unsigned wlen, rlen;
	char name[128];
	struct sd_list_req hdr;
	struct sd_list_rsp *rsp;

	addr_to_str(name, sizeof(name), e->addr, 0);

	dprintf("%s %"PRIu32"\n", name, e->port);

	fd = connect_to(name, e->port);
	if (fd < 0) {
		eprintf("%s %"PRIu32"\n", name, e->port);
		return -1;
	}

	wlen = 0;
	rlen = buf_size;

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = SD_OP_GET_OBJ_LIST;
	hdr.tgt_epoch = epoch - 1;
	hdr.flags = 0;
	hdr.data_length = rlen;

	ret = exec_req(fd, (struct sd_req *)&hdr, buf, &wlen, &rlen);

	close(fd);

	rsp = (struct sd_list_rsp *)&hdr;

	if (ret || rsp->result != SD_RES_SUCCESS) {
		eprintf("retrying: %"PRIu32", %"PRIu32"\n", ret, rsp->result);
		return -1;
	}

	dprintf("%"PRIu64"\n", rsp->data_length / sizeof(uint64_t));

	return rsp->data_length / sizeof(uint64_t);
}

int merge_objlist(uint64_t *list1, int nr_list1, uint64_t *list2, int nr_list2)
{
	int i;
	int old_nr_list1 = nr_list1;

	for (i = 0; i < nr_list2; i++) {
		if (bsearch(list2 + i, list1, old_nr_list1, sizeof(*list1), obj_cmp))
			continue;

		list1[nr_list1++] = list2[i];
	}

	qsort(list1, nr_list1, sizeof(*list1), obj_cmp);

	return nr_list1;
}

static int screen_obj_list(struct recovery_work *rw,  uint64_t *list, int list_nr)
{
	int ret, i, j;
	struct strbuf buf = STRBUF_INIT;
	struct sd_vnode *vnodes[SD_MAX_COPIES];
	int nr_objs;
	size_t len;

	nr_objs = get_nr_copies(rw->cur_vnodes);
	for (i = 0; i < list_nr; i++) {
		oid_to_vnodes(rw->cur_vnodes, list[i], nr_objs, vnodes);
		for (j = 0; j < nr_objs; j++) {
			if (vnode_is_local(vnodes[j])) {
				strbuf_add(&buf, &list[i], sizeof(uint64_t));
				break;
			}
		}
	}
	len = strbuf_copyout(&buf, list, list_nr * sizeof(uint64_t));

	ret = len / sizeof(uint64_t);
	dprintf("%d\n", ret);
	strbuf_release(&buf);

	return ret;
}

#define MAX_RETRY_CNT  6

static int newly_joined(struct sd_node *node, struct recovery_work *rw)
{
	if (bsearch(node, rw->old_vnodes->nodes, rw->old_vnodes->nr_nodes,
		    sizeof(struct sd_node), node_cmp))
		return 0;
	return 1;
}

static int fill_obj_list(struct recovery_work *rw)
{
	int i;
	uint8_t *buf = NULL;
	size_t buf_size = SD_DATA_OBJ_SIZE; /* FIXME */
	int retry_cnt;
	struct sd_node *cur = rw->cur_vnodes->nodes;
	int cur_nr = rw->cur_vnodes->nr_nodes;
	int start = random() % cur_nr;
	int end = cur_nr;

	buf = xmalloc(buf_size);
again:
	for (i = start; i < end; i++) {
		int buf_nr;
		struct sd_node *node = cur + i;

		if (newly_joined(node, rw))
			/* new node doesn't have a list file */
			continue;

		retry_cnt = 0;
	retry:
		buf_nr = request_obj_list(node, rw->epoch, buf, buf_size);
		if (buf_nr < 0) {
			retry_cnt++;
			if (retry_cnt > MAX_RETRY_CNT) {
				eprintf("failed to get object list\n");
				eprintf("some objects may be lost\n");
				continue;
			} else {
				if (next_rw) {
					dprintf("go to the next recovery\n");
					break;
				}
				dprintf("trying to get object list again\n");
				sleep(1);
				goto retry;
			}
		}
		buf_nr = screen_obj_list(rw, (uint64_t *)buf, buf_nr);
		if (buf_nr)
			rw->count = merge_objlist(rw->oids, rw->count, (uint64_t *)buf, buf_nr);
	}

	if (start != 0 && !next_rw) {
		end = start;
		start = 0;
		goto again;
	}

	dprintf("%d\n", rw->count);
	free(buf);
	return 0;
}

/* setup node list and virtual node list */
static int init_rw(struct recovery_work *rw)
{
	struct sd_node nodes[SD_MAX_NODES];
	int nr_nodes;
	uint32_t epoch = rw->epoch;

	nr_nodes = epoch_log_read_nr(epoch, (char *)nodes, sizeof(nodes));
	if (nr_nodes <= 0) {
		eprintf("failed to read epoch log for epoch %"PRIu32"\n", epoch);
		return -1;
	}
	rw->cur_vnodes = alloc_vnode_info(nodes, nr_nodes);

	nr_nodes = epoch_log_read_nr(epoch - 1, (char *)nodes, sizeof(nodes));
	if (nr_nodes <= 0) {
		eprintf("failed to read epoch log for epoch %"PRIu32"\n", epoch - 1);
		return -1;
	}
	rw->old_vnodes = alloc_vnode_info(nodes, nr_nodes);
	return 0;
}

static void do_recovery_work(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work, work);

	dprintf("%u\n", rw->epoch);

	if (!sys->nr_copies)
		return;

	init_rw(rw);

	if (fill_obj_list(rw) < 0) {
		eprintf("fatal recovery error\n");
		rw->count = 0;
		return;
	}
}

int start_recovery(uint32_t epoch)
{
	struct recovery_work *rw;

	rw = zalloc(sizeof(struct recovery_work));
	if (!rw)
		return -1;

	rw->state = RW_INIT;
	rw->oids = malloc(1 << 20); /* FIXME */
	rw->epoch = epoch;
	rw->count = 0;

	rw->work.fn = do_recovery_work;
	rw->work.done = do_recover_main;

	if (sd_store->begin_recover) {
		struct siocb iocb = { 0 };
		iocb.epoch = epoch;
		sd_store->begin_recover(&iocb);
	}

	if (recovering_work != NULL) {
		/* skip the previous epoch recovery */
		if (next_rw)
			free_recovery_work(next_rw);
		next_rw = rw;
	} else {
		recovering_work = rw;
		queue_work(sys->recovery_wqueue, &rw->work);
	}

	resume_wait_epoch_requests();

	return 0;
}
