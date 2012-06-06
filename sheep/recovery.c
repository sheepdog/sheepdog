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

	int count;
	uint64_t *oids;
	uint64_t *prio_oids;
	int nr_prio_oids;

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

		new_old = get_vnode_info_epoch(tgt_epoch);
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

static void recover_object_work(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	uint64_t oid = rw->oids[rw->done];
	int ret;

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

int node_in_recovery(void)
{
	return !!recovering_work;
}

int is_recovery_init(void)
{
	struct recovery_work *rw = recovering_work;

	return rw->state == RW_INIT;
}

static inline void prepare_schedule_oid(uint64_t oid)
{
	struct recovery_work *rw = recovering_work;
	int i;

	for (i = 0; i < rw->nr_prio_oids; i++)
		if (rw->prio_oids[i] == oid )
			return;

	/* The oid is currently being recovered */
	if (rw->oids[rw->done] == oid)
		return;

	rw->prio_oids = xrealloc(rw->prio_oids, ++rw->nr_prio_oids);
	rw->prio_oids[rw->nr_prio_oids - 1] = oid;
	dprintf("%"PRIx64" nr_prio_oids %d\n", oid, rw->nr_prio_oids);
}

bool oid_in_recovery(uint64_t oid)
{
	struct recovery_work *rw = recovering_work;
	int i;

	if (!node_in_recovery())
		return false;

	if (sd_store->exist(oid)) {
		dprintf("the object %" PRIx64 " is already recoverd\n", oid);
		return false;
	}

	if (before(rw->epoch, sys->epoch))
		return true;

	/* If we are in preparation of object list, oid is not recovered yet */
	if (rw->state == RW_INIT)
		return true;

	/* FIXME: do we need more efficient yet complex data structure? */
	for (i = rw->done - 1; i < rw->count; i++)
		if (rw->oids[i] == oid)
			break;

	/*
	 * Newly created object after prepare_object_list() might not be
	 * in the list
	 */
	if (i == rw->count) {
		eprintf("%"PRIx64" is not in the recovery list\n", oid);
		return false;
	}

	prepare_schedule_oid(oid);
	return true;
}

static void free_recovery_work(struct recovery_work *rw)
{
	put_vnode_info(rw->cur_vnodes);
	put_vnode_info(rw->old_vnodes);
	free(rw->oids);
	free(rw);
}

static inline void run_next_rw(struct recovery_work *rw)
{
	free_recovery_work(rw);
	rw = next_rw;
	next_rw = NULL;
	recovering_work = rw;
	flush_wait_obj_requests();
	queue_work(sys->recovery_wqueue, &rw->work);
	dprintf("recovery work is superseded\n");
}

static inline void finish_recovery(struct recovery_work *rw)
{
	recovering_work = NULL;
	sys->recovered_epoch = rw->epoch;
	free_recovery_work(rw);

	if (sd_store->end_recover) {
		struct siocb iocb = { 0 };
		iocb.epoch = sys->epoch;
		sd_store->end_recover(&iocb);
	}
	dprintf("recovery complete: new epoch %"PRIu32"\n",
		sys->recovered_epoch);
}

static inline bool oid_in_prio_oids(struct recovery_work *rw, uint64_t oid)
{
	int i;

	for (i = 0; i < rw->nr_prio_oids; i++)
		if (rw->prio_oids[i] == oid)
			return true;
	return false;
}

/*
 * Schedule prio_oids to be recovered first in FIFO order
 *
 * rw->done is index of the original next object to be recovered and also the
 * number of objects already recovered.
 * we just move rw->prio_oids in between:
 *   new_oids = [0..rw->done - 1] + [rw->prio_oids] + [rw->done]
 */
static inline void finish_schedule_oids(struct recovery_work *rw)
{
	int i, nr_recovered = rw->done, new_idx;
	uint64_t *new_oids;

	/* If I am the last oid, done */
	if (nr_recovered == rw->count - 1)
		goto done;

	new_oids = xmalloc(1 << 20); /* FIXME */
	memmove(new_oids, rw->oids, nr_recovered * sizeof(uint64_t));
	memmove(new_oids + nr_recovered, rw->prio_oids,
		rw->nr_prio_oids * sizeof(uint64_t));
	new_idx = nr_recovered + rw->nr_prio_oids;

	for (i = rw->done; i < rw->count; i++) {
		if (oid_in_prio_oids(rw, rw->oids[i]))
			continue;
		new_oids[new_idx++] = rw->oids[i];
	}
	dprintf("nr_recovered %d, nr_prio_oids %d, count %d, new %d\n",
		nr_recovered, rw->nr_prio_oids, rw->count, new_idx);

	free(rw->oids);
	rw->oids = new_oids;
done:
	free(rw->prio_oids);
	rw->prio_oids = NULL;
	rw->nr_prio_oids = 0;
}

static void recover_object_main(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	if (next_rw) {
		run_next_rw(rw);
		return;
	}

	if (rw->stop){
		/*
		 * Stop this recovery process and wait for epoch to be
		 * lifted and flush wait_obj queue to requeue those
		 * requests
		 */
		flush_wait_obj_requests();
		dprintf("recovery is stopped\n");
		return;
	}

	resume_wait_obj_requests(rw->oids[rw->done++]);

	if (rw->done < rw->count) {
		if (rw->nr_prio_oids)
			finish_schedule_oids(rw);

		/* Try recover next object */
		queue_work(sys->recovery_wqueue, &rw->work);
		return;
	}

	finish_recovery(rw);
}

static void finish_object_list(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	rw->state = RW_RUN;
	if (next_rw) {
		run_next_rw(rw);
		return;
	}
	if (!rw->count) {
		finish_recovery(rw);
		return;
	}
	/*
	 * We have got the object list to be recovered locally, most of
	 * objects are actually already being there, so let's resume
	 * requests in the hope that most requests will be processed
	 * without any problem.
	 */
	resume_wait_recovery_requests();
	rw->work.fn = recover_object_work;
	rw->work.done = recover_object_main;
	queue_work(sys->recovery_wqueue, &rw->work);
	return;
}

/* Fetch the object list from all the nodes in the cluster */
static int fetch_object_list(struct sd_node *e, uint32_t epoch,
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
		eprintf("failed, %"PRIu32", %"PRIu32"\n", ret, rsp->result);
		return -1;
	}

	dprintf("%"PRIu64"\n", rsp->data_length / sizeof(uint64_t));

	return rsp->data_length / sizeof(uint64_t);
}

/* Screen out objects that don't belong to this node */
static void screen_object_list(struct recovery_work *rw,
			       uint64_t *oids, int nr_oids)
{
	struct sd_vnode *vnodes[SD_MAX_COPIES];
	int old_count = rw->count;
	int nr_objs;
	int i, j;

	nr_objs = get_nr_copies(rw->cur_vnodes);
	for (i = 0; i < nr_oids; i++) {
		oid_to_vnodes(rw->cur_vnodes, oids[i], nr_objs, vnodes);
		for (j = 0; j < nr_objs; j++) {
			if (!vnode_is_local(vnodes[j]))
				continue;
			if (bsearch(&oids[i], rw->oids, old_count,
				    sizeof(uint64_t), obj_cmp))
				continue;

			rw->oids[rw->count++] = oids[i];
			break;
		}
	}
}

static int newly_joined(struct sd_node *node, struct recovery_work *rw)
{
	if (bsearch(node, rw->old_vnodes->nodes, rw->old_vnodes->nr_nodes,
		    sizeof(struct sd_node), node_cmp))
		return 0;
	return 1;
}

/* Prepare the object list that belongs to this node */
static void prepare_object_list(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	uint8_t *buf = NULL;
	size_t buf_size = SD_DATA_OBJ_SIZE; /* FIXME */
	struct sd_node *cur = rw->cur_vnodes->nodes;
	int cur_nr = rw->cur_vnodes->nr_nodes;
	int start = random() % cur_nr, i, end = cur_nr;

	dprintf("%u\n", rw->epoch);

	buf = xmalloc(buf_size);
again:
	/* We need to start at random node for better load balance */
	for (i = start; i < end; i++) {
		int buf_nr;
		struct sd_node *node = cur + i;

		if (next_rw) {
			dprintf("go to the next recovery\n");
			goto out;
		}
		if (newly_joined(node, rw))
			/* new node doesn't have a list file */
			continue;

		buf_nr = fetch_object_list(node, rw->epoch, buf, buf_size);
		if (buf_nr < 0)
			continue;
		screen_object_list(rw, (uint64_t *)buf, buf_nr);
	}

	if (start != 0) {
		end = start;
		start = 0;
		goto again;
	}

	dprintf("%d\n", rw->count);
out:
	free(buf);
}

int start_recovery(struct vnode_info *cur_vnodes, struct vnode_info *old_vnodes)
{
	struct recovery_work *rw;

	rw = zalloc(sizeof(struct recovery_work));
	if (!rw) {
		eprintf("%m\n");
		return -1;
	}

	rw->state = RW_INIT;
	rw->oids = xmalloc(1 << 20); /* FIXME */
	rw->epoch = sys->epoch;
	rw->count = 0;

	rw->cur_vnodes = grab_vnode_info(cur_vnodes);
	rw->old_vnodes = grab_vnode_info(old_vnodes);

	rw->work.fn = prepare_object_list;
	rw->work.done = finish_object_list;

	if (sd_store->begin_recover) {
		struct siocb iocb = { 0 };
		iocb.epoch = rw->epoch;
		sd_store->begin_recover(&iocb);
	}

	if (recovering_work != NULL) {
		/* skip the previous epoch recovery */
		if (next_rw)
			free_recovery_work(next_rw);
		dprintf("recovery skipped\n");
		next_rw = rw;
	} else {
		recovering_work = rw;
		queue_work(sys->recovery_wqueue, &rw->work);
	}

	resume_wait_epoch_requests();

	return 0;
}
