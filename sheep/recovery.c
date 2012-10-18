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

	bool stop;
	struct work work;
	bool suspended; /* true when automatic recovery is disabled
			 * and recovery process is suspended */

	int count;
	uint64_t *oids;
	uint64_t *prio_oids;
	int nr_prio_oids;
	int nr_scheduled_prio_oids;

	struct vnode_info *old_vinfo;
	struct vnode_info *cur_vinfo;
};

static struct recovery_work *next_rw;
static struct recovery_work *recovering_work;

static int obj_cmp(const void *oid1, const void *oid2)
{
	const uint64_t hval1 = fnv_64a_buf((void *)oid1, sizeof(uint64_t),
					   FNV1A_64_INIT);
	const uint64_t hval2 = fnv_64a_buf((void *)oid2, sizeof(uint64_t),
					   FNV1A_64_INIT);

	if (hval1 < hval2)
		return -1;
	if (hval1 > hval2)
		return 1;
	return 0;
}

static int recover_object_from_replica(uint64_t oid,
				       const struct sd_vnode *vnode,
				       uint32_t epoch, uint32_t tgt_epoch)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	unsigned rlen;
	int ret = SD_RES_NO_MEM;
	void *buf = NULL;
	struct siocb iocb = { 0 };

	if (vnode_is_local(vnode)) {
		ret = sd_store->link(oid, tgt_epoch);
		goto out;
	}

	rlen = get_objsize(oid);
	buf = valloc(rlen);
	if (!buf) {
		eprintf("%m\n");
		goto out;
	}

	sd_init_req(&hdr, SD_OP_READ_PEER);
	hdr.epoch = epoch;
	hdr.flags = SD_FLAG_CMD_RECOVERY;
	hdr.data_length = rlen;
	hdr.obj.oid = oid;
	hdr.obj.tgt_epoch = tgt_epoch;

	ret = sheep_exec_req(&vnode->nid, &hdr, buf);
	if (ret != SD_RES_SUCCESS)
		goto out;
	iocb.epoch = epoch;
	iocb.length = rsp->data_length;
	iocb.offset = rsp->obj.offset;
	iocb.buf = buf;
	ret = sd_store->create_and_write(oid, &iocb);
out:
	if (ret == SD_RES_SUCCESS) {
		dprintf("recovered oid %"PRIx64" from %d to epoch %d\n", oid,
			tgt_epoch, epoch);
		objlist_cache_insert(oid);
	}
	free(buf);
	return ret;
}

/*
 * A virtual node that does not match any node in current node list
 * means the node has left the cluster, then it's an invalid virtual node.
 */
static bool is_invalid_vnode(const struct sd_vnode *entry,
			     struct sd_node *nodes, int nr_nodes)
{
	if (bsearch(entry, nodes, nr_nodes, sizeof(struct sd_node),
		    node_id_cmp))
		return false;
	return true;
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

	old = grab_vnode_info(rw->old_vinfo);

again:
	dprintf("try recover object %"PRIx64" from epoch %"PRIu32"\n",
		oid, tgt_epoch);

	/* Let's do a breadth-first search */
	nr_copies = get_obj_copy_number(oid, old->nr_zones);
	for (i = 0; i < nr_copies; i++) {
		const struct sd_vnode *tgt_vnode;

		tgt_vnode = oid_to_vnode(old->vnodes,old->nr_vnodes, oid, i);

		if (is_invalid_vnode(tgt_vnode, rw->cur_vinfo->nodes,
				     rw->cur_vinfo->nr_nodes))
			continue;
		ret = recover_object_from_replica(oid, tgt_vnode,
						  epoch, tgt_epoch);
		if (ret == SD_RES_SUCCESS) {
			/* Succeed */
			break;
		} else if (SD_RES_OLD_NODE_VER == ret) {
			rw->stop = true;
			goto err;
		} else
			ret = -1;
	}

	/* No luck, roll back to an older configuration and try again */
	if (ret < 0) {
		struct vnode_info *new_old;

rollback:
		tgt_epoch--;
		if (tgt_epoch < 1) {
			eprintf("can not recover oid %"PRIx64"\n", oid);
			ret = -1;
			goto err;
		}

		new_old = get_vnode_info_epoch(tgt_epoch);
		if (!new_old)
			/* We rollback in case we don't get a valid epoch */
			goto rollback;

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

bool node_in_recovery(void)
{
	return !!recovering_work;
}

bool is_recovery_init(void)
{
	struct recovery_work *rw = recovering_work;

	return rw->state == RW_INIT;
}

static inline void prepare_schedule_oid(uint64_t oid)
{
	struct recovery_work *rw = recovering_work;
	int i;

	for (i = 0; i < rw->nr_prio_oids; i++)
		if (rw->prio_oids[i] == oid)
			return;
	/*
	 * We need this check because oid might not be recovered.
	 * Very much unlikely though, but it might happen indeed.
	 */
	for (i = 0; i < rw->done; i++)
		if (rw->oids[i] == oid) {
			dprintf("%"PRIx64" not recovered, don't schedule it\n",
				oid);
			return;
		}
	/* When auto recovery is enabled, the oid is currently being
	 * recovered */
	if (!sys->disable_recovery && rw->oids[rw->done] == oid)
		return;
	rw->nr_prio_oids++;
	rw->prio_oids = xrealloc(rw->prio_oids,
				 rw->nr_prio_oids * sizeof(uint64_t));
	rw->prio_oids[rw->nr_prio_oids - 1] = oid;
	resume_suspended_recovery();

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

	/*
	 * Check if oid is in the list that to be recovered later
	 *
	 * FIXME: do we need more efficient yet complex data structure?
	 */
	for (i = rw->done; i < rw->count; i++)
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
	put_vnode_info(rw->cur_vinfo);
	put_vnode_info(rw->old_vinfo);
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

static void notify_recovery_completion_work(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	struct sd_req hdr;
	int ret;

	sd_init_req(&hdr, SD_OP_COMPLETE_RECOVERY);
	hdr.obj.tgt_epoch = rw->epoch;
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = sizeof(sys->this_node);

	ret = exec_local_req(&hdr, &sys->this_node);
	if (ret != SD_RES_SUCCESS)
		eprintf("failed to notify recovery completion, %d\n",
			rw->epoch);
}

static void notify_recovery_completion_main(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	free_recovery_work(rw);
}

static inline void finish_recovery(struct recovery_work *rw)
{
	recovering_work = NULL;
	sys->recovered_epoch = rw->epoch;

	if (sd_store->end_recover)
		sd_store->end_recover(sys->epoch - 1, rw->old_vinfo);

	/* notify recovery completion to other nodes */
	rw->work.fn = notify_recovery_completion_work;
	rw->work.done = notify_recovery_completion_main;
	queue_work(sys->recovery_wqueue, &rw->work);

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
	memcpy(new_oids, rw->oids, nr_recovered * sizeof(uint64_t));
	memcpy(new_oids + nr_recovered, rw->prio_oids,
	       rw->nr_prio_oids * sizeof(uint64_t));
	new_idx = nr_recovered + rw->nr_prio_oids;

	for (i = rw->done; i < rw->count; i++) {
		if (oid_in_prio_oids(rw, rw->oids[i]))
			continue;
		new_oids[new_idx++] = rw->oids[i];
	}
	/* rw->count should eq new_idx, otherwise something is wrong */
	dprintf("%snr_recovered %d, nr_prio_oids %d, count %d = new %d\n",
		rw->count == new_idx ? "" : "WARN: ", nr_recovered,
		rw->nr_prio_oids, rw->count, new_idx);

	free(rw->oids);
	rw->oids = new_oids;
done:
	free(rw->prio_oids);
	rw->prio_oids = NULL;
	rw->nr_scheduled_prio_oids += rw->nr_prio_oids;
	rw->nr_prio_oids = 0;
}

/*
 * When automatic object recovery is disabled, the behavior of the
 * recovery process is like 'lazy recovery'.  This function returns
 * true if the recovery queue contains objects being accessed by
 * clients.  Sheep recovers such objects for availability even when
 * automatic object recovery is not enabled.
 */
static bool has_scheduled_objects(struct recovery_work *rw)
{
	return rw->done < rw->nr_scheduled_prio_oids;
}

static void recover_next_object(struct recovery_work *rw)
{
	if (next_rw) {
		run_next_rw(rw);
		return;
	}

	if (rw->nr_prio_oids)
		finish_schedule_oids(rw);

	if (sys->disable_recovery && !has_scheduled_objects(rw)) {
		dprintf("suspended\n");
		rw->suspended = true;
		/* suspend until resume_suspended_recovery() is called */
		return;
	}

	/* Try recover next object */
	queue_work(sys->recovery_wqueue, &rw->work);
}

void resume_suspended_recovery(void)
{
	if (recovering_work && recovering_work->suspended) {
		recovering_work->suspended = false;
		recover_next_object(recovering_work);
	}
}

static void recover_object_main(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	if (next_rw) {
		run_next_rw(rw);
		return;
	}

	if (rw->stop) {
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
		recover_next_object(rw);
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
	recover_next_object(rw);
	return;
}

/* Fetch the object list from all the nodes in the cluster */
static int fetch_object_list(struct sd_node *e, uint32_t epoch,
			     uint8_t *buf, size_t buf_size)
{
	char name[128];
	struct sd_list_req hdr;
	struct sd_list_rsp *rsp = (struct sd_list_rsp *)&hdr;
	int ret;

	addr_to_str(name, sizeof(name), e->nid.addr, 0);

	dprintf("%s %"PRIu32"\n", name, e->nid.port);

	sd_init_req((struct sd_req *)&hdr, SD_OP_GET_OBJ_LIST);
	hdr.tgt_epoch = epoch - 1;
	hdr.data_length = buf_size;

	ret = sheep_exec_req(&e->nid, (struct sd_req *)&hdr, buf);

	if (ret != SD_RES_SUCCESS)
		return -1;

	dprintf("%zu\n", rsp->data_length / sizeof(uint64_t));

	return rsp->data_length / sizeof(uint64_t);
}

/* Screen out objects that don't belong to this node */
static void screen_object_list(struct recovery_work *rw,
			       uint64_t *oids, int nr_oids)
{
	const struct sd_vnode *vnodes[SD_MAX_COPIES];
	int old_count = rw->count;
	int nr_objs;
	int i, j;

	for (i = 0; i < nr_oids; i++) {
again:
		nr_objs = get_obj_copy_number(oids[i], rw->cur_vinfo->nr_zones);
		if (!nr_objs) {
			dprintf("can not find copy number for object %" PRIx64
				"\n", oids[i]);
			dprintf("probably, vdi was created but "
				"post_cluster_new_vdi() is not called yet\n");
			/* FIXME: can we wait for post_cluster_new_vdi
			 *        with a better way? */
			sleep(1);
			goto again;
		}
		oid_to_vnodes(rw->cur_vinfo->vnodes, rw->cur_vinfo->nr_vnodes,
			      oids[i], nr_objs, vnodes);
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

	qsort(rw->oids, rw->count, sizeof(uint64_t), obj_cmp);
}

static bool newly_joined(struct sd_node *node, struct recovery_work *rw)
{
	if (bsearch(node, rw->old_vinfo->nodes, rw->old_vinfo->nr_nodes,
		    sizeof(struct sd_node), node_id_cmp))
		return false;
	return true;
}

/* Prepare the object list that belongs to this node */
static void prepare_object_list(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	uint8_t *buf = NULL;
	size_t buf_size = SD_DATA_OBJ_SIZE; /* FIXME */
	struct sd_node *cur = rw->cur_vinfo->nodes;
	int cur_nr = rw->cur_vinfo->nr_nodes;
	int start = random() % cur_nr, i, end = cur_nr;

	dprintf("%u\n", rw->epoch);

	wait_get_vdis_done();

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

static inline bool node_is_gateway_only(void)
{
	return sys->this_node.nr_vnodes == 0;
}

int start_recovery(struct vnode_info *cur_vinfo, struct vnode_info *old_vinfo)
{
	struct recovery_work *rw;

	if (node_is_gateway_only())
		return 0;

	rw = zalloc(sizeof(struct recovery_work));
	if (!rw) {
		eprintf("%m\n");
		return -1;
	}

	rw->state = RW_INIT;
	rw->oids = xmalloc(1 << 20); /* FIXME */
	rw->epoch = sys->epoch;
	rw->count = 0;

	rw->cur_vinfo = grab_vnode_info(cur_vinfo);
	rw->old_vinfo = grab_vnode_info(old_vinfo);

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

		/* This is necesary to invoke run_next_rw when
		 * recovery work is suspended. */
		resume_suspended_recovery();
	} else {
		recovering_work = rw;
		queue_work(sys->recovery_wqueue, &rw->work);
	}

	resume_wait_epoch_requests();

	return 0;
}
