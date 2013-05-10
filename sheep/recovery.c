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
	RW_PREPARE_LIST, /* the recovery thread is preparing object list */
	RW_RECOVER_OBJ, /* the thread is recoering objects */
	RW_NOTIFY_COMPLETION, /* the thread is notifying recovery completion */
};

/* base structure for the recovery thread */
struct recovery_work {
	uint32_t epoch;

	struct vnode_info *old_vinfo;
	struct vnode_info *cur_vinfo;

	struct work work;
};

/* for preparing lists */
struct recovery_list_work {
	struct recovery_work base;

	int count;
	uint64_t *oids;
};

/* for recoverying objects */
struct recovery_obj_work {
	struct recovery_work base;

	uint64_t oid; /* the object to be recovered */
	bool stop;
};

/*
 * recovery information
 *
 * We cannot access the members of this structure outside of the main thread.
 */
struct recovery_info {
	enum rw_state state;

	uint32_t epoch;
	uint32_t done;

	/*
	 * true when automatic recovery is disabled
	 * and no recovery work is running
	 */
	bool suspended;

	int count;
	uint64_t *oids;
	uint64_t *prio_oids;
	int nr_prio_oids;
	int nr_scheduled_prio_oids;

	struct vnode_info *old_vinfo;
	struct vnode_info *cur_vinfo;
};

struct recovery_info *next_rinfo;
static main_thread(struct recovery_info *) current_rinfo;

static void queue_recovery_work(struct recovery_info *rinfo);

/* Dynamically grown list buffer default as 4M (2T storage) */
#define DEFAULT_LIST_BUFFER_SIZE (UINT64_C(1) << 22)
static size_t list_buffer_size = DEFAULT_LIST_BUFFER_SIZE;

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

static int recover_object_from_replica(uint64_t oid, struct vnode_info *old,
				       struct vnode_info *cur,
				       uint32_t epoch, uint32_t tgt_epoch)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	unsigned rlen;
	int nr_copies, ret = SD_RES_SUCCESS, start = 0;
	void *buf = NULL;
	struct siocb iocb = { 0 };
	bool fully_replicated = true;

	nr_copies = get_obj_copy_number(oid, old->nr_zones);

	/* find local node first to try to recover from local */
	for (int i = 0; i < nr_copies; i++) {
		const struct sd_vnode *vnode;

		vnode = oid_to_vnode(old->vnodes, old->nr_vnodes, oid, i);

		if (vnode_is_local(vnode)) {
			start = i;
			break;
		}
	}

	rlen = get_objsize(oid);
	buf = xvalloc(rlen);

	/* Let's do a breadth-first search */
	for (int i = 0; i < nr_copies; i++) {
		const struct sd_vnode *vnode;
		int idx = (i + start) % nr_copies;

		vnode = oid_to_vnode(old->vnodes, old->nr_vnodes, oid, idx);

		if (is_invalid_vnode(vnode, cur->nodes, cur->nr_nodes))
			continue;

		if (vnode_is_local(vnode)) {
			if (tgt_epoch < sys_epoch())
				ret = sd_store->link(oid, tgt_epoch);
			else
				ret = SD_RES_NO_OBJ;
		} else {
			sd_init_req(&hdr, SD_OP_READ_PEER);
			hdr.epoch = epoch;
			hdr.flags = SD_FLAG_CMD_RECOVERY;
			hdr.data_length = rlen;
			hdr.obj.oid = oid;
			hdr.obj.tgt_epoch = tgt_epoch;

			ret = sheep_exec_req(&vnode->nid, &hdr, buf);
			if (ret == SD_RES_SUCCESS) {
				iocb.epoch = epoch;
				iocb.length = rsp->data_length;
				iocb.offset = rsp->obj.offset;
				iocb.buf = buf;
				ret = sd_store->create_and_write(oid, &iocb);
			}
		}

		switch (ret) {
		case SD_RES_SUCCESS:
			sd_dprintf("recovered oid %"PRIx64" from %d "
				   "to epoch %d", oid, tgt_epoch, epoch);
			objlist_cache_insert(oid);
			goto out;
		case SD_RES_OLD_NODE_VER:
			/* move to the next epoch recovery */
			goto out;
		case SD_RES_NO_OBJ:
			fully_replicated = false;
			/* fall through */
		default:
			break;
		}
	}

	/*
	 * sheep would return a stale object when
	 *  - all the nodes hold the copies, and
	 *  - all the nodes are gone
	 * at the some epoch
	 */
	if (fully_replicated && ret != SD_RES_SUCCESS)
		ret = SD_RES_STALE_OBJ;

out:
	free(buf);
	return ret;
}

/*
 * Recover the object from its track in epoch history. That is,
 * the routine will try to recovery it from the nodes it has stayed,
 * at least, *theoretically* on consistent hash ring.
 */
static int do_recover_object(struct recovery_obj_work *row)
{
	struct recovery_work *rw = &row->base;
	struct vnode_info *old, *cur;
	uint64_t oid = row->oid;
	uint32_t epoch = rw->epoch, tgt_epoch = rw->epoch;
	int ret;
	struct vnode_info *new_old;

	old = grab_vnode_info(rw->old_vinfo);
	cur = grab_vnode_info(rw->cur_vinfo);
again:
	sd_dprintf("try recover object %"PRIx64" from epoch %"PRIu32, oid,
		   tgt_epoch);

	ret = recover_object_from_replica(oid, old, cur, epoch, tgt_epoch);

	switch (ret) {
	case SD_RES_SUCCESS:
		/* Succeed */
		break;
	case SD_RES_OLD_NODE_VER:
		row->stop = true;
		break;
	case SD_RES_STALE_OBJ:
		sd_printf(SDOG_ALERT, "cannot access any replicas of "
			  "%"PRIx64" at epoch %d", oid, tgt_epoch);
		sd_printf(SDOG_ALERT, "clients may see old data");
		/* fall through */
	default:
		/* No luck, roll back to an older configuration and try again */
rollback:
		tgt_epoch--;
		if (tgt_epoch < 1) {
			sd_eprintf("can not recover oid %"PRIx64, oid);
			ret = -1;
			break;
		}

		new_old = get_vnode_info_epoch(tgt_epoch, rw->cur_vinfo);
		if (!new_old) {
			/* We rollback in case we don't get a valid epoch */
			sd_printf(SDOG_ALERT, "cannot get epoch %d", tgt_epoch);
			sd_printf(SDOG_ALERT, "clients may see old data");
			goto rollback;
		}

		put_vnode_info(cur);
		cur = old;
		old = new_old;
		goto again;
	}

	put_vnode_info(old);
	put_vnode_info(cur);
	return ret;
}

static void recover_object_work(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	struct recovery_obj_work *row = container_of(rw,
						     struct recovery_obj_work,
						     base);
	uint64_t oid = row->oid;
	int ret;

	if (sd_store->exist(oid)) {
		sd_dprintf("the object is already recovered");
		return;
	}

	ret = do_recover_object(row);
	if (ret < 0)
		sd_eprintf("failed to recover object %"PRIx64, oid);
}

bool node_in_recovery(void)
{
	return main_thread_get(current_rinfo) != NULL;
}

static inline void prepare_schedule_oid(uint64_t oid)
{
	struct recovery_info *rinfo = main_thread_get(current_rinfo);
	int i;

	for (i = 0; i < rinfo->nr_prio_oids; i++)
		if (rinfo->prio_oids[i] == oid)
			return;
	/*
	 * We need this check because oid might not be recovered.
	 * Very much unlikely though, but it might happen indeed.
	 */
	for (i = 0; i < rinfo->done; i++)
		if (rinfo->oids[i] == oid) {
			sd_dprintf("%"PRIx64" not recovered, don't schedule it",
				   oid);
			return;
		}
	/* When recovery is not suspended, oid is currently being recovered */
	if (!rinfo->suspended && rinfo->oids[rinfo->done] == oid)
		return;

	rinfo->nr_prio_oids++;
	rinfo->prio_oids = xrealloc(rinfo->prio_oids,
				    rinfo->nr_prio_oids * sizeof(uint64_t));
	rinfo->prio_oids[rinfo->nr_prio_oids - 1] = oid;
	sd_dprintf("%"PRIx64" nr_prio_oids %d", oid, rinfo->nr_prio_oids);

	resume_suspended_recovery();
}

bool oid_in_recovery(uint64_t oid)
{
	struct recovery_info *rinfo = main_thread_get(current_rinfo);
	int i;

	if (!node_in_recovery())
		return false;

	if (sd_store->exist(oid)) {
		sd_dprintf("the object %" PRIx64 " is already recoverd", oid);
		return false;
	}

	if (uatomic_read(&next_rinfo))
		return true;

	/* If we are in preparation of object list, oid is not recovered yet */
	if (rinfo->state == RW_PREPARE_LIST)
		return true;

	/*
	 * Check if oid is in the list that to be recovered later
	 *
	 * FIXME: do we need more efficient yet complex data structure?
	 */
	for (i = rinfo->done; i < rinfo->count; i++)
		if (rinfo->oids[i] == oid)
			break;

	/*
	 * Newly created object after prepare_object_list() might not be
	 * in the list
	 */
	if (i == rinfo->count) {
		sd_eprintf("%"PRIx64" is not in the recovery list", oid);
		return false;
	}

	prepare_schedule_oid(oid);
	return true;
}

static void free_recovery_work(struct recovery_work *rw)
{
	put_vnode_info(rw->cur_vinfo);
	put_vnode_info(rw->old_vinfo);
	free(rw);
}

static void free_recovery_list_work(struct recovery_list_work *rlw)
{
	put_vnode_info(rlw->base.cur_vinfo);
	put_vnode_info(rlw->base.old_vinfo);
	free(rlw->oids);
	free(rlw);
}

static void free_recovery_obj_work(struct recovery_obj_work *row)
{
	put_vnode_info(row->base.cur_vinfo);
	put_vnode_info(row->base.old_vinfo);
	free(row);
}

static void free_recovery_info(struct recovery_info *rinfo)
{
	put_vnode_info(rinfo->cur_vinfo);
	put_vnode_info(rinfo->old_vinfo);
	free(rinfo->oids);
	free(rinfo->prio_oids);
	free(rinfo);
}

/* Return true if next recovery work is queued. */
static inline bool run_next_rw(void)
{
	struct recovery_info *nrinfo = uatomic_xchg_ptr(&next_rinfo, NULL);

	if (nrinfo == NULL)
		return false;

	free_recovery_info(main_thread_get(current_rinfo));

	if (sd_store->update_epoch)
		sd_store->update_epoch(nrinfo->epoch);

	main_thread_set(current_rinfo, nrinfo);
	wakeup_all_requests();
	queue_recovery_work(nrinfo);
	sd_dprintf("recovery work is superseded");
	return true;
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
		sd_eprintf("failed to notify recovery completion, %d",
			   rw->epoch);
}

static void notify_recovery_completion_main(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	free_recovery_work(rw);
}

static inline void finish_recovery(struct recovery_info *rinfo)
{
	uint32_t recovered_epoch = rinfo->epoch;
	main_thread_set(current_rinfo, NULL);

	wakeup_all_requests();

	rinfo->state = RW_NOTIFY_COMPLETION;

	/* notify recovery completion to other nodes */
	queue_recovery_work(rinfo);
	free_recovery_info(rinfo);

	sd_dprintf("recovery complete: new epoch %"PRIu32, recovered_epoch);
}

static inline bool oid_in_prio_oids(struct recovery_info *rinfo, uint64_t oid)
{
	int i;

	for (i = 0; i < rinfo->nr_prio_oids; i++)
		if (rinfo->prio_oids[i] == oid)
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
static inline void finish_schedule_oids(struct recovery_info *rinfo)
{
	int i, nr_recovered = rinfo->done, new_idx;
	uint64_t *new_oids;

	/* If I am the last oid, done */
	if (nr_recovered == rinfo->count - 1)
		goto done;

	new_oids = xmalloc(list_buffer_size);
	memcpy(new_oids, rinfo->oids, nr_recovered * sizeof(uint64_t));
	memcpy(new_oids + nr_recovered, rinfo->prio_oids,
	       rinfo->nr_prio_oids * sizeof(uint64_t));
	new_idx = nr_recovered + rinfo->nr_prio_oids;

	for (i = rinfo->done; i < rinfo->count; i++) {
		if (oid_in_prio_oids(rinfo, rinfo->oids[i]))
			continue;
		new_oids[new_idx++] = rinfo->oids[i];
	}
	/* rw->count should eq new_idx, otherwise something is wrong */
	sd_dprintf("%snr_recovered %d, nr_prio_oids %d, count %d = new %d",
		   rinfo->count == new_idx ? "" : "WARN: ", nr_recovered,
		   rinfo->nr_prio_oids, rinfo->count, new_idx);

	free(rinfo->oids);
	rinfo->oids = new_oids;
done:
	free(rinfo->prio_oids);
	rinfo->prio_oids = NULL;
	rinfo->nr_scheduled_prio_oids += rinfo->nr_prio_oids;
	rinfo->nr_prio_oids = 0;
}

/*
 * When automatic object recovery is disabled, the behavior of the
 * recovery process is like 'lazy recovery'.  This function returns
 * true if the recovery queue contains objects being accessed by
 * clients.  Sheep recovers such objects for availability even when
 * automatic object recovery is not enabled.
 */
static bool has_scheduled_objects(struct recovery_info *rinfo)
{
	return rinfo->done < rinfo->nr_scheduled_prio_oids;
}

static void recover_next_object(struct recovery_info *rinfo)
{
	if (run_next_rw())
		return;

	if (rinfo->nr_prio_oids)
		finish_schedule_oids(rinfo);

	if (sys->disable_recovery && !has_scheduled_objects(rinfo)) {
		sd_dprintf("suspended");
		rinfo->suspended = true;
		/* suspend until resume_suspended_recovery() is called */
		return;
	}

	/* Try recover next object */
	queue_recovery_work(rinfo);
}

void resume_suspended_recovery(void)
{
	struct recovery_info *rinfo = main_thread_get(current_rinfo);

	if (rinfo && rinfo->suspended) {
		rinfo->suspended = false;
		recover_next_object(rinfo);
	}
}

static void recover_object_main(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	struct recovery_obj_work *row = container_of(rw,
						     struct recovery_obj_work,
						     base);
	struct recovery_info *rinfo = main_thread_get(current_rinfo);

	if (run_next_rw())
		goto out;

	if (row->stop) {
		/*
		 * Stop this recovery process and wait for epoch to be
		 * lifted and flush wait queue to requeue those
		 * requests
		 */
		wakeup_all_requests();
		sd_dprintf("recovery is stopped");
		goto out;
	}

	wakeup_requests_on_oid(row->oid);
	rinfo->done++;

	sd_eprintf("done:%"PRIu32" count:%"PRIu32", oid:%"PRIx64, rinfo->done,
		   rinfo->count, row->oid);

	if (rinfo->done < rinfo->count) {
		recover_next_object(rinfo);
		goto out;
	}

	finish_recovery(rinfo);
out:
	free_recovery_obj_work(row);
}

static void finish_object_list(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	struct recovery_list_work *rlw = container_of(rw,
						      struct recovery_list_work,
						      base);
	struct recovery_info *rinfo = main_thread_get(current_rinfo);

	rinfo->state = RW_RECOVER_OBJ;
	rinfo->count = rlw->count;
	rinfo->oids = rlw->oids;
	rlw->oids = NULL;
	free_recovery_list_work(rlw);

	if (run_next_rw())
		return;

	if (!rinfo->count) {
		finish_recovery(rinfo);
		return;
	}

	recover_next_object(rinfo);
	return;
}

/* Fetch the object list from all the nodes in the cluster */
static uint64_t *fetch_object_list(struct sd_node *e, uint32_t epoch,
				   size_t *nr_oids)
{
	char name[128];
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	size_t buf_size = list_buffer_size;
	uint64_t *buf = xmalloc(buf_size);
	int ret;

	addr_to_str(name, sizeof(name), e->nid.addr, 0);
	sd_dprintf("%s %"PRIu32, name, e->nid.port);

retry:
	sd_init_req(&hdr, SD_OP_GET_OBJ_LIST);
	hdr.data_length = buf_size;
	hdr.epoch = sys_epoch();
	ret = sheep_exec_req(&e->nid, &hdr, buf);

	switch (ret) {
	case SD_RES_SUCCESS:
		break;
	case SD_RES_BUFFER_SMALL:
		buf_size *= 2;
		buf = xrealloc(buf, buf_size);
		goto retry;
	default:
		sd_printf(SDOG_ALERT, "cannot get object list from %s:%d", name,
			  e->nid.port);
		sd_printf(SDOG_ALERT, "some objects may be not recovered at "
			  "epoch %d", epoch);
		free(buf);
		return NULL;
	}

	*nr_oids = rsp->data_length / sizeof(uint64_t);
	sd_dprintf("%zu", *nr_oids);
	return buf;
}

/* Screen out objects that don't belong to this node */
static void screen_object_list(struct recovery_list_work *rlw,
			       uint64_t *oids, size_t nr_oids)
{
	struct recovery_work *rw = &rlw->base;
	const struct sd_vnode *vnodes[SD_MAX_COPIES];
	int old_count = rlw->count;
	int nr_objs;
	int i, j;

	for (i = 0; i < nr_oids; i++) {
		nr_objs = get_obj_copy_number(oids[i], rw->cur_vinfo->nr_zones);
		if (!nr_objs) {
			sd_eprintf("ERROR: can not find copy number for object"
				   " %" PRIx64, oids[i]);
			continue;
		}
		oid_to_vnodes(rw->cur_vinfo->vnodes, rw->cur_vinfo->nr_vnodes,
			      oids[i], nr_objs, vnodes);
		for (j = 0; j < nr_objs; j++) {
			if (!vnode_is_local(vnodes[j]))
				continue;
			if (bsearch(&oids[i], rlw->oids, old_count,
				    sizeof(uint64_t), obj_cmp))
				continue;

			rlw->oids[rlw->count++] = oids[i];
			/* enlarge the list buffer if full */
			if (rlw->count == list_buffer_size / sizeof(uint64_t)) {
				list_buffer_size *= 2;
				rlw->oids = xrealloc(rlw->oids,
						     list_buffer_size);
			}
			break;
		}
	}

	qsort(rlw->oids, rlw->count, sizeof(uint64_t), obj_cmp);
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
	struct recovery_list_work *rlw = container_of(rw,
						      struct recovery_list_work,
						      base);
	struct sd_node *cur = rw->cur_vinfo->nodes;
	int cur_nr = rw->cur_vinfo->nr_nodes;
	int start = random() % cur_nr, i, end = cur_nr;
	uint64_t *oids;

	sd_dprintf("%u", rw->epoch);
	wait_get_vdis_done();
again:
	/* We need to start at random node for better load balance */
	for (i = start; i < end; i++) {
		size_t nr_oids;
		struct sd_node *node = cur + i;

		if (uatomic_read(&next_rinfo)) {
			sd_dprintf("go to the next recovery");
			return;
		}
		if (newly_joined(node, rw))
			/* new node doesn't have a list file */
			continue;

		oids = fetch_object_list(node, rw->epoch, &nr_oids);
		if (!oids)
			continue;
		screen_object_list(rlw, oids, nr_oids);
		free(oids);
	}

	if (start != 0) {
		end = start;
		start = 0;
		goto again;
	}

	sd_dprintf("%d", rlw->count);
}

static inline bool node_is_gateway_only(void)
{
	return sys->this_node.nr_vnodes == 0;
}

int start_recovery(struct vnode_info *cur_vinfo, struct vnode_info *old_vinfo)
{
	struct recovery_info *rinfo;

	if (node_is_gateway_only())
		goto out;

	rinfo = xzalloc(sizeof(struct recovery_info));
	rinfo->state = RW_PREPARE_LIST;
	rinfo->epoch = sys->epoch;
	rinfo->count = 0;

	rinfo->cur_vinfo = grab_vnode_info(cur_vinfo);
	rinfo->old_vinfo = grab_vnode_info(old_vinfo);

	if (sd_store->update_epoch)
		sd_store->update_epoch(rinfo->epoch);

	if (main_thread_get(current_rinfo) != NULL) {
		/* skip the previous epoch recovery */
		struct recovery_info *nrinfo;
		nrinfo = uatomic_xchg_ptr(&next_rinfo, rinfo);
		if (nrinfo)
			free_recovery_info(nrinfo);
		sd_dprintf("recovery skipped");

		/*
		 * This is necesary to invoke run_next_rw when
		 * recovery work is suspended.
		 */
		resume_suspended_recovery();
	} else {
		main_thread_set(current_rinfo, rinfo);
		queue_recovery_work(rinfo);
	}
out:
	wakeup_requests_on_epoch();
	return 0;
}

static void queue_recovery_work(struct recovery_info *rinfo)
{
	struct recovery_work *rw;
	struct recovery_list_work *rlw;
	struct recovery_obj_work *row;

	switch (rinfo->state) {
	case RW_PREPARE_LIST:
		rlw = xzalloc(sizeof(*rlw));
		rlw->oids = xmalloc(list_buffer_size);

		rw = &rlw->base;
		rw->work.fn = prepare_object_list;
		rw->work.done = finish_object_list;
		break;
	case RW_RECOVER_OBJ:
		row = xzalloc(sizeof(*row));
		row->oid = rinfo->oids[rinfo->done];

		rw = &row->base;
		rw->work.fn = recover_object_work;
		rw->work.done = recover_object_main;
		break;
	case RW_NOTIFY_COMPLETION:
		rw = xzalloc(sizeof(*rw));
		rw->work.fn = notify_recovery_completion_work;
		rw->work.done = notify_recovery_completion_main;
		break;
	default:
		panic("unknow recovery state %d", rinfo->state);
		break;
	}

	rw->epoch = rinfo->epoch;
	rw->cur_vinfo = grab_vnode_info(rinfo->cur_vinfo);
	rw->old_vinfo = grab_vnode_info(rinfo->old_vinfo);

	queue_work(sys->recovery_wqueue, &rw->work);
}
