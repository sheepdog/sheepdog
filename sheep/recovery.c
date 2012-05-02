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

	struct timer timer;
	int retry;
	struct work work;

	int nr_blocking;
	int count;
	uint64_t *oids;

	int old_nr_nodes;
	struct sd_node old_nodes[SD_MAX_NODES];
	int cur_nr_nodes;
	struct sd_node cur_nodes[SD_MAX_NODES];
	int old_nr_vnodes;
	struct sd_vnode old_vnodes[SD_MAX_VNODES];
	int cur_nr_vnodes;
	struct sd_vnode cur_vnodes[SD_MAX_VNODES];
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

/*
 * contains_node - checks that the node id is included in the target nodes
 *
 * The target nodes to store replicated objects are the first N nodes
 * from the base_idx'th on the consistent hash ring, where N is the
 * number of copies of objects.
 */
static int contains_node(struct sd_vnode *key,
			 struct sd_vnode *entry,
			 int nr, int base_idx, int copies)
{
	int i;

	for (i = 0; i < copies; i++) {
		int idx = get_nth_node(entry, nr, base_idx, i);
		if (memcmp(key->addr, entry[idx].addr, sizeof(key->addr)) == 0
		    && key->port == entry[idx].port)
			return idx;
	}
	return -1;
}

/*
 * find_tgt_node - find the node from which we should recover objects
 *
 * This function compares two node lists, the current target nodes and
 * the previous target nodes, and finds the node from the previous
 * target nodes which corresponds to the copy_idx'th node of the
 * current target nodes.  The correspondence is injective and
 * maximizes the number of nodes which can recover objects locally.
 *
 * For example, consider the number of redundancy is 5, the consistent
 * hash ring is {A, B, C, D, E, F}, and the node G is newly added.
 * The parameters of this function are
 *   old_entry = {A, B, C, D, E, F},    old_nr = 6, old_idx = 3
 *   cur_entry = {A, B, C, D, E, F, G}, cur_nr = 7, cur_idx = 3
 *
 * In this case:
 *   the previous target nodes: {D, E, F, A, B}
 *     (the first 5 nodes from the 3rd node on the previous hash ring)
 *   the current target nodes : {D, E, F, G, A}
 *     (the first 5 nodes from the 3rd node on the current hash ring)
 *
 * The correspondence between copy_idx and return value are as follows:
 * ----------------------------
 * copy_idx       0  1  2  3  4
 * src_node       D  E  F  G  A
 * tgt_node       D  E  F  B  A
 * return value   0  1  2  4  3
 * ----------------------------
 *
 * The node D, E, F, and A can recover objects from local, and the
 * node G recovers from the node B.
 */
static int find_tgt_node(struct sd_vnode *old_entry,
			 int old_nr, int old_idx, int old_copies,
			 struct sd_vnode *cur_entry,
			 int cur_nr, int cur_idx, int cur_copies,
			 int copy_idx)
{
	int i, j, idx;

	dprintf("%"PRIu32", %"PRIu32", %"PRIu32", %"PRIu32", %"PRIu32", %"PRIu32", %"PRIu32"\n",
		old_idx, old_nr, old_copies, cur_idx, cur_nr, cur_copies, copy_idx);

	/* If the same node is in the previous target nodes, return its index */
	idx = contains_node(cur_entry + get_nth_node(cur_entry, cur_nr, cur_idx, copy_idx),
			    old_entry, old_nr, old_idx, old_copies);
	if (idx >= 0) {
		dprintf("%"PRIu32", %"PRIu32", %"PRIu32", %"PRIu32"\n", idx, copy_idx, cur_idx, cur_nr);
		return idx;
	}

	for (i = 0, j = 0; ; i++, j++) {
		if (i < copy_idx) {
			/* Skip if the node can recover from its local */
			idx = contains_node(cur_entry + get_nth_node(cur_entry, cur_nr, cur_idx, i),
					    old_entry, old_nr, old_idx, old_copies);
			if (idx >= 0)
				continue;

			/* Find the next target which needs to recover from remote */
			while (j < old_copies &&
			       contains_node(old_entry + get_nth_node(old_entry, old_nr, old_idx, j),
					     cur_entry, cur_nr, cur_idx, cur_copies) >= 0)
				j++;
		}
		if (j == old_copies) {
			/*
			 * Cannot find the target because the number of zones
			 * is smaller than the number of copies.  We can select
			 * any node in this case, so select the first one.
			 */
			return old_idx;
		}

		if (i == copy_idx) {
			/* Found the target node correspoinding to copy_idx */
			dprintf("%"PRIu32", %"PRIu32", %"PRIu32"\n",
				get_nth_node(old_entry, old_nr, old_idx, j),
				copy_idx, (cur_idx + i) % cur_nr);
			return get_nth_node(old_entry, old_nr, old_idx, j);
		}

	}

	return -1;
}

static void *get_vnodes_from_epoch(uint32_t epoch, int *nr, int *copies)
{
	int nodes_nr, len = sizeof(struct sd_vnode) * SD_MAX_VNODES;
	struct sd_node nodes[SD_MAX_NODES];
	void *buf = xmalloc(len);

	nodes_nr = epoch_log_read_nr(epoch, (void *)nodes, sizeof(nodes));
	if (nodes_nr < 0) {
		nodes_nr = epoch_log_read_remote(epoch, (void *)nodes, sizeof(nodes));
		if (nodes_nr == 0) {
			free(buf);
			return NULL;
		}
		nodes_nr /= sizeof(nodes[0]);
	}
	*nr = nodes_to_vnodes(nodes, nodes_nr, buf);
	*copies = get_max_nr_copies_from(nodes, nodes_nr);

	return buf;
}

static int recover_object_from_replica(uint64_t oid,
				       struct sd_vnode *entry,
				       uint32_t epoch, uint32_t tgt_epoch)
{
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
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
	hdr.oid = oid;
	hdr.epoch = epoch;
	hdr.flags = SD_FLAG_CMD_RECOVERY | SD_FLAG_CMD_IO_LOCAL;
	hdr.tgt_epoch = tgt_epoch;
	hdr.data_length = rlen;

	ret = exec_req(fd, (struct sd_req *)&hdr, buf, &wlen, &rlen);

	close(fd);

	if (ret != 0) {
		eprintf("res: %"PRIx32"\n", rsp->result);
		ret = -1;
		goto out;
	}

	rsp = (struct sd_obj_rsp *)&hdr;

	if (rsp->result == SD_RES_SUCCESS) {
		iocb.epoch = epoch;
		iocb.length = rlen;
		iocb.buf = buf;
		ret = sd_store->atomic_put(oid, &iocb);
		if (ret != SD_RES_SUCCESS) {
			ret = -1;
			goto out;
		}
	} else if (rsp->result == SD_RES_NEW_NODE_VER ||
			rsp->result == SD_RES_OLD_NODE_VER ||
			rsp->result == SD_RES_NETWORK_ERROR) {
		dprintf("retrying: %"PRIx32", %"PRIx64"\n", rsp->result, oid);
		ret = 1;
		goto out;
	} else {
		eprintf("failed, res: %"PRIx32"\n", rsp->result);
		ret = -1;
		goto out;
	}
done:
	dprintf("recovered oid %"PRIx64" from %d to epoch %d\n", oid, tgt_epoch, epoch);
out:
	free(buf);
	return ret;
}

static void rollback_old_cur(struct sd_vnode *old, int *old_nr, int *old_copies,
			     struct sd_vnode *cur, int *cur_nr, int *cur_copies,
			     struct sd_vnode *new_old, int new_old_nr, int new_old_copies)
{
	int nr_old = *old_nr;
	int copies_old = *old_copies;

	memcpy(cur, old, sizeof(*old) * nr_old);
	*cur_nr = nr_old;
	*cur_copies = copies_old;
	memcpy(old, new_old, sizeof(*new_old) * new_old_nr);
	*old_nr = new_old_nr;
	*old_copies = new_old_copies;
}

/*
 * Recover the object from its track in epoch history. That is,
 * the routine will try to recovery it from the nodes it has stayed,
 * at least, *theoretically* on consistent hash ring.
 */
static int do_recover_object(struct recovery_work *rw, int copy_idx)
{
	struct sd_vnode *old, *cur;
	uint64_t oid = rw->oids[rw->done];
	int old_nr = rw->old_nr_vnodes, cur_nr = rw->cur_nr_vnodes;
	uint32_t epoch = rw->epoch, tgt_epoch = rw->epoch - 1;
	struct sd_vnode *tgt_entry;
	int old_idx, cur_idx, tgt_idx, old_copies, cur_copies, ret;

	old = xmalloc(sizeof(*old) * SD_MAX_VNODES);
	cur = xmalloc(sizeof(*cur) * SD_MAX_VNODES);
	memcpy(old, rw->old_vnodes, sizeof(*old) * old_nr);
	memcpy(cur, rw->cur_vnodes, sizeof(*cur) * cur_nr);
	old_copies = get_max_nr_copies_from(rw->old_nodes, rw->old_nr_nodes);
	cur_copies = get_max_nr_copies_from(rw->cur_nodes, rw->cur_nr_nodes);

again:
	old_idx = obj_to_sheep(old, old_nr, oid, 0);
	cur_idx = obj_to_sheep(cur, cur_nr, oid, 0);

	dprintf("try recover object %"PRIx64" from epoch %"PRIu32"\n", oid, tgt_epoch);

	if (cur_copies <= copy_idx) {
		eprintf("epoch (%"PRIu32") has less copies (%d) than requested copy_idx: %d\n",
		tgt_epoch, cur_copies, copy_idx);
		ret = -1;
		goto err;
	}

	tgt_idx = find_tgt_node(old, old_nr, old_idx, old_copies,
			cur, cur_nr, cur_idx, cur_copies, copy_idx);
	if (tgt_idx < 0) {
		eprintf("cannot find target node %"PRIx64"\n", oid);
		ret = -1;
		goto err;
	}
	tgt_entry = old + tgt_idx;

	ret = recover_object_from_replica(oid, tgt_entry, epoch, tgt_epoch);
	if (ret < 0) {
		struct sd_vnode *new_old;
		int new_old_nr, new_old_copies;

		tgt_epoch--;
		if (tgt_epoch < 1) {
			eprintf("can not recover oid %"PRIx64"\n", oid);
			ret = -1;
			goto err;
		}

		new_old = get_vnodes_from_epoch(tgt_epoch, &new_old_nr, &new_old_copies);
		if (!new_old) {
			ret = -1;
			goto err;
		}
		rollback_old_cur(old, &old_nr, &old_copies, cur, &cur_nr, &cur_copies,
				new_old, new_old_nr, new_old_copies);
		free(new_old);
		goto again;
	} else if (ret > 0) {
		ret = 0;
		rw->retry = 1;
	}
err:
	free(old);
	free(cur);
	return ret;
}

static int get_replica_idx(struct recovery_work *rw, uint64_t oid, int *copy_nr)
{
	int i, ret = -1;
	*copy_nr = get_max_nr_copies_from(rw->cur_nodes, rw->cur_nr_nodes);
	for (i = 0; i < *copy_nr; i++) {
		int n = obj_to_sheep(rw->cur_vnodes, rw->cur_nr_vnodes, oid, i);
		if (vnode_is_local(&rw->cur_vnodes[n])) {
			ret = i;
			break;
		}
	}
	return ret;
}

static void recover_object(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work, work);
	uint64_t oid = rw->oids[rw->done];
	uint32_t epoch = rw->epoch;
	int i, copy_idx, copy_nr, ret;
	struct siocb iocb = { 0 };

	if (!sys->nr_copies)
		return;

	eprintf("done:%"PRIu32" count:%"PRIu32", oid:%"PRIx64"\n", rw->done, rw->count, oid);

	iocb.epoch = epoch;
	ret = sd_store->open(oid, &iocb, 0);
	if (ret == SD_RES_SUCCESS) {
		sd_store->close(oid, &iocb);
		dprintf("the object is already recovered\n");
		return;
	}

	copy_idx = get_replica_idx(rw, oid, &copy_nr);
	if (copy_idx < 0) {
		ret = -1;
		goto err;
	}
	ret = do_recover_object(rw, copy_idx);
	if (ret < 0) {
		for (i = 0; i < copy_nr; i++) {
			if (i == copy_idx)
				continue;
			ret = do_recover_object(rw, i);
			if (ret == 0)
				break;
		}
	}
err:
	if (ret < 0)
		eprintf("failed to recover object %"PRIx64"\n", oid);
}

static struct recovery_work *suspended_recovery_work;

static void recover_timer(void *data)
{
	struct recovery_work *rw = (struct recovery_work *)data;
	uint64_t oid = rw->oids[rw->done];

	if (is_access_to_busy_objects(oid)) {
		suspended_recovery_work = rw;
		return;
	}

	queue_work(sys->recovery_wqueue, &rw->work);
}

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

int is_recoverying_oid(uint64_t oid)
{
	uint64_t hval = fnv_64a_buf(&oid, sizeof(uint64_t), FNV1A_64_INIT);
	uint64_t min_hval;
	struct recovery_work *rw = recovering_work;
	int ret, i;
	struct siocb iocb;

	if (oid == 0)
		return 0;

	if (!rw)
		return 0; /* there is no thread working for object recovery */

	min_hval = fnv_64a_buf(&rw->oids[rw->done + rw->nr_blocking], sizeof(uint64_t), FNV1A_64_INIT);

	if (before(rw->epoch, sys->epoch))
		return 1;

	if (rw->state == RW_INIT)
		return 1;

	memset(&iocb, 0, sizeof(iocb));
	iocb.epoch = sys->epoch;
	ret = sd_store->open(oid, &iocb, 0);
	if (ret == SD_RES_SUCCESS) {
		dprintf("the object %" PRIx64 " is already recoverd\n", oid);
		sd_store->close(oid, &iocb);
		return 0;
	}

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

static void do_recover_main(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work, work);
	uint64_t oid;

	if (rw->state == RW_INIT)
		rw->state = RW_RUN;
	else if (!rw->retry) {
		rw->done++;
		if (rw->nr_blocking > 0)
			rw->nr_blocking--;
	}

	oid = rw->oids[rw->done];

	if (rw->retry && !next_rw) {
		rw->retry = 0;

		rw->timer.callback = recover_timer;
		rw->timer.data = rw;
		add_timer(&rw->timer, 2);
		return;
	}

	if (rw->done < rw->count && !next_rw) {
		rw->work.fn = recover_object;

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

	free(rw->oids);
	free(rw);

	if (next_rw) {
		rw = next_rw;
		next_rw = NULL;

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
	int ret, i, cp, idx;
	struct strbuf buf = STRBUF_INIT;
	struct sd_vnode *nodes = rw->cur_vnodes;
	int nodes_nr = rw->cur_nr_vnodes;
	int nr_objs = get_max_nr_copies_from(rw->cur_nodes, rw->cur_nr_nodes);

	for (i = 0; i < list_nr; i++) {
		for (cp = 0; cp < nr_objs; cp++) {
			idx = obj_to_sheep(nodes, nodes_nr, list[i], cp);
			if (vnode_is_local(&nodes[idx]))
				break;
		}
		if (cp == nr_objs)
			continue;
		strbuf_add(&buf, &list[i], sizeof(uint64_t));
	}
	memcpy(list, buf.buf, buf.len);

	ret = buf.len / sizeof(uint64_t);
	dprintf("%d\n", ret);
	strbuf_release(&buf);

	return ret;
}

#define MAX_RETRY_CNT  6

static int newly_joined(struct sd_node *node, struct recovery_work *rw)
{
	struct sd_node *old = rw->old_nodes;
	int old_nr = rw->old_nr_nodes;
	int i;
	for (i = 0; i < old_nr; i++)
		if (node_cmp(node, old + i) == 0)
			break;

	if (i == old_nr)
		return 1;
	return 0;
}

static int fill_obj_list(struct recovery_work *rw)
{
	int i;
	uint8_t *buf = NULL;
	size_t buf_size = SD_DATA_OBJ_SIZE; /* FIXME */
	int retry_cnt;
	struct sd_node *cur = rw->cur_nodes;
	int cur_nr = rw->cur_nr_nodes;

	buf = malloc(buf_size);
	if (!buf) {
		eprintf("out of memory\n");
		rw->retry = 1;
		return -1;
	}
	for (i = 0; i < cur_nr; i++) {
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

	dprintf("%d\n", rw->count);
	free(buf);
	return 0;
}

/* setup node list and virtual node list */
static int init_rw(struct recovery_work *rw)
{
	uint32_t epoch = rw->epoch;

	rw->cur_nr_nodes = epoch_log_read_nr(epoch, (char *)rw->cur_nodes,
					     sizeof(rw->cur_nodes));
	if (rw->cur_nr_nodes <= 0) {
		eprintf("failed to read epoch log for epoch %"PRIu32"\n", epoch);
		return -1;
	}

	rw->old_nr_nodes = epoch_log_read_nr(epoch - 1, (char *)rw->old_nodes,
					     sizeof(rw->old_nodes));
	if (rw->old_nr_nodes <= 0) {
		eprintf("failed to read epoch log for epoch %"PRIu32"\n", epoch - 1);
		return -1;
	}
	rw->old_nr_vnodes = nodes_to_vnodes(rw->old_nodes, rw->old_nr_nodes,
					    rw->old_vnodes);
	rw->cur_nr_vnodes = nodes_to_vnodes(rw->cur_nodes, rw->cur_nr_nodes,
					    rw->cur_vnodes);

	return 0;
}

static void do_recovery_work(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work, work);

	dprintf("%u\n", rw->epoch);

	if (!sys->nr_copies)
		return;

	if (rw->cur_nr_nodes == 0)
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
		if (next_rw) {
			/* skip the previous epoch recovery */
			free(next_rw->oids);
			free(next_rw);
		}
		next_rw = rw;
	} else {
		recovering_work = rw;
		queue_work(sys->recovery_wqueue, &rw->work);
	}

	return 0;
}
