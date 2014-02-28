/*
 * Copyright (C) 2011 Taobao Inc.
 * Copyright (C) 2013 Zelin.io
 *
 * Liu Yuan <namei.unix@gmail.com>
 * Kai Zhang <kyle@zelin.io>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <pthread.h>

#include "farm.h"
#include "rbtree.h"

static char farm_object_dir[PATH_MAX];
static char farm_dir[PATH_MAX];

static struct sd_rw_lock active_vdi_lock = SD_RW_LOCK_INITIALIZER;
static struct sd_rw_lock registered_vdi_lock = SD_RW_LOCK_INITIALIZER;

struct registered_vdi_entry {
	struct rb_node rb;
	uint32_t vid;
};

struct active_vdi_entry {
	struct rb_node rb;
	char name[SD_MAX_VDI_LEN];
	uint64_t vdi_size;
	uint32_t vdi_id;
	uint32_t snap_id;
	uint8_t  nr_copies;
	uint8_t copy_policy;
	uint8_t store_policy;
};

/* We use active_vdi_tree to create active vdi on top of the snapshot chain */
static struct rb_root active_vdi_tree = RB_ROOT;
/* We have to register vdi information first before loading objects */
static struct rb_root registered_vdi_tree = RB_ROOT;

struct snapshot_work {
	struct trunk_entry entry;
	struct strbuf *trunk_buf;
	struct work work;
};
static struct work_queue *wq;
static uatomic_bool work_error;

static int vdi_cmp(const struct active_vdi_entry *e1,
		   const struct active_vdi_entry *e2)
{
	return strcmp(e1->name, e2->name);
}

static void update_active_vdi_entry(struct active_vdi_entry *vdi,
				    struct sd_inode *new)
{
	pstrcpy(vdi->name, sizeof(vdi->name), new->name);
	vdi->vdi_size = new->vdi_size;
	vdi->vdi_id = new->vdi_id;
	vdi->snap_id = new->snap_id;
	vdi->nr_copies = new->nr_copies;
	vdi->copy_policy = new->copy_policy;
	vdi->store_policy = new->store_policy;
}

static void add_active_vdi(struct sd_inode *new)
{
	struct active_vdi_entry *vdi, *ret;

	vdi = xmalloc(sizeof(struct active_vdi_entry));

	update_active_vdi_entry(vdi, new);
	sd_write_lock(&active_vdi_lock);
	ret = rb_insert(&active_vdi_tree, vdi, rb, vdi_cmp);
	if (ret && ret->snap_id < new->snap_id) {
		update_active_vdi_entry(ret, new);
		free(vdi);
	}
	sd_rw_unlock(&active_vdi_lock);
}

static int registered_vdi_cmp(struct registered_vdi_entry *a,
			      struct registered_vdi_entry *b)
{
	return intcmp(a->vid, b->vid);
}

static bool register_vdi(uint32_t vid)
{
	struct registered_vdi_entry *new = xmalloc(sizeof(*new)), *ret;

	new->vid = vid;

	sd_read_lock(&registered_vdi_lock);
	ret = rb_search(&registered_vdi_tree, new, rb, registered_vdi_cmp);
	sd_rw_unlock(&registered_vdi_lock);
	if (ret) {
		free(new);
		return false;
	}

	sd_write_lock(&registered_vdi_lock);
	rb_insert(&registered_vdi_tree, new, rb, registered_vdi_cmp);
	sd_rw_unlock(&registered_vdi_lock);
	return true;
}

static int create_active_vdis(void)
{
	struct active_vdi_entry *vdi;
	uint32_t new_vid;
	rb_for_each_entry(vdi, &active_vdi_tree, rb) {
		if (do_vdi_create(vdi->name,
				  vdi->vdi_size,
				  vdi->vdi_id, &new_vid,
				  false, vdi->nr_copies,
				  vdi->copy_policy,
				  vdi->store_policy) < 0)
			return -1;
	}
	return 0;
}

char *get_object_directory(void)
{
	return farm_object_dir;
}

static int create_directory(const char *p)
{
	int ret = -1;
	struct strbuf buf = STRBUF_INIT;

	strbuf_addstr(&buf, p);
	if (xmkdir(buf.buf, 0755) < 0) {
		if (errno == EEXIST)
			sd_err("Path is not a directory: %s", p);
		goto out;
	}

	if (!strlen(farm_dir))
		strbuf_copyout(&buf, farm_dir, sizeof(farm_dir));

	strbuf_addstr(&buf, "/objects");
	if (xmkdir(buf.buf, 0755) < 0)
		goto out;

	for (int i = 0; i < 256; i++) {
		strbuf_addf(&buf, "/%02x", i);
		if (xmkdir(buf.buf, 0755) < 0)
			goto out;

		strbuf_remove(&buf, buf.len - 3, 3);
	}

	if (!strlen(farm_object_dir))
		strbuf_copyout(&buf, farm_object_dir, sizeof(farm_object_dir));

	ret = 0;
out:
	if (ret)
		sd_err("Fail to create directory: %m");
	strbuf_release(&buf);
	return ret;
}

static int get_trunk_sha1(uint32_t idx, const char *tag, unsigned char *outsha1)
{
	int nr_logs = -1, ret = -1;
	struct snap_log *log_buf, *log_free = NULL;
	struct snap_file *snap_buf = NULL;

	log_free = log_buf = snap_log_read(&nr_logs);
	if (nr_logs < 0)
		goto out;

	for (int i = 0; i < nr_logs; i++, log_buf++) {
		if (log_buf->idx != idx && strcmp(log_buf->tag, tag))
			continue;
		snap_buf = snap_file_read(log_buf->sha1);
		if (!snap_buf)
			goto out;
		memcpy(outsha1, snap_buf->trunk_sha1, SHA1_DIGEST_SIZE);
		ret = 0;
		goto out;
	}
out:
	free(log_free);
	free(snap_buf);
	return ret;
}

static int notify_vdi_add(uint32_t vdi_id, uint8_t nr_copies,
			  uint8_t copy_policy)
{
	int ret = -1;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	char *buf = NULL;

	sd_init_req(&hdr, SD_OP_NOTIFY_VDI_ADD);
	hdr.vdi_state.new_vid = vdi_id;
	hdr.vdi_state.copies = nr_copies;
	hdr.vdi_state.copy_policy = copy_policy;
	hdr.vdi_state.set_bitmap = true;

	ret = dog_exec_req(&sd_nid, &hdr, buf);

	if (ret < 0)
		sd_err("Fail to notify vdi add event(%"PRIx32", %d)", vdi_id,
		       nr_copies);
	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("%s", sd_strerror(rsp->result));
		ret = -1;
	}

	free(buf);
	return ret;
}

int farm_init(const char *path)
{
	int ret = -1;

	if (create_directory(path) < 0)
		goto out;
	if (snap_init(farm_dir) < 0)
		goto out;
	return 0;
out:
	if (ret)
		sd_err("Fail to init farm.");
	return ret;
}

bool farm_contain_snapshot(uint32_t idx, const char *tag)
{
	unsigned char trunk_sha1[SHA1_DIGEST_SIZE];
	return (get_trunk_sha1(idx, tag, trunk_sha1) == 0);
}

static void do_save_object(struct work *work)
{
	void *buf;
	size_t size;
	struct snapshot_work *sw;

	if (uatomic_is_true(&work_error))
		return;

	sw = container_of(work, struct snapshot_work, work);

	size = get_objsize(sw->entry.oid);
	buf = xmalloc(size);

	if (dog_read_object(sw->entry.oid, buf, size, 0, true) < 0)
		goto error;

	if (slice_write(buf, size, sw->entry.sha1) < 0)
		goto error;

	free(buf);
	return;
error:
	free(buf);
	sd_err("Fail to save object, oid %"PRIx64, sw->entry.oid);
	uatomic_set_true(&work_error);
}

static void farm_show_progress(uint64_t done, uint64_t total)
{
	return show_progress(done, total, true);
}

static void save_object_done(struct work *work)
{
	struct snapshot_work *sw = container_of(work, struct snapshot_work,
						work);
	static unsigned long saved;

	if (uatomic_is_true(&work_error))
		goto out;

	strbuf_add(sw->trunk_buf, &sw->entry, sizeof(struct trunk_entry));
	farm_show_progress(uatomic_add_return(&saved, 1), object_tree_size());
out:
	free(sw);
}

static int queue_save_snapshot_work(uint64_t oid, uint32_t nr_copies,
				    uint8_t copy_policy, void *data)
{
	struct snapshot_work *sw = xzalloc(sizeof(struct snapshot_work));
	struct strbuf *trunk_buf = data;

	sw->entry.oid = oid;
	sw->entry.nr_copies = nr_copies;
	sw->entry.copy_policy = copy_policy;
	sw->trunk_buf = trunk_buf;
	sw->work.fn = do_save_object;
	sw->work.done = save_object_done;
	queue_work(wq, &sw->work);

	return 0;
}

int farm_save_snapshot(const char *tag)
{
	unsigned char snap_sha1[SHA1_DIGEST_SIZE];
	unsigned char trunk_sha1[SHA1_DIGEST_SIZE];
	struct strbuf trunk_buf;
	void *snap_log = NULL;
	int log_nr, idx, ret = -1;
	uint64_t nr_objects = object_tree_size();

	snap_log = snap_log_read(&log_nr);
	if (!snap_log)
		goto out;

	idx = log_nr + 1;

	strbuf_init(&trunk_buf, sizeof(struct trunk_entry) * nr_objects);

	wq = create_work_queue("save snapshot", WQ_ORDERED);
	if (for_each_object_in_tree(queue_save_snapshot_work,
				    &trunk_buf) < 0)
		goto out;

	work_queue_wait(wq);
	if (uatomic_is_true(&work_error))
		goto out;

	if (trunk_file_write(nr_objects, (struct trunk_entry *)trunk_buf.buf,
			     trunk_sha1) < 0)
		goto out;

	if (snap_file_write(idx, trunk_sha1, snap_sha1) < 0)
		goto out;

	if (snap_log_write(idx, tag, snap_sha1) < 0)
		goto out;

	ret = 0;
out:
	strbuf_release(&trunk_buf);
	free(snap_log);
	return ret;
}

static void do_load_object(struct work *work)
{
	void *buffer = NULL;
	size_t size;
	struct snapshot_work *sw;
	static unsigned long loaded;
	uint32_t vid;

	if (uatomic_is_true(&work_error))
		return;

	sw = container_of(work, struct snapshot_work, work);

	buffer = slice_read(sw->entry.sha1, &size);

	if (!buffer)
		goto error;

	vid = oid_to_vid(sw->entry.oid);
	if (register_vdi(vid)) {
		if (notify_vdi_add(vid, sw->entry.nr_copies,
				   sw->entry.copy_policy) < 0)
			goto error;
	}

	if (dog_write_object(sw->entry.oid, 0, buffer, size, 0, 0,
			     sw->entry.nr_copies, sw->entry.copy_policy,
			     true, true) != 0)
		goto error;

	if (is_vdi_obj(sw->entry.oid))
		add_active_vdi(buffer);

	farm_show_progress(uatomic_add_return(&loaded, 1), trunk_get_count());
	free(buffer);
	return;
error:
	free(buffer);
	sd_err("Fail to load object, oid %"PRIx64, sw->entry.oid);
	uatomic_set_true(&work_error);
}

static void load_object_done(struct work *work)
{
	struct snapshot_work *sw = container_of(work, struct snapshot_work,
						work);

	free(sw);
}

static int queue_load_snapshot_work(struct trunk_entry *entry, void *data)
{
	struct snapshot_work *sw = xzalloc(sizeof(struct snapshot_work));

	memcpy(&sw->entry, entry, sizeof(struct trunk_entry));
	sw->work.fn = do_load_object;
	sw->work.done = load_object_done;
	queue_work(wq, &sw->work);

	return 0;
}

int farm_load_snapshot(uint32_t idx, const char *tag)
{
	int ret = -1;
	unsigned char trunk_sha1[SHA1_DIGEST_SIZE];

	if (get_trunk_sha1(idx, tag, trunk_sha1) < 0)
		goto out;

	wq = create_work_queue("load snapshot", WQ_DYNAMIC);
	if (for_each_entry_in_trunk(trunk_sha1, queue_load_snapshot_work,
				    NULL) < 0)
		goto out;

	work_queue_wait(wq);
	if (uatomic_is_true(&work_error))
		goto out;

	if (create_active_vdis() < 0)
		goto out;

	ret = 0;
out:
	rb_destroy(&active_vdi_tree, struct active_vdi_entry, rb);
	rb_destroy(&registered_vdi_tree, struct registered_vdi_entry, rb);
	return ret;
}
