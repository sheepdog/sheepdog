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

#include "farm.h"
#include "list.h"

static char farm_object_dir[PATH_MAX];
static char farm_dir[PATH_MAX];

struct vdi_entry {
	char name[SD_MAX_VDI_LEN];
	uint64_t vdi_size;
	uint32_t vdi_id;
	uint32_t snap_id;
	uint8_t  nr_copies;
	struct list_head list;
};
static LIST_HEAD(last_vdi_list);

static struct vdi_entry *find_vdi(const char *name)
{
	struct vdi_entry *vdi;

	list_for_each_entry(vdi, &last_vdi_list, list) {
		if (!strcmp(vdi->name, name))
			return vdi;
	}
	return NULL;
}

static struct vdi_entry *new_vdi(const char *name, uint64_t vdi_size,
				 uint32_t vdi_id, uint32_t snap_id,
				 uint8_t nr_copies)
{
	struct vdi_entry *vdi;
	vdi = xmalloc(sizeof(struct vdi_entry));
	pstrcpy(vdi->name, sizeof(vdi->name), name);
	vdi->vdi_size = vdi_size;
	vdi->vdi_id = vdi_id;
	vdi->snap_id = snap_id;
	vdi->nr_copies = nr_copies;
	INIT_LIST_HEAD(&vdi->list);
	return vdi;
}

static void insert_vdi(struct sd_inode *new)
{
	struct vdi_entry *vdi;
	vdi = find_vdi(new->name);
	if (!vdi) {
		vdi = new_vdi(new->name,
			      new->vdi_size,
			      new->vdi_id,
			      new->snap_id,
			      new->nr_copies);
		list_add(&vdi->list, &last_vdi_list);
	} else if (vdi->snap_id < new->snap_id) {
		vdi->vdi_size = new->vdi_size;
		vdi->vdi_id = new->vdi_id;
		vdi->snap_id = new->snap_id;
		vdi->nr_copies = new->nr_copies;
	}
}

static int create_active_vdis(void)
{
	struct vdi_entry *vdi;
	uint32_t new_vid;
	list_for_each_entry(vdi, &last_vdi_list, list) {
		if (do_vdi_create(vdi->name,
				  vdi->vdi_size,
				  vdi->vdi_id, &new_vid,
				  false, vdi->nr_copies) < 0)
			return -1;
	}
	return 0;
}

static void free_vdi_list(void)
{
	struct vdi_entry *vdi, *next;
	list_for_each_entry_safe(vdi, next, &last_vdi_list, list)
		free(vdi);
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
			fprintf(stderr, "Path is not a directory: %s\n", p);
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
		fprintf(stderr, "Fail to create directory: %m\n");
	strbuf_release(&buf);
	return ret;
}

static int get_trunk_sha1(uint32_t idx, const char *tag, unsigned char *outsha1)
{
	int nr_logs = -1, ret = -1;
	struct snap_log *log_buf, *log_free = NULL;
	void *snap_buf = NULL;
	struct sha1_file_hdr hdr;

	log_free = log_buf = snap_log_read(&nr_logs);
	if (nr_logs < 0)
		goto out;

	for (int i = 0; i < nr_logs; i++, log_buf++) {
		if (log_buf->idx != idx && strcmp(log_buf->tag, tag))
			continue;
		snap_buf = snap_file_read(log_buf->sha1, &hdr);
		if (!snap_buf)
			goto out;
		memcpy(outsha1, snap_buf, SHA1_LEN);
		ret = 0;
		goto out;
	}
out:
	free(log_free);
	free(snap_buf);
	return ret;
}

static int notify_vdi_add(uint32_t vdi_id, uint32_t nr_copies)
{
	int ret = -1;
	struct sd_req hdr;
	char *buf = NULL;

	sd_init_req(&hdr, SD_OP_NOTIFY_VDI_ADD);
	hdr.vdi_state.new_vid = vdi_id;
	hdr.vdi_state.copies = nr_copies;
	hdr.vdi_state.set_bitmap = true;

	ret = collie_exec_req(sdhost, sdport, &hdr, buf);

	if (ret)
		fprintf(stderr, "Fail to notify vdi add event(%"PRIx32", %d)\n",
			vdi_id, nr_copies);

	free(buf);
	return ret;
}

static int fill_trunk_entry(uint64_t oid, int nr_copies,
			    void *buf, size_t size, void *data)
{
	int ret = -1;

	struct strbuf *trunk_entries = data;
	struct trunk_entry new_entry = {};
	struct sha1_file_hdr hdr = { .priv = 0 };
	struct strbuf object_strbuf = STRBUF_INIT;

	memcpy(hdr.tag, TAG_DATA, TAG_LEN);
	hdr.size = size;

	strbuf_add(&object_strbuf, buf, size);
	strbuf_insert(&object_strbuf, 0, &hdr, sizeof(hdr));

	if (sha1_file_write((void *)object_strbuf.buf,
			    object_strbuf.len,
			    new_entry.sha1) != 0)
		goto out;

	new_entry.oid = oid;
	new_entry.nr_copies = nr_copies;
	strbuf_add(trunk_entries, &new_entry, sizeof(struct trunk_entry));

	ret = 0;
out:
	if (ret)
		fprintf(stderr, "Fail to fill trunk entry\n.");
	strbuf_release(&object_strbuf);
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
		fprintf(stderr, "Fail to init farm.\n");
	return ret;
}

bool farm_contain_snapshot(uint32_t idx, const char *tag)
{
	unsigned char trunk_sha1[SHA1_LEN];
	return (get_trunk_sha1(idx, tag, trunk_sha1) == 0);
}

int farm_save_snapshot(const char *tag)
{
	unsigned char snap_sha1[SHA1_LEN];
	unsigned char trunk_sha1[SHA1_LEN];
	struct strbuf trunk_entries = STRBUF_INIT;
	void *snap_log = NULL;
	int log_nr, idx;
	int ret = -1;

	snap_log = snap_log_read(&log_nr);
	if (!snap_log)
		goto out;

	idx = log_nr + 1;

	if (for_each_object_in_tree(fill_trunk_entry, &trunk_entries) < 0)
		goto out;

	if (trunk_file_write(trunk_sha1, &trunk_entries) < 0)
		goto out;

	if (snap_file_write(idx, trunk_sha1, snap_sha1) < 0)
		goto out;

	if (snap_log_write(idx, tag, snap_sha1) != 0)
		goto out;

	ret = 0;
out:
	free(snap_log);
	strbuf_release(&trunk_entries);
	return ret;
}

static int restore_object(uint64_t oid, int nr_copies,
			void *buffer, size_t size, void *data)
{
	int ret = -1;

	if (sd_write_object(oid, 0, buffer, size, 0, 0,
			    nr_copies, true, true) != 0)
		goto out;

	if (is_vdi_obj(oid)) {
		if (notify_vdi_add(oid_to_vid(oid), nr_copies) < 0)
			goto out;

		insert_vdi(buffer);
	}

	ret = 0;
out:
	if (ret)
		fprintf(stderr, "Fail to restore object, oid %"PRIu64"\n", oid);
	return 0;
}

int farm_load_snapshot(uint32_t idx, const char *tag)
{
	int ret = -1;
	unsigned char trunk_sha1[SHA1_LEN];

	if (get_trunk_sha1(idx, tag, trunk_sha1) < 0)
		goto out;

	if (for_each_object_in_trunk(trunk_sha1, restore_object, NULL) < 0)
		goto out;

	if (create_active_vdis() < 0)
		goto out;

	ret = 0;
out:
	free_vdi_list();
	return ret;
}
