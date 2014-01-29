/*
 * Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "dog.h"
#include "treeview.h"
#include "sha1.h"
#include "fec.h"

static struct sd_option vdi_options[] = {
	{'P', "prealloc", false, "preallocate all the data objects"},
	{'i', "index", true, "specify the index of data objects"},
	{'s', "snapshot", true, "specify a snapshot id or tag name"},
	{'x', "exclusive", false, "write in an exclusive mode"},
	{'d', "delete", false, "delete a key"},
	{'w', "writeback", false, "use writeback mode"},
	{'c', "copies", true, "specify the data redundancy level"},
	{'F', "from", true, "create a differential backup from the snapshot"},
	{'f', "force", false, "do operation forcibly"},
	{'y', "hyper", false, "create a hyper volume"},
	{'o', "oid", true, "specify the object id of the tracking object"},
	{ 0, NULL, false, NULL },
};

static struct vdi_cmd_data {
	uint64_t index;
	int snapshot_id;
	char snapshot_tag[SD_MAX_VDI_TAG_LEN];
	bool exclusive;
	bool delete;
	bool prealloc;
	int nr_copies;
	bool writeback;
	int from_snapshot_id;
	char from_snapshot_tag[SD_MAX_VDI_TAG_LEN];
	bool force;
	uint8_t copy_policy;
	uint8_t store_policy;
	uint64_t oid;
} vdi_cmd_data = { ~0, };

struct get_vdi_info {
	const char *name;
	const char *tag;
	uint32_t vid;
	uint32_t snapid;
	uint8_t nr_copies;
	uint8_t copy_policy;
};

int dog_bnode_writer(uint64_t oid, void *mem, unsigned int len, uint64_t offset,
		     uint32_t flags, int copies, int copy_policy, bool create,
		     bool direct)
{
	return dog_write_object(oid, 0, mem, len, offset, flags, copies,
			       copy_policy, create, direct);
}

int dog_bnode_reader(uint64_t oid, void **mem, unsigned int len,
		     uint64_t offset)
{
	return dog_read_object(oid, *mem, len, offset, true);
}

static inline bool is_data_obj_writeable(const struct sd_inode *inode,
					 uint32_t idx)
{
	return inode->vdi_id == INODE_GET_VID(inode, idx);
}

static void vdi_show_progress(uint64_t done, uint64_t total)
{
	return show_progress(done, total, false);
}

struct stat_arg {
	uint64_t *my;
	uint64_t *cow;
	uint32_t vid;
};

static void stat_cb(void *data, enum btree_node_type type, void *arg)
{
	struct sd_extent *ext;
	struct stat_arg *sarg = arg;
	uint64_t *my = sarg->my;
	uint64_t *cow = sarg->cow;

	if (type == BTREE_EXT) {
		ext = (struct sd_extent *)data;
		if (ext->vdi_id == sarg->vid)
			(*my)++;
		else if (ext->vdi_id != 0)
			(*cow)++;
	}
}

static void stat_data_objs_btree(const struct sd_inode *inode,
				 uint64_t *my_objs, uint64_t *cow_objs)
{
	struct stat_arg arg = {my_objs, cow_objs, inode->vdi_id};
	traverse_btree(dog_bnode_reader, inode, stat_cb, &arg);
}

static void stat_data_objs_array(const struct sd_inode *inode,
				 uint64_t *my_objs, uint64_t *cow_objs)
{
	int nr;
	uint64_t my, cow, *p;
	uint32_t vid = inode->vdi_id;

	my = 0;
	cow = 0;
	nr = count_data_objs(inode);

	if (nr % 2 != 0) {
		if (is_data_obj_writeable(inode, 0))
			my++;
		else if (inode->data_vdi_id[0] != 0)
			cow++;
		p = (uint64_t *)(inode->data_vdi_id + 1);
	} else
		p = (uint64_t *)inode->data_vdi_id;

	/*
	 * To boost performance, this function checks data_vdi_id for each 64
	 * bit integer.
	 */
	nr /= 2;
	for (int i = 0; i < nr; i++) {
		if (p[i] == 0)
			continue;
		if (p[i] == (((uint64_t)vid << 32) | vid)) {
			my += 2;
			continue;
		}

		/* Check the higher 32 bit */
		if (p[i] >> 32 == vid)
			my++;
		else if ((p[i] & 0xFFFFFFFF00000000) != 0)
			cow++;

		/* Check the lower 32 bit */
		if ((p[i] & 0xFFFFFFFF) == vid)
			my++;
		else if ((p[i] & 0xFFFFFFFF) != 0)
			cow++;
	}

	*my_objs = my;
	*cow_objs = cow;
}

/*
 * Get the number of objects.
 *
 * 'my_objs' means the number objects which belongs to this vdi.  'cow_objs'
 * means the number of the other objects.
 */
static void stat_data_objs(const struct sd_inode *inode, uint64_t *my_objs,
			   uint64_t *cow_objs)
{
	if (inode->store_policy == 0)
		stat_data_objs_array(inode, my_objs, cow_objs);
	else
		stat_data_objs_btree(inode, my_objs, cow_objs);
}

static char *redundancy_scheme(uint8_t copy_nr, uint8_t policy)
{
	static char str[10];

	if (policy > 0) {
		int d, p;
		ec_policy_to_dp(policy, &d, &p);
		snprintf(str, sizeof(str), "%d:%d", d, p);
	} else {
		snprintf(str, sizeof(str), "%d", copy_nr);
	}
	return str;
}

static void print_vdi_list(uint32_t vid, const char *name, const char *tag,
			   uint32_t snapid, uint32_t flags,
			   const struct sd_inode *i, void *data)
{
	bool is_clone = false;
	uint64_t my_objs = 0, cow_objs = 0;
	time_t ti;
	struct tm tm;
	char dbuf[128];
	struct get_vdi_info *info = data;

	if (info && strcmp(name, info->name) != 0)
		return;

	ti = i->create_time >> 32;
	if (raw_output) {
		snprintf(dbuf, sizeof(dbuf), "%" PRIu64, (uint64_t) ti);
	} else {
		localtime_r(&ti, &tm);
		strftime(dbuf, sizeof(dbuf),
			 "%Y-%m-%d %H:%M", &tm);
	}

	stat_data_objs(i, &my_objs, &cow_objs);

	if (i->snap_id == 1 && i->parent_vdi_id != 0)
		is_clone = true;

	if (raw_output) {
		printf("%c ", vdi_is_snapshot(i) ? 's' : (is_clone ? 'c' : '='));
		while (*name) {
			if (isspace(*name) || *name == '\\')
				putchar('\\');
			putchar(*name++);
		}
		printf(" %d %s %s %s %s %" PRIx32 " %s %s\n", snapid,
		       strnumber(i->vdi_size),
		       strnumber(my_objs * SD_DATA_OBJ_SIZE),
		       strnumber(cow_objs * SD_DATA_OBJ_SIZE),
		       dbuf, vid,
		       redundancy_scheme(i->nr_copies, i->copy_policy),
		       i->tag);
	} else {
		printf("%c %-8s %5d %7s %7s %7s %s  %7" PRIx32 " %6s %13s\n",
		       vdi_is_snapshot(i) ? 's' : (is_clone ? 'c' : ' '),
		       name, snapid,
		       strnumber(i->vdi_size),
		       strnumber(my_objs * SD_DATA_OBJ_SIZE),
		       strnumber(cow_objs * SD_DATA_OBJ_SIZE),
		       dbuf, vid,
		       redundancy_scheme(i->nr_copies, i->copy_policy),
		       i->tag);
	}
}

static void print_vdi_tree(uint32_t vid, const char *name, const char *tag,
			   uint32_t snapid, uint32_t flags,
			   const struct sd_inode *i, void *data)
{
	time_t ti;
	struct tm tm;
	char buf[128];

	if (vdi_is_snapshot(i)) {
		ti = i->create_time >> 32;
		localtime_r(&ti, &tm);

		strftime(buf, sizeof(buf),
			 "[%Y-%m-%d %H:%M]", &tm);
	} else
		pstrcpy(buf, sizeof(buf), "(you are here)");

	add_vdi_tree(name, buf, vid, i->parent_vdi_id,
		     highlight && !vdi_is_snapshot(i));
}

static void print_vdi_graph(uint32_t vid, const char *name, const char *tag,
			    uint32_t snapid, uint32_t flags,
			    const struct sd_inode *i, void *data)
{
	time_t ti;
	struct tm tm;
	char dbuf[128], tbuf[128];

	ti = i->create_time >> 32;
	localtime_r(&ti, &tm);

	strftime(dbuf, sizeof(dbuf), "%Y-%m-%d", &tm);
	strftime(tbuf, sizeof(tbuf), "%H:%M:%S", &tm);

	printf("  \"%x\" -> \"%x\";\n", i->parent_vdi_id, vid);
	printf("  \"%x\" [\n"
	       "    group = \"%s\",\n"
	       "    label = \"",
	       vid, name);
	printf("Name: %10s\\n"
	       "Tag:  %10x\\n"
	       "Size: %10s\\n"
	       "Date: %10s\\n"
	       "Time: %10s",
	       name, snapid, strnumber(i->vdi_size), dbuf, tbuf);

	if (vdi_is_snapshot(i))
		printf("\"\n  ];\n\n");
	else
		printf("\",\n    color=\"red\"\n  ];\n\n");

}

static void vdi_info_filler(uint32_t vid, const char *name, const char *tag,
			    uint32_t snapid, uint32_t flags,
			    const struct sd_inode *i, void *data)
{
	struct get_vdi_info *info = data;

	if (info->name) {
		if (info->tag && info->tag[0]) {
			if (!strcmp(name, info->name) &&
			    !strcmp(tag, info->tag)) {
				info->vid = vid;
			info->nr_copies = i->nr_copies;
			info->copy_policy = i->copy_policy;
			}
		} else if (info->snapid) {
			if (!strcmp(name, info->name) &&
			    snapid == info->snapid) {
				info->vid = vid;
				info->nr_copies = i->nr_copies;
				info->copy_policy = i->copy_policy;
			}
		} else {
			if (!strcmp(name, info->name)) {
				info->vid = vid;
				info->nr_copies = i->nr_copies;
				info->copy_policy = i->copy_policy;
			}
		}
	}
}

typedef int (*obj_parser_func_t)(const char *sheep, uint64_t oid,
				 struct sd_rsp *rsp, char *buf, void *data);

static int do_print_obj(const char *sheep, uint64_t oid, struct sd_rsp *rsp,
			char *buf, void *data)
{
	switch (rsp->result) {
	case SD_RES_SUCCESS:
		printf("%s has the object\n", sheep);
		break;
	case SD_RES_NO_OBJ:
		printf("%s doesn't have the object\n", sheep);
		break;
	case SD_RES_OLD_NODE_VER:
	case SD_RES_NEW_NODE_VER:
		sd_err("The node list has changed: please try again");
		break;
	default:
		sd_err("%s: hit an unexpected error (%s)", sheep,
		       sd_strerror(rsp->result));
		break;
	}

	return 0;
}

struct obj_info_filler_info {
	bool success;
	uint64_t data_oid;
	unsigned idx;
};

static int obj_info_filler(const char *sheep, uint64_t oid, struct sd_rsp *rsp,
			   char *buf, void *data)
{
	struct obj_info_filler_info *info = data;
	struct sd_inode *inode = (struct sd_inode *)buf;
	uint32_t vdi_id;

	switch (rsp->result) {
	case SD_RES_SUCCESS:
		if (info->success)
			break;
		info->success = true;
		vdi_id = INODE_GET_VID(inode, info->idx);
		if (vdi_id) {
			info->data_oid = vid_to_data_oid(vdi_id, info->idx);
			return 1;
		}
		break;
	case SD_RES_NO_OBJ:
		break;
	case SD_RES_OLD_NODE_VER:
	case SD_RES_NEW_NODE_VER:
		sd_err("The node list has changed: please try again");
		break;
	default:
		sd_err("%s: hit an unexpected error (%s)", sheep,
		       sd_strerror(rsp->result));
		break;
	}

	return 0;
}

static void parse_objs(uint64_t oid, obj_parser_func_t func, void *data,
		       size_t size)
{
	int ret, cb_ret;
	struct sd_node *n;
	char *buf;

	buf = xzalloc(size);
	rb_for_each_entry(n, &sd_nroot, rb) {
		struct sd_req hdr;
		struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

		sd_init_req(&hdr, SD_OP_READ_PEER);
		hdr.data_length = size;
		hdr.flags = 0;
		hdr.epoch = sd_epoch;
		hdr.obj.oid = oid;
		hdr.obj.ec_index = SD_MAX_COPIES + 1; /* Ignore index */

		ret = dog_exec_req(&n->nid, &hdr, buf);
		if (ret < 0)
			continue;
		switch (rsp->result) {
			sd_err("%s", sd_strerror(rsp->result));
			continue;
		}

		cb_ret = func(addr_to_str(n->nid.addr, n->nid.port),
			      oid, rsp, buf, data);
		if (cb_ret)
			break;
	}

	free(buf);
}


static int vdi_list(int argc, char **argv)
{
	const char *vdiname = argv[optind];

	if (!raw_output)
		printf("  Name        Id    Size    Used  Shared    Creation time   VDI id  Copies  Tag\n");

	if (vdiname) {
		struct get_vdi_info info;
		memset(&info, 0, sizeof(info));
		info.name = vdiname;
		if (parse_vdi(print_vdi_list, SD_INODE_SIZE, &info) < 0)
			return EXIT_SYSFAIL;
		return EXIT_SUCCESS;
	} else {
		if (parse_vdi(print_vdi_list, SD_INODE_SIZE, NULL) < 0)
			return EXIT_SYSFAIL;
		return EXIT_SUCCESS;
	}
}

static int vdi_tree(int argc, char **argv)
{
	init_tree();
	if (parse_vdi(print_vdi_tree, SD_INODE_HEADER_SIZE, NULL) < 0)
		return EXIT_SYSFAIL;
	dump_tree();

	return EXIT_SUCCESS;
}

static int vdi_graph(int argc, char **argv)
{
	/* print a header */
	printf("digraph G {\n");
	printf("  node [shape = \"box\", fontname = \"Courier\"];\n\n");
	printf("  \"0\" [shape = \"ellipse\", label = \"root\"];\n\n");

	if (parse_vdi(print_vdi_graph, SD_INODE_HEADER_SIZE, NULL) < 0)
		return EXIT_SYSFAIL;

	/* print a footer */
	printf("}\n");

	return EXIT_SUCCESS;
}

static int find_vdi_name(const char *vdiname, uint32_t snapid, const char *tag,
			 uint32_t *vid, int for_snapshot)
{
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	char buf[SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN];

	memset(buf, 0, sizeof(buf));
	pstrcpy(buf, SD_MAX_VDI_LEN, vdiname);
	if (tag)
		pstrcpy(buf + SD_MAX_VDI_LEN, SD_MAX_VDI_TAG_LEN, tag);

	if (for_snapshot)
		sd_init_req(&hdr, SD_OP_GET_VDI_INFO);
	else
		sd_init_req(&hdr, SD_OP_LOCK_VDI);
	hdr.data_length = SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN;
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.vdi.snapid = snapid;

	ret = dog_exec_req(&sd_nid, &hdr, buf);
	if (ret < 0)
		return -1;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Cannot get VDI info for %s %d %s: %s", vdiname, snapid,
		       tag, sd_strerror(rsp->result));
		return -1;
	}
	*vid = rsp->vdi.vdi_id;

	return 0;
}

static int read_vdi_obj(const char *vdiname, int snapid, const char *tag,
			uint32_t *pvid, struct sd_inode *inode,
			size_t size)
{
	int ret;
	uint32_t vid;

	ret = find_vdi_name(vdiname, snapid, tag, &vid, 0);
	if (ret < 0) {
		sd_err("Failed to open VDI %s", vdiname);
		return EXIT_FAILURE;
	}

	ret = dog_read_object(vid_to_vdi_oid(vid), inode, size, 0, true);
	if (ret != SD_RES_SUCCESS) {
		if (snapid) {
			sd_err("Failed to read a snapshot %s:%d", vdiname,
			       snapid);
		} else if (tag && tag[0]) {
			sd_err("Failed to read a snapshot %s:%s", vdiname, tag);
		} else {
			sd_err("Failed to read a vdi %s", vdiname);
		}
		return EXIT_FAILURE;
	}

	if (pvid)
		*pvid = vid;

	return EXIT_SUCCESS;
}

int do_vdi_create(const char *vdiname, int64_t vdi_size,
		  uint32_t base_vid, uint32_t *vdi_id, bool snapshot,
		  uint8_t nr_copies, uint8_t copy_policy, uint8_t store_policy)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret;
	char buf[SD_MAX_VDI_LEN];

	memset(buf, 0, sizeof(buf));
	pstrcpy(buf, SD_MAX_VDI_LEN, vdiname);

	sd_init_req(&hdr, SD_OP_NEW_VDI);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = SD_MAX_VDI_LEN;

	hdr.vdi.base_vdi_id = base_vid;
	hdr.vdi.snapid = snapshot ? 1 : 0;
	hdr.vdi.vdi_size = vdi_size;
	hdr.vdi.copies = nr_copies;
	hdr.vdi.copy_policy = copy_policy;
	hdr.vdi.store_policy = store_policy;

	ret = dog_exec_req(&sd_nid, &hdr, buf);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Failed to create VDI %s: %s", vdiname,
		       sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	if (vdi_id)
		*vdi_id = rsp->vdi.vdi_id;

	return EXIT_SUCCESS;
}

static int vdi_create(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	uint64_t size;
	uint32_t vid;
	uint64_t oid;
	uint32_t idx, max_idx;
	struct sd_inode *inode = NULL;
	int ret;

	if (!argv[optind]) {
		sd_err("Please specify the VDI size");
		return EXIT_USAGE;
	}
	ret = option_parse_size(argv[optind], &size);
	if (ret < 0)
		return EXIT_USAGE;

	if (size > SD_OLD_MAX_VDI_SIZE && 0 == vdi_cmd_data.store_policy) {
		sd_err("VDI size is larger than %s bytes, please use '-y' to "
		       "create a hyper volume with size up to %s bytes",
		       strnumber(SD_OLD_MAX_VDI_SIZE),
		       strnumber(SD_MAX_VDI_SIZE));
		return EXIT_USAGE;
	}

	if (size > SD_MAX_VDI_SIZE) {
		sd_err("VDI size is too large");
		return EXIT_USAGE;
	}

	ret = do_vdi_create(vdiname, size, 0, &vid, false,
			    vdi_cmd_data.nr_copies, vdi_cmd_data.copy_policy,
			    vdi_cmd_data.store_policy);
	if (ret != EXIT_SUCCESS || !vdi_cmd_data.prealloc)
		goto out;

	inode = xmalloc(sizeof(*inode));

	ret = dog_read_object(vid_to_vdi_oid(vid), inode, sizeof(*inode), 0,
			      true);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to read a newly created VDI object");
		ret = EXIT_FAILURE;
		goto out;
	}
	max_idx = DIV_ROUND_UP(size, SD_DATA_OBJ_SIZE);

	for (idx = 0; idx < max_idx; idx++) {
		vdi_show_progress(idx * SD_DATA_OBJ_SIZE, inode->vdi_size);
		oid = vid_to_data_oid(vid, idx);

		ret = dog_write_object(oid, 0, NULL, 0, 0, 0, inode->nr_copies,
				      inode->copy_policy, true, true);
		if (ret != SD_RES_SUCCESS) {
			ret = EXIT_FAILURE;
			goto out;
		}

		INODE_SET_VID(inode, idx, vid);
		ret = sd_inode_write_vid(dog_bnode_writer, inode, idx, vid, vid,
					 0, false, true);
		if (ret) {
			ret = EXIT_FAILURE;
			goto out;
		}
	}
	vdi_show_progress(idx * SD_DATA_OBJ_SIZE, inode->vdi_size);
	ret = EXIT_SUCCESS;

out:
	if (ret == EXIT_SUCCESS && verbose) {
		if (raw_output)
			printf("%x\n", vid);
		else
			printf("VDI ID of newly created VDI: %x\n", vid);
	}

	free(inode);
	return ret;
}

static int vdi_snapshot(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	uint32_t vid;
	int ret;
	char buf[SD_INODE_HEADER_SIZE];
	struct sd_inode *inode = (struct sd_inode *)buf;

	if (vdi_cmd_data.snapshot_id != 0) {
		sd_err("Please specify a non-integer value for "
		       "a snapshot tag name");
		return EXIT_USAGE;
	}

	ret = read_vdi_obj(vdiname, 0, "", &vid, inode, SD_INODE_HEADER_SIZE);
	if (ret != EXIT_SUCCESS)
		return ret;

	ret = dog_write_object(vid_to_vdi_oid(vid), 0,
			       vdi_cmd_data.snapshot_tag,
			       SD_MAX_VDI_TAG_LEN,
			       offsetof(struct sd_inode, tag),
			       0, inode->nr_copies, inode->copy_policy,
			       false, false);
	if (ret != SD_RES_SUCCESS)
		return EXIT_FAILURE;

	ret = do_vdi_create(vdiname, inode->vdi_size, vid, NULL, true,
			    inode->nr_copies, inode->copy_policy,
			    inode->store_policy);

	if (ret == EXIT_SUCCESS && verbose) {
		if (raw_output)
			printf("%x\n", vid);
		else
			printf("VDI ID of newly created snapshot: %x\n", vid);
	}

	return ret;
}

static int vdi_clone(int argc, char **argv)
{
	const char *src_vdi = argv[optind++], *dst_vdi;
	uint32_t base_vid, new_vid, vdi_id;
	uint64_t oid;
	uint32_t idx, max_idx, ret;
	struct sd_inode *inode = NULL, *new_inode = NULL;
	char *buf = NULL;

	dst_vdi = argv[optind];
	if (!dst_vdi) {
		sd_err("Destination VDI name must be specified");
		ret = EXIT_USAGE;
		goto out;
	}

	if (!vdi_cmd_data.snapshot_id && !vdi_cmd_data.snapshot_tag[0]) {
		sd_err("Only snapshot VDIs can be cloned");
		sd_err("Please specify the '-s' option");
		ret = EXIT_USAGE;
		goto out;
	}

	inode = xmalloc(sizeof(*inode));

	ret = read_vdi_obj(src_vdi, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, &base_vid, inode,
			   SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	ret = do_vdi_create(dst_vdi, inode->vdi_size, base_vid, &new_vid, false,
			    vdi_cmd_data.nr_copies, inode->copy_policy,
			    inode->store_policy);
	if (ret != EXIT_SUCCESS || !vdi_cmd_data.prealloc)
		goto out;

	new_inode = xmalloc(sizeof(*inode));
	ret = read_vdi_obj(dst_vdi, 0, "", NULL, new_inode,
			SD_INODE_HEADER_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	buf = xzalloc(SD_DATA_OBJ_SIZE);
	max_idx = count_data_objs(inode);

	for (idx = 0; idx < max_idx; idx++) {
		size_t size;

		vdi_show_progress(idx * SD_DATA_OBJ_SIZE, inode->vdi_size);
		vdi_id = INODE_GET_VID(inode, idx);
		if (vdi_id) {
			oid = vid_to_data_oid(vdi_id, idx);
			ret = dog_read_object(oid, buf, SD_DATA_OBJ_SIZE, 0,
					      true);
			if (ret) {
				ret = EXIT_FAILURE;
				goto out;
			}
			size = SD_DATA_OBJ_SIZE;
		} else
			size = 0;

		oid = vid_to_data_oid(new_vid, idx);
		ret = dog_write_object(oid, 0, buf, size, 0, 0,
				       inode->nr_copies,
				       inode->copy_policy, true, true);
		if (ret != SD_RES_SUCCESS) {
			ret = EXIT_FAILURE;
			goto out;
		}

		INODE_SET_VID(new_inode, idx, new_vid);
		ret = sd_inode_write_vid(dog_bnode_writer, new_inode, idx,
					 new_vid, new_vid, 0, false, true);
		if (ret) {
			ret = EXIT_FAILURE;
			goto out;
		}
	}
	vdi_show_progress(idx * SD_DATA_OBJ_SIZE, inode->vdi_size);
	ret = EXIT_SUCCESS;

out:
	if (ret == EXIT_SUCCESS && verbose) {
		if (raw_output)
			printf("%x\n", new_vid);
		else
			printf("VDI ID of newly created clone: %x\n", new_vid);
	}

	free(inode);
	if (new_inode)
		free(new_inode);
	free(buf);
	return ret;
}

static int vdi_resize(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	uint64_t new_size;
	uint32_t vid;
	int ret;
	char buf[SD_INODE_HEADER_SIZE];
	struct sd_inode *inode = (struct sd_inode *)buf;

	if (!argv[optind]) {
		sd_err("Please specify the new size for the VDI");
		return EXIT_USAGE;
	}
	ret = option_parse_size(argv[optind], &new_size);
	if (ret < 0)
		return EXIT_USAGE;

	ret = read_vdi_obj(vdiname, 0, "", &vid, inode, SD_INODE_HEADER_SIZE);
	if (ret != EXIT_SUCCESS)
		return ret;

	if (new_size > SD_OLD_MAX_VDI_SIZE && 0 == inode->store_policy) {
		sd_err("New VDI size is too large");
		return EXIT_USAGE;
	}

	if (new_size > SD_MAX_VDI_SIZE) {
		sd_err("New VDI size is too large");
		return EXIT_USAGE;
	}

	if (new_size < inode->vdi_size) {
		sd_err("Shrinking VDIs is not implemented");
		return EXIT_USAGE;
	}
	inode->vdi_size = new_size;

	ret = dog_write_object(vid_to_vdi_oid(vid), 0,
			      inode, SD_INODE_HEADER_SIZE, 0,
			      0, inode->nr_copies, inode->copy_policy,
			      false, true);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to update an inode header");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int do_vdi_delete(const char *vdiname, int snap_id, const char *snap_tag)
{
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	char data[SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN];
	uint32_t vid;

	ret = find_vdi_name(vdiname, snap_id, snap_tag, &vid, 0);
	if (ret < 0) {
		sd_err("Failed to open VDI %s", vdiname);
		return EXIT_FAILURE;
	}

	sd_init_req(&hdr, SD_OP_DELETE_CACHE);
	hdr.obj.oid = vid_to_vdi_oid(vid);

	ret = send_light_req(&sd_nid, &hdr);
	if (ret) {
		sd_err("failed to execute request");
		return EXIT_FAILURE;
	}

	sd_init_req(&hdr, SD_OP_DEL_VDI);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = sizeof(data);
	hdr.vdi.snapid = snap_id;
	memset(data, 0, sizeof(data));
	pstrcpy(data, SD_MAX_VDI_LEN, vdiname);
	if (snap_tag)
		pstrcpy(data + SD_MAX_VDI_LEN, SD_MAX_VDI_TAG_LEN, snap_tag);

	ret = dog_exec_req(&sd_nid, &hdr, data);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Failed to delete %s: %s", vdiname,
		       sd_strerror(rsp->result));
		if (rsp->result == SD_RES_NO_VDI)
			return EXIT_MISSING;
		else
			return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int vdi_delete(int argc, char **argv)
{
	const char *vdiname = argv[optind];

	return do_vdi_delete(vdiname, vdi_cmd_data.snapshot_id,
			     vdi_cmd_data.snapshot_tag);
}

static int vdi_rollback(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	uint32_t base_vid, new_vid;
	int ret;
	char buf[SD_INODE_HEADER_SIZE];
	struct sd_inode *inode = (struct sd_inode *)buf;

	if (!vdi_cmd_data.snapshot_id && !vdi_cmd_data.snapshot_tag[0]) {
		sd_err("Please specify the '-s' option");
		return EXIT_USAGE;
	}

	ret = read_vdi_obj(vdiname, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, &base_vid, inode,
			   SD_INODE_HEADER_SIZE);
	if (ret != EXIT_SUCCESS)
		return ret;

	if (!vdi_cmd_data.force)
		confirm("This operation dicards any changes made since the"
			" previous\nsnapshot was taken.  Continue? [yes/no]: ");

	ret = do_vdi_delete(vdiname, 0, NULL);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to delete the current state");
		return EXIT_FAILURE;
	}

	ret = do_vdi_create(vdiname, inode->vdi_size, base_vid, &new_vid,
			     false, vdi_cmd_data.nr_copies, inode->copy_policy,
			     inode->store_policy);

	if (ret == EXIT_SUCCESS && verbose) {
		if (raw_output)
			printf("%x\n", new_vid);
		else
			printf("New VDI ID of rollbacked VDI: %x\n", new_vid);
	}

	return ret;
}


static int vdi_object_map(int argc, char **argv)
{
	const char *vdiname = argv[optind];
	uint64_t idx = vdi_cmd_data.index;
	struct sd_inode *inode = xmalloc(sizeof(*inode));
	uint32_t vid;
	int ret;

	ret = read_vdi_obj(vdiname, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, NULL, inode,
			   SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS) {
		sd_err("FATAL: %s not found", vdiname);
		return ret;
	}

	printf("Index       VID\n");
	if (idx != ~0) {
		vid = INODE_GET_VID(inode, idx);
		printf("%08"PRIu64" %8"PRIx32"\n", idx, vid);
	} else {
		uint32_t max_idx = count_data_objs(inode);

		for (idx = 0; idx < max_idx; idx++) {
			vid = INODE_GET_VID(inode, idx);
			if (vid)
				printf("%08"PRIu64" %8"PRIx32"\n", idx, vid);
		}
	}
	return EXIT_SUCCESS;
}

static int vdi_object_location(int argc, char **argv)
{
	const char *vdiname = argv[optind];
	uint64_t idx = vdi_cmd_data.index;
	struct get_vdi_info info;
	uint32_t vid;
	size_t size;

	memset(&info, 0, sizeof(info));
	info.name = vdiname;
	info.tag = vdi_cmd_data.snapshot_tag;
	info.vid = 0;
	info.snapid = vdi_cmd_data.snapshot_id;

	if (parse_vdi(vdi_info_filler, SD_INODE_HEADER_SIZE, &info) < 0)
		return EXIT_SYSFAIL;

	vid = info.vid;
	if (vid == 0) {
		sd_err("VDI not found");
		return EXIT_MISSING;
	}

	if (idx == ~0) {
		printf("Looking for the inode object 0x%" PRIx32 " with %d nodes\n\n",
		       vid, sd_nodes_nr);
		parse_objs(vid_to_vdi_oid(vid), do_print_obj, NULL,
			   SD_INODE_SIZE);
	} else {
		struct obj_info_filler_info oid_info = {0};

		oid_info.success = false;
		oid_info.idx = idx;

		if (idx >= MAX_DATA_OBJS) {
			printf("The offset is too large!\n");
			exit(EXIT_FAILURE);
		}

		size = get_store_objsize(info.copy_policy,
					 vid_to_data_oid(vid, 0));
		parse_objs(vid_to_vdi_oid(vid), obj_info_filler, &oid_info,
			   size);

		if (oid_info.success) {
			if (oid_info.data_oid) {
				printf("Looking for the object 0x%" PRIx64
				       " (vid 0x%" PRIx32 " idx %"PRIu64
				       ", %u copies) with %d nodes\n\n",
				       oid_info.data_oid, vid, idx,
				       info.nr_copies, sd_nodes_nr);

				parse_objs(oid_info.data_oid, do_print_obj,
					   NULL, size);
			} else
				printf("The inode object 0x%" PRIx32 " idx"
				       " %"PRIu64" is not allocated\n",
				       vid, idx);
		} else
			sd_err("Failed to read the inode object 0x%" PRIx32,
			       vid);
	}

	return EXIT_SUCCESS;
}

static int do_track_object(uint64_t oid, uint8_t nr_copies)
{
	int i, j, ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	const struct sd_vnode *vnode_buf[SD_MAX_COPIES];
	struct epoch_log *logs;
	int nr_logs, log_length;

	log_length = sd_epoch * sizeof(struct epoch_log);
	logs = xmalloc(log_length);

	sd_init_req(&hdr, SD_OP_STAT_CLUSTER);
	hdr.data_length = log_length;

	ret = dog_exec_req(&sd_nid, &hdr, logs);
	if (ret < 0)
		goto error;

	if (rsp->result != SD_RES_SUCCESS) {
		printf("%s\n", sd_strerror(rsp->result));
		goto error;
	}

	nr_logs = rsp->data_length / sizeof(struct epoch_log);
	for (i = nr_logs - 1; i >= 0; i--) {
		struct rb_root vroot = RB_ROOT;
		struct rb_root nroot = RB_ROOT;

		printf("\nobj %"PRIx64" locations at epoch %d, copies = %d\n",
		       oid, logs[i].epoch, nr_copies);
		printf("---------------------------------------------------\n");

		/*
		 * When # of nodes is less than nr_copies, we only print
		 * remaining nodes that holds all the remaining copies.
		 */
		if (logs[i].nr_nodes < nr_copies) {
			for (j = 0; j < logs[i].nr_nodes; j++) {
				const struct node_id *n = &logs[i].nodes[j].nid;

				printf("%s\n", addr_to_str(n->addr, n->port));
			}
			continue;
		}
		for (int k = 0; k < logs[i].nr_nodes; k++)
			rb_insert(&nroot, &logs[i].nodes[k], rb, node_cmp);
		nodes_to_vnodes(&nroot, &vroot);
		oid_to_vnodes(oid, &vroot, nr_copies, vnode_buf);
		for (j = 0; j < nr_copies; j++) {
			const struct node_id *n = &vnode_buf[j]->node->nid;

			printf("%s\n", addr_to_str(n->addr, n->port));
		}
		rb_destroy(&vroot, struct sd_vnode, rb);
	}

	free(logs);
	return EXIT_SUCCESS;
error:
	free(logs);
	return EXIT_SYSFAIL;
}

static int vdi_track(int argc, char **argv)
{
	const char *vdiname = argv[optind];
	unsigned idx = vdi_cmd_data.index;
	struct get_vdi_info info;
	struct obj_info_filler_info oid_info = {0};
	uint32_t vid;
	uint8_t nr_copies;
	uint64_t oid = vdi_cmd_data.oid;

	memset(&info, 0, sizeof(info));
	info.name = vdiname;
	info.tag = vdi_cmd_data.snapshot_tag;
	info.vid = 0;
	info.snapid = vdi_cmd_data.snapshot_id;

	if (parse_vdi(vdi_info_filler, SD_INODE_HEADER_SIZE, &info) < 0)
		return EXIT_SYSFAIL;

	vid = info.vid;
	nr_copies = info.nr_copies;
	if (vid == 0) {
		sd_err("VDI not found");
		return EXIT_MISSING;
	}

	if (!oid) {
		if (idx == ~0) {
			printf("Tracking the inode object 0x%" PRIx32
			       " with %d nodes\n", vid, sd_nodes_nr);
			return do_track_object(vid_to_vdi_oid(vid), nr_copies);
		}

		oid_info.success = false;
		oid_info.idx = idx;

		if (idx >= MAX_DATA_OBJS) {
			printf("The offset is too large!\n");
			goto err;
		}

		parse_objs(vid_to_vdi_oid(vid), obj_info_filler, &oid_info,
			   get_store_objsize(info.copy_policy,
					     vid_to_data_oid(vid, 0)));

		if (!oid_info.success) {
			sd_err("Failed to read the inode object 0x%" PRIx32,
			       vid);
			goto err;
		}
		if (!oid_info.data_oid) {
			printf("The inode object 0x%"PRIx32
			       " idx %u is not allocated\n", vid, idx);
			goto err;
		}

		oid = oid_info.data_oid;

		printf("Tracking the object 0x%" PRIx64
		       " (the inode vid 0x%" PRIx32 " idx %u)"
		       " with %d nodes\n", oid, vid, idx, sd_nodes_nr);
	} else
		printf("Tracking the object 0x%" PRIx64
		       " (the inode vid 0x%" PRIx32 ")"
		       " with %d nodes\n", oid, vid, sd_nodes_nr);

	return do_track_object(oid, nr_copies);

err:
	return EXIT_FAILURE;
}

static int find_vdi_attr_oid(const char *vdiname, const char *tag, uint32_t snapid,
			     const char *key, void *value, unsigned int value_len,
			     uint32_t *vid, uint64_t *oid, unsigned int *nr_copies,
			     bool create, bool excl, bool delete)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret;
	struct sheepdog_vdi_attr vattr;

	memset(&vattr, 0, sizeof(vattr));
	pstrcpy(vattr.name, SD_MAX_VDI_LEN, vdiname);
	pstrcpy(vattr.tag, SD_MAX_VDI_TAG_LEN, vdi_cmd_data.snapshot_tag);
	vattr.snap_id = vdi_cmd_data.snapshot_id;
	pstrcpy(vattr.key, SD_MAX_VDI_ATTR_KEY_LEN, key);
	if (value && value_len) {
		vattr.value_len = value_len;
		memcpy(vattr.value, value, value_len);
	}

	sd_init_req(&hdr, SD_OP_GET_VDI_ATTR);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = SD_ATTR_OBJ_SIZE;
	hdr.vdi.snapid = vdi_cmd_data.snapshot_id;

	if (create)
		hdr.flags |= SD_FLAG_CMD_CREAT;
	if (excl)
		hdr.flags |= SD_FLAG_CMD_EXCL;
	if (delete)
		hdr.flags |= SD_FLAG_CMD_DEL;

	ret = dog_exec_req(&sd_nid, &hdr, &vattr);
	if (ret < 0)
		return SD_RES_EIO;

	if (rsp->result != SD_RES_SUCCESS)
		return rsp->result;

	*vid = rsp->vdi.vdi_id;
	*oid = vid_to_attr_oid(rsp->vdi.vdi_id, rsp->vdi.attr_id);
	*nr_copies = rsp->vdi.copies;

	return SD_RES_SUCCESS;
}

static int vdi_setattr(int argc, char **argv)
{
	int ret, value_len = 0;
	uint64_t attr_oid = 0;
	uint32_t vid = 0, nr_copies = 0;
	const char *vdiname = argv[optind++], *key;
	char *value;
	uint64_t offset;

	key = argv[optind++];
	if (!key) {
		sd_err("Please specify the attribute key");
		return EXIT_USAGE;
	}

	value = argv[optind++];
	if (!value && !vdi_cmd_data.delete) {
		value = xmalloc(SD_MAX_VDI_ATTR_VALUE_LEN);

		offset = 0;
reread:
		ret = read(STDIN_FILENO, value + offset,
			   SD_MAX_VDI_ATTR_VALUE_LEN - offset);
		if (ret < 0) {
			sd_err("Failed to read attribute value from stdin: %m");
			return EXIT_SYSFAIL;
		}
		if (ret > 0) {
			offset += ret;
			goto reread;
		}
	}

	if (value)
		value_len = strlen(value);

	ret = find_vdi_attr_oid(vdiname, vdi_cmd_data.snapshot_tag,
				vdi_cmd_data.snapshot_id, key, value,
				value_len, &vid, &attr_oid,
				&nr_copies, !vdi_cmd_data.delete,
				vdi_cmd_data.exclusive, vdi_cmd_data.delete);
	if (ret) {
		if (ret == SD_RES_VDI_EXIST) {
			sd_err("The attribute '%s' already exists", key);
			return EXIT_EXISTS;
		} else if (ret == SD_RES_NO_OBJ) {
			sd_err("Attribute '%s' not found", key);
			return EXIT_MISSING;
		} else if (ret == SD_RES_NO_VDI) {
			sd_err("VDI not found");
			return EXIT_MISSING;
		} else
			sd_err("Failed to set attribute: %s", sd_strerror(ret));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int vdi_getattr(int argc, char **argv)
{
	int ret;
	uint64_t oid, attr_oid = 0;
	uint32_t vid = 0, nr_copies = 0;
	const char *vdiname = argv[optind++], *key;
	struct sheepdog_vdi_attr vattr;

	key = argv[optind++];
	if (!key) {
		sd_err("Please specify the attribute key");
		return EXIT_USAGE;
	}

	ret = find_vdi_attr_oid(vdiname, vdi_cmd_data.snapshot_tag,
				vdi_cmd_data.snapshot_id, key, NULL, 0, &vid,
				&attr_oid, &nr_copies, false, false, false);
	if (ret == SD_RES_NO_OBJ) {
		sd_err("Attribute '%s' not found", key);
		return EXIT_MISSING;
	} else if (ret == SD_RES_NO_VDI) {
		sd_err("VDI not found");
		return EXIT_MISSING;
	} else if (ret) {
		sd_err("Failed to find attribute oid: %s", sd_strerror(ret));
		return EXIT_MISSING;
	}

	oid = attr_oid;

	ret = dog_read_object(oid, &vattr, SD_ATTR_OBJ_SIZE, 0, true);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to read attribute oid: %s", sd_strerror(ret));
		return EXIT_SYSFAIL;
	}

	xwrite(STDOUT_FILENO, vattr.value, vattr.value_len);
	return EXIT_SUCCESS;
}

static int vdi_read(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	int ret;
	struct sd_inode *inode = NULL;
	uint64_t offset = 0, oid, done = 0, total = (uint64_t) -1;
	uint32_t vdi_id, idx;
	unsigned int len;
	char *buf = NULL;

	if (argv[optind]) {
		ret = option_parse_size(argv[optind++], &offset);
		if (ret < 0)
			return EXIT_USAGE;
		if (argv[optind]) {
			ret = option_parse_size(argv[optind++], &total);
			if (ret < 0)
				return EXIT_USAGE;
		}
	}

	inode = malloc(sizeof(*inode));
	buf = xmalloc(SD_DATA_OBJ_SIZE);

	ret = read_vdi_obj(vdiname, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, NULL, inode,
			   SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	if (inode->vdi_size < offset) {
		sd_err("Read offset is beyond the end of the VDI");
		ret = EXIT_FAILURE;
		goto out;
	}

	total = min(total, inode->vdi_size - offset);
	idx = offset / SD_DATA_OBJ_SIZE;
	offset %= SD_DATA_OBJ_SIZE;
	while (done < total) {
		len = min(total - done, SD_DATA_OBJ_SIZE - offset);
		vdi_id = INODE_GET_VID(inode, idx);
		if (vdi_id) {
			oid = vid_to_data_oid(vdi_id, idx);
			ret = dog_read_object(oid, buf, len, offset, false);
			if (ret != SD_RES_SUCCESS) {
				sd_err("Failed to read VDI");
				ret = EXIT_FAILURE;
				goto out;
			}
		} else
			memset(buf, 0, len);

		ret = xwrite(STDOUT_FILENO, buf, len);
		if (ret < 0) {
			sd_err("Failed to write to stdout: %m");
			ret = EXIT_SYSFAIL;
			goto out;
		}

		offset = 0;
		idx++;
		done += len;
	}
	fsync(STDOUT_FILENO);
	ret = EXIT_SUCCESS;
out:
	free(inode);
	free(buf);

	return ret;
}

static int vdi_write(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	uint32_t vid, flags, vdi_id, idx;
	int ret;
	struct sd_inode *inode = NULL;
	uint64_t offset = 0, oid, old_oid, done = 0, total = (uint64_t) -1;
	unsigned int len;
	char *buf = NULL;
	bool create;

	if (argv[optind]) {
		ret = option_parse_size(argv[optind++], &offset);
		if (ret < 0)
			return EXIT_USAGE;
		if (argv[optind]) {
			ret = option_parse_size(argv[optind++], &total);
			if (ret < 0)
				return EXIT_USAGE;
		}
	}

	inode = xmalloc(sizeof(*inode));
	buf = xmalloc(SD_DATA_OBJ_SIZE);

	ret = read_vdi_obj(vdiname, 0, "", &vid, inode, SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	if (inode->vdi_size < offset) {
		sd_err("Write offset is beyond the end of the VDI");
		ret = EXIT_FAILURE;
		goto out;
	}

	total = min(total, inode->vdi_size - offset);
	idx = offset / SD_DATA_OBJ_SIZE;
	offset %= SD_DATA_OBJ_SIZE;
	while (done < total) {
		create = false;
		old_oid = 0;
		flags = 0;
		len = min(total - done, SD_DATA_OBJ_SIZE - offset);

		vdi_id = INODE_GET_VID(inode, idx);
		if (!vdi_id)
			create = true;
		else if (!is_data_obj_writeable(inode, idx)) {
			create = true;
			old_oid = vid_to_data_oid(vdi_id, idx);
		}

		if (vdi_cmd_data.writeback)
			flags |= SD_FLAG_CMD_CACHE;

		ret = xread(STDIN_FILENO, buf, len);
		if (ret < 0) {
			sd_err("Failed to read from stdin: %m");
			ret = EXIT_SYSFAIL;
			goto out;
		} else if (ret < len) {
			/* exit after this buffer is sent */
			memset(buf + ret, 0, len - ret);
			total = done + len;
		}

		INODE_SET_VID(inode, idx, inode->vdi_id);
		oid = vid_to_data_oid(inode->vdi_id, idx);
		ret = dog_write_object(oid, old_oid, buf, len, offset, flags,
				      inode->nr_copies, inode->copy_policy,
				      create, false);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to write VDI");
			ret = EXIT_FAILURE;
			goto out;
		}

		if (create) {
			ret = sd_inode_write_vid(dog_bnode_writer, inode, idx,
						 vid, vid, flags, false, false);
			if (ret) {
				ret = EXIT_FAILURE;
				goto out;
			}
		}

		offset += len;
		if (offset == SD_DATA_OBJ_SIZE) {
			offset = 0;
			idx++;
		}
		done += len;
	}
	ret = EXIT_SUCCESS;
out:
	free(inode);
	free(buf);

	return ret;
}

static void *read_object_from(const struct sd_vnode *vnode, uint64_t oid)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret;
	void *buf;
	size_t size = get_objsize(oid);

	buf = xmalloc(size);

	sd_init_req(&hdr, SD_OP_READ_PEER);
	hdr.epoch = sd_epoch;
	hdr.flags = 0;
	hdr.data_length = size;

	hdr.obj.oid = oid;

	ret = dog_exec_req(&vnode->node->nid, &hdr, buf);
	if (ret < 0)
		exit(EXIT_SYSFAIL);

	switch (rsp->result) {
	case SD_RES_SUCCESS:
		break;
	case SD_RES_NO_OBJ:
		free(buf);
		return NULL;
	default:
		sd_err("FATAL: failed to read %"PRIx64", %s", oid,
		       sd_strerror(rsp->result));
		exit(EXIT_FAILURE);
	}
	return buf;
}

static void write_object_to(const struct sd_vnode *vnode, uint64_t oid,
			    void *buf, bool create, uint8_t ec_index)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret;

	if (create)
		sd_init_req(&hdr, SD_OP_CREATE_AND_WRITE_PEER);
	else
		sd_init_req(&hdr, SD_OP_WRITE_PEER);
	hdr.epoch = sd_epoch;
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = get_objsize(oid);
	hdr.obj.oid = oid;
	hdr.obj.ec_index = ec_index;

	ret = dog_exec_req(&vnode->node->nid, &hdr, buf);
	if (ret < 0)
		exit(EXIT_SYSFAIL);

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("FATAL: failed to write %"PRIx64", %s", oid,
		       sd_strerror(rsp->result));
		exit(EXIT_FAILURE);
	}
}

struct vdi_check_work {
	struct vdi_check_info *info;
	const struct sd_vnode *vnode;
	uint8_t hash[SHA1_DIGEST_SIZE];
	uint8_t ec_index;
	uint8_t *buf;
	bool object_found;
	struct work work;
};

enum vdi_check_result {
	VDI_CHECK_NO_OBJ_FOUND,
	VDI_CHECK_NO_MAJORITY_FOUND,
	VDI_CHECK_SUCCESS,
};

struct vdi_check_info {
	uint64_t oid;
	uint8_t nr_copies;
	uint8_t copy_policy;
	uint64_t total;
	uint64_t *done;
	int refcnt;
	struct work_queue *wq;
	enum vdi_check_result result;
	struct vdi_check_work *majority;
	struct vdi_check_work vcw[0];
};

static void free_vdi_check_info(struct vdi_check_info *info)
{
	if (info->done) {
		*info->done += SD_DATA_OBJ_SIZE;
		vdi_show_progress(*info->done, info->total);
	}
	free(info);
}

static void vdi_repair_work(struct work *work)
{
	struct vdi_check_work *vcw = container_of(work, struct vdi_check_work,
						  work);
	struct vdi_check_info *info = vcw->info;
	void *buf;

	buf = read_object_from(info->majority->vnode, info->oid);
	write_object_to(vcw->vnode, info->oid, buf, !vcw->object_found, 0);
	free(buf);
}

static void vdi_repair_main(struct work *work)
{
	struct vdi_check_work *vcw = container_of(work, struct vdi_check_work,
						  work);
	struct vdi_check_info *info = vcw->info;

	if (vcw->object_found)
		fprintf(stdout, "fixed replica %"PRIx64"\n", info->oid);
	else
		fprintf(stdout, "fixed missing %"PRIx64"\n", info->oid);

	info->refcnt--;
	if (info->refcnt == 0)
		free_vdi_check_info(info);
}

static void vdi_check_object_work(struct work *work)
{
	struct vdi_check_work *vcw = container_of(work, struct vdi_check_work,
						  work);
	struct vdi_check_info *info = vcw->info;
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

	if (is_erasure_oid(info->oid, info->copy_policy)) {
		sd_init_req(&hdr, SD_OP_READ_PEER);
		hdr.data_length = get_store_objsize(info->copy_policy,
						    info->oid);
		hdr.obj.ec_index = vcw->ec_index;
		hdr.epoch = sd_epoch;
		vcw->buf = xmalloc(hdr.data_length);
	} else
		sd_init_req(&hdr, SD_OP_GET_HASH);
	hdr.obj.oid = info->oid;
	hdr.obj.tgt_epoch = sd_epoch;

	ret = dog_exec_req(&vcw->vnode->node->nid, &hdr, vcw->buf);
	if (ret < 0)
		exit(EXIT_SYSFAIL);

	switch (rsp->result) {
	case SD_RES_SUCCESS:
		vcw->object_found = true;
		if (!is_erasure_oid(info->oid, info->copy_policy))
			memcpy(vcw->hash, rsp->hash.digest, sizeof(vcw->hash));
		break;
	case SD_RES_NO_OBJ:
		vcw->object_found = false;
		break;
	default:
		sd_err("failed to read %" PRIx64 " from %s, %s", info->oid,
		       addr_to_str(vcw->vnode->node->nid.addr,
				   vcw->vnode->node->nid.port),
		       sd_strerror(rsp->result));
		exit(EXIT_FAILURE);
	}
}

static void check_replicatoin_object(struct vdi_check_info *info)
{
	if (info->majority == NULL) {
		switch (info->result) {
		case VDI_CHECK_NO_OBJ_FOUND:
			sd_err("no node has %" PRIx64, info->oid);
			break;
		case VDI_CHECK_NO_MAJORITY_FOUND:
			sd_err("no majority of %" PRIx64, info->oid);
			break;
		default:
			sd_err("unknown result of vdi check: %d", info->result);
			exit(EXIT_FAILURE);
			break;
		}

		/* do nothing */
		return;
	}

	for (int i = 0; i < info->nr_copies; i++) {
		if (&info->vcw[i] == info->majority)
			continue;
		/* need repair when object not found or consistency broken */
		if (!info->vcw[i].object_found ||
		    memcmp(info->majority->hash, info->vcw[i].hash,
			   sizeof(info->majority->hash)) != 0) {
			info->vcw[i].work.fn = vdi_repair_work;
			info->vcw[i].work.done = vdi_repair_main;
			info->refcnt++;
			queue_work(info->wq, &info->vcw[i].work);
		}
	}
}

static void check_erasure_object(struct vdi_check_info *info)
{
	int d = 0, p = 0, i, j, k;
	int dp = ec_policy_to_dp(info->copy_policy, &d, &p);
	struct fec *ctx = ec_init(d, dp);
	int miss_idx[dp], input_idx[dp];
	uint64_t oid = info->oid;
	size_t len = get_store_objsize(info->copy_policy, oid);
	char *obj = xmalloc(len);
	uint8_t *input[dp];

	for (i = 0; i < dp; i++)
		miss_idx[i] = -1;

	for (i = 0, j = 0, k = 0; i < info->nr_copies; i++)
		if (!info->vcw[i].object_found) {
			miss_idx[j++] = i;
		} else {
			input_idx[k] = i;
			input[k] = info->vcw[i].buf;
			k++;
		}

	if (!j) { /* No object missing */
		int idx[d];

		for (i = 0; i < d; i++)
			idx[i] = i;

		for (k = 0; k < p; k++) {
			uint8_t *ds[d];
			for (j = 0; j < d; j++)
				ds[j] = info->vcw[j].buf;
			ec_decode_buffer(ctx, ds, idx, obj, d + k);
			if (memcmp(obj, info->vcw[d + k].buf, len) != 0) {
				/* TODO repair the inconsistency */
				sd_err("object %"PRIx64" is inconsistent", oid);
				goto out;
			}
		}
	} else if (j > p) {
		sd_err("failed to rebuild object %"PRIx64". %d copies get "
		       "lost, more than %d", oid, j, p);
		goto out;
	} else {
		for (k = 0; k < j; k++) {
			int m = miss_idx[k];
			uint8_t *ds[d];

			for (i = 0; i < d; i++)
				ds[i] = input[i];
			ec_decode_buffer(ctx, ds, input_idx, obj, m);
			write_object_to(info->vcw[m].vnode, oid, obj, true,
					info->vcw[m].ec_index);
			fprintf(stdout, "fixed missing %"PRIx64", "
				"copy index %d\n", info->oid, m);
		}
	}
out:
	for (i = 0; i < dp; i++)
		free(info->vcw[i].buf);
	free(obj);
	ec_destroy(ctx);
}

static void vote_majority_object(struct vdi_check_info *info)
{
	/*
	 * Voting majority object from existing ones.
	 *
	 * The linear majority vote algorithm by Boyer and Moore is used:
	 * http://www.cs.utexas.edu/~moore/best-ideas/mjrty/
	 */

	int count = 0, nr_live_copies = 0;
	struct vdi_check_work *majority = NULL;

	for (int i = 0; i < info->nr_copies; i++) {
		struct vdi_check_work *vcw = &info->vcw[i];

		if (!vcw->object_found)
			continue;
		nr_live_copies++;

		if (!count)
			majority = vcw;

		if (!memcmp(majority->hash, vcw->hash, sizeof(vcw->hash)))
			count++;
		else
			count--;
	}

	if (!majority)
		info->result = VDI_CHECK_NO_OBJ_FOUND;
	else if (count < nr_live_copies / 2) {
		/* no majority found */
		majority = NULL;
		info->result = VDI_CHECK_NO_MAJORITY_FOUND;
	} else
		info->result = VDI_CHECK_SUCCESS;

	info->majority = majority;
}

static void vdi_check_object_main(struct work *work)
{
	struct vdi_check_work *vcw = container_of(work, struct vdi_check_work,
						  work);
	struct vdi_check_info *info = vcw->info;

	info->refcnt--;
	if (info->refcnt > 0)
		return;

	if (is_erasure_oid(info->oid, info->copy_policy))
		check_erasure_object(info);
	else {
		vote_majority_object(info);
		check_replicatoin_object(info);
	}

	if (info->refcnt == 0)
		free_vdi_check_info(info);
}

static void queue_vdi_check_work(const struct sd_inode *inode, uint64_t oid,
				 uint64_t *done, struct work_queue *wq,
				 int nr_copies)
{
	struct vdi_check_info *info;
	const struct sd_vnode *tgt_vnodes[SD_MAX_COPIES];

	info = xzalloc(sizeof(*info) + sizeof(info->vcw[0]) * nr_copies);
	info->oid = oid;
	info->nr_copies = nr_copies;
	info->total = inode->vdi_size;
	info->done = done;
	info->wq = wq;
	info->copy_policy = inode->copy_policy;

	oid_to_vnodes(oid, &sd_vroot, nr_copies, tgt_vnodes);
	for (int i = 0; i < nr_copies; i++) {
		info->vcw[i].info = info;
		info->vcw[i].ec_index = i;
		info->vcw[i].vnode = tgt_vnodes[i];
		info->vcw[i].work.fn = vdi_check_object_work;
		info->vcw[i].work.done = vdi_check_object_main;
		info->refcnt++;
		queue_work(info->wq, &info->vcw[i].work);
	}
}

struct check_arg {
	const struct sd_inode *inode;
	uint64_t *done;
	struct work_queue *wq;
	int nr_copies;
};

static void check_cb(void *data, enum btree_node_type type, void *arg)
{
	struct sd_extent *ext;
	struct check_arg *carg = arg;
	uint64_t oid;

	if (type == BTREE_EXT) {
		ext = (struct sd_extent *)data;
		if (ext->vdi_id) {
			oid = vid_to_data_oid(ext->vdi_id, ext->idx);
			*(carg->done) = (uint64_t)ext->idx * SD_DATA_OBJ_SIZE;
			vdi_show_progress(*(carg->done), carg->inode->vdi_size);
			queue_vdi_check_work(carg->inode, oid, NULL, carg->wq,
					     carg->nr_copies);
		}
	}
}

int do_vdi_check(const struct sd_inode *inode)
{
	uint32_t max_idx;
	uint64_t done = 0, oid;
	uint32_t vid;
	struct work_queue *wq;
	int nr_copies = min((int)inode->nr_copies, sd_zones_nr);

	if (0 < inode->copy_policy && sd_zones_nr < nr_copies) {
		sd_err("ABORT: Not enough active zones for consistency-checking"
		       " erasure coded VDI");
		return EXIT_FAILURE;
	}

	wq = create_work_queue("vdi check", WQ_DYNAMIC);

	init_fec();

	queue_vdi_check_work(inode, vid_to_vdi_oid(inode->vdi_id), NULL, wq,
			     nr_copies);

	if (inode->store_policy == 0) {
		max_idx = count_data_objs(inode);
		vdi_show_progress(done, inode->vdi_size);
		for (uint32_t idx = 0; idx < max_idx; idx++) {
			vid = INODE_GET_VID(inode, idx);
			if (vid) {
				oid = vid_to_data_oid(vid, idx);
				queue_vdi_check_work(inode, oid, &done, wq,
						     nr_copies);
			} else {
				done += SD_DATA_OBJ_SIZE;
				vdi_show_progress(done, inode->vdi_size);
			}
		}
	} else {
		struct check_arg arg = {inode, &done, wq, nr_copies};
		traverse_btree(dog_bnode_reader, inode, check_cb, &arg);
		vdi_show_progress(inode->vdi_size, inode->vdi_size);
	}

	work_queue_wait(wq);

	fprintf(stdout, "finish check&repair %s\n", inode->name);

	return EXIT_SUCCESS;
}

static int vdi_check(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	int ret;
	struct sd_inode *inode = xmalloc(sizeof(*inode));

	ret = read_vdi_obj(vdiname, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, NULL, inode,
			   SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS) {
		sd_err("FATAL: no inode objects");
		return ret;
	}

	return do_vdi_check(inode);
}

/* vdi backup format */

#define VDI_BACKUP_FORMAT_VERSION 1
#define VDI_BACKUP_MAGIC 0x11921192

struct backup_hdr {
	uint32_t version;
	uint32_t magic;
};

struct obj_backup {
	uint32_t idx;
	uint32_t offset;
	uint32_t length;
	uint32_t reserved;
	uint8_t data[SD_DATA_OBJ_SIZE];
};

/* discards redundant area from backup data */
static void compact_obj_backup(struct obj_backup *backup, uint8_t *from_data)
{
	uint8_t *p1, *p2;

	p1 = backup->data;
	p2 = from_data;
	while (backup->length > 0 && memcmp(p1, p2, SECTOR_SIZE) == 0) {
		p1 += SECTOR_SIZE;
		p2 += SECTOR_SIZE;
		backup->offset += SECTOR_SIZE;
		backup->length -= SECTOR_SIZE;
	}

	p1 = backup->data + SD_DATA_OBJ_SIZE - SECTOR_SIZE;
	p2 = from_data + SD_DATA_OBJ_SIZE - SECTOR_SIZE;
	while (backup->length > 0 && memcmp(p1, p2, SECTOR_SIZE) == 0) {
		p1 -= SECTOR_SIZE;
		p2 -= SECTOR_SIZE;
		backup->length -= SECTOR_SIZE;
	}
}

static int get_obj_backup(uint32_t idx, uint32_t from_vid, uint32_t to_vid,
			  struct obj_backup *backup)
{
	int ret;
	uint8_t *from_data = xzalloc(SD_DATA_OBJ_SIZE);

	backup->idx = idx;
	backup->offset = 0;
	backup->length = SD_DATA_OBJ_SIZE;

	if (to_vid) {
		ret = dog_read_object(vid_to_data_oid(to_vid, idx),
				      backup->data, SD_DATA_OBJ_SIZE, 0, true);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to read object %" PRIx32 ", %d", to_vid,
			       idx);
			return EXIT_FAILURE;
		}
	} else
		memset(backup->data, 0, SD_DATA_OBJ_SIZE);

	if (from_vid) {
		ret = dog_read_object(vid_to_data_oid(from_vid, idx), from_data,
				      SD_DATA_OBJ_SIZE, 0, true);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to read object %" PRIx32 ", %d",
			       from_vid, idx);
			return EXIT_FAILURE;
		}
	}

	compact_obj_backup(backup, from_data);

	free(from_data);

	return EXIT_SUCCESS;
}

static int vdi_backup(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	int ret = EXIT_SUCCESS;
	uint32_t idx, nr_objs;
	struct sd_inode *from_inode = xzalloc(sizeof(*from_inode));
	struct sd_inode *to_inode = xzalloc(sizeof(*to_inode));
	struct backup_hdr hdr = {
		.version = VDI_BACKUP_FORMAT_VERSION,
		.magic = VDI_BACKUP_MAGIC,
	};
	struct obj_backup *backup = xzalloc(sizeof(*backup));

	if ((!vdi_cmd_data.snapshot_id && !vdi_cmd_data.snapshot_tag[0]) ||
	    (!vdi_cmd_data.from_snapshot_id &&
	     !vdi_cmd_data.from_snapshot_tag[0])) {
		sd_err("Please specify snapshots with '-F' and '-s' options");
		ret = EXIT_USAGE;
		goto out;
	}

	ret = read_vdi_obj(vdiname, vdi_cmd_data.from_snapshot_id,
			   vdi_cmd_data.from_snapshot_tag, NULL,
			   from_inode, SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	ret = read_vdi_obj(vdiname, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, NULL, to_inode,
			   SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	nr_objs = count_data_objs(to_inode);

	ret = xwrite(STDOUT_FILENO, &hdr, sizeof(hdr));
	if (ret < 0) {
		sd_err("failed to write backup header, %m");
		ret = EXIT_SYSFAIL;
		goto out;
	}

	for (idx = 0; idx < nr_objs; idx++) {
		uint32_t from_vid = INODE_GET_VID(from_inode, idx);
		uint32_t to_vid = INODE_GET_VID(to_inode, idx);

		if (to_vid == 0 && from_vid == 0)
			continue;

		ret = get_obj_backup(idx, from_vid, to_vid, backup);
		if (ret != EXIT_SUCCESS)
			goto out;

		if (backup->length == 0)
			continue;

		ret = xwrite(STDOUT_FILENO, backup,
			     sizeof(*backup) - sizeof(backup->data));
		if (ret < 0) {
			sd_err("failed to write backup data, %m");
			ret = EXIT_SYSFAIL;
			goto out;
		}
		ret = xwrite(STDOUT_FILENO, backup->data + backup->offset,
			     backup->length);
		if (ret < 0) {
			sd_err("failed to write backup data, %m");
			ret = EXIT_SYSFAIL;
			goto out;
		}
	}

	/* write end marker */
	memset(backup, 0, sizeof(*backup) - sizeof(backup->data));
	backup->idx = UINT32_MAX;
	ret = xwrite(STDOUT_FILENO, backup,
		     sizeof(*backup) - sizeof(backup->data));
	if (ret < 0) {
		sd_err("failed to write end marker, %m");
		ret = EXIT_SYSFAIL;
		goto out;
	}

	fsync(STDOUT_FILENO);
	ret = EXIT_SUCCESS;
out:
	free(from_inode);
	free(to_inode);
	free(backup);
	return ret;
}

/* restore backup data to vdi */
static int restore_obj(struct obj_backup *backup, uint32_t vid,
		       struct sd_inode *parent_inode)
{
	int ret;
	uint32_t parent_vid = INODE_GET_VID(parent_inode, backup->idx);
	uint64_t parent_oid = 0;

	if (parent_vid)
		parent_oid = vid_to_data_oid(parent_vid, backup->idx);

	/* send a copy-on-write request */
	ret = dog_write_object(vid_to_data_oid(vid, backup->idx), parent_oid,
			       backup->data, backup->length, backup->offset,
			       0, parent_inode->nr_copies,
			       parent_inode->copy_policy, true, true);
	if (ret != SD_RES_SUCCESS)
		return ret;

	return dog_write_object(vid_to_vdi_oid(vid), 0, &vid, sizeof(vid),
			SD_INODE_HEADER_SIZE + sizeof(vid) * backup->idx,
				0, parent_inode->nr_copies,
				parent_inode->copy_policy, false, true);
}

static uint32_t do_restore(const char *vdiname, int snapid, const char *tag)
{
	int ret;
	uint32_t vid;
	struct backup_hdr hdr;
	struct obj_backup *backup = xzalloc(sizeof(*backup));
	struct sd_inode *inode = xzalloc(sizeof(*inode));

	ret = xread(STDIN_FILENO, &hdr, sizeof(hdr));
	if (ret != sizeof(hdr))
		sd_err("failed to read backup header, %m");

	if (hdr.version != VDI_BACKUP_FORMAT_VERSION ||
	    hdr.magic != VDI_BACKUP_MAGIC) {
		sd_err("The backup file is corrupted");
		ret = EXIT_SYSFAIL;
		goto out;
	}

	ret = read_vdi_obj(vdiname, snapid, tag, NULL, inode, SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	ret = do_vdi_create(vdiname, inode->vdi_size, inode->vdi_id, &vid,
			    false, inode->nr_copies, inode->copy_policy,
			    inode->store_policy);
	if (ret != EXIT_SUCCESS) {
		sd_err("Failed to read VDI");
		goto out;
	}

	while (true) {
		ret = xread(STDIN_FILENO, backup,
			    sizeof(*backup) - sizeof(backup->data));
		if (ret != sizeof(*backup) - sizeof(backup->data)) {
			sd_err("failed to read backup data");
			ret = EXIT_SYSFAIL;
			break;
		}

		if (backup->idx == UINT32_MAX) {
			ret = EXIT_SUCCESS;
			break;
		}

		ret = xread(STDIN_FILENO, backup->data, backup->length);
		if (ret != backup->length) {
			sd_err("failed to read backup data");
			ret = EXIT_SYSFAIL;
			break;
		}

		ret = restore_obj(backup, vid, inode);
		if (ret != SD_RES_SUCCESS) {
			sd_err("failed to restore backup");
			do_vdi_delete(vdiname, 0, NULL);
			ret = EXIT_FAILURE;
			break;
		}
	}
out:
	free(backup);
	free(inode);

	return ret;
}

static int vdi_restore(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	int ret;
	char buf[SD_INODE_HEADER_SIZE] = {0};
	struct sd_inode *inode_for_check = xzalloc(sizeof(*inode_for_check));
	struct sd_inode *current_inode = xzalloc(sizeof(*current_inode));
	struct sd_inode *parent_inode = (struct sd_inode *)buf;
	bool need_current_recovery = false;

	if (!vdi_cmd_data.snapshot_id && !vdi_cmd_data.snapshot_tag[0]) {
		sd_err("We can restore a backup file only to snapshots");
		sd_err("Please specify the '-s' option");
		ret = EXIT_USAGE;
		goto out;
	}

	ret = read_vdi_obj(vdiname, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, NULL, inode_for_check,
			   SD_INODE_SIZE);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Snapshot ID %d or tag %s doesn't exist",
		       vdi_cmd_data.snapshot_id, vdi_cmd_data.snapshot_tag);

		goto out;
	}

	/*
	 * delete the current vdi temporarily first to avoid making
	 * the current state become snapshot
	 */
	ret = read_vdi_obj(vdiname, 0, "", NULL, current_inode,
			   SD_INODE_HEADER_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	ret = dog_read_object(vid_to_vdi_oid(current_inode->parent_vdi_id),
			     parent_inode, SD_INODE_HEADER_SIZE, 0, true);
	if (ret != SD_RES_SUCCESS) {
		printf("error\n");
		goto out;
	}

	if (is_stdin_console()) {
		sd_err("stdin must be pipe");
		ret = EXIT_USAGE;
		goto out;
	}

	ret = do_vdi_delete(vdiname, 0, NULL);
	if (ret != EXIT_SUCCESS) {
		sd_err("Failed to delete the current state");
		goto out;
	}
	need_current_recovery = true;

	/* restore backup data */
	ret = do_restore(vdiname, vdi_cmd_data.snapshot_id,
			 vdi_cmd_data.snapshot_tag);
out:
	if (need_current_recovery) {
		int recovery_ret;
		/* recreate the current vdi object */
		recovery_ret = do_vdi_create(vdiname, current_inode->vdi_size,
					     current_inode->parent_vdi_id, NULL,
					     true, current_inode->nr_copies,
					     current_inode->copy_policy,
					     current_inode->store_policy);
		if (recovery_ret != EXIT_SUCCESS) {
			sd_err("failed to resume the current vdi");
			ret = recovery_ret;
		}
	}
	free(current_inode);
	free(inode_for_check);
	return ret;
}

static int vdi_cache_flush(int argc, char **argv)
{
	const char *vdiname;
	struct sd_req hdr;
	uint32_t vid;
	int ret = EXIT_SUCCESS;

	if (optind < argc)
		vdiname = argv[optind++];
	else {
		sd_err("please specify VDI name");
		ret = EXIT_FAILURE;
		goto out;
	}

	ret = find_vdi_name(vdiname, vdi_cmd_data.snapshot_id,
			    vdi_cmd_data.snapshot_tag, &vid, 0);
	if (ret < 0) {
		sd_err("Failed to open VDI %s", vdiname);
		ret = EXIT_FAILURE;
		goto out;
	}

	sd_init_req(&hdr, SD_OP_FLUSH_VDI);
	hdr.obj.oid = vid_to_vdi_oid(vid);

	ret = send_light_req(&sd_nid, &hdr);
	if (ret) {
		sd_err("failed to execute request");
		return EXIT_FAILURE;
	}
out:
	return ret;
}

static int vdi_cache_delete(int argc, char **argv)
{
	const char *vdiname;
	struct sd_req hdr;
	uint32_t vid;
	int ret = EXIT_SUCCESS;

	if (optind < argc)
		vdiname = argv[optind++];
	else {
		sd_err("please specify VDI name");
		ret = EXIT_FAILURE;
		goto out;
	}

	ret = find_vdi_name(vdiname, vdi_cmd_data.snapshot_id,
			    vdi_cmd_data.snapshot_tag, &vid, 0);
	if (ret < 0) {
		sd_err("Failed to open VDI %s", vdiname);
		ret = EXIT_FAILURE;
		goto out;
	}

	sd_init_req(&hdr, SD_OP_DELETE_CACHE);
	hdr.obj.oid = vid_to_vdi_oid(vid);

	ret = send_light_req(&sd_nid, &hdr);
	if (ret) {
		sd_err("failed to execute request");
		return EXIT_FAILURE;
	}
out:
	return ret;
}

static int vid_to_name_tag(uint32_t vid, char *name, char *tag)
{
	struct sd_inode inode;
	int ret;

	ret = dog_read_object(vid_to_vdi_oid(vid), &inode, SD_INODE_HEADER_SIZE,
			     0, true);
	if (ret != SD_RES_SUCCESS)
		return ret;

	pstrcpy(name, SD_MAX_VDI_LEN, inode.name);
	pstrcpy(tag, SD_MAX_VDI_TAG_LEN, inode.tag);

	return SD_RES_SUCCESS;
}

static int vdi_cache_info(int argc, char **argv)
{
	struct object_cache_info info = {};
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret, i;

	sd_init_req(&hdr, SD_OP_GET_CACHE_INFO);
	hdr.data_length = sizeof(info);
	ret = dog_exec_req(&sd_nid, &hdr, &info);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("failed to get cache infomation: %s",
		       sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	fprintf(stdout, "Name\tTag\tTotal\tDirty\tClean\n");
	for (i = 0; i < info.count; i++) {
		uint64_t total = info.caches[i].total * SD_DATA_OBJ_SIZE,
			 dirty = info.caches[i].dirty * SD_DATA_OBJ_SIZE,
			 clean = total - dirty;
		char name[SD_MAX_VDI_LEN], tag[SD_MAX_VDI_TAG_LEN];

		ret = vid_to_name_tag(info.caches[i].vid, name, tag);
		if (ret != SD_RES_SUCCESS)
			return EXIT_FAILURE;
		fprintf(stdout, "%s\t%s\t%s\t%s\t%s\n",
			name, tag, strnumber(total), strnumber(dirty),
			strnumber(clean));
	}

	fprintf(stdout, "\nCache size %s, used %s, %s\n",
		strnumber(info.size), strnumber(info.used),
		info.directio ? "directio" : "non-directio");

	return EXIT_SUCCESS;
}

static int vdi_cache_purge(int argc, char **argv)
{
	const char *vdiname;
	struct sd_req hdr;
	uint32_t vid;
	int ret = EXIT_SUCCESS;

	sd_init_req(&hdr, SD_OP_CACHE_PURGE);

	if (optind < argc) {
		vdiname = argv[optind++];
		ret = find_vdi_name(vdiname, vdi_cmd_data.snapshot_id,
				    vdi_cmd_data.snapshot_tag, &vid, 0);
		if (ret < 0) {
			sd_err("Failed to open VDI %s", vdiname);
			ret = EXIT_FAILURE;
			goto out;
		}
		hdr.obj.oid = vid_to_vdi_oid(vid);
		hdr.flags = SD_FLAG_CMD_WRITE;
		hdr.data_length = 0;
	} else {
		confirm("This operation purges the cache of all the vdi"
			". Continue? [yes/no]: ");
	}

	ret = send_light_req(&sd_nid, &hdr);
	if (ret) {
		sd_err("failed to execute request");
		return EXIT_FAILURE;
	}
out:
	return ret;
}

static struct subcommand vdi_object_cmd[] = {
	{"location", NULL, NULL, "show object location information",
	 NULL, CMD_NEED_NODELIST|CMD_NEED_ARG, vdi_object_location},
	{"map", NULL, NULL, "show object map information",
	 NULL, CMD_NEED_ARG, vdi_object_map},
	{NULL},
};

static int vdi_object(int argc, char **argv)
{
	return do_generic_subcommand(vdi_object_cmd, argc, argv);
}


static struct subcommand vdi_cache_cmd[] = {
	{"flush", NULL, NULL, "flush the cache of the vdi specified.",
	 NULL, CMD_NEED_ARG, vdi_cache_flush},
	{"delete", NULL, NULL, "delete the cache of the vdi specified in all nodes.",
	 NULL, CMD_NEED_ARG, vdi_cache_delete},
	{"info", NULL, NULL, "show usage of the cache",
	 NULL, 0, vdi_cache_info},
	{"purge", NULL, NULL, "purge the cache of all vdi (no flush)",
	 NULL, 0, vdi_cache_purge},
	{NULL,},
};

static int vdi_cache(int argc, char **argv)
{
	return do_generic_subcommand(vdi_cache_cmd, argc, argv);
}

static struct subcommand vdi_cmd[] = {
	{"check", "<vdiname>", "saph", "check and repair image's consistency",
	 NULL, CMD_NEED_NODELIST|CMD_NEED_ARG,
	 vdi_check, vdi_options},
	{"create", "<vdiname> <size>", "Pycaphrv", "create an image",
	 NULL, CMD_NEED_NODELIST|CMD_NEED_ARG,
	 vdi_create, vdi_options},
	{"snapshot", "<vdiname>", "saphrv", "create a snapshot",
	 NULL, CMD_NEED_ARG,
	 vdi_snapshot, vdi_options},
	{"clone", "<src vdi> <dst vdi>", "sPcaphrv", "clone an image",
	 NULL, CMD_NEED_ARG,
	 vdi_clone, vdi_options},
	{"delete", "<vdiname>", "saph", "delete an image",
	 NULL, CMD_NEED_ARG,
	 vdi_delete, vdi_options},
	{"rollback", "<vdiname>", "saphfrv", "rollback to a snapshot",
	 NULL, CMD_NEED_ARG,
	 vdi_rollback, vdi_options},
	{"list", "[vdiname]", "aprh", "list images",
	 NULL, 0, vdi_list, vdi_options},
	{"tree", NULL, "aph", "show images in tree view format",
	 NULL, 0, vdi_tree, vdi_options},
	{"graph", NULL, "aph", "show images in Graphviz dot format",
	 NULL, 0, vdi_graph, vdi_options},
	{"object", "<vdiname>", "isaph", "show object information in the image",
	 vdi_object_cmd, CMD_NEED_ARG,
	 vdi_object, vdi_options},
	{"track", "<vdiname>", "isapho",
	 "show the object epoch trace in the image",
	 NULL, CMD_NEED_NODELIST|CMD_NEED_ARG,
	 vdi_track, vdi_options},
	{"setattr", "<vdiname> <key> [value]", "dxaph", "set a VDI attribute",
	 NULL, CMD_NEED_ARG,
	 vdi_setattr, vdi_options},
	{"getattr", "<vdiname> <key>", "aph", "get a VDI attribute",
	 NULL, CMD_NEED_ARG,
	 vdi_getattr, vdi_options},
	{"resize", "<vdiname> <new size>", "aph", "resize an image",
	 NULL, CMD_NEED_ARG,
	 vdi_resize, vdi_options},
	{"read", "<vdiname> [<offset> [<len>]]", "saph", "read data from an image",
	 NULL, CMD_NEED_ARG,
	 vdi_read, vdi_options},
	{"write", "<vdiname> [<offset> [<len>]]", "apwh", "write data to an image",
	 NULL, CMD_NEED_ARG,
	 vdi_write, vdi_options},
	{"backup", "<vdiname> <backup>", "sFaph", "create an incremental backup between two snapshots",
	 NULL, CMD_NEED_NODELIST|CMD_NEED_ARG,
	 vdi_backup, vdi_options},
	{"restore", "<vdiname> <backup>", "saph", "restore snapshot images from a backup",
	 NULL, CMD_NEED_NODELIST|CMD_NEED_ARG,
	 vdi_restore, vdi_options},
	{"cache", "<vdiname>", "saph", "Run 'dog vdi cache' for more information",
	 vdi_cache_cmd, CMD_NEED_ARG,
	 vdi_cache, vdi_options},
	{NULL,},
};

static int vdi_parser(int ch, const char *opt)
{
	char *p;

	switch (ch) {
	case 'P':
		vdi_cmd_data.prealloc = true;
		break;
	case 'i':
		vdi_cmd_data.index = strtol(opt, &p, 10);
		if (opt == p) {
			sd_err("The index must be an integer");
			exit(EXIT_FAILURE);
		}
		break;
	case 's':
		vdi_cmd_data.snapshot_id = strtol(opt, &p, 10);
		if (opt == p) {
			vdi_cmd_data.snapshot_id = 0;
			pstrcpy(vdi_cmd_data.snapshot_tag,
				sizeof(vdi_cmd_data.snapshot_tag), opt);
		} else if (vdi_cmd_data.snapshot_id == 0) {
			fprintf(stderr,
				"The snapshot id must be larger than zero\n");
			exit(EXIT_FAILURE);
		}
		break;
	case 'x':
		vdi_cmd_data.exclusive = true;
		break;
	case 'd':
		vdi_cmd_data.delete = true;
		break;
	case 'w':
		vdi_cmd_data.writeback = true;
		break;
	case 'c':
		vdi_cmd_data.nr_copies = parse_copy(opt,
						    &vdi_cmd_data.copy_policy);
		if (!vdi_cmd_data.nr_copies) {
			sd_err("Invalid parameter %s\n"
			       "To create replicated vdi, set -c x\n"
			       "  x(1 to %d)   - number of replicated copies\n"
			       "To create erasure coded vdi, set -c x:y\n"
			       "  x(2,4,8,16)  - number of data strips\n"
			       "  y(1 to 15)   - number of parity strips",
			       opt, SD_MAX_COPIES);
			exit(EXIT_FAILURE);
		}
		break;
	case 'F':
		vdi_cmd_data.from_snapshot_id = strtol(opt, &p, 10);
		if (opt == p) {
			vdi_cmd_data.from_snapshot_id = 0;
			pstrcpy(vdi_cmd_data.from_snapshot_tag,
				sizeof(vdi_cmd_data.from_snapshot_tag), opt);
		}
		break;
	case 'f':
		vdi_cmd_data.force = true;
		break;
	case 'y':
		vdi_cmd_data.store_policy = 1;
		break;
	case 'o':
		vdi_cmd_data.oid = strtoll(opt, &p, 16);
		if (opt == p) {
			sd_err("object id must be a hex integer");
			exit(EXIT_FAILURE);
		}
		break;
	}

	return 0;
}

struct command vdi_command = {
	"vdi",
	vdi_cmd,
	vdi_parser
};
