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

static struct sd_option vdi_options[] = {
	{'P', "prealloc", false, "preallocate all the data objects"},
	{'i', "index", true, "specify the index of data objects"},
	{'s', "snapshot", true, "specify a snapshot id or tag name"},
	{'x', "exclusive", false, "write in an exclusive mode"},
	{'d', "delete", false, "delete a key"},
	{'w', "writeback", false, "use writeback mode"},
	{'c', "copies", true, "specify the data redundancy (number of copies)"},
	{'F', "from", true, "create a differential backup from the snapshot"},
	{'f', "force", false, "do operation forcibly"},
	{ 0, NULL, false, NULL },
};

static struct vdi_cmd_data {
	unsigned int index;
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
} vdi_cmd_data = { ~0, };

struct get_vdi_info {
	const char *name;
	const char *tag;
	uint32_t vid;
	uint32_t snapid;
	uint8_t nr_copies;
};

static int parse_option_size(const char *value, uint64_t *ret)
{
	char *postfix;
	double sizef;

	sizef = strtod(value, &postfix);
	switch (*postfix) {
	case 'T':
		sizef *= 1024;
	case 'G':
		sizef *= 1024;
	case 'M':
		sizef *= 1024;
	case 'K':
	case 'k':
		sizef *= 1024;
	case 'b':
	case '\0':
		*ret = (uint64_t) sizef;
		break;
	default:
		sd_err("Invalid size '%s'", value);
		sd_err("You may use k, M, G or T suffixes for "
		       "kilobytes, megabytes, gigabytes and terabytes.");
		return -1;
	}

	return 0;
}

static void vdi_show_progress(uint64_t done, uint64_t total)
{
	return show_progress(done, total, false);
}

static void print_vdi_list(uint32_t vid, const char *name, const char *tag,
			   uint32_t snapid, uint32_t flags,
			   const struct sd_inode *i, void *data)
{
	int idx;
	bool is_clone = false;
	uint64_t my_objs, cow_objs;
	char vdi_size_str[16], my_objs_str[16], cow_objs_str[16];
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

	my_objs = 0;
	cow_objs = 0;
	for (idx = 0; idx < MAX_DATA_OBJS; idx++) {
		if (!i->data_vdi_id[idx])
			continue;
		if (is_data_obj_writeable(i, idx))
			my_objs++;
		else
			cow_objs++;
	}

	size_to_str(i->vdi_size, vdi_size_str, sizeof(vdi_size_str));
	size_to_str(my_objs * SD_DATA_OBJ_SIZE, my_objs_str, sizeof(my_objs_str));
	size_to_str(cow_objs * SD_DATA_OBJ_SIZE, cow_objs_str, sizeof(cow_objs_str));

	if (i->snap_id == 1 && i->parent_vdi_id != 0)
		is_clone = true;

	if (raw_output) {
		printf("%c ", vdi_is_snapshot(i) ? 's' : (is_clone ? 'c' : '='));
		while (*name) {
			if (isspace(*name) || *name == '\\')
				putchar('\\');
			putchar(*name++);
		}
		printf(" %d %s %s %s %s %" PRIx32 " %d %s\n", snapid,
				vdi_size_str, my_objs_str, cow_objs_str, dbuf, vid,
				i->nr_copies, i->tag);
	} else {
		printf("%c %-8s %5d %7s %7s %7s %s  %7" PRIx32 " %5d %13s\n",
				vdi_is_snapshot(i) ? 's' : (is_clone ? 'c' : ' '),
				name, snapid, vdi_size_str, my_objs_str, cow_objs_str,
				dbuf, vid, i->nr_copies, i->tag);
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
	char dbuf[128], tbuf[128], size_str[128];

	ti = i->create_time >> 32;
	localtime_r(&ti, &tm);

	strftime(dbuf, sizeof(dbuf), "%Y-%m-%d", &tm);
	strftime(tbuf, sizeof(tbuf), "%H:%M:%S", &tm);
	size_to_str(i->vdi_size, size_str, sizeof(size_str));

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
	       name, snapid, size_str, dbuf, tbuf);

	if (vdi_is_snapshot(i))
		printf("\"\n  ];\n\n");
	else
		printf("\",\n    color=\"red\"\n  ];\n\n");

}

static void get_oid(uint32_t vid, const char *name, const char *tag,
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
			}
		} else if (info->snapid) {
			if (!strcmp(name, info->name) &&
			    snapid == info->snapid) {
				info->vid = vid;
				info->nr_copies = i->nr_copies;
			}
		} else {
			if (!strcmp(name, info->name)) {
				info->vid = vid;
				info->nr_copies = i->nr_copies;
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
		printf("%s has the object (should be %d copies)\n",
		       sheep, rsp->obj.copies);
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

struct get_data_oid_info {
	bool success;
	uint64_t data_oid;
	unsigned idx;
};

static int get_data_oid(const char *sheep, uint64_t oid, struct sd_rsp *rsp,
			char *buf, void *data)
{
	struct get_data_oid_info *info = data;
	struct sd_inode *inode = (struct sd_inode *)buf;

	switch (rsp->result) {
	case SD_RES_SUCCESS:
		if (info->success)
			break;
		info->success = true;
		if (inode->data_vdi_id[info->idx]) {
			info->data_oid = vid_to_data_oid(inode->data_vdi_id[info->idx], info->idx);
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

static void parse_objs(uint64_t oid, obj_parser_func_t func, void *data, unsigned size)
{
	int i, ret, cb_ret;
	char *buf;

	buf = xzalloc(size);
	for (i = 0; i < sd_nodes_nr; i++) {
		struct sd_req hdr;
		struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

		sd_init_req(&hdr, SD_OP_READ_PEER);
		hdr.data_length = size;
		hdr.flags = 0;
		hdr.epoch = sd_epoch;

		hdr.obj.oid = oid;

		ret = dog_exec_req(sd_nodes[i].nid.addr,
				      sd_nodes[i].nid.port, &hdr, buf);
		if (ret < 0)
			continue;

		untrim_zero_blocks(buf, rsp->obj.offset, rsp->data_length,
				   size);

		cb_ret = func(addr_to_str(sd_nodes[i].nid.addr,
					  sd_nodes[i].nid.port),
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

	ret = dog_exec_req(sdhost, sdport, &hdr, buf);
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

	ret = sd_read_object(vid_to_vdi_oid(vid), inode, size, 0, true);
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
			 int nr_copies)
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

	ret = dog_exec_req(sdhost, sdport, &hdr, buf);
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
	int idx, max_idx, ret, nr_copies = vdi_cmd_data.nr_copies;
	struct sd_inode *inode = NULL;

	if (!argv[optind]) {
		sd_err("Please specify the VDI size");
		return EXIT_USAGE;
	}
	ret = parse_option_size(argv[optind], &size);
	if (ret < 0)
		return EXIT_USAGE;
	if (size > SD_MAX_VDI_SIZE) {
		sd_err("VDI size is too large");
		return EXIT_USAGE;
	}

	if (nr_copies > sd_nodes_nr) {
		sd_err("There are not enough nodes(%d) to hold the copies(%d)",
		       sd_nodes_nr, nr_copies);
		return EXIT_USAGE;
	}

	ret = do_vdi_create(vdiname, size, 0, &vid, false,
			    vdi_cmd_data.nr_copies);
	if (ret != EXIT_SUCCESS || !vdi_cmd_data.prealloc)
		goto out;

	inode = xmalloc(sizeof(*inode));

	ret = sd_read_object(vid_to_vdi_oid(vid), inode, sizeof(*inode), 0, true);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to read a newly created VDI object");
		ret = EXIT_FAILURE;
		goto out;
	}
	max_idx = DIV_ROUND_UP(size, SD_DATA_OBJ_SIZE);

	for (idx = 0; idx < max_idx; idx++) {
		vdi_show_progress(idx * SD_DATA_OBJ_SIZE, inode->vdi_size);
		oid = vid_to_data_oid(vid, idx);

		ret = sd_write_object(oid, 0, NULL, 0, 0, 0, inode->nr_copies,
				      true, true);
		if (ret != SD_RES_SUCCESS) {
			ret = EXIT_FAILURE;
			goto out;
		}

		inode->data_vdi_id[idx] = vid;
		ret = sd_write_object(vid_to_vdi_oid(vid), 0, &vid, sizeof(vid),
				      SD_INODE_HEADER_SIZE + sizeof(vid) * idx, 0,
				      inode->nr_copies, false, true);
		if (ret) {
			ret = EXIT_FAILURE;
			goto out;
		}
	}
	vdi_show_progress(idx * SD_DATA_OBJ_SIZE, inode->vdi_size);
	ret = EXIT_SUCCESS;

	if (verbose) {
		if (raw_output)
			printf("%x\n", vid);
		else
			printf("VDI ID of newly created VDI: %x\n", vid);
	}

out:
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

	ret = sd_write_object(vid_to_vdi_oid(vid), 0, vdi_cmd_data.snapshot_tag,
			      SD_MAX_VDI_TAG_LEN,
			      offsetof(struct sd_inode, tag),
			      0, inode->nr_copies, false, false);
	if (ret != SD_RES_SUCCESS)
		return EXIT_FAILURE;

	ret = do_vdi_create(vdiname, inode->vdi_size, vid, NULL, true,
			    inode->nr_copies);

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
	uint32_t base_vid, new_vid;
	uint64_t oid;
	int idx, max_idx, ret;
	struct sd_inode *inode = NULL;
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
			    vdi_cmd_data.nr_copies);
	if (ret != EXIT_SUCCESS || !vdi_cmd_data.prealloc)
		goto out;

	buf = xzalloc(SD_DATA_OBJ_SIZE);
	max_idx = DIV_ROUND_UP(inode->vdi_size, SD_DATA_OBJ_SIZE);

	for (idx = 0; idx < max_idx; idx++) {
		vdi_show_progress(idx * SD_DATA_OBJ_SIZE, inode->vdi_size);
		if (inode->data_vdi_id[idx]) {
			oid = vid_to_data_oid(inode->data_vdi_id[idx], idx);
			ret = sd_read_object(oid, buf, SD_DATA_OBJ_SIZE, 0, true);
			if (ret) {
				ret = EXIT_FAILURE;
				goto out;
			}
		} else
			memset(buf, 0, SD_DATA_OBJ_SIZE);

		oid = vid_to_data_oid(new_vid, idx);
		ret = sd_write_object(oid, 0, buf, SD_DATA_OBJ_SIZE, 0, 0,
				      inode->nr_copies, true, true);
		if (ret != SD_RES_SUCCESS) {
			ret = EXIT_FAILURE;
			goto out;
		}

		ret = sd_write_object(vid_to_vdi_oid(new_vid), 0, &new_vid, sizeof(new_vid),
				      SD_INODE_HEADER_SIZE + sizeof(new_vid) * idx, 0,
				      inode->nr_copies, false, true);
		if (ret) {
			ret = EXIT_FAILURE;
			goto out;
		}
	}
	vdi_show_progress(idx * SD_DATA_OBJ_SIZE, inode->vdi_size);
	ret = EXIT_SUCCESS;

	if (verbose) {
		if (raw_output)
			printf("%x\n", new_vid);
		else
			printf("VDI ID of newly created clone: %x\n", new_vid);
	}
out:
	free(inode);
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
	ret = parse_option_size(argv[optind], &new_size);
	if (ret < 0)
		return EXIT_USAGE;
	if (new_size > SD_MAX_VDI_SIZE) {
		sd_err("New VDI size is too large");
		return EXIT_USAGE;
	}

	ret = read_vdi_obj(vdiname, 0, "", &vid, inode, SD_INODE_HEADER_SIZE);
	if (ret != EXIT_SUCCESS)
		return ret;

	if (new_size < inode->vdi_size) {
		sd_err("Shrinking VDIs is not implemented");
		return EXIT_USAGE;
	}
	inode->vdi_size = new_size;

	ret = sd_write_object(vid_to_vdi_oid(vid), 0, inode, SD_INODE_HEADER_SIZE, 0,
			      0, inode->nr_copies, false, true);
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

	ret = send_light_req(&hdr, sdhost, sdport);
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

	ret = dog_exec_req(sdhost, sdport, &hdr, data);
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
	char *vdiname = argv[optind];

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
			     false, vdi_cmd_data.nr_copies);

	if (ret == EXIT_SUCCESS && verbose) {
		if (raw_output)
			printf("%x\n", new_vid);
		else
			printf("New VDI ID of rollbacked VDI: %x\n", new_vid);
	}

	return ret;
}

static int vdi_object(int argc, char **argv)
{
	const char *vdiname = argv[optind];
	unsigned idx = vdi_cmd_data.index;
	struct get_vdi_info info;
	uint32_t vid;

	memset(&info, 0, sizeof(info));
	info.name = vdiname;
	info.tag = vdi_cmd_data.snapshot_tag;
	info.vid = 0;
	info.snapid = vdi_cmd_data.snapshot_id;

	if (parse_vdi(get_oid, SD_INODE_HEADER_SIZE, &info) < 0)
		return EXIT_SYSFAIL;

	vid = info.vid;
	if (vid == 0) {
		sd_err("VDI not found");
		return EXIT_MISSING;
	}

	if (idx == ~0) {
		printf("Looking for the inode object 0x%" PRIx32 " with %d nodes\n\n",
		       vid, sd_nodes_nr);
		parse_objs(vid_to_vdi_oid(vid), do_print_obj, NULL, SD_INODE_SIZE);
	} else {
		struct get_data_oid_info oid_info = {0};

		oid_info.success = false;
		oid_info.idx = idx;

		if (idx >= MAX_DATA_OBJS) {
			printf("The offset is too large!\n");
			exit(EXIT_FAILURE);
		}

		parse_objs(vid_to_vdi_oid(vid), get_data_oid, &oid_info, SD_DATA_OBJ_SIZE);

		if (oid_info.success) {
			if (oid_info.data_oid) {
				printf("Looking for the object 0x%" PRIx64
				       " (the inode vid 0x%" PRIx32 " idx %u) with %d nodes\n\n",
				       oid_info.data_oid, vid, idx, sd_nodes_nr);

				parse_objs(oid_info.data_oid, do_print_obj, NULL, SD_DATA_OBJ_SIZE);
			} else
				printf("The inode object 0x%" PRIx32 " idx %u is not allocated\n",
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
	struct sd_vnode *vnodes;
	const struct sd_vnode *vnode_buf[SD_MAX_COPIES];
	struct epoch_log *logs;
	int vnodes_nr, nr_logs, log_length;

	log_length = sd_epoch * sizeof(struct epoch_log);
	logs = xmalloc(log_length);
	vnodes = xmalloc(sizeof(*vnodes) * SD_MAX_VNODES);

	sd_init_req(&hdr, SD_OP_STAT_CLUSTER);
	hdr.data_length = log_length;

	ret = dog_exec_req(sdhost, sdport, &hdr, logs);
	if (ret < 0)
		goto error;

	if (rsp->result != SD_RES_SUCCESS) {
		printf("%s\n", sd_strerror(rsp->result));
		goto error;
	}

	nr_logs = rsp->data_length / sizeof(struct epoch_log);
	for (i = nr_logs - 1; i >= 0; i--) {
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
		vnodes_nr = nodes_to_vnodes(logs[i].nodes,
					    logs[i].nr_nodes, vnodes);
		oid_to_vnodes(vnodes, vnodes_nr, oid, nr_copies, vnode_buf);
		for (j = 0; j < nr_copies; j++) {
			const struct node_id *n = &vnode_buf[j]->nid;

			printf("%s\n", addr_to_str(n->addr, n->port));
		}
	}

	free(logs);
	free(vnodes);
	return EXIT_SUCCESS;
error:
	free(logs);
	free(vnodes);
	return EXIT_SYSFAIL;
}

static int vdi_track(int argc, char **argv)
{
	const char *vdiname = argv[optind];
	unsigned idx = vdi_cmd_data.index;
	struct get_vdi_info info;
	struct get_data_oid_info oid_info = {0};
	uint32_t vid;
	uint8_t nr_copies;

	memset(&info, 0, sizeof(info));
	info.name = vdiname;
	info.tag = vdi_cmd_data.snapshot_tag;
	info.vid = 0;
	info.snapid = vdi_cmd_data.snapshot_id;

	if (parse_vdi(get_oid, SD_INODE_HEADER_SIZE, &info) < 0)
		return EXIT_SYSFAIL;

	vid = info.vid;
	nr_copies = info.nr_copies;
	if (vid == 0) {
		sd_err("VDI not found");
		return EXIT_MISSING;
	}

	if (idx == ~0) {
		printf("Tracking the inode object 0x%" PRIx32 " with %d nodes\n",
		       vid, sd_nodes_nr);
		return do_track_object(vid_to_vdi_oid(vid), nr_copies);
	}

	oid_info.success = false;
	oid_info.idx = idx;

	if (idx >= MAX_DATA_OBJS) {
		printf("The offset is too large!\n");
		goto err;
	}

	parse_objs(vid_to_vdi_oid(vid), get_data_oid,
		   &oid_info, SD_DATA_OBJ_SIZE);

	if (!oid_info.success) {
		sd_err("Failed to read the inode object 0x%" PRIx32, vid);
		goto err;
	}
	if (!oid_info.data_oid) {
		printf("The inode object 0x%"PRIx32" idx %u is not allocated\n",
		       vid, idx);
		goto err;
	}
	printf("Tracking the object 0x%" PRIx64
	       " (the inode vid 0x%" PRIx32 " idx %u)"
	       " with %d nodes\n",
	       oid_info.data_oid, vid, idx, sd_nodes_nr);
	return do_track_object(oid_info.data_oid, nr_copies);
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

	ret = dog_exec_req(sdhost, sdport, &hdr, &vattr);
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

	ret = sd_read_object(oid, &vattr, SD_ATTR_OBJ_SIZE, 0, true);
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
	int ret, idx;
	struct sd_inode *inode = NULL;
	uint64_t offset = 0, oid, done = 0, total = (uint64_t) -1;
	unsigned int len;
	char *buf = NULL;

	if (argv[optind]) {
		ret = parse_option_size(argv[optind++], &offset);
		if (ret < 0)
			return EXIT_USAGE;
		if (argv[optind]) {
			ret = parse_option_size(argv[optind++], &total);
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

		if (inode->data_vdi_id[idx]) {
			oid = vid_to_data_oid(inode->data_vdi_id[idx], idx);
			ret = sd_read_object(oid, buf, len, offset, false);
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
	uint32_t vid, flags;
	int ret, idx;
	struct sd_inode *inode = NULL;
	uint64_t offset = 0, oid, old_oid, done = 0, total = (uint64_t) -1;
	unsigned int len;
	char *buf = NULL;
	bool create;

	if (argv[optind]) {
		ret = parse_option_size(argv[optind++], &offset);
		if (ret < 0)
			return EXIT_USAGE;
		if (argv[optind]) {
			ret = parse_option_size(argv[optind++], &total);
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

		if (!inode->data_vdi_id[idx])
			create = true;
		else if (!is_data_obj_writeable(inode, idx)) {
			create = true;
			old_oid = vid_to_data_oid(inode->data_vdi_id[idx], idx);
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

		inode->data_vdi_id[idx] = inode->vdi_id;
		oid = vid_to_data_oid(inode->data_vdi_id[idx], idx);
		ret = sd_write_object(oid, old_oid, buf, len, offset, flags,
				      inode->nr_copies, create, false);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to write VDI");
			ret = EXIT_FAILURE;
			goto out;
		}

		if (create) {
			ret = sd_write_object(vid_to_vdi_oid(vid), 0, &vid, sizeof(vid),
					      SD_INODE_HEADER_SIZE + sizeof(vid) * idx,
					      flags, inode->nr_copies, false, false);
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

	ret = dog_exec_req(vnode->nid.addr, vnode->nid.port, &hdr, buf);

	if (ret < 0)
		exit(EXIT_SYSFAIL);

	switch (rsp->result) {
	case SD_RES_SUCCESS:
		untrim_zero_blocks(buf, rsp->obj.offset, rsp->data_length,
				   size);
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
			    void *buf, bool create)
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

	ret = dog_exec_req(vnode->nid.addr, vnode->nid.port, &hdr, buf);

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
	bool object_found;
	struct work work;
};

struct vdi_check_info {
	uint64_t oid;
	int nr_copies;
	uint64_t total;
	uint64_t *done;
	int refcnt;
	struct work_queue *wq;
	struct vdi_check_work *base;
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

	buf = read_object_from(info->base->vnode, info->oid);
	write_object_to(vcw->vnode, info->oid, buf, !vcw->object_found);
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

static void vdi_hash_check_work(struct work *work)
{
	struct vdi_check_work *vcw = container_of(work, struct vdi_check_work,
						  work);
	struct vdi_check_info *info = vcw->info;
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

	sd_init_req(&hdr, SD_OP_GET_HASH);
	hdr.obj.oid = info->oid;
	hdr.obj.tgt_epoch = sd_epoch;

	ret = dog_exec_req(vcw->vnode->nid.addr, vcw->vnode->nid.port, &hdr,
			      NULL);
	if (ret < 0)
		exit(EXIT_SYSFAIL);

	switch (ret) {
	case SD_RES_SUCCESS:
		vcw->object_found = true;
		memcpy(vcw->hash, rsp->hash.digest, sizeof(vcw->hash));
		uatomic_set(&info->base, vcw);
		break;
	case SD_RES_NO_OBJ:
		vcw->object_found = false;
		break;
	default:
		sd_err("failed to read %" PRIx64 " from %s, %s", info->oid,
		       addr_to_str(vcw->vnode->nid.addr, vcw->vnode->nid.port),
		       sd_strerror(ret));
		exit(EXIT_FAILURE);
	}
}

static void vdi_hash_check_main(struct work *work)
{
	struct vdi_check_work *vcw = container_of(work, struct vdi_check_work,
						  work);
	struct vdi_check_info *info = vcw->info;

	info->refcnt--;
	if (info->refcnt > 0)
		return;

	if (info->base  == NULL) {
		sd_err("no node has %" PRIx64, info->oid);
		exit(EXIT_FAILURE);
	}

	for (int i = 0; i < info->nr_copies; i++) {
		if (&info->vcw[i] == info->base)
			continue;
		/* need repair when object not found or consistency broken */
		if (!info->vcw[i].object_found ||
		    memcmp(info->base->hash, info->vcw[i].hash,
			   sizeof(info->base->hash)) != 0) {
			info->vcw[i].work.fn = vdi_repair_work;
			info->vcw[i].work.done = vdi_repair_main;
			info->refcnt++;
			queue_work(info->wq, &info->vcw[i].work);
		}
	}

	if (info->refcnt == 0)
		free_vdi_check_info(info);
}

static void queue_vdi_check_work(struct sd_inode *inode, uint64_t oid,
				 uint64_t *done, struct work_queue *wq)
{
	struct vdi_check_info *info;
	const struct sd_vnode *tgt_vnodes[SD_MAX_COPIES];
	int nr_copies = inode->nr_copies;

	info = xzalloc(sizeof(*info) + sizeof(info->vcw[0]) * nr_copies);
	info->oid = oid;
	info->nr_copies = nr_copies;
	info->total = inode->vdi_size;
	info->done = done;
	info->wq = wq;

	oid_to_vnodes(sd_vnodes, sd_vnodes_nr, oid, nr_copies, tgt_vnodes);
	for (int i = 0; i < nr_copies; i++) {
		info->vcw[i].info = info;
		info->vcw[i].vnode = tgt_vnodes[i];
		info->vcw[i].work.fn = vdi_hash_check_work;
		info->vcw[i].work.done = vdi_hash_check_main;
		info->refcnt++;
		queue_work(info->wq, &info->vcw[i].work);
	}
}

static int vdi_check(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	int ret, max_idx;
	uint64_t done = 0, oid;
	uint32_t vid;
	struct sd_inode *inode = xmalloc(sizeof(*inode));
	struct work_queue *wq;

	ret = read_vdi_obj(vdiname, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, &vid, inode,
			   SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS) {
		sd_err("FATAL: no inode objects");
		goto out;
	}
	if (sd_nodes_nr < inode->nr_copies) {
		sd_err("ABORT: Not enough active nodes for consistency-check");
		return EXIT_FAILURE;
	}

	wq = create_work_queue("vdi check", WQ_DYNAMIC);

	queue_vdi_check_work(inode, vid_to_vdi_oid(vid), NULL, wq);

	max_idx = DIV_ROUND_UP(inode->vdi_size, SD_DATA_OBJ_SIZE);
	vdi_show_progress(done, inode->vdi_size);
	for (int idx = 0; idx < max_idx; idx++) {
		vid = inode->data_vdi_id[idx];
		if (vid) {
			oid = vid_to_data_oid(vid, idx);
			queue_vdi_check_work(inode, oid, &done, wq);
		} else {
			done += SD_DATA_OBJ_SIZE;
			vdi_show_progress(done, inode->vdi_size);
		}
	}

	work_queue_wait(wq);

	fprintf(stdout, "finish check&repair %s\n", vdiname);
	return EXIT_SUCCESS;
out:
	return ret;
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

static int get_obj_backup(int idx, uint32_t from_vid, uint32_t to_vid,
			  struct obj_backup *backup)
{
	int ret;
	uint8_t *from_data = xzalloc(SD_DATA_OBJ_SIZE);

	backup->idx = idx;
	backup->offset = 0;
	backup->length = SD_DATA_OBJ_SIZE;

	if (to_vid) {
		ret = sd_read_object(vid_to_data_oid(to_vid, idx), backup->data,
				     SD_DATA_OBJ_SIZE, 0, true);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to read object %" PRIx32 ", %d", to_vid,
			       idx);
			return EXIT_FAILURE;
		}
	} else
		memset(backup->data, 0, SD_DATA_OBJ_SIZE);

	if (from_vid) {
		ret = sd_read_object(vid_to_data_oid(from_vid, idx), from_data,
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
	int ret = EXIT_SUCCESS, idx, nr_objs;
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

	nr_objs = DIV_ROUND_UP(to_inode->vdi_size, SD_DATA_OBJ_SIZE);

	ret = xwrite(STDOUT_FILENO, &hdr, sizeof(hdr));
	if (ret < 0) {
		sd_err("failed to write backup header, %m");
		ret = EXIT_SYSFAIL;
		goto out;
	}

	for (idx = 0; idx < nr_objs; idx++) {
		uint32_t from_vid = from_inode->data_vdi_id[idx];
		uint32_t to_vid = to_inode->data_vdi_id[idx];

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
	uint32_t parent_vid = parent_inode->data_vdi_id[backup->idx];
	uint64_t parent_oid = 0;

	if (parent_vid)
		parent_oid = vid_to_data_oid(parent_vid, backup->idx);

	/* send a copy-on-write request */
	ret = sd_write_object(vid_to_data_oid(vid, backup->idx), parent_oid,
			      backup->data, backup->length, backup->offset,
			      0, parent_inode->nr_copies, true, true);
	if (ret != SD_RES_SUCCESS)
		return ret;

	return sd_write_object(vid_to_vdi_oid(vid), 0, &vid, sizeof(vid),
			       SD_INODE_HEADER_SIZE + sizeof(vid) * backup->idx,
			       0, parent_inode->nr_copies, false, true);
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
			    false, inode->nr_copies);
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
	struct sd_inode *current_inode = xzalloc(sizeof(*current_inode));
	struct sd_inode *parent_inode = (struct sd_inode *)buf;
	bool need_current_recovery = false;

	if (!vdi_cmd_data.snapshot_id && !vdi_cmd_data.snapshot_tag[0]) {
		sd_err("We can restore a backup file only to snapshots");
		sd_err("Please specify the '-s' option");
		ret = EXIT_USAGE;
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

	ret = sd_read_object(vid_to_vdi_oid(current_inode->parent_vdi_id),
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
					     true, current_inode->nr_copies);
		if (recovery_ret != EXIT_SUCCESS) {
			sd_err("failed to resume the current vdi");
			ret = recovery_ret;
		}
	}
	free(current_inode);
	return ret;
}

static int vdi_cache_flush(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	struct sd_req hdr;
	uint32_t vid;
	int ret = EXIT_SUCCESS;

	ret = find_vdi_name(vdiname, vdi_cmd_data.snapshot_id,
			    vdi_cmd_data.snapshot_tag, &vid, 0);
	if (ret < 0) {
		sd_err("Failed to open VDI %s", vdiname);
		ret = EXIT_FAILURE;
		goto out;
	}

	sd_init_req(&hdr, SD_OP_FLUSH_VDI);
	hdr.obj.oid = vid_to_vdi_oid(vid);

	ret = send_light_req(&hdr, sdhost, sdport);
	if (ret) {
		sd_err("failed to execute request");
		return EXIT_FAILURE;
	}
out:
	return ret;
}

static int vdi_cache_delete(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	struct sd_req hdr;
	uint32_t vid;
	int ret = EXIT_SUCCESS;

	ret = find_vdi_name(vdiname, vdi_cmd_data.snapshot_id,
			    vdi_cmd_data.snapshot_tag, &vid, 0);
	if (ret < 0) {
		sd_err("Failed to open VDI %s", vdiname);
		ret = EXIT_FAILURE;
		goto out;
	}

	sd_init_req(&hdr, SD_OP_DELETE_CACHE);
	hdr.obj.oid = vid_to_vdi_oid(vid);

	ret = send_light_req(&hdr, sdhost, sdport);
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

	ret = sd_read_object(vid_to_vdi_oid(vid), &inode, SD_INODE_HEADER_SIZE,
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
	char size_str[UINT64_DECIMAL_SIZE], used_str[UINT64_DECIMAL_SIZE];
	int ret, i;

	sd_init_req(&hdr, SD_OP_GET_CACHE_INFO);
	hdr.data_length = sizeof(info);
	ret = dog_exec_req(sdhost, sdport, &hdr, &info);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("failed to get cache infomation: %s",
		       sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	fprintf(stdout, "Name\tTag\tTotal\tDirty\tClean\n");
	for (i = 0; i < info.count; i++) {
		char total_str[UINT64_DECIMAL_SIZE],
		     dirty_str[UINT64_DECIMAL_SIZE],
		     clean_str[UINT64_DECIMAL_SIZE];
		uint64_t total = info.caches[i].total * SD_DATA_OBJ_SIZE,
			 dirty = info.caches[i].dirty * SD_DATA_OBJ_SIZE,
			 clean = total - dirty;
		char name[SD_MAX_VDI_LEN], tag[SD_MAX_VDI_TAG_LEN];

		size_to_str(total, total_str, sizeof(total_str));
		size_to_str(dirty, dirty_str, sizeof(dirty_str));
		size_to_str(clean, clean_str, sizeof(clean_str));
		ret = vid_to_name_tag(info.caches[i].vid, name, tag);
		if (ret != SD_RES_SUCCESS)
			return EXIT_FAILURE;
		fprintf(stdout, "%s\t%s\t%s\t%s\t%s\n",
			name, tag, total_str, dirty_str, clean_str);
	}

	size_to_str(info.size, size_str, sizeof(size_str));
	size_to_str(info.used, used_str, sizeof(used_str));
	fprintf(stdout, "\nCache size %s, used %s\n", size_str, used_str);

	return EXIT_SUCCESS;
}

static struct subcommand vdi_cache_cmd[] = {
	{"flush", NULL, NULL, "flush the cache of the vdi specified.",
	 NULL, CMD_NEED_ARG, vdi_cache_flush},
	{"delete", NULL, NULL, "delete the cache of the vdi specified in all nodes.",
	 NULL, CMD_NEED_ARG, vdi_cache_delete},
	{"info", NULL, NULL, "show usage of the cache",
	 NULL, 0, vdi_cache_info},
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
	{"create", "<vdiname> <size>", "Pcaphrv", "create an image",
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
	 NULL, CMD_NEED_NODELIST|CMD_NEED_ARG,
	 vdi_object, vdi_options},
	{"track", "<vdiname>", "isaph", "show the object epoch trace in the image",
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

static int vdi_parser(int ch, char *opt)
{
	char *p;
	int nr_copies;

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
		nr_copies = strtol(opt, &p, 10);
		if (opt == p || nr_copies < 0 || nr_copies > SD_MAX_COPIES) {
			sd_err("Invalid copies number, must be "
			       "an integer between 0 and %d", SD_MAX_COPIES);
			exit(EXIT_FAILURE);
		}
		vdi_cmd_data.nr_copies = nr_copies;
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
	}

	return 0;
}

struct command vdi_command = {
	"vdi",
	vdi_cmd,
	vdi_parser
};
