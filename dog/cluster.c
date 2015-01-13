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

#include <time.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>

#include "dog.h"
#include "sheep.h"
#include "farm/farm.h"

static struct sd_option cluster_options[] = {
	{'b', "store", true, "specify backend store"},
	{'c', "copies", true, "specify the default data redundancy (number of copies)"},
	{'f', "force", false, "do not prompt for confirmation"},
	{'m', "multithread", false,
	 "use multi-thread for 'cluster snapshot save'"},
	{'t', "strict", false,
	 "do not serve write request if number of nodes is not sufficient"},
	{'z', "block_size_shift", true, "specify the shift num of default"
	      " data object size"},
	{'V', "fixedvnodes", false, "disable automatic vnodes calculation"},
	{ 0, NULL, false, NULL },
};

static struct cluster_cmd_data {
	uint8_t copies;
	uint8_t copy_policy;
	uint8_t multithread;
	uint8_t block_size_shift;
	bool force;
	bool strict;
	char name[STORE_LEN];
	bool fixed_vnodes;
} cluster_cmd_data;

#define DEFAULT_STORE	"plain"

static int list_store(void)
{
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	char buf[512] = { 0 };

	sd_init_req(&hdr, SD_OP_GET_STORE_LIST);
	hdr.data_length = 512;

	ret = dog_exec_req(&sd_nid, &hdr, buf);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Restore failed: %s", sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	printf("Available stores:\n");
	printf("---------------------------------------\n");
	printf("%s\n", buf);
	return EXIT_SYSFAIL;
}

static bool no_vdi(const unsigned long *vdis)
{
	return find_next_bit(vdis, SD_NR_VDIS, 0) == SD_NR_VDIS;
}

#define FORMAT_PRINT				\
	"    __\n"				\
	"   ()'`;\n"				\
	"   /\\|`\n"				\
	"  /  |   Caution! The cluster is not empty.\n" \
	"(/_)_|_  Are you sure you want to continue? [yes/no]: "

static int cluster_format(int argc, char **argv)
{
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	struct timeval tv;
	char store_name[STORE_LEN];
	static DECLARE_BITMAP(vdi_inuse, SD_NR_VDIS);
	struct sd_node *n;

	rb_for_each_entry(n, &sd_nroot, rb) {
		struct sd_req info_req;
		struct sd_rsp *info_rsp = (struct sd_rsp *)&info_req;
		struct cluster_info cinfo;

		sd_init_req(&info_req, SD_OP_CLUSTER_INFO);
		info_req.data_length = sizeof(cinfo);
		ret = dog_exec_req(&n->nid, &info_req, &cinfo);
		if (ret < 0) {
			sd_err("Fail to execute request");
			return EXIT_FAILURE;
		}
		if (info_rsp->result != SD_RES_SUCCESS) {
			sd_err("%s", sd_strerror(info_rsp->result));
			return EXIT_FAILURE;
		}

		if (n->nr_vnodes != 0) {
			if ((cinfo.flags & SD_CLUSTER_FLAG_AUTO_VNODES)
				&& cluster_cmd_data.fixed_vnodes) {
				sd_err("Can not apply the option of '-V', "
					"because there are vnode strategy of sheep "
					"is auto in the cluster");
				return EXIT_FAILURE;
			} else if (!(cinfo.flags & SD_CLUSTER_FLAG_AUTO_VNODES)
				&& !cluster_cmd_data.fixed_vnodes) {
				sd_err("Need to specify the option of '-V', "
					"because there are vnode strategy of sheep "
					"is fixed in the cluster");
				return EXIT_FAILURE;
			}
		}
	}

	if (cluster_cmd_data.copies > sd_nodes_nr) {
		char info[1024];
		snprintf(info, sizeof(info), "Number of copies (%d) is larger "
			 "than number of nodes (%d).\n"
			 "Are you sure you want to continue? [yes/no]: ",
			 cluster_cmd_data.copies, sd_nodes_nr);
		confirm(info);
	}

	sd_init_req(&hdr, SD_OP_READ_VDIS);
	hdr.data_length = sizeof(vdi_inuse);

	ret = dog_exec_req(&sd_nid, &hdr, vdi_inuse);
	if (ret < 0)
		return EXIT_SYSFAIL;
	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("%s", sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	if (!no_vdi(vdi_inuse))
		confirm(FORMAT_PRINT);

	gettimeofday(&tv, NULL);

	sd_init_req(&hdr, SD_OP_MAKE_FS);
	hdr.cluster.copies = cluster_cmd_data.copies;
	hdr.cluster.copy_policy = cluster_cmd_data.copy_policy;
	hdr.cluster.block_size_shift = cluster_cmd_data.block_size_shift;
	hdr.cluster.ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;

	if (strlen(cluster_cmd_data.name))
		pstrcpy(store_name, STORE_LEN, cluster_cmd_data.name);
	else
		pstrcpy(store_name, STORE_LEN, DEFAULT_STORE);
	hdr.data_length = strlen(store_name) + 1;
	hdr.flags |= SD_FLAG_CMD_WRITE;
	if (cluster_cmd_data.strict)
		hdr.cluster.flags |= SD_CLUSTER_FLAG_STRICT;

#ifdef HAVE_DISKVNODES
	hdr.cluster.flags |= SD_CLUSTER_FLAG_DISKMODE;
#endif

	if (cluster_cmd_data.fixed_vnodes)
		hdr.cluster.flags &= ~SD_CLUSTER_FLAG_AUTO_VNODES;
	else
		hdr.cluster.flags |= SD_CLUSTER_FLAG_AUTO_VNODES;

	printf("using backend %s store\n", store_name);
	ret = dog_exec_req(&sd_nid, &hdr, store_name);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Format failed: %s", sd_strerror(rsp->result));
		if (rsp->result == SD_RES_NO_STORE)
			return list_store();
		else
			return EXIT_SYSFAIL;
	}

	return EXIT_SUCCESS;
}

static void print_nodes(const struct epoch_log *logs, uint16_t flags)
{
	int i, nr_disk;
	const struct sd_node *entry;

	for (i = 0; i < logs->nr_nodes; i++) {
		entry = logs->nodes + i;
		if (flags & SD_CLUSTER_FLAG_DISKMODE) {
			for (nr_disk = 0; nr_disk < DISK_MAX; nr_disk++) {
				if (entry->disks[nr_disk].disk_id == 0)
					break;
			}
			printf("%s%s:%d(%d)",
				(i == 0) ? "" : ", ",
				addr_to_str(entry->nid.addr, entry->nid.port),
					entry->nr_vnodes, nr_disk);
		} else
			printf("%s%s:%d",
				(i == 0) ? "" : ", ",
				addr_to_str(entry->nid.addr, entry->nid.port),
					entry->nr_vnodes);
	}
}

static int cluster_info(int argc, char **argv)
{
	int i, ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	struct epoch_log *logs, *log;
	char *next_log;
	int nr_logs, log_length;
	time_t ti, ct;
	struct tm tm;
	char time_str[128];
	uint32_t nodes_nr;

	nodes_nr = sd_nodes_nr;
	log_length = sd_epoch * (sizeof(struct epoch_log)
			+ nodes_nr * sizeof(struct sd_node));
	logs = xmalloc(log_length);

retry:
	sd_init_req(&hdr, SD_OP_STAT_CLUSTER);
	hdr.data_length = log_length;
	hdr.cluster.nodes_nr = nodes_nr;

	ret = dog_exec_req(&sd_nid, &hdr, logs);
	if (ret < 0)
		goto error;
	if (rsp->result == SD_RES_BUFFER_SMALL) {
		nodes_nr *= 2;
		log_length = sd_epoch * (sizeof(struct epoch_log)
				+ nodes_nr * sizeof(struct sd_node));
		logs = xrealloc(logs, log_length);
		goto retry;
	}

	/* show cluster status */
	if (!raw_output)
		printf("Cluster status: ");
	if (rsp->result == SD_RES_SUCCESS)
		printf("running, auto-recovery %s\n", logs->disable_recovery ?
		       "disabled" : "enabled");
	else
		printf("%s\n", sd_strerror(rsp->result));

	if (verbose) {
		/* show cluster backend store */
		if (!raw_output)
			printf("Cluster store: ");
		if (rsp->result == SD_RES_SUCCESS) {
			char copy[10];
			int data, parity;
			if (!logs->copy_policy)
				snprintf(copy, sizeof(copy), "%d",
					 logs->nr_copies);
			else {
				ec_policy_to_dp(logs->copy_policy,
						&data, &parity);
				snprintf(copy, sizeof(copy), "%d:%d",
					 data, parity);
			}
			printf("%s with %s redundancy policy\n",
			       logs->drv_name, copy);

			/* show vnode strategy */
			if (!raw_output)
				printf("Cluster vnodes strategy: ");
			if (logs->flags & SD_CLUSTER_FLAG_AUTO_VNODES)
				printf("auto\n");
			else
				printf("fixed\n");

		} else
			printf("%s\n", sd_strerror(rsp->result));

		/* show vnode mode (node or disk) for cluster */
		if (!raw_output)
			printf("Cluster vnode mode: ");
		if (logs->flags & SD_CLUSTER_FLAG_DISKMODE)
			printf("disk\n");
		else
			printf("node\n");
	} else
		printf("\n");

	if (!raw_output && rsp->data_length > 0) {
		ct = logs[0].ctime >> 32;
		printf("Cluster created at %s\n", ctime(&ct));
		printf("Epoch Time           Version [Host:Port:V-Nodes,,,]");
		printf("\n");
	}

	nr_logs = rsp->data_length / (sizeof(struct epoch_log)
			+ nodes_nr * sizeof(struct sd_node));
	next_log = (char *)logs;
	for (i = 0; i < nr_logs; i++) {
		log = (struct epoch_log *)next_log;
		ti = log->time;
		if (raw_output) {
			snprintf(time_str, sizeof(time_str), "%" PRIu64, (uint64_t) ti);
		} else {
			localtime_r(&ti, &tm);
			strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm);
		}

		printf(raw_output ? "%s %d" : "%s %6d", time_str, log->epoch);
		printf(" [");
		print_nodes(log, logs->flags);
		printf("]\n");
		next_log = (char *)log->nodes
				+ nodes_nr * sizeof(struct sd_node);
	}

	free(logs);
	return EXIT_SUCCESS;
error:
	free(logs);
	return EXIT_SYSFAIL;
}

static int cluster_shutdown(int argc, char **argv)
{
	int ret;
	struct sd_req hdr;

	sd_init_req(&hdr, SD_OP_SHUTDOWN);

	ret = send_light_req(&sd_nid, &hdr);
	if (ret) {
		sd_err("failed to execute request");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static void print_list(void *buf, unsigned len)
{
	struct snap_log *log_buf = (struct snap_log *)buf;
	unsigned nr = len / sizeof(struct snap_log);

	printf("Index\t\tTag\t\tSnapshot Time\n");
	for (unsigned i = 0; i < nr; i++, log_buf++) {
		time_t *t = (time_t *)&log_buf->time;
		printf("%d\t\t", log_buf->idx);
		printf("%s\t\t", log_buf->tag);
		printf("%s", ctime(t));
	}
}

static int list_snapshot(int argc, char **argv)
{
	const char *path = argv[optind++];
	void *buf = NULL;
	int log_nr;
	int ret = EXIT_SYSFAIL;

	if (farm_init(path) != SD_RES_SUCCESS)
		goto out;

	buf = snap_log_read(&log_nr);
	if (IS_ERR(buf))
		goto out;

	print_list(buf, log_nr * sizeof(struct snap_log));
	ret = EXIT_SUCCESS;
out:
	if (ret)
		sd_err("Fail to list snapshot.");
	free(buf);
	return ret;
}

static void fill_cb(struct sd_index *idx, void *arg, int ignore)
{
	struct sd_inode *inode = (struct sd_inode *)arg;
	uint64_t oid;

	if (idx->vdi_id) {
		oid = vid_to_data_oid(idx->vdi_id, idx->idx);
		object_tree_insert(oid, inode->nr_copies,
				   inode->copy_policy, inode->block_size_shift);
	}
}

static void fill_object_tree(uint32_t vid, const char *name, const char *tag,
			     uint32_t snapid, uint32_t flags,
			     const struct sd_inode *i, void *data)
{
	uint64_t vdi_oid = vid_to_vdi_oid(vid), vmstate_oid;
	uint32_t vdi_id;
	uint32_t nr_objs, nr_vmstate_object;
	uint32_t object_size = (UINT32_C(1) << i->block_size_shift);
	struct vdi_option *opt = (struct vdi_option *)data;
	bool matched;

	/* ignore active vdi */
	if (!vdi_is_snapshot(i))
		return;

	/* iff vdi specified in command line */
	if (opt->count > 0) {
		matched = false;
		for (int n = 0; n < opt->count; n++)
			if (strcmp(name, opt->name[n]) == 0) {
				matched = true;
				break;
			}
		if (!matched)
			return;
	}

	if (i->name[0] != '\0')
		opt->nr_snapshot++;

	/* fill vdi object id */
	object_tree_insert(vdi_oid, i->nr_copies, i->copy_policy,
			   i->block_size_shift);

	/* fill data object id */
	if (i->store_policy == 0) {
		nr_objs = count_data_objs(i);
		for (uint32_t idx = 0; idx < nr_objs; idx++) {
			vdi_id = sd_inode_get_vid(i, idx);
			if (!vdi_id)
				continue;
			uint64_t oid = vid_to_data_oid(vdi_id, idx);
			object_tree_insert(oid, i->nr_copies, i->copy_policy,
					   i->block_size_shift);
		}
	} else
		sd_inode_index_walk(i, fill_cb, &i);

	/* fill vmstate object id */
	nr_vmstate_object = DIV_ROUND_UP(i->vm_state_size, object_size);
	for (uint32_t idx = 0; idx < nr_vmstate_object; idx++) {
		vmstate_oid = vid_to_vmstate_oid(vid, idx);
		object_tree_insert(vmstate_oid, i->nr_copies,
				   i->copy_policy, i->block_size_shift);
	}
}

static int save_snapshot(int argc, char **argv)
{
	const char *tag = argv[optind++];
	char *path, *p;
	int ret = EXIT_SYSFAIL, uninitialized_var(unused);
	struct vdi_option opt;

	unused = strtol(tag, &p, 10);
	if (tag != p) {
		sd_err("Tag should not start with number.");
		return EXIT_USAGE;
	}

	path = argv[optind++];
	if (!path) {
		sd_err("Please specify the path to save snapshot.");
		return EXIT_USAGE;
	}

	if (farm_init(path) != SD_RES_SUCCESS)
		goto out;

	if (farm_contain_snapshot(0, tag)) {
		sd_err("Snapshot tag has already been used for another"
		       " snapshot, please, use another one.");
		goto out;
	}

	opt.nr_snapshot = 0;
	opt.count = argc - optind;
	opt.name = argv + optind;
	if (parse_vdi(fill_object_tree, SD_INODE_SIZE,
			&opt, false) != SD_RES_SUCCESS)
		goto out;

	if (opt.nr_snapshot == 0) {
		sd_err("Cannot execute. It may be caused by:");
		if (opt.count > 0) {
			sd_err("1. The specified VDIs are not found.");
			sd_err("2. The specified VDIs don't have snapshots.");
		} else {
			sd_err("1. The cluster is empty.");
			sd_err("2. All VDIs of the cluster "
					  "don't have snapshots.");
		}
		goto out;
	}

	if (farm_save_snapshot(tag, cluster_cmd_data.multithread)
	    != SD_RES_SUCCESS)
		goto out;

	ret = EXIT_SUCCESS;
out:
	if (ret)
		sd_err("Fail to save snapshot to path: %s.", path);
	object_tree_free();
	return ret;
}

static int load_snapshot(int argc, char **argv)
{
	char *tag = argv[optind++];
	char *path, *p;
	uint32_t idx;
	int ret = EXIT_SYSFAIL;
	struct snap_log_hdr hdr;

	idx = strtol(tag, &p, 10);
	if (tag == p)
		idx = 0;

	path = argv[optind++];
	if (!path) {
		sd_err("Please specify the path to save snapshot.");
		return EXIT_USAGE;
	}

	if (farm_init(path) != SD_RES_SUCCESS)
		goto out;

	if (!farm_contain_snapshot(idx, tag)) {
		sd_err("Snapshot index or tag does not exist.");
		goto out;
	}

	if (snap_log_read_hdr(&hdr) <= 0)
		goto out;

	cluster_cmd_data.copies = hdr.copy_number;
	cluster_cmd_data.copy_policy = hdr.copy_policy;
	cluster_cmd_data.block_size_shift = hdr.block_size_shift;
	if (cluster_format(0, NULL) != SD_RES_SUCCESS)
		goto out;

	if (farm_load_snapshot(idx, tag, argc - optind, argv + optind)
			!= SD_RES_SUCCESS)
		goto out;

	ret = EXIT_SUCCESS;

out:
	if (ret)
		sd_err("Fail to load snapshot");
	return ret;
}

static int show_snapshot(int argc, char **argv)
{
	char *tag = argv[optind++];
	char *path, *p;
	uint32_t idx;
	int ret = EXIT_SYSFAIL;

	idx = strtol(tag, &p, 10);
	if (tag == p)
		idx = 0;

	path = argv[optind++];
	if (!path) {
		sd_err("Please specify the path to show snapshot.");
		return EXIT_USAGE;
	}

	if (farm_init(path) != SD_RES_SUCCESS)
		goto out;

	if (!farm_contain_snapshot(idx, tag)) {
		sd_err("Snapshot index or tag does not exist.");
		goto out;
	}

	if (farm_show_snapshot(idx, tag, argc - optind, argv + optind)
			!= SD_RES_SUCCESS)
		goto out;

	ret = EXIT_SUCCESS;

out:
	if (ret)
		sd_err("Fail to show snapshot");
	return ret;
}

#define RECOVER_PRINT \
	"Caution! Please try starting all the cluster nodes normally before\n" \
	"running this command.\n\n" \
	"The cluster may need to be force recovered if:\n" \
	"  - the master node fails to start because of epoch mismatch; or\n" \
	"  - some nodes fail to start after a cluster shutdown.\n\n" \
	"Are you sure you want to continue? [yes/no]: "

static int cluster_force_recover(int argc, char **argv)
{
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	struct sd_node nodes[SD_MAX_NODES];

	if (!cluster_cmd_data.force)
		confirm(RECOVER_PRINT);

	sd_init_req(&hdr, SD_OP_FORCE_RECOVER);
	hdr.data_length = sizeof(nodes);

	ret = dog_exec_req(&sd_nid, &hdr, nodes);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("failed to execute request, %s",
		       sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int cluster_disable_recover(int argc, char **argv)
{
	int ret;
	struct sd_req hdr;

	sd_init_req(&hdr, SD_OP_DISABLE_RECOVER);

	ret = send_light_req(&sd_nid, &hdr);
	if (ret)
		return EXIT_FAILURE;

	printf("Cluster recovery: disable\n");
	return EXIT_SUCCESS;
}

static int cluster_enable_recover(int argc, char **argv)
{
	int ret;
	struct sd_req hdr;

	sd_init_req(&hdr, SD_OP_ENABLE_RECOVER);

	ret = send_light_req(&sd_nid, &hdr);
	if (ret)
		return EXIT_FAILURE;

	printf("Cluster recovery: enable\n");
	return EXIT_SUCCESS;
}

/* Subcommand list of recover */
static struct subcommand cluster_recover_cmd[] = {
	{"force", NULL, NULL, "force recover cluster immediately",
	 NULL, 0, cluster_force_recover},
	{"enable", NULL, NULL, "enable automatic recovery and "
				"run once recover if necessary",
	 NULL, 0, cluster_enable_recover},
	{"disable", NULL, NULL, "disable automatic recovery",
	 NULL, 0, cluster_disable_recover},
	{NULL},
};

static int cluster_recover(int argc, char **argv)
{
	return do_generic_subcommand(cluster_recover_cmd, argc, argv);
}

/* Subcommand list of snapshot */
static struct subcommand cluster_snapshot_cmd[] = {
	{"save", NULL, "h", "save snapshot to localpath",
	 NULL, CMD_NEED_ARG|CMD_NEED_NODELIST,
	 save_snapshot, NULL},
	{"list", NULL, "h", "list snapshot of localpath",
	 NULL, CMD_NEED_ARG, list_snapshot, NULL},
	{"load", NULL, "h", "load snapshot from localpath",
	 NULL, CMD_NEED_ARG | CMD_NEED_NODELIST, load_snapshot, NULL},
	{"show", NULL, "h", "show vdi list from snapshot",
	 NULL, CMD_NEED_ARG | CMD_NEED_NODELIST, show_snapshot, NULL},
	{NULL},
};

static int cluster_snapshot(int argc, char **argv)
{
	return do_generic_subcommand(cluster_snapshot_cmd, argc, argv);
}

static int cluster_reweight(int argc, char **argv)
{
	int ret;
	struct sd_req hdr;

	sd_init_req(&hdr, SD_OP_REWEIGHT);
	ret = send_light_req(&sd_nid, &hdr);
	if (ret)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}

static void cluster_check_cb(uint32_t vid, const char *name, const char *tag,
			     uint32_t snapid, uint32_t flags,
			     const struct sd_inode *inode, void *data)
{
	if (vdi_is_snapshot(inode))
		printf("fix snapshot %s (id: %d, tag: \"%s\")\n", name,
		       snapid, tag);
	else
		printf("fix vdi %s\n", name);

	do_vdi_check(inode);
}

static int cluster_check(int argc, char **argv)
{
	if (parse_vdi(cluster_check_cb, SD_INODE_SIZE, NULL, true) < 0)
		return EXIT_SYSFAIL;

	return EXIT_SUCCESS;
}

#define ALTER_CLUSTER_COPY_PRINT				\
	"    __\n"				\
	"   ()'`;\n"				\
	"   /\\|`  Caution! Changing cluster's redundancy level will affect\n" \
	"  /  |   all the VDIs to be created later.\n" \
	"(/_)_|_  Are you sure you want to continue? [yes/no]: "

static int cluster_alter_copy(int argc, char **argv)
{
	int ret, log_length;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	struct epoch_log *logs;

	if (cluster_cmd_data.copy_policy != 0) {
		sd_err("Changing redundancy level of erasure coded vdi "
			   "is not supported yet.");
		return EXIT_USAGE;
	}
	if (!cluster_cmd_data.copies) {
		cluster_cmd_data.copies = SD_DEFAULT_COPIES;
		printf("The cluster's redundancy level is not specified, "
			   "use %d as default.\n", SD_DEFAULT_COPIES);
	}

	if (cluster_cmd_data.copies > sd_nodes_nr) {
		char info[1024];
		snprintf(info, sizeof(info), "Number of copies (%d) is larger "
			 "than number of nodes (%d).\n"
			 "Are you sure you want to continue? [yes/no]: ",
			 cluster_cmd_data.copies, sd_nodes_nr);
		confirm(info);
	}

	log_length = sizeof(struct epoch_log);
	logs = xmalloc(log_length);
	sd_init_req(&hdr, SD_OP_STAT_CLUSTER);
	hdr.data_length = log_length;
	ret = dog_exec_req(&sd_nid, &hdr, logs);
	if (ret < 0)
		goto failure;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Response's result: %s", sd_strerror(rsp->result));
		goto failure;
	}
	if (logs->copy_policy) {
		sd_err("The cluster's copy policy is erasure code, "
			   "changing it is not supported yet.");
		goto failure;
	}
	if (logs->nr_copies == cluster_cmd_data.copies) {
		sd_err("The cluster's redundancy level is already set to %d, "
			   "nothing changed.", cluster_cmd_data.copies);
		goto failure;
	}

	confirm(ALTER_CLUSTER_COPY_PRINT);

	sd_init_req(&hdr, SD_OP_ALTER_CLUSTER_COPY);
	hdr.cluster.copies = cluster_cmd_data.copies;
	hdr.cluster.copy_policy = cluster_cmd_data.copy_policy;
	ret = send_light_req(&sd_nid, &hdr);
	if (ret == 0) {
		sd_info("The cluster's redundancy level is set to %d, "
				"the old one was %d.",
				cluster_cmd_data.copies, logs->nr_copies);
		goto success;
	} else {
		sd_err("Changing the cluster's redundancy level failure.");
		goto failure;
	}

success:
	free(logs);
	return EXIT_SUCCESS;
failure:
	free(logs);
	return EXIT_FAILURE;
}

static struct subcommand cluster_cmd[] = {
	{"info", NULL, "aprhvT", "show cluster information",
	 NULL, CMD_NEED_NODELIST, cluster_info, cluster_options},
	{"format", NULL, "bctaphzTV", "create a Sheepdog store",
	 NULL, CMD_NEED_NODELIST, cluster_format, cluster_options},
	{"shutdown", NULL, "aphT", "stop Sheepdog",
	 NULL, 0, cluster_shutdown, cluster_options},
	{"snapshot", "<tag|idx> <path> [vdi1] [vdi2] ...",
	 "aphTm", "snapshot/restore the cluster",
	 cluster_snapshot_cmd, CMD_NEED_ARG,
	 cluster_snapshot, cluster_options},
	{"recover", NULL, "afphT",
	 "See 'dog cluster recover' for more information",
	 cluster_recover_cmd, CMD_NEED_ARG,
	 cluster_recover, cluster_options},
	{"reweight", NULL, "aphT", "reweight the cluster", NULL, 0,
	 cluster_reweight, cluster_options},
	{"check", NULL, "aphT", "check and repair cluster", NULL,
	 CMD_NEED_NODELIST, cluster_check, cluster_options},
	{"alter-copy", NULL, "aphTc", "set the cluster's redundancy level",
	 NULL, CMD_NEED_NODELIST, cluster_alter_copy, cluster_options},
	{NULL,},
};

static int cluster_parser(int ch, const char *opt)
{
	uint32_t block_size_shift;
	switch (ch) {
	case 'b':
		pstrcpy(cluster_cmd_data.name, sizeof(cluster_cmd_data.name),
			opt);
		break;
	case 'c':
		cluster_cmd_data.copies =
			parse_copy(opt, &cluster_cmd_data.copy_policy);
		if (!cluster_cmd_data.copies) {
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
	case 'f':
		cluster_cmd_data.force = true;
		break;
	case 'm':
		cluster_cmd_data.multithread = true;
	case 't':
		cluster_cmd_data.strict = true;
		break;
	case 'z':
		block_size_shift = (uint32_t)atoi(opt);
		if (block_size_shift > 31) {
			sd_err("Object Size is limited to 2^31."
			" Please set shift bit lower than 31");
			exit(EXIT_FAILURE);
		} else if (block_size_shift < 20) {
			sd_err("Object Size is larger than 2^20."
			" Please set shift bit larger than 20");
			exit(EXIT_FAILURE);
		}
		cluster_cmd_data.block_size_shift = block_size_shift;
		break;
	case 'V':
		cluster_cmd_data.fixed_vnodes = true;
		break;
	}

	return 0;
}

struct command cluster_command = {
	"cluster",
	cluster_cmd,
	cluster_parser
};
