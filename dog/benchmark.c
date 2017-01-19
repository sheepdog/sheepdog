/*
 * Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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
#include "work.h"

static struct sd_option benchmark_options[] = {
	{'w', "workqueue", true, "specify workqueue type"},
	{'f', "force", false, "do not prompt for confirmation"},
	{'t', "total", true, "a number of total operation (e.g. I/O request)"},
	{'n', "nr-threads", true, "a number of worker threads"
	 " (only used for fixed workqueue)"},
	{ 0, NULL, false, NULL },
};

#define DEFAULT_TOTAL 1000
#define WQ_TYPE_LEN 32

static struct benchmark_cmd_data {
	char workqueue_type[WQ_TYPE_LEN];
	bool force;
	int total;
	int nr_threads;
} benchmark_cmd_data;

struct benchmark_io_work {
	struct work work;

	uint32_t vid;
	uint64_t obj_index, offset;
	char *buf;
	int buf_len;

	uint8_t nr_copies, copy_policy;
};

static void benchmark_io_main(struct work *work)
{
	struct benchmark_io_work *io_work;
	io_work = container_of(work, struct benchmark_io_work, work);

	free(io_work);
}

static void benchmark_io_worker(struct work *work)
{
	struct benchmark_io_work *io_work;
	uint64_t oid;
	int ret;

	io_work = container_of(work, struct benchmark_io_work, work);
	oid = vid_to_data_oid(io_work->vid, io_work->obj_index);

	ret = dog_write_object(oid, 0, io_work->buf, io_work->buf_len,
			       io_work->offset, 0, io_work->nr_copies,
			       io_work->copy_policy, false, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to write object %"PRIx64", %s",
		       oid, sd_strerror(ret));
		exit(1);
	}
}

static int benchmark_io(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	enum wq_thread_control wq_type = WQ_ORDERED;
	struct work_queue *wq;
	int ret, total;
	struct sd_inode *inode;
	uint32_t vid;
	int nr_objects, buf_len;
	uint64_t obj_index = 0, offset = 0;
	char *buf;
	int nr_threads = 1;

	if (!benchmark_cmd_data.force)
		confirm("Caution! benchmark io command will erase all data of"
			" target VDI.\n Are you sure you want to continue?"
			" [yes/no]");

	if (strlen(benchmark_cmd_data.workqueue_type) != 0) {
		if (!strcmp("ordered", benchmark_cmd_data.workqueue_type))
			wq_type = WQ_ORDERED;
		else if (!strcmp("dynamic",
				 benchmark_cmd_data.workqueue_type))
			wq_type = WQ_DYNAMIC;
		else if (!strcmp("fixed",
				 benchmark_cmd_data.workqueue_type))
			wq_type = WQ_FIXED;
		else {
			sd_err("unknown workqueue type: %s",
			       benchmark_cmd_data.workqueue_type);
			sd_err("assumed workqueue types:"
			       " ordered, dynamic");
			return EXIT_SYSFAIL;
		}
	}

	if (benchmark_cmd_data.nr_threads)
		nr_threads = benchmark_cmd_data.nr_threads;

	if (wq_type != WQ_FIXED)
		wq = create_work_queue("benchmark", wq_type);
	else
		wq = create_fixed_work_queue("benchmark", nr_threads);
	if (!wq) {
		sd_err("failed to create work queue");
		return EXIT_SYSFAIL;
	}

	inode = xzalloc(sizeof(*inode));

	ret = read_vdi_obj(vdiname, 0, "", &vid, inode, sizeof(*inode));
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to lookup VDI %s: %s", vdiname, sd_strerror(ret));
		return EXIT_SYSFAIL;
	}

	buf_len = 1 << inode->block_size_shift;
	buf = xzalloc(buf_len);

	nr_objects = inode->vdi_size / (1 << inode->block_size_shift);
	for (int i = 0; i < nr_objects; i++) {
		if (inode->data_vdi_id[i] != vid) {
			sd_err("VDI %s has unallocated data", vdiname);
			return EXIT_SYSFAIL;
		}
	}

	if (benchmark_cmd_data.total != 0)
		total = benchmark_cmd_data.total;
	else
		total = DEFAULT_TOTAL;

	while (0 < total--) {
		struct benchmark_io_work *w = xzalloc(sizeof(*w));

		w->vid = vid;
		w->obj_index = (obj_index++) % nr_objects;
		w->buf = buf;
		w->buf_len = buf_len;
		w->offset = offset;
		w->nr_copies = inode->nr_copies;
		w->copy_policy = inode->copy_policy;

		w->work.fn = benchmark_io_worker;
		w->work.done = benchmark_io_main;

		queue_work(wq, &w->work);

		offset += buf_len; /* object size */
	}
	work_queue_wait(wq);

	return 0;
}

static int benchmark_parser(int ch, const char *opt)
{
	switch (ch) {
	case 'w':
		pstrcpy(benchmark_cmd_data.workqueue_type,
			sizeof(benchmark_cmd_data.workqueue_type), opt);
		break;
	case 'f':
		benchmark_cmd_data.force = true;
		break;
	case 't':
		benchmark_cmd_data.total = atoi(opt);
		break;
	case 'n':
		benchmark_cmd_data.nr_threads = atoi(opt);
		break;
	default:
		sd_err("unknown option: %c", ch);
		return -1;
	}

	return 0;
}

static struct subcommand benchmark_cmd[] = {
	{"io", "<vdiname>", "aprhTfwtn", "benchmark I/O performance",
	 NULL, CMD_NEED_NODELIST|CMD_NEED_ARG, benchmark_io, benchmark_options},
	{NULL,},
};

struct command benchmark_command = {
	"benchmark",
	benchmark_cmd,
	benchmark_parser
};
