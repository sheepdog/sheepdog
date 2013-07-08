/*
 * Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * journaling.c: DynamoRIO based fault injector for testing the journaling
 * mechanism of sheep
 */

#include "dr_api.h"
#include "drwrap.h"
#include "drmgr.h"
#include "hashtable.h"
#include "dr_tools.h"

#include "../common.h"
#include <stdint.h>

/*
 * CAUTION: This definition of struct journal_descriptor must be same
 * to the definition in journal.c. We have to update the below
 * definition if we update the definition in journal.c because there's
 * no technique for keeping the consistency automatically.
 */
struct journal_descriptor {
	uint32_t magic;
	uint16_t flag;
	uint16_t reserved;
	union {
		uint32_t epoch;
		uint64_t oid;
	};
	uint64_t offset;
	uint64_t size;
	uint8_t create;
	uint8_t pad[475];
} __packed;

/* JOURNAL_DESC + JOURNAL_MARKER must be 512 algined for DIO */
#define JOURNAL_DESC_MAGIC 0xfee1900d
#define JOURNAL_DESC_SIZE 508
#define JOURNAL_MARKER_SIZE 4 /* Use marker to detect partial write */
#define JOURNAL_META_SIZE (JOURNAL_DESC_SIZE + JOURNAL_MARKER_SIZE)

#define JOURNAL_END_MARKER 0xdeadbeef

#define JF_STORE 0
#define JF_REMOVE_OBJ 2

#include <string.h>
#include <syscall.h>

#include <stdint.h>

enum scenario_id {
	SID_UNDEF = -1,

	SID_DO_NOTHING = 0,
	SID_DEATH_AFTER_STORE,
};

enum scenario_id sid = SID_UNDEF;

static int tls_idx;
static int jfile_fds[2];

enum thread_state {
	THREAD_STATE_DEFAULT,

	THREAD_STATE_OPENING_JFILE_0,
	THREAD_STATE_OPENING_JFILE_1,

	THREAD_STATE_WRITING_JFILE,
};

enum pwrite_state {
	PWRITE_WRITING_STORE,
};

struct per_thread_journal_state {
	enum thread_state state;
	int using_fd;

	enum pwrite_state pwrite_state;
};

static void thread_init_event(void *drcontext)
{
	struct per_thread_journal_state *new_jstate;

	new_jstate = xzalloc(sizeof(*new_jstate));

	drmgr_set_tls_field(drcontext, tls_idx, new_jstate);
}

static void thread_exit_event(void *drcontext)
{
	struct per_thread_journal_state *jstate;

	jstate = (struct per_thread_journal_state *)
		drmgr_get_tls_field(drcontext, tls_idx);
	xfree(jstate);
}

static void pre_open(void *drcontext)
{
	const char *path;
	struct per_thread_journal_state *jstate;

	jstate = (struct per_thread_journal_state *)
		drmgr_get_tls_field(drcontext, tls_idx);

	path = (const char *)dr_syscall_get_param(drcontext, 0);

	if (strstr(path, "journal_file0")) {
		fi_printf("journal_file0 is opened\n");
		DR_ASSERT(jstate->state == THREAD_STATE_DEFAULT);
		jstate->state = THREAD_STATE_OPENING_JFILE_0;
	} else if (strstr(path, "journal_file1")) {
		fi_printf("journal_file1 is opened\n");
		DR_ASSERT(jstate->state == THREAD_STATE_DEFAULT);
		jstate->state = THREAD_STATE_OPENING_JFILE_1;
	}
}

static void pre_close(void *drcontext)
{
}

static void pre_read(void *drcontext)
{
}

static void pre_write(void *drcontext)
{
}

static void pre_pwrite(void *drcontext)
{
	int fd;
	struct per_thread_journal_state *jstate;
	struct journal_descriptor *jd;

	fd = (int)dr_syscall_get_param(drcontext, 0);
	if (fd != jfile_fds[0] && fd != jfile_fds[1])
		return;

	jstate = (struct per_thread_journal_state *)
		drmgr_get_tls_field(drcontext, tls_idx);

	fi_printf("writing journal\n");
	jstate->using_fd = fd;
	jstate->state = THREAD_STATE_WRITING_JFILE;

	jd = (struct journal_descriptor *)dr_syscall_get_param(drcontext, 1);
	DR_ASSERT(jd->magic == JOURNAL_DESC_MAGIC);
	if (jd->flag == JF_STORE)
		jstate->pwrite_state = PWRITE_WRITING_STORE;
	else if (jd->flag == JF_REMOVE_OBJ)
		fi_printf("FIXME: testing object removal is not supported yet");
	else
		die("unknown journal flag: %d\n", jd->flag);
}

static bool pre_syscall(void *drcontext, int sysnum)
{
	switch (sysnum) {
	case SYS_open:
		pre_open(drcontext);
		break;
	case SYS_close:
		pre_close(drcontext);
		break;
	case SYS_read:
		pre_read(drcontext);
		break;
	case SYS_write:
		pre_write(drcontext);
		break;
	case SYS_pwrite64:
		pre_pwrite(drcontext);
		break;
	default:
		break;
	}

	return true;
}

static void post_open(void *drcontext)
{
	int fd;
	struct per_thread_journal_state *jstate;

	jstate = (struct per_thread_journal_state *)
		drmgr_get_tls_field(drcontext, tls_idx);

	if (jstate->state == THREAD_STATE_DEFAULT)
		return;

	fd = (int)dr_syscall_get_result(drcontext);

	if (jstate->state == THREAD_STATE_OPENING_JFILE_0) {
		fi_printf("fd of jfile0: %d\n", fd);
		jfile_fds[0] = fd;
	} else if (jstate->state == THREAD_STATE_OPENING_JFILE_1) {
		fi_printf("fd of jfile1: %d\n", fd);
		jfile_fds[1] = fd;
	}

	jstate->state = THREAD_STATE_DEFAULT;
}

static void post_close(void *drcontext)
{
}

static void post_read(void *drcontext)
{
}

static void post_write(void *drcontext)
{
}

static void post_pwrite64(void *drcontext)
{
	int fd;
	struct per_thread_journal_state *jstate;

	jstate = (struct per_thread_journal_state *)
		drmgr_get_tls_field(drcontext, tls_idx);

	if (jstate->state != THREAD_STATE_WRITING_JFILE)
		return;

	fd = jstate->using_fd;
	DR_ASSERT(fd == jfile_fds[0] || fd == jfile_fds[1]);

	switch (sid) {
	case SID_DEATH_AFTER_STORE:
		if (jstate->pwrite_state != PWRITE_WRITING_STORE)
			return;

		fi_printf("scenario is death after writing normal store,"
			" exiting\n");
		exit(1);
		break;
	default:
		die("invalid SID: %d\n", sid);
		break;
	}
}

static void post_syscall(void *drcontext, int sysnum)
{
	switch (sysnum) {
	case SYS_open:
		post_open(drcontext);
		break;
	case SYS_close:
		post_close(drcontext);
		break;
	case SYS_read:
		post_read(drcontext);
		break;
	case SYS_write:
		post_write(drcontext);
		break;
	case SYS_pwrite64:
		post_pwrite64(drcontext);
		break;
	}
}

static bool pre_syscall_filter(void *drcontext, int sysnum)
{
	return true;
}

static bool post_syscall_filter(void *drcontext, int sysnum)
{
	return true;
}

DR_EXPORT void dr_init(client_id_t id)
{
	const char *option;

	option = dr_get_options(id);
	fi_printf("the passed option to this client: %s\n", option);
	sid = atoi(option);
	fi_printf("sid: %d\n", sid);

	init_log_file();

	dr_register_filter_syscall_event(pre_syscall_filter);
	drmgr_init();

	tls_idx = drmgr_register_tls_field();
	drmgr_register_pre_syscall_event(pre_syscall);
	drmgr_register_post_syscall_event(post_syscall);

	drmgr_register_thread_init_event(thread_init_event);
	drmgr_register_thread_exit_event(thread_exit_event);

	jfile_fds[0] = -1;
	jfile_fds[1] = -1;
}
