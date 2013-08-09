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

#include "sheep_priv.h"
#include "trace/trace.h"

static void thread_check_enter(const struct caller *this_fn, int depth)
{
	if (strcmp(this_fn->section, MAIN_FN_SECTION) == 0) {
		if (!is_main_thread())
			panic("%s must be called in main thread",
			      this_fn->name);
	} else if (strcmp(this_fn->section, WORKER_FN_SECTION) == 0) {
		if (!is_worker_thread())
			panic("%s must be called in worker thread",
			      this_fn->name);
	}
}

static struct tracer thread_checker = {
	.name = "thread_checker",

	.enter = thread_check_enter,
};

tracer_register(thread_checker);
