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

#define MAX_EVENT_DURATION 1000 /* us */
static int event_handler_depth = -1;
static uint64_t start_time;

static void event_handler_enter(const struct caller *this_fn, int depth)
{
	if (!is_main_thread())
		return;

	if (event_handler_depth < 0) {
		if (strcmp(this_fn->name, "do_event_loop") == 0)
			event_handler_depth = depth + 1;
	}

	if (depth == event_handler_depth)
		start_time = clock_get_time();
}

static void event_handler_exit(const struct caller *this_fn, int depth)
{
	if (!is_main_thread())
		return;

	if (depth == event_handler_depth) {
		uint64_t duration = clock_get_time() - start_time;
		unsigned quot = duration / 1000, rem = duration % 1000;

		if (quot > MAX_EVENT_DURATION)
			sd_warn("%s wastes too much time in event loop: "
				"%u.%-3u us", this_fn->name, quot, rem);
	}
}

static struct tracer loop_checker = {
	.name = "loop_checker",

	.enter = event_handler_enter,
	.exit = event_handler_exit,
};

tracer_register(loop_checker);

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
