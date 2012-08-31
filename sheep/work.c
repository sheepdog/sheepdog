/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * This code is based on bs.c from Linux target framework (tgt):
 *   Copyright (C) 2007 FUJITA Tomonori <tomof@acm.org>
 *   Copyright (C) 2007 Mike Christie <michaelc@cs.wisc.edu>
 */
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/eventfd.h>
#include <linux/types.h>
#include <urcu/uatomic.h>

#include "list.h"
#include "util.h"
#include "work.h"
#include "logger.h"
#include "event.h"
#include "trace/trace.h"

static int efd;
int total_ordered_workers;
LIST_HEAD(worker_info_list);

enum wq_state {
	WQ_DEAD = (1U << 1),
};

/*
 * Short thread is created on demand and destroyed after serving the work for
 * gateway or io requests, aiming to solve two problems:
 *
 *  1. timeout of IO requests from guests. With on-demand short threads, we
 *     guarantee that there is always one thread available to execute the
 *     request as soon as possible.
 *  2. sheep halt for corner case that all gateway and io threads are executing
 *     local requests that ask for creation of another thread to execute the
 *     requests and sleep-wait for responses.
 */
struct short_work {
	struct work *work;
	struct worker_info *wi;
};

static void *run_short_thread(void *arg)
{
	struct short_work *sw = arg;
	eventfd_t value = 1;
	static unsigned long idx = 0;
	int err;

	/* Tell runtime to release resources after termination */
	err = pthread_detach(pthread_self());
	if (err)
		panic("%s\n", strerror(err));

	set_thread_name(sw->wi->name, uatomic_add_return(&idx, 1));

	sw->work->fn(sw->work);

	pthread_mutex_lock(&sw->wi->finished_lock);
	list_add_tail(&sw->work->w_list, &sw->wi->finished_list);
	pthread_mutex_unlock(&sw->wi->finished_lock);

	eventfd_write(efd, value);
	free(sw);
	pthread_exit(NULL);
}

static inline void create_short_thread(struct worker_info *wi,
				       struct work *work)
{
	pthread_t thread;
	struct short_work *sw = xmalloc(sizeof *sw);
	int err;

	sw->work = work;
	sw->wi = wi;

	err = pthread_create(&thread, NULL, run_short_thread, sw);
	if (err)
		panic("%s\n", strerror(err));
	short_thread_begin();
}

void queue_work(struct work_queue *q, struct work *work)
{
	struct worker_info *wi = container_of(q, struct worker_info, q);

	if (wi->ordered) {
		pthread_mutex_lock(&wi->pending_lock);
		list_add_tail(&work->w_list, &wi->q.pending_list);
		pthread_mutex_unlock(&wi->pending_lock);

		pthread_cond_signal(&wi->pending_cond);
	} else
		create_short_thread(wi, work);
}

static void bs_thread_request_done(int fd, int events, void *data)
{
	int ret;
	struct worker_info *wi;
	struct work *work;
	eventfd_t value;
	LIST_HEAD(list);

	ret = eventfd_read(fd, &value);
	if (ret < 0)
		return;

	list_for_each_entry(wi, &worker_info_list, worker_info_siblings) {
		pthread_mutex_lock(&wi->finished_lock);
		list_splice_init(&wi->finished_list, &list);
		pthread_mutex_unlock(&wi->finished_lock);

		while (!list_empty(&list)) {
			work = list_first_entry(&list, struct work, w_list);
			list_del(&work->w_list);

			work->done(work);
			if (!wi->ordered)
				short_thread_end();
		}
	}
}

static void *worker_routine(void *arg)
{
	struct worker_info *wi = arg;
	struct work *work;
	eventfd_t value = 1;

	set_thread_name(wi->name, 0);

	pthread_mutex_lock(&wi->startup_lock);
	/* started this thread */
	pthread_mutex_unlock(&wi->startup_lock);

	while (!(wi->q.wq_state & WQ_DEAD)) {

		pthread_mutex_lock(&wi->pending_lock);
retest:
		if (list_empty(&wi->q.pending_list)) {
			pthread_cond_wait(&wi->pending_cond, &wi->pending_lock);
			if (wi->q.wq_state & WQ_DEAD) {
				pthread_mutex_unlock(&wi->pending_lock);
				pthread_exit(NULL);
			}
			goto retest;
		}

		work = list_first_entry(&wi->q.pending_list,
				       struct work, w_list);

		list_del(&work->w_list);
		pthread_mutex_unlock(&wi->pending_lock);

		work->fn(work);

		pthread_mutex_lock(&wi->finished_lock);
		list_add_tail(&work->w_list, &wi->finished_list);
		pthread_mutex_unlock(&wi->finished_lock);

		eventfd_write(efd, value);
	}

	pthread_exit(NULL);
}

static int init_eventfd(void)
{
	int ret;
	static bool done = false;

	if (done)
		return 0;

	efd = eventfd(0, EFD_NONBLOCK);
	if (efd < 0) {
		eprintf("failed to create an event fd: %m\n");
		return 1;
	}

	ret = register_event(efd, bs_thread_request_done, NULL);
	if (ret) {
		eprintf("failed to register event fd %m\n");
		close(efd);
		return 1;
	}

	done = true;

	return 0;
}

struct work_queue *init_work_queue(const char *name, bool ordered)
{
	int ret;
	struct worker_info *wi;

	ret = init_eventfd();
	if (ret)
		return NULL;

	wi = zalloc(sizeof(*wi));
	if (!wi)
		return NULL;

	wi->name = name;
	wi->ordered = ordered;

	INIT_LIST_HEAD(&wi->finished_list);

	pthread_mutex_init(&wi->finished_lock, NULL);

	if (ordered) {
		INIT_LIST_HEAD(&wi->q.pending_list);

		pthread_cond_init(&wi->pending_cond, NULL);
		pthread_mutex_init(&wi->pending_lock, NULL);
		pthread_mutex_init(&wi->startup_lock, NULL);

		pthread_mutex_lock(&wi->startup_lock);

		ret = pthread_create(&wi->worker_thread, NULL, worker_routine,
				     wi);
		if (ret) {
			eprintf("failed to create worker thread: %s\n",
				strerror(ret));
			goto destroy_threads;
		}

		pthread_mutex_unlock(&wi->startup_lock);
		total_ordered_workers++;
	}

	list_add(&wi->worker_info_siblings, &worker_info_list);

	return &wi->q;
destroy_threads:

	wi->q.wq_state |= WQ_DEAD;
	pthread_mutex_unlock(&wi->startup_lock);
	pthread_join(wi->worker_thread, NULL);
	eprintf("stopped worker thread\n");

/* destroy_cond_mutex: */
	pthread_cond_destroy(&wi->pending_cond);
	pthread_mutex_destroy(&wi->pending_lock);
	pthread_mutex_destroy(&wi->startup_lock);
	pthread_mutex_destroy(&wi->finished_lock);

	return NULL;
}

#ifdef COMPILE_UNUSED_CODE
static void exit_work_queue(struct work_queue *q)
{
	struct worker_info *wi = container_of(q, struct worker_info, q);

	q->wq_state |= WQ_DEAD;
	pthread_cond_broadcast(&wi->pending_cond);

	pthread_join(wi->worker_thread, NULL);

	pthread_cond_destroy(&wi->pending_cond);
	pthread_mutex_destroy(&wi->pending_lock);
	pthread_mutex_destroy(&wi->startup_lock);
	pthread_mutex_destroy(&wi->finished_lock);
}
#endif
