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
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/eventfd.h>
#include <linux/types.h>

#include "list.h"
#include "util.h"
#include "work.h"
#include "logger.h"
#include "event.h"

static int efd;
static LIST_HEAD(worker_info_list);

struct work_queue {
	int wq_state;
	int nr_active;
	struct list_head pending_list;
	struct list_head blocked_list;
};

enum wq_state {
	WQ_BLOCKED = (1U << 0),
	WQ_DEAD = (1U << 1),
};

struct worker_info {
	struct list_head worker_info_siblings;

	int nr_threads;

	pthread_mutex_t finished_lock;
	struct list_head finished_list;

	/* wokers sleep on this and signaled by tgtd */
	pthread_cond_t pending_cond;
	/* locked by tgtd and workers */
	pthread_mutex_t pending_lock;
	/* protected by pending_lock */
	struct work_queue q;

	pthread_mutex_t startup_lock;

	pthread_t worker_thread[0];
};

static void work_queue_set_blocked(struct work_queue *q)
{
	q->wq_state |= WQ_BLOCKED;
}

static void work_queue_clear_blocked(struct work_queue *q)
{
	q->wq_state &= ~WQ_BLOCKED;
}

static int work_queue_blocked(struct work_queue *q)
{
	return q->wq_state & WQ_BLOCKED;
}

static int work_enabled(struct work_queue *q, struct work *w)
{
	int enabled = 0;

	switch (w->attr) {
	case WORK_SIMPLE:
		if (!work_queue_blocked(q))
			enabled = 1;
		break;
	case WORK_ORDERED:
		if (!work_queue_blocked(q) && !q->nr_active)
			enabled = 1;
		break;
	default:
		enabled = -1;
	}

	return enabled;
}

static void work_post_queued(struct work_queue *q, struct work *w)
{
	q->nr_active++;
	if (w->attr == WORK_ORDERED)
		work_queue_set_blocked(q);
}

static void __queue_work(struct work_queue *q, struct work *work, int enabled)
{
	struct worker_info *wi = container_of(q, struct worker_info, q);

	if (enabled) {
		pthread_mutex_lock(&wi->pending_lock);

		list_add_tail(&work->w_list, &wi->q.pending_list);

		pthread_mutex_unlock(&wi->pending_lock);

		pthread_cond_signal(&wi->pending_cond);

		work_post_queued(q, work);
	} else
		list_add_tail(&work->w_list, &wi->q.blocked_list);
}

void queue_work(struct work_queue *q, struct work *work)
{
	int enabled;

	if (!list_empty(&q->blocked_list))
		enabled = 0;
	else
		enabled = work_enabled(q, work);

	__queue_work(q, work, enabled);
}

static void work_post_done(struct work_queue *q, enum work_attr attr)
{
	struct work *n, *t;

	q->nr_active--;
	if (attr == WORK_ORDERED)
		work_queue_clear_blocked(q);

	list_for_each_entry_safe(n, t, &q->blocked_list, w_list) {
		if (!work_enabled(q, n))
			break;

		list_del(&n->w_list);
		__queue_work(q, n, 1);
	}
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
			enum work_attr attr;
			work = list_first_entry(&list, struct work, w_list);
			list_del(&work->w_list);

			/*
			 * work->done might free the work so we must
			 * save its attr for qork_post_done().
			 */
			attr = work->attr;
			work->done(work, 0);
			work_post_done(&wi->q, attr);
		}
	}
}

static void *worker_routine(void *arg)
{
	struct worker_info *wi = arg;
	struct work *work;
	int i, idx = 0;
	eventfd_t value = 1;

	for (i = 0; i < wi->nr_threads; i++) {
		if (wi->worker_thread[i] == pthread_self()) {
			idx = i;
			break;
		}
	}

	pthread_mutex_lock(&wi->startup_lock);
	dprintf("started this thread %d\n", idx);
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

		work->fn(work, idx);

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
	static int done = 0;

	if (done++)
		return 0;

	efd = eventfd(0, EFD_NONBLOCK);
	if (efd < 0) {
		eprintf("failed to create an event fd, %m\n");
		return 1;
	}

	ret = register_event(efd, bs_thread_request_done, NULL);

	return 0;
}

struct work_queue *init_work_queue(int nr)
{
	int i, ret;
	struct worker_info *wi;

	ret = init_eventfd();
	if (ret)
		return NULL;

	wi = zalloc(sizeof(*wi) + nr * sizeof(pthread_t));
	if (!wi)
		return NULL;

	wi->nr_threads = nr;

	INIT_LIST_HEAD(&wi->q.pending_list);
	INIT_LIST_HEAD(&wi->q.blocked_list);
	INIT_LIST_HEAD(&wi->finished_list);

	pthread_cond_init(&wi->pending_cond, NULL);

	pthread_mutex_init(&wi->finished_lock, NULL);
	pthread_mutex_init(&wi->pending_lock, NULL);
	pthread_mutex_init(&wi->startup_lock, NULL);

	pthread_mutex_lock(&wi->startup_lock);
	for (i = 0; i < wi->nr_threads; i++) {
		ret = pthread_create(&wi->worker_thread[i], NULL,
				     worker_routine, wi);

		if (ret) {
			eprintf("failed to create a worker thread, %d %s\n",
				i, strerror(ret));
			if (ret)
				goto destroy_threads;
		}
	}
	pthread_mutex_unlock(&wi->startup_lock);

	list_add(&wi->worker_info_siblings, &worker_info_list);

	return &wi->q;
destroy_threads:

	wi->q.wq_state |= WQ_DEAD;
	pthread_mutex_unlock(&wi->startup_lock);
	for (; i > 0; i--) {
		pthread_join(wi->worker_thread[i - 1], NULL);
		eprintf("stopped the worker thread %d\n", i - 1);
	}

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
	int i;
	struct worker_info *wi = container_of(q, struct worker_info, q);

	q->wq_state |= WQ_DEAD;
	pthread_cond_broadcast(&wi->pending_cond);

	for (i = 0; wi->worker_thread[i] &&
		     i < wi->nr_threads; i++)
		pthread_join(wi->worker_thread[i], NULL);

	pthread_cond_destroy(&wi->pending_cond);
	pthread_mutex_destroy(&wi->pending_lock);
	pthread_mutex_destroy(&wi->startup_lock);
	pthread_mutex_destroy(&wi->finished_lock);
}
#endif
