/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

#include "list.h"
#include "util.h"
#include "event.h"

static int efd;
static LIST_HEAD(events_list);

static void timer_handler(int fd, int events, void *data)
{
	struct timer *t = data;
	uint64_t val;

	if (read(fd, &val, sizeof(val)) < 0)
		return;

	t->callback(t->data);

	unregister_event(fd);
	close(fd);
}

void add_timer(struct timer *t, unsigned int mseconds)
{
	struct itimerspec it;
	int tfd;

	tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (tfd < 0) {
		sd_err("timerfd_create: %m");
		return;
	}

	memset(&it, 0, sizeof(it));
	it.it_value.tv_sec = mseconds / 1000;
	it.it_value.tv_nsec = (mseconds % 1000) * 1000000;

	if (timerfd_settime(tfd, 0, &it, NULL) < 0) {
		sd_err("timerfd_settime: %m");
		return;
	}

	if (register_event(tfd, timer_handler, t) < 0)
		sd_err("failed to register timer fd");
}

struct event_info {
	event_handler_t handler;
	int fd;
	void *data;
	struct list_head ei_list;
	int prio;
};

static struct epoll_event *events;
static int nr_events;

int init_event(int nr)
{
	nr_events = nr;
	events = xcalloc(nr_events, sizeof(struct epoll_event));

	efd = epoll_create(nr);
	if (efd < 0) {
		sd_err("failed to create epoll fd");
		return -1;
	}
	return 0;
}

static struct event_info *lookup_event(int fd)
{
	struct event_info *ei;

	list_for_each_entry(ei, &events_list, ei_list) {
		if (ei->fd == fd)
			return ei;
	}
	return NULL;
}

int register_event_prio(int fd, event_handler_t h, void *data, int prio)
{
	int ret;
	struct epoll_event ev;
	struct event_info *ei;

	ei = xzalloc(sizeof(*ei));
	ei->fd = fd;
	ei->handler = h;
	ei->data = data;
	ei->prio = prio;

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.ptr = ei;

	ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
	if (ret) {
		sd_err("failed to add epoll event: %m");
		free(ei);
	} else
		list_add(&ei->ei_list, &events_list);

	return ret;
}

void unregister_event(int fd)
{
	int ret;
	struct event_info *ei;

	ei = lookup_event(fd);
	if (!ei)
		return;

	ret = epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
	if (ret)
		sd_err("failed to delete epoll event for fd %d: %m", fd);

	list_del(&ei->ei_list);
	free(ei);

	/*
	 * Although ei is no longer valid pointer, ei->handler() might be about
	 * to be called in do_event_loop().  Refreshing the event loop is safe.
	 */
	event_force_refresh();
}

int modify_event(int fd, unsigned int new_events)
{
	int ret;
	struct epoll_event ev;
	struct event_info *ei;

	ei = lookup_event(fd);
	if (!ei) {
		sd_err("event info for fd %d not found", fd);
		return 1;
	}

	memset(&ev, 0, sizeof(ev));
	ev.events = new_events;
	ev.data.ptr = ei;

	ret = epoll_ctl(efd, EPOLL_CTL_MOD, fd, &ev);
	if (ret) {
		sd_err("failed to delete epoll event for fd %d: %m", fd);
		return 1;
	}
	return 0;
}

static bool event_loop_refresh;

void event_force_refresh(void)
{
	event_loop_refresh = true;
}

static int epoll_event_cmp(const struct epoll_event *_a, struct epoll_event *_b)
{
	struct event_info *a, *b;

	a = (struct event_info *)_a->data.ptr;
	b = (struct event_info *)_b->data.ptr;

	/* we need sort event_info array in reverse order */
	return intcmp(b->prio, a->prio);
}

static void do_event_loop(int timeout, bool sort_with_prio)
{
	int i, nr;

refresh:
	event_loop_refresh = false;
	nr = epoll_wait(efd, events, nr_events, timeout);
	if (sort_with_prio)
		xqsort(events, nr, epoll_event_cmp);

	if (nr < 0) {
		if (errno == EINTR)
			return;
		sd_err("epoll_wait failed: %m");
		exit(1);
	} else if (nr) {
		for (i = 0; i < nr; i++) {
			struct event_info *ei;

			ei = (struct event_info *)events[i].data.ptr;
			ei->handler(ei->fd, events[i].events, ei->data);

			if (event_loop_refresh)
				goto refresh;
		}
	}
}

void event_loop(int timeout)
{
	do_event_loop(timeout, false);
}

void event_loop_prio(int timeout)
{
	do_event_loop(timeout, true);
}
