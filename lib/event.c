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
#include "logger.h"

static int efd;
static LIST_HEAD(events_list);

#define TICK 1

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

void add_timer(struct timer *t, unsigned int seconds)
{
	struct itimerspec it;
	int tfd;

	tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (tfd < 0) {
		eprintf("timerfd_create: %m\n");
		return;
	}

	memset(&it, 0, sizeof(it));
	it.it_value.tv_sec = seconds;

	if (timerfd_settime(tfd, 0, &it, NULL) < 0) {
		eprintf("timerfd_settime: %m\n");
		return;
	}

	if (register_event(tfd, timer_handler, t) < 0) {
		eprintf("failed to register timer fd\n");
	}
}

struct event_info {
	event_handler_t handler;
	int fd;
	void *data;
	struct list_head ei_list;
};

int init_event(int nr)
{
	efd = epoll_create(nr);
	if (efd < 0) {
		eprintf("failed to create epoll fd\n");
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

int register_event(int fd, event_handler_t h, void *data)
{
	int ret;
	struct epoll_event ev;
	struct event_info *ei;

	ei = zalloc(sizeof(*ei));
	if (!ei)
		return -ENOMEM;

	ei->fd = fd;
	ei->handler = h;
	ei->data = data;

	ev.events = EPOLLIN;
	ev.data.ptr = ei;

	ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
	if (ret) {
		eprintf("failed to add epoll event: %m\n");
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
	if (!ei) {
		eprintf("event info for fd %d not found\n", fd);
		return;
	}

	ret = epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
	if (ret)
		eprintf("failed to delete epoll event for fd %d: %m\n", fd);

	list_del(&ei->ei_list);
	free(ei);
}

int modify_event(int fd, unsigned int events)
{
	int ret;
	struct epoll_event ev;
	struct event_info *ei;

	ei = lookup_event(fd);
	if (!ei) {
		eprintf("event info for fd %d not found\n", fd);
		return 1;
	}

	memset(&ev, 0, sizeof(ev));
	ev.events = events;
	ev.data.ptr = ei;

	ret = epoll_ctl(efd, EPOLL_CTL_MOD, fd, &ev);
	if (ret) {
		eprintf("failed to delete epoll event for fd %d: %m\n", fd);
		return 1;
	}
	return 0;
}

void event_loop(int timeout)
{
	int i, nr;
	struct epoll_event events[128];

	nr = epoll_wait(efd, events, ARRAY_SIZE(events), TICK * 1000);
	if (nr < 0) {
		if (errno == EINTR)
			return;
		eprintf("epoll_wait failed: %m\n");
		exit(1);
	} else if (nr) {
		for (i = 0; i < nr; i++) {
			struct event_info *ei;

			ei = (struct event_info *)events[i].data.ptr;
			ei->handler(ei->fd, events[i].events, ei->data);
		}
	}
}
