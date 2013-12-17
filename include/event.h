#ifndef __EVENT_H__
#define __EVENT_H__

#include "list.h"
#include <limits.h>

struct event_info;

typedef void (*event_handler_t)(int fd, int events, void *data);

int init_event(int nr);
int register_event_prio(int fd, event_handler_t h, void *data, int prio);
void unregister_event(int fd);
int modify_event(int fd, unsigned int events);
void event_loop(int timeout);
void event_loop_prio(int timeout);
void event_force_refresh(void);

struct timer {
	void (*callback)(void *);
	void *data;
};

void add_timer(struct timer *t, unsigned int mseconds);

#define EVENT_PRIO_MAX     INT_MAX
#define EVENT_PRIO_DEFAULT 0
#define EVENT_PRIO_MIN     INT_MIN

/*
 * We can register/unregister the events in the worker thread with the
 * assumption:
 *
 * - one event will only be manipluated by a single entity.
 *
 * By allowing register/unregister events in the work thread, we get the
 * following benefits:
 *
 * 1. avoid to be trapped to main thread for better performance
 * 2. make sure registeration is done before some other events
 *
 * This doesn't mean we can manipulate the same event with multiple threads
 * simultaneously.
 */
static inline int register_event(int fd, event_handler_t h, void *data)
{
	return register_event_prio(fd, h, data, EVENT_PRIO_DEFAULT);
}

#endif
