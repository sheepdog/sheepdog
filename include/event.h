#ifndef __EVENT_H__
#define __EVENT_H__

#include "list.h"

struct event_info;

typedef void (*event_handler_t)(int fd, int events, void *data);

int init_event(int nr);
int register_event(int fd, event_handler_t h, void *data);
void unregister_event(int fd);
int modify_event(int fd, unsigned int events);
void event_loop(int timeout);

struct timer {
	void (*callback)(void *);
	void *data;
};

void add_timer(struct timer *t, unsigned int seconds);

#endif
