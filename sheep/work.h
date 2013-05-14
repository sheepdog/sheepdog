#ifndef __WORK_H__
#define __WORK_H__

#include <stdbool.h>

struct work;

typedef void (*work_func_t)(struct work *);

struct work {
	struct list_head w_list;
	work_func_t fn;
	work_func_t done;
};

struct work_queue {
	int wq_state;
	struct list_head pending_list;
};

enum wq_thread_control {
	WQ_ORDERED, /* Only 1 thread created for work queue */
	WQ_DYNAMIC, /* # of threads proportional to nr_nodes created */
	WQ_UNLIMITED, /* Unlimited # of threads created */
};

struct work_queue *init_work_queue(const char *name, enum wq_thread_control);
struct work_queue *init_ordered_work_queue(const char *name);
void queue_work(struct work_queue *q, struct work *work);
int init_wqueue_eventfd(void);

#endif
