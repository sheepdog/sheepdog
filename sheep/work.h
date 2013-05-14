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

/*
 * 'get_nr_nodes' is the function to get the current number of nodes and used
 * for dynamic work queues.  'create_cb' will be called when worker threads are
 * created and 'destroy_cb' will be called when worker threads are destroyed.
 */
int init_work_queue(size_t (*get_nr_nodes)(void), void (*create_cb)(pthread_t),
		    void (*destroy_cb)(pthread_t));
struct work_queue *create_work_queue(const char *name, enum wq_thread_control);
struct work_queue *create_ordered_work_queue(const char *name);
void queue_work(struct work_queue *q, struct work *work);

#endif
