#ifndef __WORK_H__
#define __WORK_H__

#include <stdbool.h>

struct work;
struct work_queue;

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

struct worker_info {
	const char *name;

	struct list_head finished_list;
	struct list_head worker_info_siblings;

	pthread_mutex_t finished_lock;
	pthread_mutex_t startup_lock;

	/* wokers sleep on this and signaled by tgtd */
	pthread_cond_t pending_cond;
	/* locked by tgtd and workers */
	pthread_mutex_t pending_lock;
	/* protected by pending_lock */
	struct work_queue q;
	size_t nr_pending;
	size_t nr_running;
	size_t nr_threads;
	/* we cannot shrink work queue till this time */
	uint64_t tm_end_of_protection;
	enum wq_thread_control tc;
};

extern struct list_head worker_info_list;

struct work_queue *init_work_queue(const char *name, enum wq_thread_control);
struct work_queue *init_ordered_work_queue(const char *name);
void queue_work(struct work_queue *q, struct work *work);
int init_wqueue_eventfd(void);

#endif
