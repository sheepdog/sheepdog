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

struct worker_info {
	const char *name;

	struct list_head worker_info_siblings;

	bool ordered;

	pthread_mutex_t finished_lock;
	struct list_head finished_list;

	/* wokers sleep on this and signaled by tgtd */
	pthread_cond_t pending_cond;
	/* locked by tgtd and workers */
	pthread_mutex_t pending_lock;
	/* protected by pending_lock */
	struct work_queue q;

	pthread_mutex_t startup_lock;

	pthread_t worker_thread; /* used for an ordered work queue */
};

extern struct list_head worker_info_list;
extern int total_ordered_workers;

/* if 'ordered' is true, the work queue are processes in order. */
struct work_queue *init_work_queue(const char *name, bool ordered);
void queue_work(struct work_queue *q, struct work *work);
int init_wqueue_eventfd(void);

#endif
