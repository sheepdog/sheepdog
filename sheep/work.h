#ifndef __WORK_H__
#define __WORK_H__

struct work;
struct work_queue;

typedef void (*work_func_t)(struct work *);

enum work_attr {
	WORK_SIMPLE,
	WORK_ORDERED,
};

struct work {
	struct list_head w_list;
	work_func_t fn;
	work_func_t done;
	enum work_attr attr;
};

struct work_queue {
	int wq_state;
	int nr_active;
	struct list_head pending_list;
	struct list_head blocked_list;
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

extern struct list_head worker_info_list;
extern int total_nr_workers;

struct work_queue *init_work_queue(int nr);
void queue_work(struct work_queue *q, struct work *work);

#endif
