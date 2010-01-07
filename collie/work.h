#ifndef __WORK_H__
#define __WORK_H__

struct work;

typedef void (*work_func_t)(struct work *, int idx);

struct work_queue {
	struct list_head pending_list;
	int nr_pendings;
	int state;
};

struct work {
	struct list_head w_list;
	work_func_t fn;
	work_func_t done;
};

struct work_queue *init_worker(int nr);
void exit_worker(struct work_queue *q);
void queue_work(struct work_queue *q, struct work *work);

#endif
