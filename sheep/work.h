#ifndef __WORK_H__
#define __WORK_H__

#define NR_WORKER_THREAD 4

struct work;

typedef void (*work_func_t)(struct work *, int idx);

struct work {
	struct list_head w_list;
	work_func_t fn;
	work_func_t done;
};

int init_worker(void);
void exit_worker(void);
void queue_work(struct work *work);

#endif
