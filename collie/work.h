#ifndef __WORK_H__
#define __WORK_H__

struct work;

typedef void (*work_func_t)(struct work *, int idx);

enum work_attr {
	WORK_SIMPLE,
	WORK_ORDERED,
};

struct work_queue {
	int wq_state;
	int nr_active;
	struct list_head pending_list;
	struct list_head blocked_list;
};

struct work {
	struct list_head w_list;
	work_func_t fn;
	work_func_t done;
	enum work_attr attr;
};

struct work_queue *init_work_queue(int nr);
void exit_work_queue(struct work_queue *q);
void queue_work(struct work_queue *q, struct work *work);
void resume_work_queue(struct work_queue *q);
void wait_work_queue_inactive(struct work_queue *q);

#endif
