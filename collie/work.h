#ifndef __WORK_H__
#define __WORK_H__

struct work;

typedef void (*work_func_t)(struct work *, int idx);

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

int init_work_queue(int nr);
void queue_work(struct work *work);

#endif
