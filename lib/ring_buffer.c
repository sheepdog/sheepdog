#include <pthread.h>
#include <stdlib.h>

#include "util.h"
#include "logger.h"

notrace void rbuffer_create(struct rbuffer *rbuf, size_t capacity, size_t sz)
{
	rbuf->buffer = xmalloc(capacity * sz);
	rbuf->buffer_end = rbuf->buffer + capacity * sz;
	rbuf->capacity = capacity;
	rbuf->count = 0;
	rbuf->sz = sz;
	rbuf->head = rbuf->tail = rbuf->buffer;
}

notrace void rbuffer_destroy(struct rbuffer *rbuf)
{
	free(rbuf->buffer);
}

notrace void rbuffer_reset(struct rbuffer *rbuf)
{
	rbuf->count = 0;
	rbuf->head = rbuf->tail = rbuf->buffer;
}

/* Push the item to the tail of the buffer */
notrace void rbuffer_push(struct rbuffer *rbuf, const void *item)
{
	if (rbuf->count == rbuf->capacity) {
		dprintf("buffer full\n");
		return;
	}
	memcpy(rbuf->tail, item, rbuf->sz);
	rbuf->tail += rbuf->sz;
	if (rbuf->tail == rbuf->buffer_end)
		rbuf->tail = rbuf->buffer;
	rbuf->count++;
}

/* Push the item from the head of the buffer */
notrace void rbuffer_pop(struct rbuffer *rbuf, void *item)
{
	if (rbuf->count == 0) {
		dprintf("no item left\n");
		return;
	}
	memcpy(item, rbuf->head, rbuf->sz);
	rbuf->head += rbuf->sz;
	if (rbuf->head == rbuf->buffer_end)
		rbuf->head = rbuf->buffer;
	rbuf->count--;
}
