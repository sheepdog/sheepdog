#ifndef __UTIL_H__
#define __UTIL_H__

#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <unistd.h>

#include "bitops.h"
#include "list.h"
#include "logger.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __cpu_to_be16(x) bswap_16(x)
#define __cpu_to_be32(x) bswap_32(x)
#define __cpu_to_be64(x) bswap_64(x)
#define __be16_to_cpu(x) bswap_16(x)
#define __be32_to_cpu(x) bswap_32(x)
#define __be64_to_cpu(x) bswap_64(x)
#define __cpu_to_le32(x) (x)
#else
#define __cpu_to_be16(x) (x)
#define __cpu_to_be32(x) (x)
#define __cpu_to_be64(x) (x)
#define __be16_to_cpu(x) (x)
#define __be32_to_cpu(x) (x)
#define __be64_to_cpu(x) (x)
#define __cpu_to_le32(x) bswap_32(x)
#endif

#define notrace __attribute__((no_instrument_function))

static inline int before(uint32_t seq1, uint32_t seq2)
{
        return (int32_t)(seq1 - seq2) < 0;
}

static inline int after(uint32_t seq1, uint32_t seq2)
{
	return (int32_t)(seq2 - seq1) < 0;
}

#define min(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x < _y ? _x : _y; })

#define max(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x > _y ? _x : _y; })

static inline void *zalloc(size_t size)
{
	return calloc(1, size);
}

typedef void (*try_to_free_t)(size_t);
extern try_to_free_t set_try_to_free_routine(try_to_free_t);

extern void *xmalloc(size_t size);
extern void *xzalloc(size_t size);
extern void *xrealloc(void *ptr, size_t size);
extern void *xcalloc(size_t nmemb, size_t size);
extern ssize_t xread(int fd, void *buf, size_t len);
extern ssize_t xwrite(int fd, const void *buf, size_t len);
extern ssize_t xpread(int fd, void *buf, size_t count, off_t offset);
extern ssize_t xpwrite(int fd, const void *buf, size_t count, off_t offset);
extern int rmdir_r(char *dir_path);

/* ring_buffer.c */
struct rbuffer {
	struct list_head list;
	char *buffer;           /* data buffer */
	char *buffer_end;
	size_t capacity;        /* initial maximum number of items in the buffer */
	size_t count;           /* number of items in the buffer */
	size_t sz;              /* size of each item in the buffer */
	char *head;
	char *tail;
};

static inline size_t rbuffer_size(struct rbuffer *rbuf)
{
	return rbuf->count * rbuf->sz;
}

void rbuffer_push(struct rbuffer *rbuf, const void *item);
void rbuffer_pop(struct rbuffer *rbuf, void *item);
void rbuffer_destroy(struct rbuffer *rbuf);
void rbuffer_create(struct rbuffer *rbuf, size_t capacity, size_t item_size);
void rbuffer_reset(struct rbuffer *rbuf);

#endif
