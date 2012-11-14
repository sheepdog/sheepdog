#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <unistd.h>
#include <urcu/uatomic.h>

#include "bitops.h"
#include "list.h"
#include "logger.h"

#define SECTOR_SIZE (1U << 9)

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
#define __packed __attribute((packed))

#define uninitialized_var(x) (x = x)

static inline int before(uint32_t seq1, uint32_t seq2)
{
	return (int32_t)(seq1 - seq2) < 0;
}

static inline int after(uint32_t seq1, uint32_t seq2)
{
	return (int32_t)(seq2 - seq1) < 0;
}

#define min(x, y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x < _y ? _x : _y; })

#define max(x, y) ({ \
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
extern void pstrcpy(char *buf, int buf_size, const char *str);
extern int rmdir_r(char *dir_path);

void trim_zero_sectors(void *buf, uint64_t *offset, uint32_t *len);
void set_trimmed_sectors(void *buf, uint64_t offset, uint32_t len,
			 uint32_t requested_len);

#ifdef assert
#undef assert
#endif

#ifndef NDEBUG

#define assert(expr) ((expr) ?						\
			(void)0 :					\
			panic("assert: %s:%d: %s: "			\
				"Asserting `%s' failed.\n",		\
				__FILE__, __LINE__, __func__, #expr))

#else

#define assert(expr) ((void)0)

#endif	/* NDEBUG */

/* urcu helpers */

/* Boolean data type which can be accessed by multiple threads */
typedef unsigned long uatomic_bool;

static inline bool uatomic_is_true(uatomic_bool *val)
{
	return uatomic_read(val) == 1;
}

/* success if the old value is false */
static inline bool uatomic_set_true(uatomic_bool *val)
{
	return uatomic_cmpxchg(val, 0, 1) == 0;
}

static inline void uatomic_set_false(uatomic_bool *val)
{
	assert(uatomic_is_true(val));
	uatomic_set(val, 0);
}

#endif
