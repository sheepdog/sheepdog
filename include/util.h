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

#define __printf(a, b)                  __attribute__((format(printf, a, b)))

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
try_to_free_t set_try_to_free_routine(try_to_free_t);

void *xmalloc(size_t size);
void *xzalloc(size_t size);
void *xrealloc(void *ptr, size_t size);
void *xcalloc(size_t nmemb, size_t size);
void *xvalloc(size_t size);
ssize_t xread(int fd, void *buf, size_t len);
ssize_t xwrite(int fd, const void *buf, size_t len);
ssize_t xpread(int fd, void *buf, size_t count, off_t offset);
ssize_t xpwrite(int fd, const void *buf, size_t count, off_t offset);
void pstrcpy(char *buf, int buf_size, const char *str);
int rmdir_r(char *dir_path);
bool is_numeric(const char *p);
int install_sighandler(int signum, void (*handler)(int), bool once);
int install_crash_handler(void (*handler)(int));
pid_t gettid(void);
bool is_xattr_enabled(const char *path);

void trim_zero_sectors(void *buf, uint64_t *offset, uint32_t *len);
void untrim_zero_sectors(void *buf, uint64_t offset, uint32_t len,
			 uint32_t requested_len);

#ifdef assert
#undef assert
#endif

#ifndef NDEBUG

#define assert(expr) ((expr) ?						\
			(void)0 : panic("Asserting `%s' failed.", #expr))

#else

#define assert(expr) ((void)0)

#endif	/* NDEBUG */

/* urcu helpers */

/* Boolean data type which can be accessed by multiple threads */
typedef struct { unsigned long val; } uatomic_bool;

static inline bool uatomic_is_true(uatomic_bool *val)
{
	return uatomic_read(&val->val) == 1;
}

/* success if the old value is false */
static inline bool uatomic_set_true(uatomic_bool *val)
{
	return uatomic_cmpxchg(&val->val, 0, 1) == 0;
}

static inline void uatomic_set_false(uatomic_bool *val)
{
	uatomic_set(&val->val, 0);
}

#endif
