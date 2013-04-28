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
int xmkdir(const char *pathname, mode_t mode);
void pstrcpy(char *buf, int buf_size, const char *str);
int rmdir_r(char *dir_path);
int purge_directory(char *dir_path);
bool is_numeric(const char *p);
int install_sighandler(int signum, void (*handler)(int), bool once);
int install_crash_handler(void (*handler)(int));
void reraise_crash_signal(int signo, int status);
pid_t gettid(void);
bool is_xattr_enabled(const char *path);

void trim_zero_sectors(void *buf, uint64_t *offset, uint32_t *len);
void untrim_zero_sectors(void *buf, uint64_t offset, uint32_t len,
			 uint32_t requested_len);
int atomic_create_and_write(const char *path, char *buf, size_t len);

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

/*
 * uatomic_xchg_ptr - uatomic_xchg for pointers
 *
 * Swaps the old value stored at location p with new value given by
 * val.  Returns old value.
 */
#define uatomic_xchg_ptr(p, val)			\
({							\
	uintptr_t ret;					\
	ret = uatomic_xchg((uintptr_t *)(p), (val));	\
	(typeof(*(p)))ret;				\
})

/* colors */
#define TEXT_NORMAL         "\033[0m"
#define TEXT_BOLD           "\033[1m"
#define TEXT_RED            "\033[0;31m"
#define TEXT_BOLD_RED       "\033[1;31m"
#define TEXT_GREEN          "\033[0;32m"
#define TEXT_BOLD_GREEN     "\033[1;32m"
#define TEXT_YELLOW         "\033[0;33m"
#define TEXT_BOLD_YELLOW    "\033[1;33m"
#define TEXT_BLUE           "\033[0;34m"
#define TEXT_BOLD_BLUE      "\033[1;34m"
#define TEXT_MAGENTA        "\033[0;35m"
#define TEXT_BOLD_MAGENTA   "\033[1;35m"
#define TEXT_CYAN           "\033[0;36m"
#define TEXT_BOLD_CYAN      "\033[1;36m"

static inline bool is_stdin_console(void)
{
	return isatty(STDIN_FILENO);
}

static inline bool is_stdout_console(void)
{
	return isatty(STDOUT_FILENO);
}

extern mode_t sd_def_fmode;
extern mode_t sd_def_dmode;


/* Force a compilation error if the condition is true */
#define BUILD_BUG_ON(condition) ((void)sizeof(struct { int: -!!(condition); }))

#endif
