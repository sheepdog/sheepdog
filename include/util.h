#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <unistd.h>
#include <search.h>
#include <urcu/uatomic.h>
#include <pthread.h>
#include <errno.h>
#include <sys/param.h>

#include "logger.h"
#include "list.h"
#include "compiler.h"

#define SECTOR_SIZE (1U << 9)
#define BLOCK_SIZE (1U << 12)

#define round_up(x, y) roundup(x, y)
#define round_down(x, y) (((x) / (y)) * (y))

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

#define uninitialized_var(x) x = x

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

/*
 * Compares two integer values
 *
 * If the first argument is larger than the second one, intcmp() returns 1.  If
 * two members are equal, returns 0.  Otherwise, returns -1.
 */
#define intcmp(x, y) \
({					\
	typeof(x) _x = (x);		\
	typeof(y) _y = (y);		\
	(void) (&_x == &_y);		\
	_x < _y ? -1 : _x > _y ? 1 : 0;	\
})

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
int xfallocate(int fd, int mode, off_t offset, off_t len);
int xftruncate(int fd, off_t length);
int eventfd_xread(int efd);
void eventfd_xwrite(int efd, int value);
void pstrcpy(char *buf, int buf_size, const char *str);
char *chomp(char *str);
int rmdir_r(const char *dir_path);
int purge_directory(const char *dir_path);
bool is_numeric(const char *p);
const char *data_to_str(void *data, size_t data_length);
int install_sighandler(int signum, void (*handler)(int), bool once);
int install_crash_handler(void (*handler)(int));
void reraise_crash_signal(int signo, int status);
pid_t gettid(void);
int tkill(int tid, int sig);
bool is_xattr_enabled(const char *path);
const char *my_exe_path(void);

int split_path(const char *path, size_t nr_segs, char **segs);
void make_path(char *path, size_t size, size_t nr_segs, const char **segs);

int atomic_create_and_write(const char *path, const char *buf, size_t len,
			    bool force_create);

void find_zero_blocks(const void *buf, uint64_t *poffset, uint32_t *plen);
void trim_zero_blocks(void *buf, uint64_t *poffset, uint32_t *plen);

/* a type safe version of qsort() */
#define xqsort(base, nmemb, compar)					\
({									\
	if (nmemb > 1) {						\
		qsort(base, nmemb, sizeof(*(base)),			\
		      (comparison_fn_t)compar);				\
		assert(compar(base, base + 1) <= 0);			\
	}								\
})

/* a type safe version of bsearch() */
#define xbsearch(key, base, nmemb, compar)				\
({									\
	typeof(&(base)[0]) __ret = NULL;				\
	if (nmemb > 0) {						\
		assert(compar(key, key) == 0);				\
		assert(compar(base, base) == 0);			\
		__ret = bsearch(key, base, nmemb, sizeof(*(base)),	\
				(comparison_fn_t)compar);		\
	}								\
	__ret;								\
})

/*
 * Binary Search of the ascending sorted array. When the key is not found, this
 * returns the next greater position.
 */
#define nbsearch(key, base, nmemb, compar)				\
({									\
	typeof(key) __m,  __l = base, __r = base + nmemb - 1;		\
	int __ret;							\
									\
	while(__l <= __r && likely(nmemb > 0)) {			\
		__m = __l + (__r - __l) / 2;				\
		__ret = compar(key, __m);				\
		if (__ret < 0)						\
			__r = __m - 1;					\
		else if (__ret > 0)					\
			__l = __m + 1;					\
		else {							\
			__l = __m;					\
			break;						\
		}							\
	}								\
	__l;								\
})

/* a type safe version of lfind() */
#define xlfind(key, base, nmemb, compar)				\
({									\
	typeof(&(base)[0]) __ret = NULL;				\
	if (nmemb > 0) {						\
		size_t __n = nmemb;					\
		assert(compar(key, key) == 0);				\
		assert(compar(base, base) == 0);			\
		__ret = lfind(key, base, &__n, sizeof(*(base)),		\
			      (comparison_fn_t)compar);			\
	}								\
	__ret;								\
})

/*
 * Search 'key' in the array 'base' linearly and remove it if it found.
 *
 * If 'key' is found in 'base', this function increments *nmemb and returns
 * true.
 */
#define xlremove(key, base, nmemb, compar)				\
({									\
	bool __removed = false;						\
	typeof(&(base)[0]) __e;						\
									\
	__e = xlfind(key, base, *(nmemb), compar);			\
	if (__e != NULL) {						\
		(*(nmemb))--;						\
		memmove(__e, __e + 1,					\
			sizeof(*(base)) * (*(nmemb) - (__e - (base)))); \
		__removed = true;					\
	}								\
	__removed;							\
})

#ifdef assert
#error "Don't include assert.h, use util.h for assert()"
#endif

#ifndef NDEBUG
#define assert(expr)						\
({								\
	if (!(expr)) {						\
		sd_emerg("Asserting `%s' failed.", #expr);	\
		abort();					\
	}							\
})
#else
#define assert(expr) ((void)0)
#endif	/* NDEBUG */

#define SWAP(a, b) { typeof(a) tmp; tmp = a; a = b; b = tmp; }

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

/*
 * refcnt_t: reference counter which can be manipulated by multiple threads
 * safely
 */

typedef struct {
	int val;
} refcnt_t;

static inline void refcount_set(refcnt_t *rc, int val)
{
	uatomic_set(&rc->val, val);
}

static inline int refcount_read(refcnt_t *rc)
{
	return uatomic_read(&rc->val);
}

static inline int refcount_inc(refcnt_t *rc)
{
	return uatomic_add_return(&rc->val, 1);
}

static inline int refcount_dec(refcnt_t *rc)
{
	assert(1 <= uatomic_read(&rc->val));
	return uatomic_sub_return(&rc->val, 1);
}

/* wrapper for pthread_mutex */

#define SD_MUTEX_INITIALIZER { .mutex = PTHREAD_MUTEX_INITIALIZER }

struct sd_mutex {
	pthread_mutex_t mutex;
};

static inline void sd_init_mutex(struct sd_mutex *mutex)
{
	int ret;

	do {
		ret = pthread_mutex_init(&mutex->mutex, NULL);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to initialize a lock, %s", strerror(ret));
}

static inline void sd_init_mutex_attr(struct sd_mutex *mutex,
				      pthread_mutexattr_t *attr)
{
	int ret;

	do {
		ret = pthread_mutex_init(&mutex->mutex, attr);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to initialize a lock with attr, %s",
		      strerror(ret));
}

static inline void sd_destroy_mutex(struct sd_mutex *mutex)
{
	int ret;

	do {
		ret = pthread_mutex_destroy(&mutex->mutex);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to destroy a lock, %s", strerror(ret));
}

static inline void sd_mutex_lock(struct sd_mutex *mutex)
{
	int ret;

	do {
		ret = pthread_mutex_lock(&mutex->mutex);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to lock for reading, %s", strerror(ret));
}

static inline int sd_mutex_trylock(struct sd_mutex *mutex)
{
	return pthread_mutex_trylock(&mutex->mutex);
}

static inline void sd_mutex_unlock(struct sd_mutex *mutex)
{
	int ret;

	do {
		ret = pthread_mutex_unlock(&mutex->mutex);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to unlock, %s", strerror(ret));
}

/* wrapper for pthread_cond */

#define SD_COND_INITIALIZER { .cond = PTHREAD_COND_INITIALIZER }

struct sd_cond {
	pthread_cond_t cond;
};

static inline void sd_cond_init(struct sd_cond *cond)
{
	int ret;

	do {
		ret = pthread_cond_init(&cond->cond, NULL);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to initialize a lock, %s", strerror(ret));

}

static inline void sd_destroy_cond(struct sd_cond *cond)
{
	int ret;

	do {
		ret = pthread_cond_destroy(&cond->cond);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to destroy a lock, %s", strerror(ret));
}

static inline int sd_cond_signal(struct sd_cond *cond)
{
	return pthread_cond_signal(&cond->cond);
}

static inline int sd_cond_wait(struct sd_cond *cond, struct sd_mutex *mutex)
{
	return pthread_cond_wait(&cond->cond, &mutex->mutex);
}

static inline int sd_cond_wait_timeout(struct sd_cond *cond,
				       struct sd_mutex *mutex, int second)
{
	struct timespec wait_time;
	wait_time.tv_sec = second;
	wait_time.tv_nsec = 0;
	return pthread_cond_timedwait(&cond->cond, &mutex->mutex, &wait_time);
}

static inline int sd_cond_broadcast(struct sd_cond *cond)
{
	return pthread_cond_broadcast(&cond->cond);
}

/* wrapper for pthread_rwlock */

#define SD_RW_LOCK_INITIALIZER { .rwlock = PTHREAD_RWLOCK_INITIALIZER }

struct sd_rw_lock {
	pthread_rwlock_t rwlock;
};

static inline void sd_init_rw_lock(struct sd_rw_lock *lock)
{
	int ret;

	do {
		ret = pthread_rwlock_init(&lock->rwlock, NULL);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to initialize a lock, %s", strerror(ret));
}

static inline void sd_destroy_rw_lock(struct sd_rw_lock *lock)
{
	int ret;

	do {
		ret = pthread_rwlock_destroy(&lock->rwlock);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to destroy a lock, %s", strerror(ret));
}

static inline void sd_read_lock(struct sd_rw_lock *lock)
{
	int ret;

	do {
		ret = pthread_rwlock_rdlock(&lock->rwlock);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to lock for reading, %s", strerror(ret));
}

/*
 * Even though POSIX manual it doesn't return EAGAIN, we indeed have met the
 * case that it returned EAGAIN
 */
static inline void sd_write_lock(struct sd_rw_lock *lock)
{
	int ret;

	do {
		ret = pthread_rwlock_wrlock(&lock->rwlock);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to lock for writing, %s", strerror(ret));
}

static inline void sd_rw_unlock(struct sd_rw_lock *lock)
{
	int ret;

	do {
		ret = pthread_rwlock_unlock(&lock->rwlock);
	} while (ret == EAGAIN);

	if (unlikely(ret != 0))
		panic("failed to unlock, %s", strerror(ret));
}

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

#define CLEAR_SCREEN        "\033[2J"
#define RESET_CURSOR        "\033[1;1H"

static inline bool is_stdin_console(void)
{
	return isatty(STDIN_FILENO);
}

static inline bool is_stdout_console(void)
{
	return isatty(STDOUT_FILENO);
}

static inline void clear_screen(void)
{
	printf(CLEAR_SCREEN);
	printf(RESET_CURSOR);
}

extern mode_t sd_def_fmode;
extern mode_t sd_def_dmode;

#define MAX_ERRNO	4095

#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

/*
 * For SD, we should pass a '-SD_RES_SOME_ERROR' to ERR_PTR at first, then we
 * use PTR_ERR() to get the actual error code, because we use positive integer
 * for error code.
 */
static inline void * __must_check ERR_PTR(long error)
{
	assert(error < 0);
	return (void *)error;
}

static inline long __must_check PTR_ERR(const void *ptr)
{
	return -(long)ptr;
}

static inline long __must_check IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline long __must_check IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

static inline uint64_t clock_get_time(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000000000LL + (uint64_t)ts.tv_nsec;
}

#endif
