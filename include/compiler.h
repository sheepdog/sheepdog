/*
 * Copyright (C) 2009-2013 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SD_COMPILER_H
#define SD_COMPILER_H

#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <stdint.h>

#include "config.h"

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#define __packed __attribute((packed))

#define asmlinkage  __attribute__((regparm(0)))

#define __printf(a, b) __attribute__((format(printf, a, b)))

/* Force a compilation error if the condition is true */
#define BUILD_BUG_ON(condition) ((void)sizeof(struct { int: -!!(condition); }))

#ifdef HAVE_SYS_SIGNALFD_H
#include <sys/signalfd.h>
#else
#define SFD_NONBLOCK	(04000)
struct signalfd_siginfo {
	uint32_t ssi_signo;
	int32_t ssi_errno;
	int32_t ssi_code;
	uint32_t ssi_pid;
	uint32_t ssi_uid;
	int32_t ssi_fd;
	uint32_t ssi_tid;
	uint32_t ssi_band;
	uint32_t ssi_overrun;
	uint32_t ssi_trapno;
	int32_t ssi_status;
	int32_t ssi_int;
	uint64_t ssi_ptr;
	uint64_t ssi_utime;
	uint64_t ssi_stime;
	uint64_t ssi_addr;
	uint16_t ssi_addr_lsb;
	uint8_t __pad[46];
};

static inline int signalfd(int __fd, const sigset_t *__mask, int __flags)
{
	return syscall(__NR_signalfd4, __fd, __mask, _NSIG / 8, __flags);
}
#endif

#ifdef HAVE_SYS_EVENTFD_H
#include <sys/eventfd.h>
#else
#define EFD_SEMAPHORE	(1)
#define EFD_NONBLOCK	(04000)
#define eventfd_t	uint64_t
static inline int eventfd_write(int fd, eventfd_t value)
{
	return write(fd, &value, sizeof(eventfd_t)) !=
			sizeof(eventfd_t) ? -1 : 0;
}

static inline int eventfd_read(int fd, eventfd_t *value)
{
	return read(fd, value, sizeof(eventfd_t)) !=
			sizeof(eventfd_t) ? -1 : 0;
}

static inline int eventfd(unsigned int initval, int flags)
{
	return syscall(__NR_eventfd2, initval, flags);
}
#endif

#ifdef HAVE_SYS_TIMERFD_H
#include <sys/timerfd.h>
#else
#define TFD_NONBLOCK (04000)
static inline int timerfd_create(clockid_t __clock_id, int __flags)
{
	return syscall(__NR_timerfd_create, __clock_id, __flags);
}

static inline int timerfd_settime(int __ufd, int __flags,
		__const struct itimerspec *__utmr, struct itimerspec *__otmr)
{
	return syscall(__NR_timerfd_settime, __ufd, __flags, __utmr, __otmr);
}
#endif

#ifndef HAVE_FALLOCATE
static inline int fallocate(int fd, int mode, __off_t offset, __off_t len)
{
	return syscall(__NR_fallocate, fd, mode, offset, len);
}
#endif

#ifdef __x86_64__

#define X86_FEATURE_SSSE3	(4 * 32 + 9) /* Supplemental SSE-3 */
#define X86_FEATURE_OSXSAVE	(4 * 32 + 27) /* "" XSAVE enabled in the OS */
#define X86_FEATURE_AVX	(4 * 32 + 28) /* Advanced Vector Extensions */

#define XSTATE_FP	0x1
#define XSTATE_SSE	0x2
#define XSTATE_YMM	0x4

#define XCR_XFEATURE_ENABLED_MASK	0x00000000

static inline int cpu_has(int flag)
{
	uint32_t eax, ebx, ecx, edx;

	eax = (flag & 0x100) ? 7 :
		(flag & 0x20) ? 0x80000001 : 1;
	ecx = 0;

	asm volatile("cpuid"
		     : "+a" (eax), "=b" (ebx), "=d" (edx), "+c" (ecx));

	return ((flag & 0x100 ? ebx :
		 (flag & 0x80) ? ecx : edx) >> (flag & 31)) & 1;
}

static inline uint64_t xgetbv(uint32_t idx)
{
	uint32_t eax, edx;

	asm volatile(".byte 0x0f,0x01,0xd0" /* xgetbv */
		     : "=a" (eax), "=d" (edx)
		     : "c" (idx));
	return eax + ((uint64_t)edx << 32);
}

#define cpu_has_ssse3           cpu_has(X86_FEATURE_SSSE3)
#define cpu_has_avx		cpu_has(X86_FEATURE_AVX)
#define cpu_has_osxsave		cpu_has(X86_FEATURE_OSXSAVE)

#endif /* __x86_64__ */

#endif	/* SD_COMPILER_H */
