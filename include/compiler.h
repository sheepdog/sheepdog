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

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#define __packed __attribute((packed))

#define __printf(a, b) __attribute__((format(printf, a, b)))

/* Force a compilation error if the condition is true */
#define BUILD_BUG_ON(condition) ((void)sizeof(struct { int: -!!(condition); }))

#endif	/* SD_COMPILER_H */
