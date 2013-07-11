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

#define notrace __attribute__((no_instrument_function))
#define __packed __attribute((packed))

#define __printf(a, b) __attribute__((format(printf, a, b)))

#endif	/* SD_COMPILER_H */
