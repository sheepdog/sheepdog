/*
 * Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LTTNG_DISABLE_H
#define LTTNG_DISABLE_H

#define tracepoint(provider, name, ...)	do { } while (0)

#endif	/* LTTNG_DISABLE_H */
