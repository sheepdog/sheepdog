/*
 * Copyright (C) 2013 Zelin.io
 *
 * Kai Zhang <kyle@zelin.io>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "sheep_priv.h"

int read_object(uint64_t oid, char *data, unsigned int datalen,
		uint64_t offset)
{
	return 0;
}

int write_object(uint64_t oid, char *data, unsigned int datalen,
		 uint64_t offset, bool create)
{
	return 0;
}

int read_backend_object(uint64_t oid, char *data, unsigned int datalen,
			uint64_t offset)
{
	return 0;
}

int remove_object(uint64_t oid)
{
	return 0;
}
