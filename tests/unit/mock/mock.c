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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "list.h"
#include "mock.h"

LIST_HEAD(mock_methods);

static struct mock_method *find_method(const char *name)
{
	struct mock_method *method;
	int len;
	list_for_each_entry(method, &mock_methods, list) {
		len = strlen(method->name);
		if (strncmp(method->name, name, len) == 0)
			return method;
	}
	return NULL;
}

int __method_nr_call(const char *name)
{
	struct mock_method *method = find_method(name);
	if (method)
		return method->nr_call;
	else {
		fprintf(stderr, "%s is not a mock method", name);
		exit(1);
	}
}

void __method_reset_all(void)
{
	struct mock_method *method;
	list_for_each_entry(method, &mock_methods, list)
		method->nr_call = 0;
}
