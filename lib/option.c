/*
 * Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "option.h"
#include "logger.h"

char *build_short_options(const struct sd_option *sd_opts)
{
	static char sopts[256], *p;
	const struct sd_option *opt;

	p = sopts;
	sd_for_each_option(opt, sd_opts) {
		*p++ = opt->ch;
		if (opt->has_arg)
			*p++ = ':';
	}
	*p = '\0';

	return sopts;
}

struct option *build_long_options(const struct sd_option *sd_opts)
{
	static struct option lopts[256], *p;
	const struct sd_option *opt;

	p = lopts;
	sd_for_each_option(opt, sd_opts) {
		p->name = opt->name;
		p->has_arg = opt->has_arg;
		p->flag = NULL;
		p->val = opt->ch;
		p++;
	}
	memset(p, 0, sizeof(struct option));

	return lopts;
}

const char *option_get_help(const struct sd_option *sd_opts, int ch)
{
	const struct sd_option *opt;

	sd_for_each_option(opt, sd_opts) {
		if (opt->ch == ch)
			return opt->help;
	}
	return NULL;
}

int option_parse(char *arg, const char *delim, struct option_parser *parsers)
{
	char *savep, *opt;
	struct option_parser *iter = NULL;

	opt = strtok_r(arg, delim, &savep);
	do {
		for (iter = parsers; iter->option; iter++) {
			int len = strlen(iter->option);

			if (!strncmp(iter->option, opt, len)) {
				if (iter->parser(opt + len) < 0)
					return -1;
				break;
			}
		}
		if (!iter->option) {
			sd_err("invalid option %s", opt);
			return -1;
		}
	} while ((opt = strtok_r(NULL, delim, &savep)));

	return 0;
}
