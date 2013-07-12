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
#ifndef __SD_OPTION_H__
#define __SD_OPTION_H__

#include <stdbool.h>
#include <getopt.h>

struct sd_option {
	int ch;
	const char *name;
	bool has_arg;
	const char *desc;
	const char *help;
};

char *build_short_options(const struct sd_option *opts);
struct option *build_long_options(const struct sd_option *opts);
const char *option_get_help(const struct sd_option *, int);

#define sd_for_each_option(opt, opts)		\
	for (opt = (opts); opt->name; opt++)

#endif /* __SD_OPTION_H__ */
