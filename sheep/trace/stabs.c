/*
 * Copyright (C) 2012 Taobao Inc.
 *
 * Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stab.h>
#include <stdint.h>
#include <string.h>

#include "trace.h"

/* referrence to the MIT JOS code */

/* Entries in the STABS table are formatted as follows */
struct stab {
	uint32_t index;		/* index into string table of name */
	uint8_t type;		/* type of symbol */
	uint8_t misc;		/* misc info (usually empty) */
	uint16_t desc;		/* description field */
	uint32_t value;		/* value of symbol */
};

extern const struct stab __STAB_BEGIN__[];
extern const struct stab __STAB_END__[];
extern const char __STABSTR_BEGIN__[];
extern const char __STABSTR_END__[];

/*
   stab_bsearch(stabs, region_left, region_right, type, addr)

   Some stab types are arranged in increasing order by instruction
   address.  For example, N_FUN stabs (stab entries with type ==
   N_FUN), which mark functions, and N_SO stabs, which mark source files.

   Given an instruction address, this function finds the single stab
   entry of type 'type' that contains that address.

   The search modifies *region_left and *region_right to bracket the
   'addr'.  *region_left points to the matching stab that contains
   'addr', and *region_right points just before the next stab.  If
   *region_left > *region_right, then 'addr' is not contained in any
   matching stab.

   For example, given these N_SO stabs:
   Index  Type   Address
   0      SO     f0100000
   13     SO     f0100040
   117    SO     f0100176
   118    SO     f0100178
   555    SO     f0100652
   556    SO     f0100654
   657    SO     f0100849
   this code:
	left = 0, right = 657;
	stab_bsearch(stabs, &left, &right, N_SO, 0xf0100184);
   will exit setting left = 118, right = 554.
 */
static notrace void stab_bsearch(const struct stab *stabs, int *region_left, int *region_right,
		int type, uintptr_t addr)
{
	int l = *region_left, r = *region_right, any_matches = 0;

	while (l <= r) {
		int true_m = (l + r) / 2, m = true_m;

		/* search for earliest stab with right type */
		while (m >= l && stabs[m].type != type)
			m--;
		if (m < l) {	/* no match in [l, m] */
			l = true_m + 1;
			continue;
		}

		/* actual binary search */
		any_matches = 1;
		if (stabs[m].value < addr) {
			*region_left = m;
			l = true_m + 1;
		} else if (stabs[m].value > addr) {
			*region_right = m - 1;
			r = m - 1;
		} else {
			/* exact match for 'addr', but continue loop to find
			 * *region_right
			 */
			*region_left = m;
			l = m;
			addr++;
		}
	}

	if (!any_matches)
		*region_right = *region_left - 1;
	else {
		/* find rightmost region containing 'addr' */
		for (l = *region_right;
				l > *region_left && stabs[l].type != type;
				l--)
			/* do nothing */;
		*region_left = l;
	}
}

/*
 * Fill in the 'info' structure with information about the specified
 * instruction address, 'addr'.
 *
 * Returns
 *  0 if information was found
 * -1 if not.
 *
 * NB: But even if it returns negative it has stored some
 * information into '*info'.
 */

notrace int get_ipinfo(uintptr_t addr, struct ipinfo *info)
{
	const struct stab *stabs, *stab_end;
	const char *stabstr, *stabstr_end;
	int lfile, rfile, lfun, rfun, lline, rline;

	info->file = "<unknown>";
	info->line = 0;
	info->fn_name = "<unknown>";
	info->fn_namelen = 9;
	info->fn_addr = addr;
	info->fn_narg = 0;

	stabs = __STAB_BEGIN__;
	stab_end = __STAB_END__;
	stabstr = __STABSTR_BEGIN__;
	stabstr_end = __STABSTR_END__;

	if (stabstr_end <= stabstr || stabstr_end[-1] != 0)
		return -1;

	/* Now we find the right stabs that define the function containing
	 * 'eip'.  First, we find the basic source file containing 'eip'.
	 * Then, we look in that source file for the function.  Then we look
	 * for the line number.
	 */

	lfile = 0;
	rfile = (stab_end - stabs) - 1;
	stab_bsearch(stabs, &lfile, &rfile, N_SO, addr);
	if (lfile == 0)
		return -1;

	lfun = lfile;
	rfun = rfile;
	stab_bsearch(stabs, &lfun, &rfun, N_FUN, addr);

	if (lfun <= rfun) {
		/* stabs[lfun] points to the function name
		 * in the string table, but check bounds just in case.
		 */
		if (stabs[lfun].index < stabstr_end - stabstr)
			info->fn_name = stabstr + stabs[lfun].index;
		info->fn_addr = stabs[lfun].value;
		addr -= info->fn_addr;
		/* Search within the function definition for the line number. */
		lline = lfun;
		rline = rfun;
	} else {
		/* Couldn't find function stab!  Maybe we're in an assembly
		 * file.  Search the whole file for the line number.
		 */
		info->fn_addr = addr;
		lline = lfile;
		rline = rfile;
	}
	/* Ignore stuff after the colon. */
	info->fn_namelen = strchr(info->fn_name, ':') - info->fn_name;


	/* Search within [lline, rline] for the line number stab. */
	stab_bsearch(stabs, &lline, &rline, N_SLINE, addr);
	if (lline <= rline)
		info->line = stabs[lline].desc;
	else
		return -1;
	/* Search backwards from the line number for the relevant filename
	 * stab.
	 * We can't just use the "lfile" stab because inlined functions
	 * can interpolate code from a different file!
	 * Such included source files use the N_SOL stab type.
	 */
	while (lline >= lfile &&
		stabs[lline].type != N_SOL &&
		(stabs[lline].type != N_SO || !stabs[lline].value))
		lline--;
	if (lline >= lfile && stabs[lline].index < stabstr_end - stabstr)
		info->file = stabstr + stabs[lline].index;
	/* Set fn_narg to the number of arguments taken by the function,
	 * or 0 if there was no containing function.
	 */
	if (lfun < rfun)
		for (lline = lfun + 1; lline < rfun && stabs[lline].type == N_PSYM;
		     lline++)
			info->fn_narg++;

	return 0;
}
