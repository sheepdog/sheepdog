/*
 * Copyright (C) 2009 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <dirent.h>
#include <curses.h>
#include <term.h>

#ifndef MAX_DEPTH
#define MAX_DEPTH    100
#endif

typedef struct _proc {
	char label[256];
	char tag[256];
	uint64_t oid;
	int highlight;
	struct _child *children;
	struct _proc *parent;
	struct _proc *next;
} PROC;

typedef struct _child {
	PROC *child;
	struct _child *next;
} CHILD;

static struct {
	const char *empty_2;	/*    */
	const char *branch_2;	/* |- */
	const char *vert_2;	/* |  */
	const char *last_2;	/* `- */
	const char *single_3;	/* --- */
	const char *first_3;	/* -+- */
} sym_ascii = {
"  ", "|-", "| ", "`-", "---", "-+-"}

, *sym = &sym_ascii;

static PROC *list = NULL;
static int width[MAX_DEPTH], more[MAX_DEPTH];
static int trunc = 1;
static int output_width = 132;
static int cur_x = 1;
static char last_char = 0;

static void out_char(char c)
{
	cur_x += (c & 0xc0) != 0x80;	/* only count first UTF-8 char */
	if (cur_x <= output_width || !trunc)
		putchar(c);
	if (cur_x == output_width + 1 && trunc && ((c & 0xc0) != 0x80)) {
		if (last_char || (c & 0x80))
			putchar('+');
		else {
			last_char = c;
			cur_x--;
			return;
		}
	}
}

static void out_string(const char *str)
{
	while (*str)
		out_char(*str++);
}

static void out_newline(void)
{
	if (last_char && cur_x == output_width)
		putchar(last_char);
	last_char = 0;
	putchar('\n');
	cur_x = 1;
}

void init_tree(void)
{
	list = NULL;
}

static PROC *find_proc(uint64_t oid)
{
	PROC *walk;

	for (walk = list; walk; walk = walk->next)
		if (walk->oid == oid)
			break;
	return walk;
}

static PROC *new_proc(const char *label, const char *tag, uint64_t oid)
{
	PROC *new;

	if (!(new = malloc(sizeof(PROC)))) {
		perror("malloc");
		exit(1);
	}
	strcpy(new->label, label);
	strcpy(new->tag, tag);
	new->oid = oid;
	new->highlight = 0;
	new->children = NULL;
	new->parent = NULL;
	new->next = list;
	return list = new;
}

static void add_child(PROC * parent, PROC * child)
{
	CHILD *new, **walk;

	if (!(new = malloc(sizeof(CHILD)))) {
		perror("malloc");
		exit(1);
	}
	new->child = child;
	for (walk = &parent->children; *walk; walk = &(*walk)->next) ;
	new->next = *walk;
	*walk = new;
}

void add_proc(const char *label, const char *tag, uint64_t oid, uint64_t poid, int highlight)
{
	PROC *this, *parent, *root;

	if (!(this = find_proc(oid)))
		this = new_proc(label, tag, oid);
	else {
		strcpy(this->label, label);
		strcpy(this->tag, tag);
	}
	this->highlight = highlight;
	if (oid == poid) {
		poid = 0;
		return;
	}
	if (!(parent = find_proc(poid))) {
		root = find_proc(1);
		parent = new_proc("", label, -oid);
		add_child(root, parent);
	}

	add_child(parent, this);
	this->parent = parent;
}

static void _dump_tree(PROC * current, int level, int leaf, int last)
{
	CHILD *walk, *next;
	int lvl, i, add, offset, tag_len, first;
	const char *tmp, *here;

	if (!current)
		return;
	if (level >= MAX_DEPTH - 1) {
		fprintf(stderr, "Internal error: MAX_DEPTH not big enough.\n");
		exit(1);
	}
	if (!leaf)
		for (lvl = 0; lvl < level; lvl++) {
			for (i = width[lvl] + 1; i; i--)
				out_char(' ');
			out_string(lvl ==
				   level -
				   1 ? last ? sym->
				   last_2 : sym->branch_2 : more[lvl +
								 1] ? sym->
				   vert_2 : sym->empty_2);
		}
	add = 0;
	if (current->highlight && (tmp = tgetstr("md", NULL)))
		tputs(tmp, 1, putchar);
	tag_len = 0;
	for (here = current->tag; *here; here++) {
		out_char(*here);
		tag_len++;
	}
	offset = cur_x;
	if (current->highlight && (tmp = tgetstr("me", NULL)))
		tputs(tmp, 1, putchar);
	if (!current->children) {
		out_newline();
	} else {
		more[level] = !last;
		width[level] = tag_len + cur_x - offset + add;
		if (cur_x >= output_width && trunc) {
			out_string(sym->first_3);
			out_string("+");
			out_newline();
		} else {
			first = 1;
			for (walk = current->children; walk; walk = next) {
				next = walk->next;
				if (first) {
					out_string(next ? sym->
						   first_3 : sym->single_3);
					first = 0;
				}
				_dump_tree(walk->child, level + 1,
					   walk == current->children, !next);
			}
		}
	}
}

void dump_tree(void)
{
	const CHILD *walk;

	sym = &sym_ascii;

	for (walk = find_proc(1)->children; walk; walk = walk->next)
		_dump_tree(walk->child, 0, 1, 1);
}
