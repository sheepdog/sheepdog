/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
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

#include "list.h"
#include "treeview.h"

#ifndef MAX_DEPTH
#define MAX_DEPTH    100
#endif

#define TEXT_NORMAL "\033[0m"
#define TEXT_BOLD   "\033[1m"

struct vdi_tree {
	char name[1024];
	char label[256];
	uint32_t vid;
	uint32_t pvid;
	int highlight;
	struct list_head children;
	struct list_head siblings;
};

static int *width, *more;
static struct vdi_tree *root;

static struct vdi_tree *find_vdi(struct vdi_tree *parent, uint32_t vid,
				 const char *name)
{
	struct vdi_tree *vdi, *ret;

	list_for_each_entry(vdi, &parent->children, siblings) {
		if (vdi->vid == vid && !strcmp(vdi->name, name))
			return vdi;

		ret = find_vdi(vdi, vid, name);
		if (ret)
			return ret;
	}
	return NULL;
}

static struct vdi_tree *new_vdi(const char *name, const char *label,
				uint64_t vid, uint64_t pvid, int highlight)
{
	struct vdi_tree *vdi;

	vdi = malloc(sizeof(struct vdi_tree));
	if (!vdi) {
		fprintf(stderr, "Failed to allocate memory\n");
		return NULL;
	}
	strcpy(vdi->name, name);
	strcpy(vdi->label, label);
	vdi->vid = vid;
	vdi->pvid = pvid;
	vdi->highlight = highlight;
	INIT_LIST_HEAD(&vdi->children);
	return vdi;
}

void init_tree(void)
{
	root = new_vdi("", "", 0, 0, 0);
}

void add_vdi_tree(const char *name, const char *label, uint32_t vid,
		  uint32_t pvid, int highlight)
{
	struct vdi_tree *vdi, *parent;

	vdi = new_vdi(name, label, vid, pvid, highlight);
	if (!vdi)
		return;

	parent = find_vdi(root, pvid, name);
	if (!parent)
		parent = root;

	list_add_tail(&vdi->siblings, &parent->children);
}

static void compaction(struct vdi_tree *parent)
{
	struct vdi_tree *vdi, *e, *new_parent;

	list_for_each_entry_safe(vdi, e, &parent->children, siblings) {
		new_parent = find_vdi(root, vdi->pvid, vdi->name);
		if (new_parent && parent != new_parent) {
			list_del(&vdi->siblings);
			list_add_tail(&vdi->siblings, &new_parent->children);
		}

		compaction(vdi);
	}
}

static int get_depth(struct vdi_tree *parent)
{
	struct vdi_tree *vdi;
	int max_depth = 0, depth;

	list_for_each_entry(vdi, &parent->children, siblings) {
		depth = get_depth(vdi);
		if (max_depth < depth)
			max_depth = depth;
	}
	return max_depth + 1;
}

static void spaces(int n)
{
	while (n--)
		putchar(' ');
}

static void indent(int level, int first, int last)
{
	int lvl;

	if (first)
		printf(last ? "---" : "-+-");
	else {
		for (lvl = 0; lvl < level - 1; lvl++) {
			spaces(width[lvl] + 1);
			printf(more[lvl + 1] ? "| " : "  ");
		}

		spaces(width[level - 1] + 1);
		printf(last ? "`-" : "|-");
	}
}

static void _dump_tree(struct vdi_tree *current, int level, int first, int last)
{
	struct vdi_tree *vdi;

	indent(level, first, last);

	if (current->highlight)
		printf(TEXT_BOLD);

	printf("%s", current->label);

	if (current->highlight)
		printf(TEXT_NORMAL);

	if (list_empty(&current->children)) {
		putchar('\n');
		return;
	}

	more[level] = !last;
	width[level] = strlen(current->label);

	list_for_each_entry(vdi, &current->children, siblings) {
		_dump_tree(vdi, level + 1,
			   &vdi->siblings == current->children.next,
			   vdi->siblings.next == &current->children);
	}
}

void dump_tree(void)
{
	struct vdi_tree *vdi;
	int depth;

	compaction(root);

	depth = get_depth(root);

	width = malloc(sizeof(int) * depth);
	more = malloc(sizeof(int) * depth);
	if (!width || !more) {
		fprintf(stderr, "Failed to allocate memory\n");
		return;
	}

	list_for_each_entry(vdi, &root->children, siblings) {
		printf("%s", vdi->name);
		more[0] = 0;
		width[0] = strlen(vdi->name);
		_dump_tree(vdi, 1, 1, 1);
	}
}
