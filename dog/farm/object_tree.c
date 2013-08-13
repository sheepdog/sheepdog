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

#include "farm.h"
#include "rbtree.h"

struct object_tree_entry {
	uint64_t oid;
	int nr_copies;
	struct rb_node node;
	struct list_head list;
};

struct object_tree {
	int nr_objs;
	struct rb_root root;
	struct list_head list;
};

static struct object_tree tree = {
	.nr_objs = 0,
	.root = RB_ROOT,
	.list = LIST_HEAD_INIT(tree.list)
};
static struct object_tree_entry *cached_entry;

static struct object_tree_entry *do_insert(struct rb_root *root,
				      struct object_tree_entry *new)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct object_tree_entry *entry;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct object_tree_entry, node);

		if (new->oid < entry->oid)
			p = &(*p)->rb_left;
		else if (new->oid > entry->oid)
			p = &(*p)->rb_right;
		else
			return entry; /* already has this entry */
	}
	rb_link_node(&new->node, parent, p);
	rb_insert_color(&new->node, root);

	return NULL; /* insert sucessfully */
}

void object_tree_insert(uint64_t oid, int nr_copies)
{
	struct rb_root *root = &tree.root;
	struct object_tree_entry *p = NULL;

	if (!cached_entry)
		cached_entry = xzalloc(sizeof(*cached_entry));
	cached_entry->oid = oid;
	cached_entry->nr_copies = nr_copies;
	rb_init_node(&cached_entry->node);
	p = do_insert(root, cached_entry);
	if (!p) {
		list_add(&cached_entry->list, &tree.list);
		tree.nr_objs++;
		cached_entry = NULL;
	}
}

void object_tree_print(void)
{
	struct rb_node *p = rb_first(&tree.root);
	struct object_tree_entry *entry;
	printf("nr_objs: %d\n", tree.nr_objs);

	while (p) {
		entry = rb_entry(p, struct object_tree_entry, node);
		printf("Obj id: %"PRIx64"\n", entry->oid);
		p = rb_next(p);
	}
}

void object_tree_free(void)
{
	struct object_tree_entry *entry, *next;
	list_for_each_entry_safe(entry, next, &tree.list, list)
		free(entry);

	free(cached_entry);
}

int object_tree_size(void)
{
	return tree.nr_objs;
}

int for_each_object_in_tree(int (*func)(uint64_t oid, int nr_copies,
					void *data), void *data)
{
	struct rb_node *p = rb_first(&tree.root);
	struct object_tree_entry *entry;
	int ret = -1;

	while (p) {
		entry = rb_entry(p, struct object_tree_entry, node);

		if (func(entry->oid, entry->nr_copies, data) < 0)
			goto out;

		p = rb_next(p);
	}
	ret = 0;
out:
	return ret;
}
