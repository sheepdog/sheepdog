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
	uint8_t nr_copies;
	uint8_t copy_policy;
	uint8_t block_size_shift;
	struct rb_node node;
};

struct object_tree {
	int nr_objs;
	struct rb_root root;
};

static struct object_tree tree = {
	.nr_objs = 0,
	.root = RB_ROOT,
};
static struct object_tree_entry *cached_entry;

static int object_tree_cmp(const struct object_tree_entry *a,
			   const struct object_tree_entry *b)
{
	return intcmp(a->oid, b->oid);
}

static struct object_tree_entry *do_insert(struct rb_root *root,
				      struct object_tree_entry *new)
{
	return rb_insert(root, new, node, object_tree_cmp);
}

void object_tree_insert(uint64_t oid, uint32_t nr_copies,
			uint8_t copy_policy, uint8_t block_size_shift)
{
	struct rb_root *root = &tree.root;
	struct object_tree_entry *p = NULL;

	if (!cached_entry)
		cached_entry = xzalloc(sizeof(*cached_entry));
	cached_entry->oid = oid;
	cached_entry->nr_copies = nr_copies;
	cached_entry->copy_policy = copy_policy;
	cached_entry->block_size_shift = block_size_shift;

	rb_init_node(&cached_entry->node);
	p = do_insert(root, cached_entry);
	if (!p) {
		tree.nr_objs++;
		cached_entry = NULL;
	}
}

void object_tree_print(void)
{
	struct object_tree_entry *entry;
	printf("nr_objs: %d\n", tree.nr_objs);

	rb_for_each_entry(entry, &tree.root, node)
		printf("Obj id: %016"PRIx64"\n", entry->oid);
}

void object_tree_free(void)
{
	rb_destroy(&tree.root, struct object_tree_entry, node);
	free(cached_entry);
}

int object_tree_size(void)
{
	return tree.nr_objs;
}

int for_each_object_in_tree(int (*func)(uint64_t oid, uint32_t nr_copies,
					uint8_t copy_policy,
					uint8_t block_size_shift, void *data),
			    void *data)
{
	struct object_tree_entry *entry;
	int ret = -1;

	rb_for_each_entry(entry, &tree.root, node) {
		if (func(entry->oid, entry->nr_copies, entry->copy_policy,
			 entry->block_size_shift, data) < 0)
			goto out;
	}
	ret = 0;
out:
	return ret;
}
