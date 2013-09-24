#ifndef __RBTREE_H_
#define __RBTREE_H_

#include "compiler.h"

/* We have to be 64-bytes aligned to get 32/64 bits compatibility */
struct rb_node {
	unsigned long  rb_parent_color __attribute__ ((aligned (8)));
#define RB_RED          0
#define RB_BLACK        1
	struct rb_node *rb_right __attribute__ ((aligned (8)));
	struct rb_node *rb_left __attribute__ ((aligned (8)));
};

struct rb_root {
	struct rb_node *rb_node;
};


#define rb_parent(r)   ((struct rb_node *)((r)->rb_parent_color & ~3))
#define rb_color(r)   ((r)->rb_parent_color & 1)
#define rb_is_red(r)   (!rb_color(r))
#define rb_is_black(r) rb_color(r)
#define rb_set_red(r)  do { (r)->rb_parent_color &= ~1; } while (0)
#define rb_set_black(r)  do { (r)->rb_parent_color |= 1; } while (0)

static inline void rb_set_parent(struct rb_node *rb, struct rb_node *p)
{
	rb->rb_parent_color = (rb->rb_parent_color & 3) | (unsigned long)p;
}
static inline void rb_set_color(struct rb_node *rb, int color)
{
	rb->rb_parent_color = (rb->rb_parent_color & ~1) | color;
}

#define RB_ROOT { .rb_node = NULL }
static inline void INIT_RB_ROOT(struct rb_root *root)
{
	root->rb_node = NULL;
}

#define rb_entry(ptr, type, member) container_of(ptr, type, member)

#define RB_EMPTY_ROOT(root)     ((root)->rb_node == NULL)
#define RB_EMPTY_NODE(node)     (rb_parent(node) == node)
#define RB_CLEAR_NODE(node)     (rb_set_parent(node, node))

static inline void rb_init_node(struct rb_node *rb)
{
	rb->rb_parent_color = 0;
	rb->rb_right = NULL;
	rb->rb_left = NULL;
	RB_CLEAR_NODE(rb);
}

void rb_insert_color(struct rb_node *, struct rb_root *);
void rb_erase(struct rb_node *, struct rb_root *);

/* Find logical next and previous nodes in a tree */
struct rb_node *rb_next(const struct rb_node *);
struct rb_node *rb_prev(const struct rb_node *);
struct rb_node *rb_first(const struct rb_root *);
struct rb_node *rb_last(const struct rb_root *);

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
void rb_replace_node(struct rb_node *victim, struct rb_node *new,
		struct rb_root *root);

static inline void rb_link_node(struct rb_node *node, struct rb_node *parent,
		struct rb_node **rb_link)
{
	node->rb_parent_color = (unsigned long)parent;
	node->rb_left = node->rb_right = NULL;

	*rb_link = node;
}

/*
 * Search for a value in the rbtree.  This returns NULL when the key is not
 * found in the rbtree.
 */
#define rb_search(root, key, member, compar)				\
({									\
	struct rb_node *__n = (root)->rb_node;				\
	typeof(key) __ret = NULL, __data;				\
									\
	while (__n) {							\
		__data = rb_entry(__n, typeof(*key), member);		\
		int __cmp = compar(key, __data);			\
									\
		if (__cmp < 0)						\
			__n = __n->rb_left;				\
		else if (__cmp > 0)					\
			__n = __n->rb_right;				\
		else {							\
			__ret = __data;					\
			break;						\
		}							\
	}								\
	__ret;								\
})

/*
 * Insert a new node into the rbtree.  This returns NULL on success, or the
 * existing node on error.
 */
#define rb_insert(root, new, member, compar)				\
({									\
	struct rb_node **__n = &(root)->rb_node, *__parent = NULL;	\
	typeof(new) __old = NULL, __data;				\
									\
	while (*__n) {							\
		__data = rb_entry(*__n, typeof(*new), member);		\
		int __cmp = compar(new, __data);			\
									\
		__parent = *__n;					\
		if (__cmp < 0)						\
			__n = &((*__n)->rb_left);			\
		else if (__cmp > 0)					\
			__n = &((*__n)->rb_right);			\
		else {							\
			__old = __data;					\
			break;						\
		}							\
	}								\
									\
	if (__old == NULL) {						\
		/* Add new node and rebalance tree. */			\
		rb_link_node(&((new)->member), __parent, __n);		\
		rb_insert_color(&((new)->member), root);		\
	}								\
									\
	__old;							\
})

/*
 * Search for a value in the rbtree.  When the key is not found in the rbtree,
 * this returns the next greater node. Note, if key > greatest node, we'll
 * return first node.
 *
 * For an empty tree, we return NULL.
 */
#define rb_nsearch(root, key, member, compar)                           \
({                                                                      \
        struct rb_node *__n = (root)->rb_node;                          \
        typeof(key) __ret = NULL, __data;                               \
                                                                        \
        while (__n) {                                                   \
                __data = rb_entry(__n, typeof(*key), member);           \
                int __cmp = compar(key, __data);                        \
                                                                        \
                if (__cmp < 0) {                                        \
                        __ret = __data;                                 \
                        __n = __n->rb_left;                             \
                } else if (__cmp > 0)                                   \
                        __n = __n->rb_right;                            \
                else {                                                  \
                        __ret = __data;                                 \
                        break;                                          \
                }                                                       \
        }                                                               \
        if (!__ret && !RB_EMPTY_ROOT(root))                             \
                __ret = rb_entry(rb_first(root), typeof(*key), member); \
        __ret;                                                          \
})

/* Iterate over a rbtree safe against removal of rbnode */
#define rb_for_each(pos, root)						\
	for (struct rb_node *LOCAL(n) = (pos = rb_first(root), NULL);	\
	     pos && (LOCAL(n) = rb_next(pos), 1);			\
	     pos = LOCAL(n))

/* Iterate over a rbtree of given type safe against removal of rbnode */
#define rb_for_each_entry(pos, root, member)				\
	for (struct rb_node *LOCAL(p) = rb_first(root), *LOCAL(n);	\
	     LOCAL(p) && (LOCAL(n) = rb_next(LOCAL(p)), 1) &&		\
		     (pos = rb_entry(LOCAL(p), typeof(*pos), member), 1); \
	     LOCAL(p) = LOCAL(n))

/* Destroy the tree and free the memory */
#define rb_destroy(root, type, member)					\
({									\
	type *__dummy;							\
	rb_for_each_entry(__dummy, root, member) {			\
		rb_erase(&__dummy->member, root);			\
		free(__dummy);						\
	}								\
})

/* Copy the tree 'root' as 'outroot' */
#define rb_copy(root, type, member, outroot, compar)			\
({									\
	type *__src, *__dst;						\
	rb_for_each_entry(__src, root, member) {			\
		__dst = xmalloc(sizeof(*__dst));			\
		*__dst = *__src;					\
		rb_insert(outroot, __dst, member, compar);		\
	}								\
})

#endif /* __RBTREE_H_ */
