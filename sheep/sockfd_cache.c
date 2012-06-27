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

#include <urcu/uatomic.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "sheep.h"
#include "sheep_priv.h"
#include "list.h"
#include "rbtree.h"
#include "logger.h"
#include "util.h"

struct node_id {
	uint8_t addr[16];
	uint16_t port;
};

struct sockfd_cache {
	struct rb_root root;
	pthread_rwlock_t lock;
	int count;
};

static struct sockfd_cache sockfd_cache = {
	.root = RB_ROOT,
	.lock = PTHREAD_RWLOCK_INITIALIZER,
};

struct sockfd_cache_entry {
	struct rb_node rb;
	int fd;
	uint8_t refcount;
	struct node_id nid;
};

static inline int node_id_cmp(const void *a, const void *b)
{
	const struct node_id *node1 = a;
	const struct node_id *node2 = b;
	int cmp;

	cmp = memcmp(node1->addr, node2->addr, sizeof(node1->addr));
	if (cmp != 0)
		return cmp;

	if (node1->port < node2->port)
		return -1;
	if (node1->port > node2->port)
		return 1;
	return 0;
}

static struct sockfd_cache_entry *
sockfd_cache_insert(struct sockfd_cache_entry *new)
{
	struct rb_node **p = &sockfd_cache.root.rb_node;
	struct rb_node *parent = NULL;
	struct sockfd_cache_entry *entry;

	while (*p) {
		int cmp;

		parent = *p;
		entry = rb_entry(parent, struct sockfd_cache_entry, rb);
		cmp = node_id_cmp(&new->nid, &entry->nid);

		if (cmp < 0)
			p = &(*p)->rb_left;
		else if (cmp > 0)
			p = &(*p)->rb_right;
		else
			return entry;
	}
	rb_link_node(&new->rb, parent, p);
	rb_insert_color(&new->rb, &sockfd_cache.root);

	return NULL; /* insert successfully */
}

static struct sockfd_cache_entry *sockfd_cache_search(struct node_id *nid)
{
	struct rb_node *n = sockfd_cache.root.rb_node;
	struct sockfd_cache_entry *t;

	while (n) {
		int cmp;

		t = rb_entry(n, struct sockfd_cache_entry, rb);
		cmp = node_id_cmp(nid, &t->nid);

		if (cmp < 0)
			n = n->rb_left;
		else if (cmp > 0)
			n = n->rb_right;
		else
			return t; /* found it */
	}

	return NULL;
}

static struct sockfd_cache_entry *sockfd_cache_grab(struct node_id *nid)
{
	struct sockfd_cache_entry *entry;

	pthread_rwlock_rdlock(&sockfd_cache.lock);
	entry = sockfd_cache_search(nid);
	pthread_rwlock_unlock(&sockfd_cache.lock);
	assert(entry);
	/* if refcount == 0, set it to 1, otherwise someone holds it */
	if (uatomic_cmpxchg(&entry->refcount, 0, 1))
		return NULL;

	return entry;
}

void sockfd_cache_del(struct node_id *nid)
{
	struct sockfd_cache_entry *entry;
	char name[INET6_ADDRSTRLEN];
	int n;

	entry = sockfd_cache_grab(nid);
	/* Hmmm, some victim still holds it, he is supposed to delete it */
	if (!entry)
		return;

	rb_erase(&entry->rb, &sockfd_cache.root);
	free(entry);
	n = uatomic_sub_return(&sockfd_cache.count, 1);
	addr_to_str(name, sizeof(name), nid->addr, 0);
	dprintf("%s:%d, count %d\n", name, nid->port, n);
}

static void sockfd_cache_add_nolock(struct node_id *nid)
{
	struct sockfd_cache_entry *new = xzalloc(sizeof(*new));

	new->fd = -1;
	memcpy(&new->nid, nid, sizeof(struct node_id));
	if (sockfd_cache_insert(new)) {
		free(new);
		return;
	}
	sockfd_cache.count++;
}

void sockfd_cache_add_group(struct sd_node *nodes, int nr)
{
	struct sd_node *p;
	struct node_id *nid;

	dprintf("%d\n", nr);
	pthread_rwlock_wrlock(&sockfd_cache.lock);
	while (nr--) {
		p = nodes + nr;
		nid = (struct node_id *)p;
		sockfd_cache_add_nolock(nid);
	}
	pthread_rwlock_unlock(&sockfd_cache.lock);
}

void sockfd_cache_add(struct sd_node *node)
{
	struct sockfd_cache_entry *new = xzalloc(sizeof(*new));
	char name[INET6_ADDRSTRLEN];
	int n;

	new->fd = -1;
	memcpy(&new->nid, node, sizeof(struct node_id));
	pthread_rwlock_rdlock(&sockfd_cache.lock);
	if (sockfd_cache_insert(new)) {
		free(new);
		pthread_rwlock_unlock(&sockfd_cache.lock);
		return;
	}
	pthread_rwlock_unlock(&sockfd_cache.lock);
	n = uatomic_add_return(&sockfd_cache.count, 1);
	addr_to_str(name, sizeof(name), node->addr, 0);
	dprintf("%s:%d, count %d\n", name, node->port, n);
}

static int sockfd_cache_get(struct node_id *nid)
{
	struct sockfd_cache_entry *entry;
	char name[INET6_ADDRSTRLEN];
	int fd;

	entry = sockfd_cache_grab(nid);
	if (!entry)
		return -1;

	if (entry->fd != -1)
		return entry->fd;

	/* Create a new connection for this vnode */
	addr_to_str(name, sizeof(name), nid->addr, 0);
	dprintf("create connection %s:%d\n", name, nid->port);
	fd = connect_to(name, nid->port);
	if (fd < 0) {
		uatomic_dec(&entry->refcount);
		return -1;
	}
	entry->fd = fd;

	return fd;
}

static void sockfd_cache_put(struct node_id *nid)
{
	struct sockfd_cache_entry *entry;
	char name[INET6_ADDRSTRLEN];
	int refcnt;

	addr_to_str(name, sizeof(name), nid->addr, 0);
	dprintf("%s:%d\n", name, nid->port);
	pthread_rwlock_rdlock(&sockfd_cache.lock);
	entry = sockfd_cache_search(nid);
	pthread_rwlock_unlock(&sockfd_cache.lock);
	assert(entry);
	refcnt = uatomic_cmpxchg(&entry->refcount, 1, 0);
	assert(refcnt == 1);
}

int sheep_get_fd(struct sd_vnode *vnode)
{
	struct node_id *nid = (struct node_id *)vnode;
	char name[INET6_ADDRSTRLEN];
	int fd = sockfd_cache_get(nid);

	if (fd != -1)
		return fd;

	addr_to_str(name, sizeof(name), nid->addr, 0);
	fd = connect_to(name, nid->port);
	if (fd < 0) {
		dprintf("failed connect to %s:%d\n", name, nid->port);
		return -1;
	}

	dprintf("%d\n", fd);
	return fd;
}

void sheep_put_fd(struct sd_vnode *vnode, int fd)
{
	struct node_id *nid = (struct node_id *)vnode;
	struct sockfd_cache_entry *entry;

	pthread_rwlock_rdlock(&sockfd_cache.lock);
	entry = sockfd_cache_search(nid);
	pthread_rwlock_unlock(&sockfd_cache.lock);
	assert(entry);
	if (entry->fd == fd) {
		sockfd_cache_put(nid);
	} else {
		dprintf("%d\n", fd);
		close(fd);
	}
}

void sheep_del_fd(struct sd_vnode *vnode, int fd)
{
	struct node_id *nid = (struct node_id *)vnode;
	struct sockfd_cache_entry *entry;

	pthread_rwlock_rdlock(&sockfd_cache.lock);
	entry = sockfd_cache_search(nid);
	pthread_rwlock_unlock(&sockfd_cache.lock);
	assert(entry);
	if (entry->fd == fd) {
		sockfd_cache_put(nid);
		sockfd_cache_del(nid);
	} else {
		dprintf("%d\n", fd);
		close(fd);
	}
}
