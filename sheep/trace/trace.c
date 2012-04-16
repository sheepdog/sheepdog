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

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include "trace.h"
#include "logger.h"
#include "list.h"
#include "work.h"
#include "sheepdog_proto.h"

#define TRACE_HASH_BITS       7
#define TRACE_HASH_SIZE       (1 << TRACE_HASH_BITS)

static struct hlist_head trace_hashtable[TRACE_HASH_SIZE];
static LIST_HEAD(caller_list);
static pthread_mutex_t trace_lock = PTHREAD_MUTEX_INITIALIZER;

static trace_func_t trace_func = trace_call;
static int trace_count;
static int trace_buffer_inited;

static LIST_HEAD(buffer_list);
pthread_cond_t trace_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t trace_mux = PTHREAD_MUTEX_INITIALIZER;

union instruction {
	unsigned char start[INSN_SIZE];
	struct {
		char opcode;
		int offset;
	} __attribute__((packed));
};

static notrace void suspend(int num)
{
	dprintf("worker thread %u going to suspend\n", (int)pthread_self());

	pthread_mutex_lock(&trace_mux);
	trace_count--;
	if (!trace_buffer_inited)
		trace_init_buffer(&buffer_list); /* init worker threads rbuffer */
	pthread_cond_wait(&trace_cond, &trace_mux);
	pthread_mutex_unlock(&trace_mux);
	dprintf("worker thread going to resume\n");
}

static inline int trace_hash(unsigned long ip)
{
	return hash_64(ip, TRACE_HASH_BITS);
}

static notrace unsigned char *get_new_call(unsigned long ip, unsigned long addr)
{
	static union instruction code;

	code.opcode = 0xe8; /* opcode of call */
	code.offset = (int)(addr - ip - INSN_SIZE);

	return code.start;
}

static notrace void replace_call(unsigned long ip, unsigned long func)
{
	unsigned char *new;

	new = get_new_call(ip, func);
	memcpy((void *)ip, new, INSN_SIZE);
}

static inline void replace_mcount_call(unsigned long func)
{
	unsigned long ip = (unsigned long)mcount_call;

	replace_call(ip, func);
}

static inline void replace_trace_call(unsigned long func)
{
	unsigned long ip = (unsigned long)trace_call;

	replace_call(ip, func);
}

static notrace int make_text_writable(unsigned long ip)
{
	unsigned long start = ip & ~(getpagesize() - 1);

	return mprotect((void *)start, getpagesize() + INSN_SIZE, PROT_READ | PROT_EXEC | PROT_WRITE);
}

notrace struct caller *trace_lookup_ip(unsigned long ip, int create)
{
	int h = trace_hash(ip);
	struct hlist_head *head = trace_hashtable + h;
	struct hlist_node *node;
	struct ipinfo info;
	struct caller *new = NULL;

	pthread_mutex_lock(&trace_lock);
	if (hlist_empty(head))
		goto not_found;

	hlist_for_each_entry(new, node, head, hash) {
		if (new->mcount == ip)
			goto out;
	}
not_found:
	if (get_ipinfo(ip, &info) < 0) {
		dprintf("ip: %lx not found\n", ip);
		new = NULL;
		goto out;
	}
	if (create) {
		new = malloc(sizeof(*new));
		if (!new) {
			eprintf("out of memory\n");
			goto out;
		}
		new->mcount = ip;
		new->namelen = info.fn_namelen;
		new->name = info.fn_name;
		hlist_add_head(&new->hash, head);
		list_add(&new->list, &caller_list);
		dprintf("add %.*s\n", info.fn_namelen, info.fn_name);
	} else {
		dprintf("%.*s\n not found", info.fn_namelen, info.fn_name);
		new = NULL;
	}
out:
	pthread_mutex_unlock(&trace_lock);
	return new;
}

/*
 * Try to NOP all the mcount call sites that are supposed to be traced.
 * Later we can enable it by asking these sites to point to trace_caller,
 * where we can override trace_call() with our own trace function. We can
 * do this, because below function record the IP of 'call mcount' inside the
 * callers.
 *
 * IP points to the return address.
 */
static notrace void do_trace_init(unsigned long ip)
{

	if (make_text_writable(ip) < 0)
		return;

	memcpy((void *)ip, NOP5, INSN_SIZE);
	trace_lookup_ip(ip, 1);
}

notrace int register_trace_function(trace_func_t func)
{
	if (make_text_writable((unsigned long)trace_call) < 0)
		return -1;

	replace_trace_call((unsigned long)func);
	trace_func = func;
	return 0;
}

static notrace void suspend_worker_threads(void)
{
	struct worker_info *wi;
	int i;
	trace_count = total_nr_workers;
	list_for_each_entry(wi, &worker_info_list, worker_info_siblings) {
		for (i = 0; i < wi->nr_threads; i++)
			if (pthread_kill(wi->worker_thread[i], SIGUSR2) != 0)
				dprintf("%m\n");
	}
wait_for_worker_suspend:
	pthread_mutex_lock(&trace_mux);
	if (trace_count > 0) {
		pthread_mutex_unlock(&trace_mux);
		pthread_yield();
		goto wait_for_worker_suspend;
	}
	pthread_mutex_unlock(&trace_mux);
	trace_buffer_inited = 1;
}

static notrace void resume_worker_threads(void)
{
	pthread_mutex_lock(&trace_mux);
	pthread_cond_broadcast(&trace_cond);
	pthread_mutex_unlock(&trace_mux);
}

static notrace void patch_all_sites(unsigned long addr)
{
	struct caller *ca;
	unsigned char *new;

	pthread_mutex_lock(&trace_lock);
	list_for_each_entry(ca, &caller_list, list) {
		new = get_new_call(ca->mcount, addr);
		memcpy((void *)ca->mcount, new, INSN_SIZE);
	}
	pthread_mutex_unlock(&trace_lock);
}

static notrace void nop_all_sites(void)
{
	struct caller *ca;

	pthread_mutex_lock(&trace_lock);
	list_for_each_entry(ca, &caller_list, list) {
		memcpy((void *)ca->mcount, NOP5, INSN_SIZE);
	}
	pthread_mutex_unlock(&trace_lock);
}

notrace int trace_enable(void)
{
	if (trace_func == trace_call) {
		dprintf("no tracer available\n");
		return SD_RES_NO_TAG;
	}

	suspend_worker_threads();
	patch_all_sites((unsigned long)trace_caller);
	resume_worker_threads();
	dprintf("patch tracer done\n");
	return SD_RES_SUCCESS;
}

notrace int trace_disable(void)
{
	suspend_worker_threads();
	nop_all_sites();
	resume_worker_threads();
	dprintf("patch nop done\n");
	return SD_RES_SUCCESS;
}

int init_signal(void)
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_handler = suspend;
	/* trace uses this signal to suspend the worker threads */
	if (sigaction(SIGUSR2, &act, NULL) < 0) {
		dprintf("%m\n");
		return -1;
	}
	return 0;
}

notrace int trace_copy_buffer(void *buf)
{
	struct rbuffer *rbuf;
	int total = 0;

	list_for_each_entry(rbuf, &buffer_list, list) {
		int rbuf_size = rbuffer_size(rbuf);
		if (rbuf_size) {
			memcpy((char *)buf + total, rbuf->buffer, rbuf_size);
			total += rbuf_size;
		}
	}
	return total;
}

notrace void trace_reset_buffer(void)
{
	struct rbuffer *rbuf;

	list_for_each_entry(rbuf, &buffer_list, list) {
		rbuffer_reset(rbuf);
	}
}

notrace int trace_init()
{
	sigset_t block;

	sigemptyset(&block);
	sigaddset(&block, SIGUSR2);
	if (pthread_sigmask(SIG_BLOCK, &block, NULL) != 0) {
		dprintf("%m\n");
		return -1;
	}

	if (make_text_writable((unsigned long)mcount_call) < 0) {
		dprintf("%m\n");
		return -1;
	}

	trace_init_buffer(&buffer_list); /* init main thread ring buffer */
	replace_mcount_call((unsigned long)do_trace_init);
	dprintf("main thread %u\n", (int)pthread_self());
	dprintf("trace support enabled.\n");
	return 0;
}
