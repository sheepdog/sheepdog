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
#include "sheepdog_proto.h"
#include "strbuf.h"

#define TRACE_HASH_BITS       7
#define TRACE_HASH_SIZE       (1 << TRACE_HASH_BITS)

static struct hlist_head trace_hashtable[TRACE_HASH_SIZE];
static LIST_HEAD(caller_list);
static pthread_mutex_t trace_lock = PTHREAD_MUTEX_INITIALIZER;

static trace_func_t trace_func = trace_call;

static int total_nr_workers;

static pthread_mutex_t suspend_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t suspend_cond = PTHREAD_COND_INITIALIZER;
static int suspend_count;

static struct strbuf *buffer;
static int nr_cpu;
static LIST_HEAD(worker_list);

struct worker {
	struct list_head list;
	pthread_t id;
};

union instruction {
	unsigned char start[INSN_SIZE];
	struct {
		char opcode;
		int offset;
	} __attribute__((packed));
};

static notrace void suspend(int num)
{
	pthread_mutex_lock(&suspend_lock);
	suspend_count--;
	pthread_cond_wait(&suspend_cond, &suspend_lock);
	pthread_mutex_unlock(&suspend_lock);
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

notrace struct caller *trace_lookup_ip(unsigned long ip, bool create)
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
		sd_dprintf("ip: %lx not found", ip);
		new = NULL;
		goto out;
	}
	if (create) {
		new = malloc(sizeof(*new));
		if (!new) {
			sd_eprintf("out of memory");
			goto out;
		}
		new->mcount = ip;
		new->namelen = info.fn_namelen;
		new->name = info.fn_name;
		hlist_add_head(&new->hash, head);
		list_add(&new->list, &caller_list);
		sd_dprintf("add %.*s", info.fn_namelen, info.fn_name);
	} else {
		sd_dprintf("%.*s\n not found", info.fn_namelen, info.fn_name);
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
	trace_lookup_ip(ip, true);
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
	struct worker *w;

	pthread_mutex_lock(&trace_lock);
	suspend_count = total_nr_workers;
	list_for_each_entry(w, &worker_list, list) {
		if (pthread_kill(w->id, SIGUSR2) != 0)
			panic("%m");
	}

wait_for_worker_suspend:
	/* Hold the lock, then all other worker can sleep on it */
	pthread_mutex_lock(&suspend_lock);
	if (suspend_count > 0) {
		pthread_mutex_unlock(&suspend_lock);
		pthread_yield();
		goto wait_for_worker_suspend;
	}
	pthread_mutex_unlock(&suspend_lock);
	pthread_mutex_unlock(&trace_lock);
}

static notrace void resume_worker_threads(void)
{
	pthread_mutex_lock(&suspend_lock);
	pthread_cond_broadcast(&suspend_cond);
	pthread_mutex_unlock(&suspend_lock);
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
		sd_dprintf("no tracer available");
		return SD_RES_NO_TAG;
	}

	suspend_worker_threads();
	patch_all_sites((unsigned long)trace_caller);
	resume_worker_threads();
	sd_dprintf("tracer enabled");

	return SD_RES_SUCCESS;
}

notrace int trace_disable(void)
{
	suspend_worker_threads();
	nop_all_sites();
	resume_worker_threads();
	sd_dprintf("tracer disabled");

	return SD_RES_SUCCESS;
}

int trace_init_signal(void)
{
	/* trace uses this signal to suspend the worker threads */
	if (install_sighandler(SIGUSR2, suspend, false) < 0) {
		sd_dprintf("%m");
		return -1;
	}
	return 0;
}

notrace int trace_buffer_pop(void *buf, uint32_t len)
{
	int readin, count = 0, requested = len;
	char *buff = (char *)buf;
	int i;

	for (i = 0; i < nr_cpu; i++) {
		readin = strbuf_stripout(&buffer[i], buff, len);
		count += readin;
		if (count == requested)
			return count;
		if (readin == 0)
			continue;

		len -= readin;
		buff += readin;
	}

	return count;
}

notrace void trace_buffer_push(int cpuid, struct trace_graph_item *item)
{
	strbuf_add(&buffer[cpuid], item, sizeof(*item));
}

notrace int trace_init(void)
{
	int i;

	if (make_text_writable((unsigned long)mcount_call) < 0) {
		sd_dprintf("%m");
		return -1;
	}

	replace_mcount_call((unsigned long)do_trace_init);

	nr_cpu = sysconf(_SC_NPROCESSORS_ONLN);
	buffer = xzalloc(sizeof(*buffer) * nr_cpu);
	for (i = 0; i < nr_cpu; i++)
		strbuf_init(&buffer[i], 0);

	sd_iprintf("trace support enabled. cpu count %d.", nr_cpu);
	return 0;
}

notrace void trace_register_thread(pthread_t id)
{
	struct worker *new = xmalloc(sizeof(*new));

	new->id = id;

	pthread_mutex_lock(&trace_lock);
	list_add(&new->list, &worker_list);
	total_nr_workers++;
	pthread_mutex_unlock(&trace_lock);
	sd_dprintf("nr %d, add pid %lx", total_nr_workers, id);
}

notrace void trace_unregister_thread(pthread_t id)
{
	struct worker *w, *tmp;

	pthread_mutex_lock(&trace_lock);
	list_for_each_entry_safe(w, tmp, &worker_list, list) {
		if (w->id == id) {
			list_del(&w->list);
			total_nr_workers--;
		}
	}
	pthread_mutex_unlock(&trace_lock);
	sd_dprintf("nr %d, del pid %lx", total_nr_workers, id);
}
