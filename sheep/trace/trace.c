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

#include <bfd.h>

#include "trace.h"

/* Intel recommended one for 5 bytes nops (nopl 0x0(%rax,%rax,1)) */
static const unsigned char NOP5[INSN_SIZE] = {0x0f, 0x1f, 0x44, 0x00, 0x00};

static LIST_HEAD(tracers);
static __thread int ret_stack_index;
static __thread struct {
	const struct caller *caller;
	unsigned long ret;
} trace_ret_stack[SD_MAX_STACK_DEPTH];

static struct caller *callers;
static size_t nr_callers;

static struct strbuf *buffer;
static pthread_mutex_t *buffer_lock;
static int nr_cpu;

static __thread bool in_trace;

union instruction {
	unsigned char start[INSN_SIZE];
	struct {
		char opcode;
		int offset;
	} __attribute__((packed));
};

static int caller_cmp(const struct caller *a, const struct caller *b)
{
	return intcmp(a->mcount, b->mcount);
}

static unsigned char *get_new_call(unsigned long ip, unsigned long addr)
{
	static union instruction code;

	code.opcode = 0xe8; /* opcode of call */
	code.offset = (int)(addr - ip - INSN_SIZE);

	return code.start;
}

static void replace_call(unsigned long ip, unsigned long func)
{
	unsigned char *new;

	new = get_new_call(ip, func);
	memcpy((void *)ip, new, INSN_SIZE);
}

static int make_text_writable(unsigned long ip)
{
	unsigned long start = ip & ~(getpagesize() - 1);

	return mprotect((void *)start, getpagesize() + INSN_SIZE, PROT_READ | PROT_EXEC | PROT_WRITE);
}

static struct caller *trace_lookup_ip(unsigned long ip)
{
	const struct caller key = {
		.mcount = ip,
	};

	return xbsearch(&key, callers, nr_callers, caller_cmp);
}

void regist_tracer(struct tracer *tracer)
{
	list_add_tail(&tracer->list, &tracers);
}

static void patch_all_sites(unsigned long addr)
{
	for (int i = 0; i < nr_callers; i++)
		replace_call(callers[i].mcount, addr);
}

static void nop_all_sites(void)
{
	for (int i = 0; i < nr_callers; i++)
		memcpy((void *)callers[i].mcount, NOP5, INSN_SIZE);
}

/* the entry point of the function */
__attribute__((no_instrument_function))
void trace_function_enter(unsigned long ip, unsigned long *ret_addr)
{
	struct tracer *tracer;
	const struct caller *caller;

	if (in_trace)
		/* don't trace while tracing */
		return;
	in_trace = true;

	assert(ret_stack_index < ARRAY_SIZE(trace_ret_stack));

	caller = trace_lookup_ip(ip);

	list_for_each_entry(tracer, &tracers, list) {
		if (tracer->enter != NULL && uatomic_is_true(&tracer->enabled))
			tracer->enter(caller, ret_stack_index);
	}

	trace_ret_stack[ret_stack_index].caller = caller;
	trace_ret_stack[ret_stack_index].ret = *ret_addr;
	ret_stack_index++;
	*ret_addr = (unsigned long)trace_return_caller;

	in_trace = false;
}

/* the exit point of the function */
__attribute__((no_instrument_function))
unsigned long trace_function_exit(void)
{
	struct tracer *tracer;

	assert(!in_trace);
	in_trace = true;

	ret_stack_index--;

	list_for_each_entry(tracer, &tracers, list) {
		if (tracer->exit != NULL && uatomic_is_true(&tracer->enabled))
			tracer->exit(trace_ret_stack[ret_stack_index].caller,
				     ret_stack_index);
	}

	in_trace = false;

	return trace_ret_stack[ret_stack_index].ret;
}

static size_t count_enabled_tracers(void)
{
	size_t nr = 0;
	struct tracer *t;

	list_for_each_entry(t, &tracers, list) {
		if (uatomic_is_true(&t->enabled))
			nr++;
	}

	return nr;
}

static struct tracer *find_tracer(const char *name)
{
	struct tracer *t;

	list_for_each_entry(t, &tracers, list) {
		if (strcmp(t->name, name) == 0)
			return t;
	}

	return NULL;
}

int trace_enable(const char *name)
{
	struct tracer *tracer = find_tracer(name);

	if (tracer == NULL) {
		sd_debug("no such tracer, %s", name);
		return SD_RES_NO_SUPPORT;
	} else if (uatomic_is_true(&tracer->enabled)) {
		sd_debug("tracer %s is already enabled", name);
		return SD_RES_INVALID_PARMS;
	}

	uatomic_set_true(&tracer->enabled);

	if (count_enabled_tracers() == 1) {
		suspend_worker_threads();
		patch_all_sites((unsigned long)trace_caller);
		resume_worker_threads();
	}
	sd_debug("tracer %s enabled", tracer->name);

	return SD_RES_SUCCESS;
}

int trace_disable(const char *name)
{
	struct tracer *tracer = find_tracer(name);

	if (tracer == NULL) {
		sd_debug("no such tracer, %s", name);
		return SD_RES_NO_SUPPORT;
	} else if (!uatomic_is_true(&tracer->enabled)) {
		sd_debug("tracer %s is not enabled", name);
		return SD_RES_INVALID_PARMS;
	}

	uatomic_set_false(&tracer->enabled);
	if (count_enabled_tracers() == 0) {
		suspend_worker_threads();
		nop_all_sites();
		resume_worker_threads();
	}
	sd_debug("tracer %s disabled", tracer->name);

	return SD_RES_SUCCESS;
}

/*
 * Set the current tracer status to 'buf' and return the length of the
 * data. 'buf' must have enough space to store all the tracer list.
 */
size_t trace_status(char *buf)
{
	struct tracer *t;
	char *p = buf;

	list_for_each_entry(t, &tracers, list) {
		strcpy(p, t->name);
		p += strlen(p);

		*p++ = '\t';

		if (uatomic_is_true(&t->enabled))
			strcpy(p, "enabled");
		else
			strcpy(p, "disabled");
		p += strlen(p);

		*p++ = '\n';
	}

	*p++ = '\0';

	return p - buf;
}

int trace_buffer_pop(void *buf, uint32_t len)
{
	int readin, count = 0, requested = len;
	char *buff = (char *)buf;
	int i;

	for (i = 0; i < nr_cpu; i++) {
		pthread_mutex_lock(&buffer_lock[i]);
		readin = strbuf_stripout(&buffer[i], buff, len);
		pthread_mutex_unlock(&buffer_lock[i]);
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

void trace_buffer_push(int cpuid, struct trace_graph_item *item)
{
	pthread_mutex_lock(&buffer_lock[cpuid]);
	strbuf_add(&buffer[cpuid], item, sizeof(*item));
	pthread_mutex_unlock(&buffer_lock[cpuid]);
}

/* assume that mcount call exists in the first FIND_MCOUNT_RANGE bytes */
#define FIND_MCOUNT_RANGE 32

static unsigned long find_mcount_call(unsigned long entry_addr)
{
	unsigned long start = entry_addr;
	unsigned long end = entry_addr + FIND_MCOUNT_RANGE;

	while (start < end) {
		union instruction *code;
		unsigned long addr;

		/* 0xe8 means a opcode of call */
		code = memchr((void *)start, 0xe8, end - start);
		addr = (unsigned long)code;

		if (code == NULL)
			break;

		if ((int)((unsigned long)mcount - addr - INSN_SIZE) ==
		    code->offset)
			return addr;

		start = addr + 1;
	}

	return 0;
}

static bfd *get_bfd(void)
{
	char fname[PATH_MAX] = {0};
	bfd *abfd;

	if (readlink("/proc/self/exe", fname, sizeof(fname)) < 0)
		panic("failed to get a path of the program.");

	abfd = bfd_openr(fname, NULL);
	if (abfd == 0) {
		sd_err("cannot open %s", fname);
		return NULL;
	}

	if (!bfd_check_format(abfd, bfd_object)) {
		sd_err("invalid format");
		return NULL;
	}

	if (!(bfd_get_file_flags(abfd) & HAS_SYMS)) {
		sd_err("no symbols found");
		return NULL;
	}

	return abfd;
}

/* Create a caller list which has a mcount call. */
static int init_callers(void)
{
	int max_symtab_size;
	asymbol **symtab;
	int symcount;
	bfd *abfd;

	abfd = get_bfd();
	if (abfd == NULL)
		return -1;

	max_symtab_size = bfd_get_symtab_upper_bound(abfd);
	if (max_symtab_size < 0) {
		sd_err("failed to get symtab size");
		return -1;
	}

	symtab = xmalloc(max_symtab_size);
	symcount = bfd_canonicalize_symtab(abfd, symtab);

	callers = xzalloc(sizeof(*callers) * symcount);
	for (int i = 0; i < symcount; i++) {
		asymbol *sym = symtab[i];
		unsigned long ip, addr = bfd_asymbol_value(sym);
		const char *name = bfd_asymbol_name(sym);
		const char *section =
			bfd_get_section_name(abfd, bfd_get_section(sym));

		if (addr == 0 || !(sym->flags & BSF_FUNCTION))
			/* sym is not a function */
			continue;

		ip = find_mcount_call(addr);
		if (ip == 0) {
			sd_debug("%s doesn't have mcount call", name);
			continue;
		}
		if (make_text_writable(ip) < 0)
			panic("failed to make mcount call writable");

		callers[nr_callers].addr = addr;
		callers[nr_callers].mcount = ip;
		callers[nr_callers].name = strdup(name);
		callers[nr_callers].section = strdup(section);
		nr_callers++;
	}
	xqsort(callers, nr_callers, caller_cmp);

	free(symtab);
	bfd_close(abfd);

	return 0;
}

/*
 * Try to NOP all the mcount call sites that are supposed to be traced.  Later
 * we can enable it by asking these sites to point to trace_caller.
 */
int trace_init(void)
{
	int i;

	if (init_callers() < 0)
		return -1;

	nop_all_sites();

#ifdef DEBUG
	trace_enable("thread_checker");
	trace_enable("loop_checker");
#endif

	nr_cpu = sysconf(_SC_NPROCESSORS_ONLN);
	buffer = xzalloc(sizeof(*buffer) * nr_cpu);
	buffer_lock = xzalloc(sizeof(*buffer_lock) * nr_cpu);
	for (i = 0; i < nr_cpu; i++) {
		strbuf_init(&buffer[i], 0);
		pthread_mutex_init(&buffer_lock[i], NULL);
	}

	sd_info("trace support enabled. cpu count %d.", nr_cpu);
	return 0;
}
