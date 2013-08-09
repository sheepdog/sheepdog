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

static struct caller *callers;
static size_t nr_callers;

static trace_func_t trace_func = trace_call;

static struct strbuf *buffer;
static int nr_cpu;

union instruction {
	unsigned char start[INSN_SIZE];
	struct {
		char opcode;
		int offset;
	} __attribute__((packed));
};

static notrace int caller_cmp(const struct caller *a, const struct caller *b)
{
	return intcmp(a->mcount, b->mcount);
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

notrace struct caller *trace_lookup_ip(unsigned long ip)
{
	const struct caller key = {
		.mcount = ip,
	};

	return xbsearch(&key, callers, nr_callers, caller_cmp);
}

notrace int register_trace_function(trace_func_t func)
{
	if (make_text_writable((unsigned long)trace_call) < 0)
		return -1;

	replace_trace_call((unsigned long)func);
	trace_func = func;
	return 0;
}

static notrace void patch_all_sites(unsigned long addr)
{
	for (int i = 0; i < nr_callers; i++)
		replace_call(callers[i].mcount, addr);
}

static notrace void nop_all_sites(void)
{
	for (int i = 0; i < nr_callers; i++)
		memcpy((void *)callers[i].mcount, NOP5, INSN_SIZE);
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
		sd_eprintf("cannot open %s", fname);
		return NULL;
	}

	if (!bfd_check_format(abfd, bfd_object)) {
		sd_eprintf("invalid format");
		return NULL;
	}

	if (!(bfd_get_file_flags(abfd) & HAS_SYMS)) {
		sd_eprintf("no symbols found");
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
		sd_eprintf("failed to get symtab size");
		return -1;
	}

	symtab = xmalloc(max_symtab_size);
	symcount = bfd_canonicalize_symtab(abfd, symtab);

	callers = xzalloc(sizeof(*callers) * symcount);
	for (int i = 0; i < symcount; i++) {
		asymbol *sym = symtab[i];
		unsigned long ip, addr = bfd_asymbol_value(sym);
		const char *name = bfd_asymbol_name(sym);

		if (addr == 0 || !(sym->flags & BSF_FUNCTION))
			/* sym is not a function */
			continue;

		ip = find_mcount_call(addr);
		if (ip == 0) {
			sd_dprintf("%s doesn't have mcount call", name);
			continue;
		}
		if (make_text_writable(ip) < 0)
			panic("failed to make mcount call writable");

		callers[nr_callers].addr = addr;
		callers[nr_callers].mcount = ip;
		callers[nr_callers].name = strdup(name);
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
notrace int trace_init(void)
{
	int i;

	if (init_callers() < 0)
		return -1;

	nop_all_sites();

	nr_cpu = sysconf(_SC_NPROCESSORS_ONLN);
	buffer = xzalloc(sizeof(*buffer) * nr_cpu);
	for (i = 0; i < nr_cpu; i++)
		strbuf_init(&buffer[i], 0);

	sd_iprintf("trace support enabled. cpu count %d.", nr_cpu);
	return 0;
}
