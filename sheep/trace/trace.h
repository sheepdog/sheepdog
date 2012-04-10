#ifndef TRACE_H
#define TRACE_H

#define INSN_SIZE       5       /* call(1b) + offset(4b) = 5b */

#ifndef __ASSEMBLY__
#include <stdlib.h>

#include "list.h"
#include "util.h"

struct ipinfo {
	const char *file;           /* Source code filename for EIP */
	int line;                   /* Source code linenumber for EIP */
	const char *fn_name;        /* Name of function containing EIP */
	int fn_namelen;             /* Length of function name */
	unsigned long fn_addr;      /* Address of start of function */
	int fn_narg;                /* Number of function arguments */
};

struct caller {
	struct list_head list;
	struct hlist_node hash;
	unsigned long mcount;
	int namelen;
	const char *name;
};

typedef void (*trace_func_t)(unsigned long ip, unsigned long *parent_ip);

/* stabs.c */
extern int get_ipinfo(unsigned long ip, struct ipinfo *info);

/* mcount.S */
extern void mcount(void);
extern void mcount_call(void);
extern void trace_caller(void);
extern void trace_call(unsigned long, unsigned long *);
extern const unsigned char NOP5[];

/* trace.c */
extern pthread_cond_t trace_cond;
extern pthread_mutex_t trace_mux;

extern int trace_init(void);
extern int register_trace_function(trace_func_t func);
extern int trace_enable(void);
extern int trace_disable(void);
extern struct caller *trace_lookup_ip(unsigned long ip, int create);

#define register_tracer(new)			\
static void __attribute__((constructor))	\
register_ ## _tracer(void) 			\
{  						\
	register_trace_function(new);		\
}

#endif /* __ASSEMBLY__ */
#endif
