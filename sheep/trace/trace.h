#ifndef TRACE_H
#define TRACE_H

#include "util.h"

struct ipinfo {
	const char *file;           /* Source code filename for EIP */
	int line;                   /* Source code linenumber for EIP */
	const char *fn_name;        /* Name of function containing EIP */
	int fn_namelen;             /* Length of function name */
	unsigned long fn_addr;      /* Address of start of function */
	int fn_narg;                /* Number of function arguments */
};

/* stabs.c */
extern int get_ipinfo(unsigned long ip, struct ipinfo *info);

/* mcount.S */
extern void mcount(void);
extern void mcount_call(void);
extern void trace_caller(void);
extern void trace_call(unsigned long, unsigned long *);

#endif
