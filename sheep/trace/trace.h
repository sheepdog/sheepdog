#ifndef TRACE_H
#define TRACE_H

/* mcount.S */
extern void mcount(void);
extern void mcount_call(void);
extern void trace_caller(void);
extern void trace_call(unsigned long, unsigned long *);

#endif
