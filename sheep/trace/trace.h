#ifndef TRACE_H
#define TRACE_H

#define INSN_SIZE       5       /* call(1b) + offset(4b) = 5b */

#ifndef __ASSEMBLY__

#include "sheep_priv.h"

struct caller {
	unsigned long addr;
	unsigned long mcount;
	const char *name;
};

typedef void (*trace_func_t)(unsigned long ip, unsigned long *parent_ip);
/* Type of the callback handlers for function entry and return */
typedef void (*trace_func_graph_ret_t)(struct trace_graph_item *);
typedef void (*trace_func_graph_ent_t)(struct trace_graph_item *);

/* graph.c */

/* mcount.S */
void mcount(void);
void trace_caller(void);
void trace_call(unsigned long, unsigned long *);
extern const unsigned char NOP5[];
void trace_return_caller(void);
unsigned long trace_return_call(void);

/* trace.c */
#ifdef HAVE_TRACE
  int trace_init(void);
  int register_trace_function(trace_func_t func);
  int trace_enable(void);
  int trace_disable(void);
  struct caller *trace_lookup_ip(unsigned long ip);
  int trace_buffer_pop(void *buf, uint32_t len);
  void trace_buffer_push(int cpuid, struct trace_graph_item *item);

#else
  static inline int trace_init(void) { return 0; }
  static inline int trace_enable(void) { return 0; }
  static inline int trace_disable(void) { return 0; }
  static inline int trace_buffer_pop(void *buf, uint32_t len) { return 0; }
  static inline void trace_buffer_push(
	  int cpuid, struct trace_graph_item *item) { return; }

#endif /* HAVE_TRACE */

#define register_tracer(new)			\
static void __attribute__((constructor))	\
register_ ## _tracer(void) 			\
{  						\
	register_trace_function(new);		\
}

#endif /* __ASSEMBLY__ */
#endif
