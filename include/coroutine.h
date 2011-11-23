#ifndef __COROUTINE__
#define __COROUTINE__

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

#include "list.h"

struct coroutine;

typedef void coroutine_entry_func_t(void *opaque);

struct coroutine *coroutine_create(coroutine_entry_func_t *entry);
void coroutine_enter(struct coroutine *coroutine, void *opaque);
void coroutine_yield(void);
struct coroutine *coroutine_self(void);
int in_coroutine(void);

#endif
