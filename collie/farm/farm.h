#ifndef FARM_H
#define FARM_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <memory.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <linux/limits.h>

#include "collie.h"
#include "sheepdog_proto.h"
#include "sheep.h"
#include "logger.h"
#include "strbuf.h"
#include "sha1.h"

typedef int (*object_handler_func_t)(uint64_t oid, int nr_copies, void *buf,
				     size_t size, void *data);

/* object_tree.c */
int object_tree_size(void);
void object_tree_insert(uint64_t oid, int nr_copies);
void object_tree_free(void);
void object_tree_print(void);
int for_each_object_in_tree(object_handler_func_t func, void *data);

#endif
