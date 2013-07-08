#ifndef DR_FI_COMMON_H
#define DR_FI_COMMON_H

#include "dr_api.h"
#include <stdlib.h>

extern file_t log_file;

#define fi_printf(fmt, args...) do {					\
		if (log_file == INVALID_FILE)				\
			dr_printf("%s(%d), " fmt,			\
				__func__, __LINE__, ## args);		\
		else							\
			dr_fprintf(log_file, "%s(%d), " fmt,		\
				__func__, __LINE__, ## args);		\
	} while (0)

#define die(fmt, args...) do {						\
		fi_printf("FATAL %s(%d), " fmt,				\
			__func__, __LINE__, ## args);			\
	} while (0)

void *xmalloc(size_t size);
void *xzalloc(size_t size);
void *xcalloc(size_t size, size_t nmnb);
void xfree(void *ptr);

void init_log_file(void);

#endif	/* DR_FI_COMMON_H */
