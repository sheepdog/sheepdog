#include "dr_api.h"
#include "drmgr.h"
#include "common.h"

#include <stdlib.h>
#include <string.h>

void *xmalloc(size_t size)
{
	void *ret;

	ret = __wrap_malloc(size);
	if (!ret)
		die("allocating memory with __wrap_malloc() failed\n");

	return ret;
}

void *xzalloc(size_t size)
{
	void *ret;

	ret = xmalloc(size);
	memset(ret, 0, size);

	return ret;
}

void *xcalloc(size_t size, size_t nmnb)
{
	void *ret;
	size_t length = size * nmnb;

	ret = __wrap_malloc(length);
	if (!ret)
		die("allocating memory with __wrap_malloc() failed\n");
	memset(ret, 0, length);

	return ret;
}

void xfree(void *ptr)
{
	__wrap_free(ptr);
}

file_t log_file = INVALID_FILE;

void init_log_file(void)
{
	log_file = dr_open_file("fi.log", DR_FILE_WRITE_APPEND);
	if (log_file == INVALID_FILE)
		die("opening fi.log failed\n");
}
