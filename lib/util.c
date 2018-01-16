/*
 * Taken and modified from git by Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>


#include "util.h"

mode_t sd_def_dmode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP;
mode_t sd_def_fmode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

void *xmalloc(size_t size)
{
	void *ret = malloc(size);
	if (unlikely(!ret))
		panic("Out of memory");
	return ret;
}

void *xzalloc(size_t size)
{
	return xcalloc(1, size);
}

void *xrealloc(void *ptr, size_t size)
{
	errno = 0;
	void *ret = realloc(ptr, size);
	if (unlikely(errno == ENOMEM))
		panic("Out of memory");
	return ret;
}

void *xcalloc(size_t nmemb, size_t size)
{
	void *ret = calloc(nmemb, size);
	if (unlikely(!ret))
		panic("Out of memory");
	return ret;
}

/* zeroed memory version of posix_memalign() */
void *xvalloc(size_t size)
{
	void *ret = NULL;
	int err = posix_memalign((void **)&ret, getpagesize(), size);
	if (unlikely(err))
		panic("Out of memory");
	memset(ret, 0, size);
	return ret;
}

/* preallocate the whole object */
int prealloc(int fd, uint64_t size)
{
	int ret = xfallocate(fd, 0, 0, size);
	if (ret < 0) {
		if (errno != ENOSYS && errno != EOPNOTSUPP) {
			return ret;
		}

		return xftruncate(fd, size);
	}

	return 0;
}

static ssize_t _read(int fd, void *buf, size_t len)
{
	ssize_t nr;
	while (true) {
		nr = read(fd, buf, len);
		if (unlikely(nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

static ssize_t _write(int fd, const void *buf, size_t len)
{
	ssize_t nr;
	while (true) {
		nr = write(fd, buf, len);
		if (unlikely(nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

ssize_t xread(int fd, void *buf, size_t count)
{
	char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t loaded = _read(fd, p, count);
		if (unlikely(loaded < 0))
			return -1;
		if (unlikely(loaded == 0))
			return total;
		count -= loaded;
		p += loaded;
		total += loaded;
	}

	return total;
}

ssize_t xwrite(int fd, const void *buf, size_t count)
{
	const char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t written = _write(fd, p, count);
		if (unlikely(written < 0))
			return -1;
		if (unlikely(!written)) {
			errno = ENOSPC;
			return -1;
		}
		count -= written;
		p += written;
		total += written;
	}

	return total;
}

static ssize_t _pread(int fd, void *buf, size_t len, off_t offset)
{
	ssize_t nr;
	while (true) {
		nr = pread(fd, buf, len, offset);
		if (unlikely(nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

static ssize_t _pwrite(int fd, const void *buf, size_t len, off_t offset)
{
	ssize_t nr;
	while (true) {
		nr = pwrite(fd, buf, len, offset);
		if (unlikely(nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

ssize_t xpread(int fd, void *buf, size_t count, off_t offset)
{
	char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t loaded = _pread(fd, p, count, offset);
		if (unlikely(loaded < 0))
			return -1;
		if (unlikely(loaded == 0))
			return total;
		count -= loaded;
		p += loaded;
		total += loaded;
		offset += loaded;
	}

	return total;
}

ssize_t xpwrite(int fd, const void *buf, size_t count, off_t offset)
{
	const char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t written = _pwrite(fd, p, count, offset);
		if (unlikely(written < 0))
			return -1;
		if (unlikely(!written)) {
			errno = ENOSPC;
			return -1;
		}
		count -= written;
		p += written;
		total += written;
		offset += written;
	}

	return total;
}

/* Return EEXIST when path exists but not a directory */
int xmkdir(const char *pathname, mode_t mode)
{
	if (mkdir(pathname, mode) < 0) {
		struct stat st;

		if (errno != EEXIST)
			return -1;

		if (stat(pathname, &st) < 0)
			return -1;

		if (!S_ISDIR(st.st_mode)) {
			errno = EEXIST;
			return -1;
		}
	}
	return 0;
}

int xfallocate(int fd, int mode, off_t offset, off_t len)
{
	int ret;

	do {
		ret = fallocate(fd, mode, offset, len);
	} while (unlikely(ret < 0) && (errno == EAGAIN || errno == EINTR));

	return ret;
}

int xftruncate(int fd, off_t length)
{
	int ret;

	do {
		ret = ftruncate(fd, length);
	} while (unlikely(ret < 0) && (errno == EAGAIN || errno == EINTR));

	return ret;
}

/*
 * Return the read value on success, or -1 if efd has been made nonblocking and
 * errno is EAGAIN.  If efd has been marked blocking or the eventfd counter is
 * not zero, this function doesn't return error.
 */
int eventfd_xread(int efd)
{
	int ret;
	eventfd_t value = 0;

	do {
		ret = eventfd_read(efd, &value);
	} while (unlikely(ret < 0) && errno == EINTR);

	if (ret == 0)
		ret = value;
	else if (unlikely(errno != EAGAIN))
		panic("eventfd_read() failed, %m");

	return ret;
}

void eventfd_xwrite(int efd, int value)
{
	int ret;

	do {
		ret = eventfd_write(efd, (eventfd_t)value);
	} while (unlikely(ret < 0) && (errno == EINTR || errno == EAGAIN));

	if (unlikely(ret < 0))
		panic("eventfd_write() failed, %m");
}

/*
 * Copy the string str to buf. If str length is bigger than buf_size -
 * 1 then it is clamped to buf_size - 1.
 * NOTE: this function does what strncpy should have done to be
 * useful. NEVER use strncpy.
 *
 * @param buf destination buffer
 * @param buf_size size of destination buffer
 * @param str source string
 */
void pstrcpy(char *buf, int buf_size, const char *str)
{
	int c;
	char *q = buf;

	if (buf_size <= 0)
		return;

	while (true) {
		c = *str++;
		if (c == 0 || q >= buf + buf_size - 1)
			break;
		*q++ = c;
	}
	*q = '\0';
}

/* remove a newline character from the end of a string */
char *chomp(char *str)
{
	char *p = strchr(str, '\n');
	if (p != NULL)
		*p = '\0';

	return str;
}

bool is_numeric(const char *s)
{
	const char *p = s;

	if (*p) {
		char c;

		while ((c = *p++))
			if (!isdigit(c))
				return false;
		return true;
	}
	return false;
}

/*
 * We regard 'data' as string when it contains '\0' in the first 256 characters.
 */
const char *data_to_str(void *data, size_t data_length)
{
	data_length = MIN(data_length, 256);

	if (data == NULL)
		return "(null)";

	if (memchr(data, '\0', data_length) != NULL)
		return data;

	return "(not string)";
}

pid_t gettid(void)
{
	return syscall(SYS_gettid);
}

int tkill(int tid, int sig)
{
	return syscall(SYS_tgkill, getpid(), tid, sig);
}

bool is_xattr_enabled(const char *path)
{
	int ret, dummy;

	ret = getxattr(path, "user.dummy", &dummy, sizeof(dummy));

	return !(ret == -1 && errno == ENOTSUP);
}

const char *my_exe_path(void)
{
	static __thread char path[PATH_MAX];
	ssize_t ret;

	if (path[0] == '\0') {
		ret = readlink("/proc/self/exe", path, sizeof(path));
		if (ret == -1)
			panic("%m");
	}

	return path;
}

/*
 * Split the given path and sets the split parts to 'segs'.
 *
 * This returns the number of split segments.
 *
 * For example:
 *   split_path("/a/b/c", 3, segs);
 *     -> Returns 3 and segs will be { "a", "b", "c" }.
 *   split_path("/a//b//c", 3, segs);
 *     -> Returns 3 and segs will be { "a", "b", "c" }.
 *   split_path("/a/b/c", 2, segs);
 *     -> Returns 2 and segs will be { "a", "b/c" }.
 *   split_path("/a/b/c", 4, segs);
 *     -> Returns 3 and segs will be { "a", "b", "c", undefined }.
 */
int split_path(const char *path, size_t nr_segs, char **segs)
{
	for (int i = 0; i < nr_segs; i++) {
		while (*path == '/')
			path++;

		if (*path == '\0')
			return i;

		if (i == nr_segs - 1) {
			segs[i] = strdup(path);
			if (segs[i] == NULL)
				panic("OOM");
		} else {
			char *p = strchrnul(path, '/');
			int len = p - path;

			segs[i] = xmalloc(len + 1);
			memcpy(segs[i], path, len);
			segs[i][len] = '\0';

			path = p;
		}
	}

	return nr_segs;
}

/* Concatenate 'segs' with '/' separators. */
void make_path(char *path, size_t size, size_t nr_segs, const char **segs)
{
	for (int i = 0; i < nr_segs; i++) {
		int len = snprintf(path, size, "/%s", segs[i]);
		path += len;
		size -= len;
	}
}

/*
 * Returns a list organized in an intermediate format suited
 * to chaining of merge() calls: null-terminated, no reserved or
 * sentinel head node, "prev" links not maintained.
 */
static struct list_node *merge(void *priv,
			       int (*cmp)(void *priv, struct list_node *a,
					  struct list_node *b),
			       struct list_node *a, struct list_node *b)
{
	struct list_node head, *tail = &head;

	while (a && b) {
		/* if equal, take 'a' -- important for sort stability */
		if ((*cmp)(priv, a, b) <= 0) {
			tail->next = a;
			a = a->next;
		} else {
			tail->next = b;
			b = b->next;
		}
		tail = tail->next;
	}
	tail->next = a?:b;
	return head.next;
}

/*
 * Combine final list merge with restoration of standard doubly-linked
 * list structure.  This approach duplicates code from merge(), but
 * runs faster than the tidier alternatives of either a separate final
 * prev-link restoration pass, or maintaining the prev links
 * throughout.
 */
static void
merge_and_restore_back_links(void *priv,
			     int (*cmp)(void *priv, struct list_node *a,
					struct list_node *b),
			     struct list_head *head,
			     struct list_node *a, struct list_node *b)
{
	struct list_node *tail = &head->n;

	while (a && b) {
		/* if equal, take 'a' -- important for sort stability */
		if ((*cmp)(priv, a, b) <= 0) {
			tail->next = a;
			a->prev = tail;
			a = a->next;
		} else {
			tail->next = b;
			b->prev = tail;
			b = b->next;
		}
		tail = tail->next;
	}
	tail->next = a ? : b;

	do {
		/*
		 * In worst cases this loop may run many iterations.
		 * Continue callbacks to the client even though no
		 * element comparison is needed, so the client's cmp()
		 * routine can invoke cond_resched() periodically.
		 */
		(*cmp)(priv, tail->next, tail->next);

		tail->next->prev = tail;
		tail = tail->next;
	} while (tail->next);

	tail->next = &head->n;
	head->n.prev = tail;
}

/*
 * list_sort - sort a list
 * @priv: private data, opaque to list_sort(), passed to @cmp
 * @head: the list to sort
 * @cmp: the elements comparison function
 *
 * This function implements "merge sort", which has O(nlog(n))
 * complexity.
 *
 * The comparison function @cmp must return a negative value if @a
 * should sort before @b, and a positive value if @a should sort after
 * @b. If @a and @b are equivalent, and their original relative
 * ordering is to be preserved, @cmp must return 0.
 */
void list_sort(void *priv, struct list_head *head,
	       int (*cmp)(void *priv, struct list_node *a,
			  struct list_node *b))
{
	/* sorted partial lists -- last slot is a sentinel */
#define MAX_LIST_LENGTH_BITS 20
	struct list_node *part[MAX_LIST_LENGTH_BITS+1];
	int lev;  /* index into part[] */
	int max_lev = 0;
	struct list_node *list;

	if (list_empty(head))
		return;

	memset(part, 0, sizeof(part));

	head->n.prev->next = NULL;
	list = head->n.next;

	while (list) {
		struct list_node *cur = list;
		list = list->next;
		cur->next = NULL;

		for (lev = 0; part[lev]; lev++) {
			cur = merge(priv, cmp, part[lev], cur);
			part[lev] = NULL;
		}
		if (lev > max_lev) {
			if (unlikely(lev >= ARRAY_SIZE(part)-1)) {
				/*
				 * list passed to list_sort() too long for
				 * efficiency
				 */
				lev--;
			}
			max_lev = lev;
		}
		part[lev] = cur;
	}

	for (lev = 0; lev < max_lev; lev++)
		if (part[lev])
			list = merge(priv, cmp, part[lev], list);

	merge_and_restore_back_links(priv, cmp, head, part[max_lev], list);
}

/*
 * Find zero blocks from the beginning and end of buffer
 *
 * The caller passes the offset of 'buf' with 'poffset' so that this function
 * can align the return values to BLOCK_SIZE.  'plen' points the length of the
 * buffer.  If there are zero blocks at the beginning of the buffer, this
 * function increases the offset and decreases the length on condition that
 * '*poffset' is block-aligned.  If there are zero blocks at the end of the
 * buffer, this function also decreases the length on condition that '*plen' is
 * block-aligned.
 */
void find_zero_blocks(const void *buf, uint64_t *poffset, uint32_t *plen)
{
	const uint8_t zero[BLOCK_SIZE] = {0};
	const uint8_t *p = buf;
	uint64_t start = *poffset;
	uint64_t offset = 0;
	uint32_t len = *plen;

	/* trim zero blocks from the beginning of buffer */
	while (len >= BLOCK_SIZE) {
		size_t size = BLOCK_SIZE - (start + offset) % BLOCK_SIZE;

		if (memcmp(p + offset, zero, size) != 0)
			break;

		offset += size;
		len -= size;
	}

	/* trim zero sectors from the end of buffer */
	while (len >= BLOCK_SIZE) {
		size_t size = (start + offset + len) % BLOCK_SIZE;
		if (size == 0)
			size = BLOCK_SIZE;

		if (memcmp(p + offset + len - size, zero, size) != 0)
			break;

		len -= size;
	}

	*plen = len;
	*poffset = start + offset;
}

/*
 * Trim zero blocks from the beginning and end of buffer
 *
 * This function is similar to find_zero_blocks(), but this updates 'buf' so
 * that the zero block are removed from the beginning of buffer.
 */
void trim_zero_blocks(void *buf, uint64_t *poffset, uint32_t *plen)
{
	uint8_t *p = buf;
	uint64_t orig_offset = *poffset;

	find_zero_blocks(buf, poffset, plen);
	if (orig_offset < *poffset)
		memmove(p, p + *poffset - orig_offset, *plen);
}

char *xstrdup(const char *s)
{
	char *ret;

	ret = strdup(s);
	if (!ret)
		panic("Out of memory");

	return ret;
}

/*
 * Convert a decimal string like as strtoll to uint32_t/uint16_t
 *
 * returns:
 *   - a converted value if success i.e. neither negative value nor overflow
 *   - undefined if something went wrong and set errno accordingly
 *
 * errno:
 *   - 0 if success
 *   - EINVAL if one of the following:
 *       - nptr was an empty string
 *       - there was an unconvertible character in nptr
 *   - ERANGE if negative/positive overflow occurred
 */
uint32_t str_to_u32(const char *nptr)
{
	char *endptr;
	errno = 0;
	const long long conv = strtoll(nptr, &endptr, 10);
	/* empty string or unconvertible character */
	if (nptr == endptr || *endptr != '\0') {
		errno = EINVAL;
		return (uint32_t)conv;
	}
	/* negative value or overflow */
	if (conv < 0LL || UINT32_MAX < conv) {
		errno = ERANGE;
		return UINT32_MAX;
	}
	return (uint32_t)conv;
}

uint16_t str_to_u16(const char *nptr)
{
	const uint32_t conv = str_to_u32(nptr);
	/* overflow */
	if (UINT16_MAX < conv) {
		errno = ERANGE;
		return UINT16_MAX;
	}
	return (uint16_t)conv;
}
