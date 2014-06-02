/*
 * Taken and modfied from git by Liu Yuan <namei.unix@gmail.com>
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

#include "util.h"

mode_t sd_def_dmode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP;
mode_t sd_def_fmode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

static void do_nothing(size_t size)
{
}

static void (*try_to_free_routine)(size_t size) = do_nothing;

try_to_free_t set_try_to_free_routine(try_to_free_t routine)
{
	try_to_free_t old = try_to_free_routine;
	if (!routine)
		routine = do_nothing;
	try_to_free_routine = routine;
	return old;
}

void *xmalloc(size_t size)
{
	void *ret = malloc(size);
	if (unlikely(!ret) && unlikely(!size))
		ret = malloc(1);
	if (unlikely(!ret)) {
		try_to_free_routine(size);
		ret = malloc(size);
		if (!ret && !size)
			ret = malloc(1);
		if (!ret)
			panic("Out of memory");
	}
	return ret;
}

void *xzalloc(size_t size)
{
	return xcalloc(1, size);
}

void *xrealloc(void *ptr, size_t size)
{
	void *ret = realloc(ptr, size);
	if (unlikely(!ret) && unlikely(!size))
		ret = realloc(ptr, 1);
	if (unlikely(!ret)) {
		try_to_free_routine(size);
		ret = realloc(ptr, size);
		if (!ret && !size)
			ret = realloc(ptr, 1);
		if (!ret)
			panic("Out of memory");
	}
	return ret;
}

void *xcalloc(size_t nmemb, size_t size)
{
	void *ret = calloc(nmemb, size);
	if (unlikely(!ret) && unlikely(!nmemb || !size))
		ret = calloc(1, 1);
	if (unlikely(!ret)) {
		try_to_free_routine(nmemb * size);
		ret = calloc(nmemb, size);
		if (!ret && (!nmemb || !size))
			ret = calloc(1, 1);
		if (!ret)
			panic("Out of memory");
	}
	return ret;
}

/* zeroed memory version of valloc() */
void *xvalloc(size_t size)
{
	void *ret = valloc(size);
	if (unlikely(!ret))
		panic("Out of memory");
	memset(ret, 0, size);
	return ret;
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

/* Purge directory recursively */
int purge_directory(const char *dir_path)
{
	int ret = 0;
	struct stat s;
	DIR *dir;
	struct dirent *d;
	char path[PATH_MAX];

	dir = opendir(dir_path);
	if (!dir) {
		if (errno != ENOENT)
			sd_err("failed to open %s: %m", dir_path);
		return -errno;
	}

	while ((d = readdir(dir))) {
		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		snprintf(path, sizeof(path), "%s/%s", dir_path, d->d_name);
		ret = stat(path, &s);
		if (ret) {
			sd_err("failed to stat %s: %m", path);
			goto out;
		}
		if (S_ISDIR(s.st_mode))
			ret = rmdir_r(path);
		else
			ret = unlink(path);

		if (ret != 0) {
			sd_err("failed to remove %s %s: %m",
			       S_ISDIR(s.st_mode) ? "directory" : "file", path);
			goto out;
		}
	}
out:
	closedir(dir);
	return ret;
}

/* remove directory recursively */
int rmdir_r(const char *dir_path)
{
	int ret;

	ret = purge_directory(dir_path);
	if (ret == 0)
		ret = rmdir(dir_path);

	return ret;
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

/*
 * If 'once' is true, the signal will be restored to the default state
 * after 'handler' is called.
 */
int install_sighandler(int signum, void (*handler)(int), bool once)
{
	struct sigaction sa = {};

	sa.sa_handler = handler;
	if (once)
		sa.sa_flags = SA_RESETHAND | SA_NODEFER;
	sigemptyset(&sa.sa_mask);

	return sigaction(signum, &sa, NULL);
}

int install_crash_handler(void (*handler)(int))
{
	return install_sighandler(SIGSEGV, handler, true) ||
		install_sighandler(SIGABRT, handler, true) ||
		install_sighandler(SIGBUS, handler, true) ||
		install_sighandler(SIGILL, handler, true) ||
		install_sighandler(SIGFPE, handler, true);
}

/*
 * Re-raise the signal 'signo' for the default signal handler to dump
 * a core file, and exit with 'status' if the default handler cannot
 * terminate the process.  This function is expected to be called in
 * the installed signal handlers with install_crash_handler().
 */
void reraise_crash_signal(int signo, int status)
{
	int ret = raise(signo);

	/* We won't get here normally. */
	if (ret != 0)
		sd_emerg("failed to re-raise signal %d (%s).",
			  signo, strsignal(signo));
	else
		sd_emerg("default handler for the re-raised "
			  "signal %d (%s) didn't work expectedly", signo,
			  strsignal(signo));

	exit(status);
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
	int ret;

	if (path[0] == '\0') {
		ret = readlink("/proc/self/exe", path, sizeof(path));
		if (ret < -1)
			panic("%m");
	}

	return path;
}

/*
 * Split the given path and sets the splitted parts to 'segs'.
 *
 * This returns the number of splitted segments.
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
 * If force_create is true, this function create the file even when the
 * temporary file exists.
 */
int atomic_create_and_write(const char *path, const char *buf, size_t len,
			    bool force_create)
{
	int fd, ret;
	char tmp_path[PATH_MAX];

	snprintf(tmp_path, PATH_MAX, "%s.tmp", path);
again:
	fd = open(tmp_path, O_WRONLY | O_CREAT | O_SYNC | O_EXCL, sd_def_fmode);
	if (fd < 0) {
		if (errno == EEXIST) {
			if (force_create) {
				sd_debug("clean up a temporary file %s",
					 tmp_path);
				unlink(tmp_path);
				goto again;
			} else
				sd_debug("someone else is dealing with %s",
					 tmp_path);
		} else
			sd_err("failed to open temporal file %s, %m", tmp_path);
		ret = -1;
		goto end;
	}

	ret = xwrite(fd, buf, len);
	if (unlikely(ret != len)) {
		sd_err("failed to write %s, %m", path);
		ret = -1;
		goto close_fd;
	}

	ret = rename(tmp_path, path);
	if (unlikely(ret < 0)) {
		sd_err("failed to rename %s, %m", path);
		ret = -1;
	}

close_fd:
	close(fd);
end:
	return ret;
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
 * The caller passes the offset of 'buf' with 'poffset' so that this funciton
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
