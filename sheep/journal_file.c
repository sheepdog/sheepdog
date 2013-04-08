/*
 * Copyright (C) 2012 Taobao Inc.
 *
 * Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/mman.h>

#include "sheep_priv.h"

struct journal_file {
	int fd;
	off_t pos;
	int commit_fd;
	uatomic_bool in_commit;
};

struct journal_descriptor {
	uint32_t magic;
	uint32_t reserved;
	uint64_t oid;
	uint64_t offset;
	uint64_t size;
	uint8_t create;
	uint8_t pad[475];
} __packed;

/* JOURNAL_DESC + JOURNAL_MARKER must be 512 algined for DIO */
#define JOURNAL_DESC_MAGIC 0xfee1900d
#define JOURNAL_DESC_SIZE 508
#define JOURNAL_MARKER_SIZE 4 /* Use marker to detect partial write */
#define JOURNAL_META_SIZE (JOURNAL_DESC_SIZE + JOURNAL_MARKER_SIZE)

#define JOURNAL_END_MARKER 0xdeadbeef

static const char *jfile_name[2] = { "journal_file0", "journal_file1", };
static int jfile_fds[2];
static size_t jfile_size;

static struct journal_file jfile;
static pthread_spinlock_t jfile_lock;

static int create_journal_file(const char *root, const char *name)
{
	int fd, flags = O_DSYNC | O_RDWR | O_TRUNC | O_CREAT | O_DIRECT;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", root, name);
	fd = open(path, flags, 0644);
	if (fd < 0) {
		sd_eprintf("open %s %m", name);
		return -1;
	}
	if (prealloc(fd, jfile_size) < 0) {
		sd_eprintf("prealloc %s %m", name);
		return -1;
	}

	return fd;
}

/* We should have two valid FDs, otherwise something goes wrong */
static int get_old_new_jfile(const char *p, int *old, int *new)
{
	int fd1, fd2;
	int flags = O_RDONLY;
	char path[PATH_MAX];
	struct stat st1, st2;

	snprintf(path, sizeof(path), "%s/%s", p, jfile_name[0]);
	fd1 = open(path, flags);
	if (fd1 < 0) {
		if (errno == ENOENT)
			return 0;

		sd_eprintf("open1 %m");
		return -1;
	}
	snprintf(path, sizeof(path), "%s/%s", p, jfile_name[1]);
	fd2 = open(path, flags);
	if (fd2 < 0) {
		sd_eprintf("open2 %m");
		close(fd1);
		return -1;
	}

	if (fstat(fd1, &st1) < 0 || fstat(fd2, &st2) < 0) {
		sd_eprintf("stat %m");
		goto out;
	}

	if (st1.st_mtime < st2.st_mtime) {
		*old = fd1;
		*new = fd2;
	} else {
		*old = fd2;
		*new = fd1;
	}

	return 0;
out:
	close(fd1);
	close(fd2);
	return -1;
}

static bool journal_entry_full_write(struct journal_descriptor *jd)
{
	char *end = (char *)jd +
		roundup(jd->size, SECTOR_SIZE) + JOURNAL_META_SIZE;
	uint32_t marker = *(((uint32_t *)end) - 1);

	if (marker != JOURNAL_END_MARKER)
		return false;
	return true;
}

static int replay_journal_entry(struct journal_descriptor *jd)
{
	char path[PATH_MAX];
	ssize_t size;
	int fd, flags = O_WRONLY, ret = 0;
	void *buf;
	char *p = (char *)jd;

	sd_dprintf("%"PRIx64", size %"PRIu64", off %"PRIu64", %d", jd->oid,
		   jd->size, jd->offset, jd->create);

	if (jd->create)
		flags |= O_CREAT;
	snprintf(path, sizeof(path), "%s/%016" PRIx64, get_object_path(jd->oid),
		 jd->oid);
	fd = open(path, flags, def_fmode);
	if (fd < 0) {
		sd_eprintf("open %m");
		return -1;
	}

	if (jd->create) {
		ret = prealloc(fd, get_objsize(jd->oid));
		if (ret < 0)
			goto out;
	}
	buf = xmalloc(jd->size);
	p += JOURNAL_DESC_SIZE;
	memcpy(buf, p, jd->size);
	size = xpwrite(fd, buf, jd->size, jd->offset);
	if (size != jd->size) {
		sd_eprintf("write %zd, size %zu, errno %m", size, jd->size);
		ret = -1;
		goto out;
	}
out:
	close(fd);
	return ret;
}

static int do_recover(int fd)
{
	struct journal_descriptor *jd;
	void *map;
	char *p, *end;
	struct stat st;

	if (fstat(fd, &st) < 0) {
		sd_eprintf("fstat %m");
		return -1;
	}

	map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (map == MAP_FAILED) {
		sd_eprintf("%m");
		return -1;
	}

	end = (char *)map + st.st_size;
	for (p = map; p < end;) {
		jd = (struct journal_descriptor *)p;
		if (jd->magic != JOURNAL_DESC_MAGIC) {
			/* Empty area */
			p += SECTOR_SIZE;
			continue;
		}
		/* We skip partial write because it is not acked back to VM */
		if (!journal_entry_full_write(jd))
			goto skip;

		if (replay_journal_entry(jd) < 0)
			return -1;
skip:
		p += JOURNAL_META_SIZE + roundup(jd->size, SECTOR_SIZE);
	}
	munmap(map, st.st_size);
	/* Do a final sync() to assure data is reached to the disk */
	sync();
	return 0;
}

/*
 * We recover the journal file in order of wall time in the corner case that
 * sheep crashes while in the middle of journal committing. For most of cases,
 * we actually only recover one jfile, the other would be empty. This process
 * is fast with buffered IO that only take several secends at most.
 */
static int check_recover_journal_file(const char *p)
{
	int old = 0, new = 0;

	if (get_old_new_jfile(p, &old, &new) < 0)
		return -1;

	/* No journal file found */
	if (old == 0)
		return 0;

	if (do_recover(old) < 0)
		return -1;
	if (do_recover(new) < 0)
		return -1;

	return 0;
}

int journal_file_init(const char *path, size_t size, bool skip)
{
	int fd;

	if (!skip && check_recover_journal_file(path) < 0)
		return -1;

	jfile_size = (size * 1024 * 1024) / 2;

	fd = create_journal_file(path, jfile_name[0]);
	if (fd < 0)
		return -1;
	jfile.fd = jfile_fds[0] = fd;

	fd = create_journal_file(path, jfile_name[1]);
	jfile_fds[1] = fd;

	pthread_spin_init(&jfile_lock, PTHREAD_PROCESS_PRIVATE);
	return 0;
}

static inline bool jfile_enough_space(size_t size)
{
	if (jfile.pos + size > jfile_size)
		return false;
	return true;
}

/*
 * We rely on the kernel's page cache to cache data objects to 1) boost read
 * perfmance 2) simplify read path so that data commiting is simply a
 * sync() operation and We do it in a dedicated thread to avoid blocking
 * the writer by switch back and forth between two journal files.
 */
static void *commit_data(void *ignored)
{
	int err;

	/* Tell runtime to release resources after termination */
	err = pthread_detach(pthread_self());
	if (err)
		panic("%s", strerror(err));

	sync();
	if (ftruncate(jfile.commit_fd, 0) < 0)
		panic("truncate %m");
	if (prealloc(jfile.commit_fd, jfile_size) < 0)
		panic("prealloc");

	uatomic_set_false(&jfile.in_commit);

	pthread_exit(NULL);
}

/* FIXME: Try not sleep inside lock */
static void switch_journal_file(void)
{
	int old = jfile.fd, err;
	pthread_t thread;

retry:
	if (!uatomic_set_true(&jfile.in_commit)) {
		sd_eprintf("journal file in committing, "
			   "you might need enlarge jfile size");
		usleep(100000); /* Wait until committing is finished */
		goto retry;
	}

	if (old == jfile_fds[0])
		jfile.fd = jfile_fds[1];
	else
		jfile.fd = jfile_fds[0];
	jfile.commit_fd = old;
	jfile.pos = 0;

	err = pthread_create(&thread, NULL, commit_data, NULL);
	if (err)
		panic("%s", strerror(err));
}

int journal_file_write(uint64_t oid, const char *buf, size_t size,
		       off_t offset, bool create)
{
	uint32_t marker = JOURNAL_END_MARKER;
	int ret = SD_RES_SUCCESS;
	ssize_t written, rusize = roundup(size, SECTOR_SIZE),
		wsize = JOURNAL_META_SIZE + rusize;
	off_t woff;
	char *wbuffer, *p;
	struct journal_descriptor jd = {
		.magic = JOURNAL_DESC_MAGIC,
		.offset = offset,
		.size = size,
		.oid = oid,
		.create = create,
	};

	pthread_spin_lock(&jfile_lock);
	if (!jfile_enough_space(wsize))
		switch_journal_file();
	woff = jfile.pos;
	jfile.pos += wsize;
	pthread_spin_unlock(&jfile_lock);

	p = wbuffer = xvalloc(wsize);
	memcpy(p, &jd, JOURNAL_DESC_SIZE);
	p += JOURNAL_DESC_SIZE;
	memcpy(p, buf, size);
	p += size;
	if (size < rusize) {
		memset(p, 0, rusize - size);
		p += rusize - size;
	}
	memcpy(p, &marker, JOURNAL_MARKER_SIZE);

	sd_dprintf("oid %lx, pos %zu, wsize %zu", oid, jfile.pos, wsize);
	/*
	 * Concurrent writes with the same FD is okay because we don't have any
	 * critical sections that need lock inside kernel write path, since we
	 * a) bypass page cache, b) don't modify i_size of this inode.
	 *
	 * Feel free to correct me If I am wrong.
	 */
	written = xpwrite(jfile.fd, wbuffer, wsize, woff);
	if (written != wsize) {
		sd_eprintf("failed, written %zd, len %zu", written, wsize);
		/* FIXME: teach journal file handle EIO gracefully */
		ret = SD_RES_EIO;
		goto out;
	}
out:
	free(wbuffer);
	return ret;
}
