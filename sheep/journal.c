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

#include "sheep_priv.h"

struct journal_file {
	int fd;
	off_t pos;
	int commit_fd;
	uatomic_bool in_commit;
};

/*
 * CAUTION: This definition of struct journal_descriptor must be same
 * to the definition in tests/dynamorio/journaling/journaling.c. We
 * have to update the definition in the DR client definition if we
 * update the below definition because there's no technique for
 * keeping the consistency automatically.
 */
struct journal_descriptor {
	uint32_t magic;
	uint16_t flag;
	uint16_t reserved;
	union {
		uint32_t epoch;
		uint64_t oid;
	};
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

#define JF_STORE 0
#define JF_REMOVE_OBJ 2

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
	fd = open(path, flags, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		sd_err("open %s %m", name);
		return -1;
	}
	if (prealloc(fd, jfile_size) < 0) {
		sd_err("prealloc %s %m", name);
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

		sd_err("open1 %m");
		return -1;
	}
	snprintf(path, sizeof(path), "%s/%s", p, jfile_name[1]);
	fd2 = open(path, flags);
	if (fd2 < 0) {
		sd_err("open2 %m");
		close(fd1);
		return -1;
	}

	if (fstat(fd1, &st1) < 0 || fstat(fd2, &st2) < 0) {
		sd_err("stat %m");
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
		round_up(jd->size, SECTOR_SIZE) + JOURNAL_META_SIZE;
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
	void *buf = NULL;
	char *p = (char *)jd;

	snprintf(path, PATH_MAX, "%s/%016"PRIx64,
		 md_get_object_path(jd->oid), jd->oid);

	if (jd->flag == JF_REMOVE_OBJ) {
		sd_info("%s (remove)", path);
		unlink(path);

		return 0;
	}

	sd_info("%s, size %" PRIu64 ", off %" PRIu64 ", %d", path, jd->size,
		jd->offset, jd->create);

	if (jd->create)
		flags |= O_CREAT;

	fd = open(path, flags, sd_def_fmode);
	if (fd < 0) {
		sd_err("open %m");
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
		sd_err("write %zd, size %" PRIu64 ", errno %m", size, jd->size);
		ret = -1;
		goto out;
	}
out:
	free(buf);
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
		sd_err("fstat %m");
		return -1;
	}

	if (!st.st_size) {
		/*
		 * An empty journal file can be produced when sheep crashes
		 * between ftruncate() and prealloc() of commit_data().
		 * Such a file should be ignored simply.
		 */
		close(fd);
		return 0;
	}

	map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (map == MAP_FAILED) {
		sd_err("%m");
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
		p += JOURNAL_META_SIZE + round_up(jd->size, SECTOR_SIZE);
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
static void check_recover_journal_file(const char *p)
{
	int old = 0, new = 0;

	if (get_old_new_jfile(p, &old, &new) < 0)
		return;

	/* No journal file found */
	if (old == 0)
		return;

	if (do_recover(old) < 0)
		panic("recoverying from journal file (old) failed");
	if (do_recover(new) < 0)
		panic("recoverying from journal file (new) failed");
}

int journal_file_init(const char *path, size_t size, bool skip)
{
	int fd;

	if (!skip)
		check_recover_journal_file(path);

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

void clean_journal_file(const char *p)
{
	int ret;
	char path[PATH_MAX];

	sync();

	snprintf(path, sizeof(path), "%s/%s", p, jfile_name[0]);
	ret = unlink(path);
	if (ret < 0)
		sd_err("unlink(%s): %m", path);

	snprintf(path, sizeof(path), "%s/%s", p, jfile_name[1]);
	ret = unlink(path);
	if (ret < 0)
		sd_err("unlink(%s): %m", path);
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
	if (unlikely(err))
		panic("%s", strerror(err));

	sync();
	if (unlikely(xftruncate(jfile.commit_fd, 0) < 0))
		panic("truncate %m");
	if (unlikely(prealloc(jfile.commit_fd, jfile_size) < 0))
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
	if (unlikely(!uatomic_set_true(&jfile.in_commit))) {
		sd_err("journal file in committing, "
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
	if (unlikely(err))
		panic("%s", strerror(err));
}

static int journal_file_write(struct journal_descriptor *jd, const char *buf)
{
	uint32_t marker = JOURNAL_END_MARKER;
	int ret = SD_RES_SUCCESS;
	uint64_t size = jd->size;
	ssize_t written, rusize = round_up(size, SECTOR_SIZE),
		wsize = JOURNAL_META_SIZE + rusize;
	off_t woff;
	char *wbuffer, *p;

	pthread_spin_lock(&jfile_lock);
	if (!jfile_enough_space(wsize))
		switch_journal_file();
	woff = jfile.pos;
	jfile.pos += wsize;
	pthread_spin_unlock(&jfile_lock);

	p = wbuffer = xvalloc(wsize);
	memcpy(p, jd, JOURNAL_DESC_SIZE);
	p += JOURNAL_DESC_SIZE;
	memcpy(p, buf, size);
	p += size;
	if (size < rusize) {
		memset(p, 0, rusize - size);
		p += rusize - size;
	}
	memcpy(p, &marker, JOURNAL_MARKER_SIZE);
	/*
	 * Concurrent writes with the same FD is okay because we don't have any
	 * critical sections that need lock inside kernel write path, since we
	 * a) bypass page cache, b) don't modify i_size of this inode.
	 *
	 * Feel free to correct me If I am wrong.
	 */
	written = xpwrite(jfile.fd, wbuffer, wsize, woff);
	if (unlikely(written != wsize)) {
		sd_err("failed, written %zd, len %zd", written, wsize);
		/* FIXME: teach journal file handle EIO gracefully */
		ret = SD_RES_EIO;
		goto out;
	}
out:
	free(wbuffer);
	return ret;
}

int journal_write_store(uint64_t oid, const char *buf, size_t size,
			off_t offset, bool create)
{
	struct journal_descriptor jd = {
		.magic = JOURNAL_DESC_MAGIC,
		.flag = JF_STORE,
		.offset = offset,
		.size = size,
		.create = create,
	};
	/* We have to explicitly do assignment to get all GCC compatible */
	jd.oid = oid;
	return journal_file_write(&jd, buf);
}

int journal_remove_object(uint64_t oid)
{
	struct journal_descriptor jd = {
		.magic = JOURNAL_DESC_MAGIC,
		.flag = JF_REMOVE_OBJ,
		.size = 0,
	};
	jd.oid = oid;
	return journal_file_write(&jd, NULL);
}

static __attribute__((used)) void journal_c_build_bug_ons(void)
{
	/* never called, only for checking BUILD_BUG_ON()s */
	BUILD_BUG_ON(sizeof(struct journal_descriptor) != JOURNAL_DESC_SIZE);
}
