#ifndef STRBUF_H
#define STRBUF_H

#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "util.h"

struct strbuf {
	size_t alloc;
	size_t len;
	int eof;
	char *buf;
};

#define alloc_nr(x) (((x)+16)*3/2)

/*
 * Realloc the buffer pointed at by variable 'x' so that it can hold
 * at least 'nr' entries; the number of entries currently allocated
 * is 'alloc', using the standard growing factor alloc_nr() macro.
 *
 * DO NOT USE any expression with side-effect for 'x' or 'alloc'.
 */
#define ALLOC_GROW(x, nr, alloc) \
	do { \
		if ((nr) > alloc) { \
			if (alloc_nr(alloc) < (nr)) \
			alloc = (nr); \
			else \
			alloc = alloc_nr(alloc); \
			x = xrealloc((x), alloc * sizeof(*(x))); \
		} \
	} while(0)

#define STRBUF_INIT  { 0, 0, 0, NULL }

/*----- strbuf life cycle -----*/
extern void strbuf_init(struct strbuf *, size_t);
extern void strbuf_release(struct strbuf *);
extern void strbuf_reset(struct strbuf *);
extern char *strbuf_detach(struct strbuf *);
extern void strbuf_attach(struct strbuf *, void *, size_t, size_t);

/*----- strbuf size related -----*/
static inline size_t strbuf_avail(struct strbuf *sb) {
	return sb->alloc ? sb->alloc - sb->len - 1 : 0;
}
static inline void strbuf_setlen(struct strbuf *sb, size_t len) {
	assert (len < sb->alloc);
	sb->len = len;
	sb->buf[len] = '\0';
}

extern void strbuf_grow(struct strbuf *, size_t);

/*----- content related -----*/
extern void strbuf_rtrim(struct strbuf *);

/*----- add data in your buffer -----*/
static inline void strbuf_addch(struct strbuf *sb, int c) {
	strbuf_grow(sb, 1);
	sb->buf[sb->len++] = c;
	sb->buf[sb->len] = '\0';
}

/* inserts after pos, or appends if pos >= sb->len */
extern void strbuf_insert(struct strbuf *, size_t pos, const void *, size_t);
extern void strbuf_remove(struct strbuf *, size_t pos, size_t len);

/* splice pos..pos+len with given data */
extern void strbuf_splice(struct strbuf *, size_t pos, size_t len,
		const void *, size_t);

extern void strbuf_add(struct strbuf *, const void *, size_t);
static inline void strbuf_addstr(struct strbuf *sb, const char *s) {
	strbuf_add(sb, s, strlen(s));
}
static inline void strbuf_addbuf(struct strbuf *sb, struct strbuf *sb2) {
	strbuf_add(sb, sb2->buf, sb2->len);
}

__attribute__((format(printf,2,3)))
extern void strbuf_addf(struct strbuf *sb, const char *fmt, ...);

extern size_t strbuf_fread(struct strbuf *, size_t, FILE *);
/* XXX: if read fails, any partial read is undone */
extern ssize_t strbuf_read(struct strbuf *, int fd, size_t hint);
int strbuf_getline(struct strbuf *sb, FILE *fp, int term);

#endif
