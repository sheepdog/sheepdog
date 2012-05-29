/* Taken from git by Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "strbuf.h"
#include "logger.h"

void strbuf_init(struct strbuf *sb, size_t hint)
{
	memset(sb, 0, sizeof(*sb));
	if (hint)
		strbuf_grow(sb, hint);
}

void strbuf_release(struct strbuf *sb)
{
	free(sb->buf);
	memset(sb, 0, sizeof(*sb));
}

void strbuf_reset(struct strbuf *sb)
{
	if (sb->len)
		strbuf_setlen(sb, 0);
	sb->eof = 0;
}

char *strbuf_detach(struct strbuf *sb)
{
	char *res = sb->buf;
	strbuf_init(sb, 0);
	return res;
}

void strbuf_attach(struct strbuf *sb, void *buf, size_t len, size_t alloc)
{
	strbuf_release(sb);
	sb->buf   = buf;
	sb->len   = len;
	sb->alloc = alloc;
	strbuf_grow(sb, 0);
	sb->buf[sb->len] = '\0';
}

void strbuf_grow(struct strbuf *sb, size_t extra)
{
	if (sb->len + extra + 1 <= sb->len)
		panic("you want to use way too much memory");
	ALLOC_GROW(sb->buf, sb->len + extra + 1, sb->alloc);
}

void strbuf_rtrim(struct strbuf *sb)
{
	while (sb->len > 0 && isspace((unsigned char)sb->buf[sb->len - 1]))
		sb->len--;
	sb->buf[sb->len] = '\0';
}

void strbuf_insert(struct strbuf *sb, size_t pos, const void *data, size_t len)
{
	strbuf_grow(sb, len);
	if (pos > sb->len)
		panic("`pos' is too far after the end of the buffer");
	memmove(sb->buf + pos + len, sb->buf + pos, sb->len - pos);
	memcpy(sb->buf + pos, data, len);
	strbuf_setlen(sb, sb->len + len);
}

void strbuf_splice(struct strbuf *sb, size_t pos, size_t len,
		const void *data, size_t dlen)
{
	if (pos + len < pos)
		panic("you want to use way too much memory");
	if (pos > sb->len)
		panic("`pos' is too far after the end of the buffer");
	if (pos + len > sb->len)
		panic("`pos + len' is too far after the end of the buffer");

	if (dlen >= len)
		strbuf_grow(sb, dlen - len);
	memmove(sb->buf + pos + dlen,
			sb->buf + pos + len,
			sb->len - pos - len);
	memcpy(sb->buf + pos, data, dlen);
	strbuf_setlen(sb, sb->len + dlen - len);
}

void strbuf_remove(struct strbuf *sb, size_t pos, size_t len)
{
	strbuf_splice(sb, pos, len, NULL, 0);
}

void strbuf_add(struct strbuf *sb, const void *data, size_t len)
{
	strbuf_grow(sb, len);
	memcpy(sb->buf + sb->len, data, len);
	strbuf_setlen(sb, sb->len + len);
}

void strbuf_addf(struct strbuf *sb, const char *fmt, ...)
{
	int len;
	va_list ap;

	va_start(ap, fmt);
	len = vsnprintf(sb->buf + sb->len, sb->alloc - sb->len, fmt, ap);
	va_end(ap);
	if (len < 0)
		len = 0;
	if (len > strbuf_avail(sb)) {
		strbuf_grow(sb, len);
		va_start(ap, fmt);
		len = vsnprintf(sb->buf + sb->len, sb->alloc - sb->len, fmt, ap);
		va_end(ap);
		if (len > strbuf_avail(sb))
			panic("this should not happen, your snprintf is broken");
	}
	strbuf_setlen(sb, sb->len + len);
}

size_t strbuf_fread(struct strbuf *sb, size_t size, FILE *f)
{
	size_t res;

	strbuf_grow(sb, size);
	res = fread(sb->buf + sb->len, 1, size, f);
	if (res > 0)
		strbuf_setlen(sb, sb->len + res);
	return res;
}

ssize_t strbuf_read(struct strbuf *sb, int fd, size_t hint)
{
	size_t oldlen = sb->len;

	strbuf_grow(sb, hint ? hint : 8192);
	for (;;) {
		ssize_t cnt;

		cnt = xread(fd, sb->buf + sb->len, sb->alloc - sb->len - 1);
		if (cnt < 0) {
			strbuf_setlen(sb, oldlen);
			return -1;
		}
		if (!cnt)
			break;
		sb->len += cnt;
		strbuf_grow(sb, 8192);
	}

	sb->buf[sb->len] = '\0';
	return sb->len - oldlen;
}

static int strbuf_getwholeline(struct strbuf *sb, FILE *fp, int term)
{
	int ch;

	if (feof(fp))
		return EOF;

	strbuf_reset(sb);
	while ((ch = fgetc(fp)) != EOF) {
		strbuf_grow(sb, 1);
		sb->buf[sb->len++] = ch;
		if (ch == term)
			break;
	}
	if (ch == EOF && sb->len == 0)
		return EOF;

	sb->buf[sb->len] = '\0';
	return 0;
}

int strbuf_getline(struct strbuf *sb, FILE *fp, int term)
{
	if (strbuf_getwholeline(sb, fp, term))
		return EOF;
	if (sb->buf[sb->len-1] == term)
		strbuf_setlen(sb, sb->len-1);
	return 0;
}

int strbuf_copyout(struct strbuf *sb, void *buf, size_t len)
{
	len = min(len, sb->len + 1);
	memcpy(buf, sb->buf, len);

	return len;
}
