#ifndef __BITOPS_H__
#define __BITOPS_H__

#include <stdint.h>

#include "util.h"

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define BITS_PER_BYTE		8
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define DECLARE_BITMAP(name, bits) \
	unsigned long name[BITS_TO_LONGS(bits)]
#define BITS_PER_LONG (BITS_PER_BYTE * sizeof(long))

#define __ffs(x)  (x ? __builtin_ffsl(x) - 1 : 0)
#define ffz(x)  __ffs(~(x))

#define BITOP_WORD(nr)		((nr) / BITS_PER_LONG)

/*
 * Iterate over a bitmap
 *
 * @nr: the bit number to use as a loop cursor
 * @addr: the bitmap you iterate over
 * @bits: the number of bits this bitmap contains
 */
#define FOR_EACH_BIT(nr, addr, bits)					\
	for (nr = find_next_bit((addr), (bits), 0);			\
	     nr < (bits);						\
	     nr = find_next_bit((addr), (bits), nr + 1))

/*
 * Change the size of allocated bitmap
 *
 * This doesn't change the contents of the old bitmap pointed to by `ptr`, and
 * initializes the newly allocated area with zeros.
 */
static inline unsigned long *alloc_bitmap(unsigned long *old_bmap,
					  size_t old_bits, size_t new_bits)
{
	size_t old_size = BITS_TO_LONGS(old_bits) * sizeof(long);
	size_t new_size = BITS_TO_LONGS(new_bits) * sizeof(long);
	unsigned long *new_bmap =  xrealloc(old_bmap, new_size);

	if (old_bits < new_bits)
		memset((char *)new_bmap + old_size, 0, new_size - old_size);

	return new_bmap;
}

static inline unsigned long find_next_zero_bit(const unsigned long *addr,
					       unsigned long size,
					       unsigned long offset)
{
	const unsigned long *p = addr + BITOP_WORD(offset);
	unsigned long result = offset & ~(BITS_PER_LONG-1);
	unsigned long tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset %= BITS_PER_LONG;
	if (offset) {
		tmp = *(p++);
		tmp |= ~0UL >> (BITS_PER_LONG - offset);
		if (size < BITS_PER_LONG)
			goto found_first;
		if (~tmp)
			goto found_middle;
		size -= BITS_PER_LONG;
		result += BITS_PER_LONG;
	}
	while (size & ~(BITS_PER_LONG-1)) {
		tmp = *(p++);
		if (~tmp)
			goto found_middle;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = *p;

found_first:
	tmp |= ~0UL << size;
	if (tmp == ~0UL)	/* Are any bits zero? */
		return result + size;	/* Nope. */
found_middle:
	return result + ffz(tmp);
}

static inline unsigned long find_next_bit(const unsigned long *addr,
					  unsigned long size,
					  unsigned long offset)
{
	const unsigned long *p = addr + BITOP_WORD(offset);
	unsigned long result = offset & ~(BITS_PER_LONG-1);
	unsigned long tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset %= BITS_PER_LONG;
	if (offset) {
		tmp = *(p++);
		tmp &= (~0UL << offset);
		if (size < BITS_PER_LONG)
			goto found_first;
		if (tmp)
			goto found_middle;
		size -= BITS_PER_LONG;
		result += BITS_PER_LONG;
	}
	while (size & ~(BITS_PER_LONG-1)) {
		tmp = *(p++);
		if (tmp)
			goto found_middle;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = *p;

found_first:
	tmp &= (~0UL >> (BITS_PER_LONG - size));
	if (tmp == 0UL)		/* Are any bits set? */
		return result + size;	/* Nope. */
found_middle:
	return result + __ffs(tmp);
}

static inline void set_bit(int nr, unsigned long *addr)
{
	addr[nr / BITS_PER_LONG] |= 1UL << (nr % BITS_PER_LONG);
}

static inline void atomic_set_bit(int nr, unsigned long *addr)
{
	uatomic_or(addr + nr / BITS_PER_LONG, 1UL << (nr % BITS_PER_LONG));
}

static inline int test_bit(unsigned int nr, const unsigned long *addr)
{
	return ((1UL << (nr % BITS_PER_LONG)) &
		(((unsigned long *)addr)[nr / BITS_PER_LONG])) != 0;
}

static inline void clear_bit(unsigned int nr, unsigned long *addr)
{
	addr[nr / BITS_PER_LONG] &= ~(1UL << (nr % BITS_PER_LONG));
}

/*
 * fls64 - find last set bit in a 64-bit word
 * @x: the word to search
 *
 * This is defined in a similar way as the libc and compiler builtin
 * ffsll, but returns the position of the most significant set bit.
 *
 * fls64(value) returns 0 if value is 0 or the position of the last
 * set bit if value is nonzero. The last (most significant) bit is
 * at position 64.
 */
#if __SIZEOF_LONG__ == 4
static __always_inline int fls64(uint64_t x)
{
	uint32_t h = x >> 32;

	if (x == 0)
		return 0;

	if (h)
		return 64 - __builtin_clzl(h);
	return 32 - __builtin_clzl(x);
}
#elif __SIZEOF_LONG__ == 8
static __always_inline int fls64(uint64_t x)
{
	if (x == 0)
		return 0;
	return 64 - __builtin_clzl(x);
}
#else
#error __SIZEOF_LONG__ not 4 or 8
#endif

#endif /* __BITOPS_H__ */
