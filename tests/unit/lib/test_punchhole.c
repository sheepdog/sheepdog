#include <stdbool.h>
#include <stdlib.h>	/* mkostemp */
#include <sys/stat.h>	/* stat */
#include <fcntl.h>	/* O_* flags */
#include <unity.h>
#include <cmock.h>
#include <linux/falloc.h>

#include "util.h"
#include "Mocklogger.h"

static void test_block_size_equals_4K(void)
{
	TEST_ASSERT_EQUAL(4096, BLOCK_SIZE);
}

static void test_find_zero_blocks_null(void)
{
	uint64_t offset = 0;
	uint32_t len = 0;
	find_zero_blocks(NULL, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(0, offset);
	TEST_ASSERT_EQUAL_UINT32(0, len);
}

static void test_find_zero_blocks_1(void)
{
	const uint8_t buf[1] = {0};
	uint64_t offset = 0;
	uint32_t len = 1;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(0, offset);
	TEST_ASSERT_EQUAL_UINT32(1, len);
}

static void test_find_zero_blocks_4095(void)
{
	const uint8_t buf[4095] = {0};
	uint64_t offset = 0;
	uint32_t len = 4095;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(0, offset);
	TEST_ASSERT_EQUAL_UINT32(4095, len);
}

static void test_find_zero_blocks_4K_zero(void)
{
	const uint8_t buf[BLOCK_SIZE] = {0};
	uint64_t offset = 0;
	uint32_t len = BLOCK_SIZE;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(BLOCK_SIZE, offset);
	TEST_ASSERT_EQUAL_UINT32(0, len);
}

static void test_find_zero_blocks_4K_nonzero_at_head(void)
{
	uint8_t buf[BLOCK_SIZE] = {0};
		buf[0] = 1;
	uint64_t offset = 0;
	uint32_t len = BLOCK_SIZE;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(0, offset);
	TEST_ASSERT_EQUAL_UINT32(BLOCK_SIZE, len);
}

static void test_find_zero_blocks_4K_nonzero_at_tail(void)
{
	uint8_t buf[BLOCK_SIZE] = {0};
		buf[BLOCK_SIZE - 1] = 1;
	uint64_t offset = 0;
	uint32_t len = BLOCK_SIZE;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(0, offset);
	TEST_ASSERT_EQUAL_UINT32(BLOCK_SIZE, len);
}

static void test_find_zero_blocks_4K_nonzero_at_middle(void)
{
	uint8_t buf[BLOCK_SIZE] = {0};
		buf[BLOCK_SIZE / 2] = 1;
	uint64_t offset = 0;
	uint32_t len = BLOCK_SIZE;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(0, offset);
	TEST_ASSERT_EQUAL_UINT32(BLOCK_SIZE, len);
}

static void test_find_zero_blocks_4097_zero_offset_0(void)
{
	const uint8_t buf[BLOCK_SIZE + 1] = {0};
	uint64_t offset = 0;
	uint32_t len = BLOCK_SIZE + 1;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(BLOCK_SIZE, offset);
	TEST_ASSERT_EQUAL_UINT32(1, len);
}

static void test_find_zero_blocks_4097_zero_offset_1(void)
{
	const uint8_t buf[BLOCK_SIZE + 1] = {0};
	uint64_t offset = 1;
	uint32_t len = BLOCK_SIZE;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(BLOCK_SIZE, offset);
	TEST_ASSERT_EQUAL_UINT32(1, len);
}

static void test_find_zero_blocks_4097_zero_offset_2(void)
{
	const uint8_t buf[BLOCK_SIZE + 1] = {0};
	uint64_t offset = 2;
	uint32_t len = BLOCK_SIZE - 1;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(2, offset);
	TEST_ASSERT_EQUAL_UINT32(BLOCK_SIZE - 1, len);
}

static void test_find_zero_blocks_4097_nonzero_at_0(void)
{
	uint8_t buf[BLOCK_SIZE + 1] = {0};
		buf[0] = 1;
	uint64_t offset = 0;
	uint32_t len = BLOCK_SIZE + 1;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(0, offset);
	TEST_ASSERT_EQUAL_UINT32(BLOCK_SIZE, len);
}

static void test_find_zero_blocks_4097_nonzero_at_4096(void)
{
	uint8_t buf[BLOCK_SIZE + 1] = {0};
		buf[BLOCK_SIZE] = 1;
	uint64_t offset = 0;
	uint32_t len = BLOCK_SIZE + 1;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(BLOCK_SIZE, offset);
	TEST_ASSERT_EQUAL_UINT32(1, len);
}

static void test_find_zero_blocks_8K_zero_zero(void)
{
	const uint8_t buf[BLOCK_SIZE * 2] = {0};
	uint64_t offset = 0;
	uint32_t len = BLOCK_SIZE * 2;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(BLOCK_SIZE * 2, offset);
	TEST_ASSERT_EQUAL_UINT32(0, len);
}

static void test_find_zero_blocks_8K_zero_head(void)
{
	uint8_t buf[BLOCK_SIZE * 2] = {0};
		buf[BLOCK_SIZE] = 1;
	uint64_t offset = 0;
	uint32_t len = BLOCK_SIZE * 2;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(BLOCK_SIZE, offset);
	TEST_ASSERT_EQUAL_UINT32(BLOCK_SIZE, len);
}

static void test_find_zero_blocks_8K_zero_tail(void)
{
	uint8_t buf[BLOCK_SIZE * 2] = {0};
		buf[BLOCK_SIZE * 2 - 1] = 1;
	uint64_t offset = 0;
	uint32_t len = BLOCK_SIZE * 2;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(BLOCK_SIZE, offset);
	TEST_ASSERT_EQUAL_UINT32(BLOCK_SIZE, len);
}

static void test_find_zero_blocks_8K_head_zero(void)
{
	uint8_t buf[BLOCK_SIZE * 2] = {0};
		buf[0] = 1;
	uint64_t offset = 0;
	uint32_t len = BLOCK_SIZE * 2;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(0, offset);
	TEST_ASSERT_EQUAL_UINT32(BLOCK_SIZE, len);
}

static void test_find_zero_blocks_8K_tail_zero(void)
{
	uint8_t buf[BLOCK_SIZE * 2] = {0};
		buf[BLOCK_SIZE - 1] = 1;
	uint64_t offset = 0;
	uint32_t len = BLOCK_SIZE * 2;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(0, offset);
	TEST_ASSERT_EQUAL_UINT32(BLOCK_SIZE, len);
}

static void test_find_zero_blocks_8K_head_tail(void)
{
	uint8_t buf[BLOCK_SIZE * 2] = {0};
		buf[0] = 1;
		buf[BLOCK_SIZE * 2 - 1] = 1;
	uint64_t offset = 0;
	uint32_t len = BLOCK_SIZE * 2;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(0, offset);
	TEST_ASSERT_EQUAL_UINT32(BLOCK_SIZE * 2, len);
}

static void test_find_zero_blocks_8K_tail_head(void)
{
	uint8_t buf[BLOCK_SIZE * 2] = {0};
		buf[BLOCK_SIZE - 1] = 1;
		buf[BLOCK_SIZE] = 1;
	uint64_t offset = 0;
	uint32_t len = BLOCK_SIZE * 2;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(0, offset);
	TEST_ASSERT_EQUAL_UINT32(BLOCK_SIZE * 2, len);
}

static void test_find_zero_blocks_12K_zero_zero_tail(void)
{
	uint8_t buf[BLOCK_SIZE * 3] = {0};
		buf[BLOCK_SIZE * 3 - 1] = 1;
	uint64_t offset = 0;
	uint32_t len = BLOCK_SIZE * 3;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(BLOCK_SIZE * 2, offset);
	TEST_ASSERT_EQUAL_UINT32(BLOCK_SIZE, len);
}

static void test_find_zero_blocks_12K_head_zero_zero(void)
{
	uint8_t buf[BLOCK_SIZE * 3] = {0};
		buf[0] = 1;
	uint64_t offset = 0;
	uint32_t len = BLOCK_SIZE * 3;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(0, offset);
	TEST_ASSERT_EQUAL_UINT32(BLOCK_SIZE, len);
}

static void test_find_zero_blocks_12K_zero_middle_zero(void)
{
	uint8_t buf[BLOCK_SIZE * 3] = {0};
		buf[BLOCK_SIZE + BLOCK_SIZE / 2] = 1;
	uint64_t offset = 0;
	uint32_t len = BLOCK_SIZE * 3;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(BLOCK_SIZE, offset);
	TEST_ASSERT_EQUAL_UINT32(BLOCK_SIZE, len);
}

static void test_find_zero_blocks_12K_head_zero_tail(void)
{
	uint8_t buf[BLOCK_SIZE * 3] = {0};
		buf[0] = 1;
		buf[BLOCK_SIZE * 3 - 1] = 1;
	uint64_t offset = 0;
	uint32_t len = BLOCK_SIZE * 3;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(0, offset);
	TEST_ASSERT_EQUAL_UINT32(BLOCK_SIZE * 3, len);
}

static void test_find_zero_blocks_20K_zero_zero_middle_zero_zero(void)
{
	uint8_t buf[BLOCK_SIZE * 5] = {0};
		buf[BLOCK_SIZE * 5 / 2] = 1;
	uint64_t offset = 0;
	uint32_t len = BLOCK_SIZE * 5;
	find_zero_blocks(buf, &offset, &len);
	TEST_ASSERT_EQUAL_UINT64(BLOCK_SIZE * 2, offset);
	TEST_ASSERT_EQUAL_UINT32(BLOCK_SIZE, len);
}

static int subtest_make_temporary_file(void)
{
	const static int flags = O_WRONLY | O_CREAT | O_SYNC | O_EXCL;

	char template[] = "/tmp/test_util.XXXXXX";
	const int fd = mkostemp(template, flags);
	TEST_ASSERT_TRUE(fd != -1);

	/* Deleting temporary file when close */
	TEST_ASSERT_EQUAL_INT(0, unlink(template));

	return fd;
}

static bool subtest_try_discard_head(int fd, uint64_t head)
{
	const static int mode = FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE;

	TEST_ASSERT_EQUAL(0, head % BLOCK_SIZE);

	if (head > 0) {
		TEST_ASSERT_EQUAL_INT(0, xfallocate(fd, mode, 0, head));
		return true;
	}

	return false;
}

static bool subtest_try_discard_tail(int fd, uint64_t head, uint32_t len,
				     size_t end)
{
	const static int mode = FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE;

	TEST_ASSERT_EQUAL(0, head % BLOCK_SIZE);

	const size_t tail = head + len;
	if (tail < end) {
		TEST_ASSERT_EQUAL(0, len % BLOCK_SIZE);

		const size_t block_end = roundup(end, BLOCK_SIZE);
		TEST_ASSERT_EQUAL_INT(0, block_end % BLOCK_SIZE);
		TEST_ASSERT_TRUE(end <= block_end);
		TEST_ASSERT_TRUE(end >= block_end - BLOCK_SIZE);
		TEST_ASSERT_EQUAL_INT(0, xfallocate(fd, mode, tail,
						    block_end - tail));
		return true;
	}

	return false;
}

static void test_make_sparse_file(void)
{
	const static size_t BUF_LEN = BLOCK_SIZE / 2 * 7;
	uint8_t buf[BLOCK_SIZE / 2 * 7] = {0};
                buf[BLOCK_SIZE] = 1;
	        buf[BLOCK_SIZE * 2 - 1] = 1;

	const int fd = subtest_make_temporary_file();

	struct stat s;

	TEST_ASSERT_EQUAL_INT(0, fstat(fd, &s));
	TEST_ASSERT_EQUAL(0, s.st_size);
	TEST_ASSERT_EQUAL(0, s.st_blocks);

	TEST_ASSERT_EQUAL(BUF_LEN, xwrite(fd, buf, BUF_LEN));

	TEST_ASSERT_EQUAL_INT(0, fstat(fd, &s));
	TEST_ASSERT_EQUAL(BUF_LEN, s.st_size);
	TEST_ASSERT_TRUE(BLOCK_SIZE <= s.st_blocks * 512);
	TEST_ASSERT_TRUE(s.st_size <= s.st_blocks * 512);
	TEST_ASSERT_TRUE(s.st_size >= s.st_blocks * 512 - BLOCK_SIZE);

	uint64_t head = 0;
	uint32_t len = BUF_LEN;
	find_zero_blocks(buf, &head, &len);
	TEST_ASSERT_EQUAL_UINT64(BLOCK_SIZE, head);
	TEST_ASSERT_EQUAL_UINT32(BLOCK_SIZE, len);
	TEST_ASSERT_TRUE(subtest_try_discard_head(fd, head));
	TEST_ASSERT_TRUE(subtest_try_discard_tail(fd, head, len, BUF_LEN));

	TEST_ASSERT_EQUAL_INT(0, fstat(fd, &s));
	TEST_ASSERT_EQUAL(BUF_LEN, s.st_size);
	TEST_ASSERT_EQUAL(BLOCK_SIZE, s.st_blocks * 512);

	uint8_t buf_actual[BLOCK_SIZE / 2 * 7] = {0};
	TEST_ASSERT_EQUAL_INT(0, lseek(fd, 0, SEEK_SET)); /* rewind */
	TEST_ASSERT_EQUAL(BUF_LEN, read(fd, buf_actual, BUF_LEN));
	TEST_ASSERT_EQUAL_INT(0, memcmp(buf, buf_actual, BUF_LEN));

	TEST_ASSERT_EQUAL(0, close(fd));
}

static void test_make_nonsparse_file(void)
{
	const static size_t BUF_LEN = BLOCK_SIZE / 2 * 7;
	uint8_t buf[BLOCK_SIZE / 2 * 7];
	memset(buf, 1, BUF_LEN);

	const int fd = subtest_make_temporary_file();

	struct stat s;

	TEST_ASSERT_EQUAL_INT(0, fstat(fd, &s));
	TEST_ASSERT_EQUAL(0, s.st_size);
	TEST_ASSERT_EQUAL(0, s.st_blocks);

	TEST_ASSERT_EQUAL(BUF_LEN, xwrite(fd, buf, BUF_LEN));

	TEST_ASSERT_EQUAL_INT(0, fstat(fd, &s));
	TEST_ASSERT_EQUAL(BUF_LEN, s.st_size);
	TEST_ASSERT_TRUE(BLOCK_SIZE <= s.st_blocks * 512);
	TEST_ASSERT_TRUE(s.st_size <= s.st_blocks * 512);
	TEST_ASSERT_TRUE(s.st_size >= s.st_blocks * 512 - BLOCK_SIZE);

	uint64_t head = 0;
	uint32_t len = BUF_LEN;
	find_zero_blocks(buf, &head, &len);
	TEST_ASSERT_EQUAL_UINT64(0, head);
	TEST_ASSERT_EQUAL_UINT32(BUF_LEN, len);
	TEST_ASSERT_FALSE(subtest_try_discard_head(fd, head));
	TEST_ASSERT_FALSE(subtest_try_discard_tail(fd, head, len, BUF_LEN));

	TEST_ASSERT_EQUAL_INT(0, fstat(fd, &s));
	TEST_ASSERT_EQUAL(BUF_LEN, s.st_size);
	TEST_ASSERT_TRUE(BLOCK_SIZE <= s.st_blocks * 512);
	TEST_ASSERT_TRUE(s.st_size <= s.st_blocks * 512);
	TEST_ASSERT_TRUE(s.st_size >= s.st_blocks * 512 - BLOCK_SIZE);

	uint8_t buf_actual[BLOCK_SIZE / 2 * 7] = {0};
	TEST_ASSERT_EQUAL_INT(0, lseek(fd, 0, SEEK_SET)); /* rewind */
	TEST_ASSERT_EQUAL(BUF_LEN, read(fd, buf_actual, BUF_LEN));
	TEST_ASSERT_EQUAL_INT(0, memcmp(buf, buf_actual, BUF_LEN));

	TEST_ASSERT_EQUAL(0, close(fd));
}

int main(int argc, char **argv)
{
	UNITY_BEGIN();
	RUN_TEST(test_block_size_equals_4K);
	RUN_TEST(test_find_zero_blocks_null);
	RUN_TEST(test_find_zero_blocks_1);
	RUN_TEST(test_find_zero_blocks_4095);
	RUN_TEST(test_find_zero_blocks_4K_zero);
	RUN_TEST(test_find_zero_blocks_4K_nonzero_at_head);
	RUN_TEST(test_find_zero_blocks_4K_nonzero_at_tail);
	RUN_TEST(test_find_zero_blocks_4K_nonzero_at_middle);
	RUN_TEST(test_find_zero_blocks_4097_zero_offset_0);
	RUN_TEST(test_find_zero_blocks_4097_zero_offset_1);
	RUN_TEST(test_find_zero_blocks_4097_zero_offset_2);
	RUN_TEST(test_find_zero_blocks_4097_nonzero_at_0);
	RUN_TEST(test_find_zero_blocks_4097_nonzero_at_4096);
	RUN_TEST(test_find_zero_blocks_8K_zero_zero);
	RUN_TEST(test_find_zero_blocks_8K_zero_head);
	RUN_TEST(test_find_zero_blocks_8K_zero_tail);
	RUN_TEST(test_find_zero_blocks_8K_head_zero);
	RUN_TEST(test_find_zero_blocks_8K_tail_zero);
	RUN_TEST(test_find_zero_blocks_8K_head_tail);
	RUN_TEST(test_find_zero_blocks_8K_tail_head);
	RUN_TEST(test_find_zero_blocks_12K_zero_zero_tail);
	RUN_TEST(test_find_zero_blocks_12K_head_zero_zero);
	RUN_TEST(test_find_zero_blocks_12K_zero_middle_zero);
	RUN_TEST(test_find_zero_blocks_12K_head_zero_tail);
	RUN_TEST(test_find_zero_blocks_20K_zero_zero_middle_zero_zero);
	RUN_TEST(test_make_sparse_file);
	RUN_TEST(test_make_nonsparse_file);
	return UNITY_END();
}
