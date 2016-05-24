#include <fcntl.h>	/* open */
#include <stdbool.h>
#include <stdio.h>	/* tmpnam */
#include <string.h>	/* memset */
#include <sys/stat.h>	/* stat */
#include <unistd.h>	/* access */

#include <unity.h>
#include <cmock.h>

#include "Mocklogger.h"
#include "util.h"
#include "common.h"

int sd_log_level = SDOG_INFO;

#define BUF_LEN (BLOCK_SIZE / 2 * 7)
static char buf[BUF_LEN];
static char obj_path[L_tmpnam];
static char tmp_path[L_tmpnam + 4];
static int tmp_fd;

void setUp(void)
{
	memset(buf, 0, BUF_LEN);
	buf[BLOCK_SIZE] = 1;
	buf[BLOCK_SIZE * 2 - 1] = 1;

	strcpy(obj_path, "");
	strcpy(tmp_path, "");
	tmp_fd = -1;

	if(!tmpnam(obj_path))
		return;

	sprintf(tmp_path, "%s.tmp", obj_path);
}

void tearDown(void)
{
	if(strlen(obj_path) > 0)
		unlink(obj_path);

	if(strlen(tmp_path) > 0)
		unlink(tmp_path);

	if(tmp_fd != -1)
		close(tmp_fd);
}

static void subtest_try_unlink(const char *pathname)
{
	TEST_ASSERT_TRUE(strlen(pathname) > 0);

	const int r = unlink(pathname);
	const int e = errno;
	TEST_ASSERT_TRUE(r == 0 || e == ENOENT);
}

static int subtest_open(const char *pathname, int flags, mode_t mode)
{
	TEST_ASSERT_TRUE(strlen(pathname) > 0);

	const int fd = open(pathname, flags, mode);
	TEST_ASSERT_FALSE(fd < 0);
	return fd;
}

static void subtest_object_content(void)
{
	const int fd = subtest_open(obj_path, O_RDONLY, 0);

	char buf_actual[BUF_LEN] = {0};
	TEST_ASSERT_EQUAL(BUF_LEN, read(fd, buf_actual, BUF_LEN));
	TEST_ASSERT_EQUAL_INT(0, memcmp(buf, buf_actual, BUF_LEN));

	TEST_ASSERT_EQUAL_INT(0, close(fd));
}

static void test_atomic_create_and_write_nonexist(void)
{
	subtest_try_unlink(tmp_path);

	TEST_ASSERT_EQUAL_INT(0, atomic_create_and_write(obj_path, buf, BUF_LEN, false, false));
	TEST_ASSERT_EQUAL_INT(0, access(obj_path, F_OK));
	TEST_ASSERT_EQUAL_INT(-1, access(tmp_path, F_OK));

	struct stat s;
	TEST_ASSERT_EQUAL_INT(0, stat(obj_path, &s));
	TEST_ASSERT_EQUAL(BUF_LEN, s.st_size);
	TEST_ASSERT_TRUE(BLOCK_SIZE <= s.st_blocks * 512);
	TEST_ASSERT_TRUE(s.st_size <= s.st_blocks * 512);
	TEST_ASSERT_TRUE(s.st_size >= s.st_blocks * 512 - BLOCK_SIZE);

	subtest_object_content();
}

static void test_atomic_create_and_write_nonforce(void)
{
	subtest_try_unlink(tmp_path);

	tmp_fd = subtest_open(tmp_path, O_WRONLY | O_CREAT | O_SYNC | O_EXCL, S_IRWXU);
	TEST_ASSERT_EQUAL_INT(-1, atomic_create_and_write(obj_path, buf, BUF_LEN, false, false));
	TEST_ASSERT_EQUAL_INT(-1, access(obj_path, F_OK));
	TEST_ASSERT_EQUAL_INT(0, access(tmp_path, F_OK));
}

static void test_atomic_create_and_write_force(void)
{
	subtest_try_unlink(tmp_path);

	tmp_fd = subtest_open(tmp_path, O_WRONLY | O_CREAT | O_SYNC | O_EXCL, S_IRWXU);
	TEST_ASSERT_EQUAL_INT(0, atomic_create_and_write(obj_path, buf, BUF_LEN, true, false));
	TEST_ASSERT_EQUAL_INT(0, access(obj_path, F_OK));
	TEST_ASSERT_EQUAL_INT(-1, access(tmp_path, F_OK));

	struct stat s;
	TEST_ASSERT_EQUAL_INT(0, stat(obj_path, &s));
	TEST_ASSERT_EQUAL(BUF_LEN, s.st_size);
	TEST_ASSERT_TRUE(BLOCK_SIZE <= s.st_blocks * 512);
	TEST_ASSERT_TRUE(s.st_size <= s.st_blocks * 512);
	TEST_ASSERT_TRUE(s.st_size >= s.st_blocks * 512 - BLOCK_SIZE);

	subtest_object_content();
}

static void test_atomic_create_and_write_sparse(void)
{
	subtest_try_unlink(tmp_path);

	TEST_ASSERT_EQUAL_INT(0, atomic_create_and_write(obj_path, buf, BUF_LEN, false, true));
	TEST_ASSERT_EQUAL_INT(0, access(obj_path, F_OK));
	TEST_ASSERT_EQUAL_INT(-1, access(tmp_path, F_OK));

	struct stat s;
	TEST_ASSERT_EQUAL_INT(0, stat(obj_path, &s));
	TEST_ASSERT_EQUAL(BUF_LEN, s.st_size);
	TEST_ASSERT_EQUAL(BLOCK_SIZE, s.st_blocks * 512);

	subtest_object_content();
}

int main(int argc, char **argv)
{
	UNITY_BEGIN();
	RUN_TEST(test_atomic_create_and_write_nonexist);
	RUN_TEST(test_atomic_create_and_write_nonforce);
	RUN_TEST(test_atomic_create_and_write_force);
	RUN_TEST(test_atomic_create_and_write_sparse);
	return UNITY_END();
}
