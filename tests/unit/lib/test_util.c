#include <stdint.h>
#include <stdlib.h>
#include <unity.h>
#include <cmock.h>

#include "util.h"
#include "Mocklogger.h"

/* is_numeric */

static void test_is_numeric_returns_true_if_valid_octet(void)
{
	TEST_ASSERT_TRUE(is_numeric("01"));
	TEST_ASSERT_TRUE(is_numeric("07"));
	TEST_ASSERT_TRUE(is_numeric("010"));
	TEST_ASSERT_TRUE(is_numeric("0644"));
}

static void test_is_numeric_returns_true_if_invalid_octet(void)
{
	TEST_ASSERT_TRUE(is_numeric("08"));
	TEST_ASSERT_TRUE(is_numeric("09"));
}

static void test_is_numeric_returns_true_if_decimal(void)
{
	TEST_ASSERT_TRUE(is_numeric("0"));
	TEST_ASSERT_TRUE(is_numeric("1"));
	TEST_ASSERT_TRUE(is_numeric("9"));
	TEST_ASSERT_TRUE(is_numeric("1234567890"));
}

static void test_is_numeric_returns_false_if_non_digit_contained(void)
{
	TEST_ASSERT_FALSE(is_numeric("-1")); // negative integer
	TEST_ASSERT_FALSE(is_numeric("0b0")); // binary
	TEST_ASSERT_FALSE(is_numeric("0x0")); // hexadecimal
	TEST_ASSERT_FALSE(is_numeric("cafebabe")); // hexadecimal
	TEST_ASSERT_FALSE(is_numeric(" 0")); // whitespace contained
}

/* str_to_u32 */

static void assert_str_to_u32(uint32_t expected, const char *nptr)
{
	errno = 0;
	const uint32_t actual = str_to_u32(nptr);
	const int err = errno;
	TEST_ASSERT_EQUAL_INT(0, err);
	TEST_ASSERT_EQUAL_UINT32(expected, actual);
}

#define assert_str_to_u32_success(n) assert_str_to_u32(n, #n)

static void assert_str_to_u32_error(int expected, const char *nptr)
{
	errno = 0;
	str_to_u32(nptr);
	const int actual = errno;
	TEST_ASSERT_EQUAL_INT(expected, actual);
}

static void assert_str_to_u32_ERANGE(const char *nptr)
{
	assert_str_to_u32_error(ERANGE, nptr);
}

static void assert_str_to_u32_EINVAL(const char *nptr)
{
	assert_str_to_u32_error(EINVAL, nptr);
}

static void test_str_to_u32_success(void)
{
	assert_str_to_u32_success(0);
	assert_str_to_u32_success(1);
	assert_str_to_u32_success(2);
	/* INT16_MAX {-1/+0/+1} */
	assert_str_to_u32_success(32766);
	assert_str_to_u32_success(32767);
	assert_str_to_u32_success(32768);
	/* UINT16_MAX {-1/+0/+1} */
	assert_str_to_u32_success(65534);
	assert_str_to_u32_success(65535);
	assert_str_to_u32_success(65536);
	/* INT32_MAX {-1/+0/+1} */
	assert_str_to_u32_success(2147483646);
	assert_str_to_u32_success(2147483647);
	assert_str_to_u32_success(2147483648);
	/* UINT32_MAX {-1/+0} */
	assert_str_to_u32_success(4294967294);
	assert_str_to_u32_success(4294967295);
}

static void test_str_to_u32_ERANGE(void)
{
	/* UINT32_MAX +1 */
	assert_str_to_u32_ERANGE("4294967296");
	/* INT64_MAX {-1/+0/+1} */
	assert_str_to_u32_ERANGE("9223372036854775806");
	assert_str_to_u32_ERANGE("9223372036854775807");
	assert_str_to_u32_ERANGE("9223372036854775808");
	/* UINT64_MAX {-1/+0/+1} */
	assert_str_to_u32_ERANGE("18446744073709551614");
	assert_str_to_u32_ERANGE("18446744073709551615");
	assert_str_to_u32_ERANGE("18446744073709551616");
	/* INT64_MIN {-1/+0/+1} */
	assert_str_to_u32_ERANGE("-9223372036854775809");
	assert_str_to_u32_ERANGE("-9223372036854775808");
	assert_str_to_u32_ERANGE("-9223372036854775807");
	/* INT32_MIN {-1/+0/+1} */
	assert_str_to_u32_ERANGE("-2147483649");
	assert_str_to_u32_ERANGE("-2147483648");
	assert_str_to_u32_ERANGE("-2147483647");
	/* INT16_MIN {-1/+0/+1} */
	assert_str_to_u32_ERANGE("-32769");
	assert_str_to_u32_ERANGE("-32768");
	assert_str_to_u32_ERANGE("-32767");

	assert_str_to_u32_ERANGE("-2");
	assert_str_to_u32_ERANGE("-1");
}

static void test_str_to_u32_EINVAL(void)
{
	assert_str_to_u32_EINVAL("");
	assert_str_to_u32_EINVAL(" ");
	assert_str_to_u32_EINVAL("+");
	assert_str_to_u32_EINVAL("-");
	assert_str_to_u32_EINVAL("a");
	assert_str_to_u32_EINVAL("42a");
}

/* str_to_u16 */

static void assert_str_to_u16(uint16_t expected, const char *nptr)
{
	errno = 0;
	const uint16_t actual = str_to_u16(nptr);
	const int err = errno;
	TEST_ASSERT_EQUAL_INT(0, err);
	TEST_ASSERT_EQUAL_UINT16(expected, actual);
}

#define assert_str_to_u16_success(n) assert_str_to_u16(n, #n)

static void assert_str_to_u16_error(int expected, const char *nptr)
{
	errno = 0;
	str_to_u16(nptr);
	const int actual = errno;
	TEST_ASSERT_EQUAL_INT(expected, actual);
}

static void assert_str_to_u16_ERANGE(const char *nptr)
{
	assert_str_to_u16_error(ERANGE, nptr);
}

static void assert_str_to_u16_EINVAL(const char *nptr)
{
	assert_str_to_u16_error(EINVAL, nptr);
}

static void test_str_to_u16_success(void)
{
	assert_str_to_u16_success(0);
	assert_str_to_u16_success(1);
	assert_str_to_u16_success(2);
	/* INT16_MAX {-1/+0/+1} */
	assert_str_to_u16_success(32766);
	assert_str_to_u16_success(32767);
	assert_str_to_u16_success(32768);
	/* UINT16_MAX {-1/+0} */
	assert_str_to_u16_success(65534);
	assert_str_to_u16_success(65535);
}

static void test_str_to_u16_ERANGE(void)
{
	/* UINT16_MAX +1 */
	assert_str_to_u16_ERANGE("65536");
	/* INT32_MAX {-1/+0/+1} */
	assert_str_to_u16_ERANGE("2147483646");
	assert_str_to_u16_ERANGE("2147483647");
	assert_str_to_u16_ERANGE("2147483648");
	/* UINT32_MAX {-1/+0} */
	assert_str_to_u16_ERANGE("4294967294");
	assert_str_to_u16_ERANGE("4294967295");
	assert_str_to_u16_ERANGE("4294967296");
	/* INT64_MAX {-1/+0/+1} */
	assert_str_to_u16_ERANGE("9223372036854775806");
	assert_str_to_u16_ERANGE("9223372036854775807");
	assert_str_to_u16_ERANGE("9223372036854775808");
	/* UINT64_MAX {-1/+0/+1} */
	assert_str_to_u16_ERANGE("18446744073709551614");
	assert_str_to_u16_ERANGE("18446744073709551615");
	assert_str_to_u16_ERANGE("18446744073709551616");
	/* INT64_MIN {-1/+0/+1} */
	assert_str_to_u16_ERANGE("-9223372036854775809");
	assert_str_to_u16_ERANGE("-9223372036854775808");
	assert_str_to_u16_ERANGE("-9223372036854775807");
	/* INT32_MIN {-1/+0/+1} */
	assert_str_to_u16_ERANGE("-2147483649");
	assert_str_to_u16_ERANGE("-2147483648");
	assert_str_to_u16_ERANGE("-2147483647");
	/* INT16_MIN {-1/+0/+1} */
	assert_str_to_u16_ERANGE("-32769");
	assert_str_to_u16_ERANGE("-32768");
	assert_str_to_u16_ERANGE("-32767");

	assert_str_to_u16_ERANGE("-2");
	assert_str_to_u16_ERANGE("-1");
}

static void test_str_to_u16_EINVAL(void)
{
	assert_str_to_u16_EINVAL("");
	assert_str_to_u16_EINVAL(" ");
	assert_str_to_u16_EINVAL("+");
	assert_str_to_u16_EINVAL("-");
	assert_str_to_u16_EINVAL("a");
	assert_str_to_u16_EINVAL("42a");
}

int main(int argc, char **argv)
{
	UNITY_BEGIN();
	RUN_TEST(test_is_numeric_returns_true_if_valid_octet);
	RUN_TEST(test_is_numeric_returns_true_if_invalid_octet);
	RUN_TEST(test_is_numeric_returns_true_if_decimal);
	RUN_TEST(test_is_numeric_returns_false_if_non_digit_contained);
	RUN_TEST(test_str_to_u32_success);
	RUN_TEST(test_str_to_u32_ERANGE);
	RUN_TEST(test_str_to_u32_EINVAL);
	RUN_TEST(test_str_to_u16_success);
	RUN_TEST(test_str_to_u16_ERANGE);
	RUN_TEST(test_str_to_u16_EINVAL);
	return UNITY_END();
}
