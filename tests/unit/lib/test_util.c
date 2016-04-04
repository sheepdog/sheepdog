#include <stdlib.h>
#include <unity.h>
#include <cmock.h>

#include "util.h"
#include "Mocklogger.h"

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

int main(int argc, char **argv)
{
	UNITY_BEGIN();
	RUN_TEST(test_is_numeric_returns_true_if_valid_octet);
	RUN_TEST(test_is_numeric_returns_true_if_invalid_octet);
	RUN_TEST(test_is_numeric_returns_true_if_decimal);
	RUN_TEST(test_is_numeric_returns_false_if_non_digit_contained);
	return UNITY_END();
}
