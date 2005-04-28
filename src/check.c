#include <stdlib.h>
#include <check.h>
#include <string.h>

#include <pam_mount.h>

gboolean debug;

START_TEST(test_exists)
{
	fail_unless(exists("/etc/passwd") == 1, "exists test failed");
	fail_unless(exists("/etc/NOSUCHFILE") == 0, "exists test failed");
}
END_TEST 

START_TEST(test_owns)
{
	fail_unless(owns("root", "/etc/passwd") == 1, "owns test failed");
	fail_unless(owns("mike", "/etc/passwd") == 0, "owns test failed");
}
END_TEST 

START_TEST(test_str_to_long)
{
	fail_unless(str_to_long("123456789") == 123456789, 
	            "str_to_long test failed");
	fail_unless(str_to_long("0") == 0, "str_to_long test failed");
	fail_unless(str_to_long("-1") == -1, "str_to_long test failed");
	fail_unless(str_to_long("NULL") == LONG_MAX, "str_to_long test failed");
	fail_unless(str_to_long("a") == LONG_MAX, "str_to_long test failed");
}
END_TEST 

START_TEST(test_static_string_valid)
{
	char str[2];

	fail_unless(static_string_valid(NULL, 2) == FALSE, 
	            "static_string_valid test failed");

	str[0] = 'a'; str[1] = 'a';
	fail_unless(static_string_valid(str, 2) == FALSE,
	            "static_string_valid test failed");

	str[0] = 'a'; str[1] = 0x00;
	fail_unless(static_string_valid(str, 2) == TRUE,
	            "static_string_valid test failed");
}
END_TEST 

static Suite *misc_suite(void)
{
	Suite *s = suite_create("misc_suite");

	TCase *tc_exists = tcase_create("test_exits");
	TCase *tc_owns = tcase_create("test_owns");
	TCase *tc_str_to_long = tcase_create("test_str_to_long");
	TCase *tc_static_string_valid = 
	       tcase_create("test_static_string_valid");

	tcase_add_test(tc_exists, test_exists);
	tcase_add_test(tc_owns, test_owns);
	tcase_add_test(tc_str_to_long, test_str_to_long);
	tcase_add_test(tc_static_string_valid, test_static_string_valid);

	suite_add_tcase(s, tc_exists);
	suite_add_tcase(s, tc_owns);
	suite_add_tcase(s, tc_str_to_long);
	suite_add_tcase(s, tc_static_string_valid);

	return s;
}

int main(void)
{
	int nf;
	Suite *s = misc_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	nf = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
