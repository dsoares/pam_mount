#include <stdlib.h>
#include <check.h>
#include <string.h>
#include <dotconf.h>
#include <optlist.h>
#include <pam_mount.h>
#include <pam_mount_private.h>

gboolean debug;
config_t config;

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

        fail_unless(!static_string_valid(NULL, 2),
	            "static_string_valid test failed");

	str[0] = 'a'; str[1] = 'a';
        fail_unless(!static_string_valid(str, 2),
	            "static_string_valid test failed");

	str[0] = 'a'; str[1] = '\0';
        fail_unless(static_string_valid(str, 2),
	            "static_string_valid test failed");
}
END_TEST 

START_TEST(test_read_volume)
{
	/* This is a little ugly because read_volume is a callback -- it
	 * is not meant to be called directly like this.
	 */

	int ctx = 1;
	char *some_user = "some_user";
	char *fs_key_cipher = "fs_key_cipher";
	char *fs_key_path = "fs_key_path";
	char *server = "server";
	char *volume = "volume";
	char *mountpoint = "mountpoint";
	char *options = "foo,bar=baz";

	char str[MAX_PAR + 1];

	/* argument 1 (some_user) must match user in config_t. */
	/* argument 2 (local) must be a valid volume type. */
	char *volume_config[] = { some_user, "local", server, volume, mountpoint,
			   options, fs_key_cipher, fs_key_path };
	struct configoption option = {
		"name",
		0,
		0,
		(void *) &config,
		0
	};
	struct command cmd = {
		"name",
		&option,
		{ 0, NULL, volume_config },
		8,
		NULL,
		(void *) &ctx
	};

	config.user = some_user;
	config.volume = NULL;
	config.volcount = 0;

	fail_unless(read_volume(&cmd, (context_t *) &ctx) == NULL,
		    "test_read_volume test failed");
	fail_unless(config.volume[0].type == LCLMOUNT,
		    "test_read_volume test failed");
	fail_unless(config.volume[0].globalconf == 1,
		    "test_read_volume test failed");
	fail_unless(strcmp(config.volume[0].fs_key_cipher, fs_key_cipher) == 0,
		    "test_read_volume test failed");
	fail_unless(strcmp(config.volume[0].fs_key_path, fs_key_path) == 0,
		    "test_read_volume test failed");
	fail_unless(strcmp(config.volume[0].server, server) == 0,
		    "test_read_volume test failed");
	fail_unless(strcmp(config.volume[0].user, some_user) == 0,
		    "test_read_volume test failed");
	fail_unless(strcmp(config.volume[0].volume, volume) == 0,
		    "test_read_volume test failed");
	fail_unless(strcmp(config.volume[0].mountpoint, mountpoint) == 0,
		    "test_read_volume test failed");
	fail_unless(strcmp(optlist_to_str(str, config.volume[0].options),
	options) == 0, "test_read_volume test failed");
} END_TEST

static Suite *misc_suite(void)
{
	Suite *s = suite_create("misc_suite");

	TCase *tc_exists = tcase_create("test_exits");
	TCase *tc_owns = tcase_create("test_owns");
	TCase *tc_str_to_long = tcase_create("test_str_to_long");
	TCase *tc_static_string_valid = 
	       tcase_create("test_static_string_valid");
	TCase *tc_read_volume =
	       tcase_create("test_read_volume");

	tcase_add_test(tc_exists, test_exists);
	tcase_add_test(tc_owns, test_owns);
	tcase_add_test(tc_str_to_long, test_str_to_long);
	tcase_add_test(tc_static_string_valid, test_static_string_valid);
	tcase_add_test(tc_read_volume, test_read_volume);

	suite_add_tcase(s, tc_exists);
	suite_add_tcase(s, tc_owns);
	suite_add_tcase(s, tc_str_to_long);
	suite_add_tcase(s, tc_static_string_valid);
	suite_add_tcase(s, tc_read_volume);

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
