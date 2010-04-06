/*
 *	Show processes using directories/files/mountpoints
 *	written by Jan Engelhardt, 2008
 *	Released in the Public Domain.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libHX/ctype_helper.h>
#include <libHX/defs.h>
#include <libHX/option.h>
#include "pam_mount.h"

static unsigned int parse_signal(const char *str)
{
	static const char *signames[] = {
		[SIGHUP] = "HUP",	[SIGINT] = "INT",
		[SIGQUIT] = "QUIT",	[SIGKILL] = "KILL",
		[SIGTERM] = "TERM",	[SIGALRM] = "ALRM",
		[SIGPIPE] = "PIPE",
	};
	unsigned int ret;
	char *end;

	if (HX_isdigit(*str)) {
		ret = strtoul(str, &end, 10);
		if (*end == '\0')
			return ret;
	}

	for (ret = 0; ret < ARRAY_SIZE(signames); ++ret)
		if (signames[ret] != NULL && strcmp(str, signames[ret]) == 0)
			return ret;
	return 0;
}

int main(int argc, const char **argv)
{
	unsigned int signum = 0;
	char *signum_str = NULL;
	struct HXoption options_table[] = {
		{.sh = 'k', .type = HXTYPE_STRING, .ptr = &signum_str,
		 .help = "Signal to send (if any)", .htyp = "NUM/NAME"},
		HXOPT_AUTOHELP,
		HXOPT_TABLEEND,
	};
	int ret;

	ret = HX_init();
	if (ret <= 0)
		fprintf(stderr, "HX_init: %s\n", strerror(errno));
	if (HX_getopt(options_table, &argc, &argv, HXOPT_USAGEONERR) < 0)
		return EXIT_FAILURE + 1;
	if (argc == 1) {
		fprintf(stderr, "You need to supply at least a path\n");
		return EXIT_FAILURE + 1;
	}

	if (signum_str != NULL)
		signum = parse_signal(signum_str);
	ret = false;
	while (*++argv != NULL)
		ret |= ofl(*argv, signum);
	HX_exit();
	return ret ? EXIT_SUCCESS : EXIT_FAILURE;
}
