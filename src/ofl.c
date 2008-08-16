/*
 *	Show processes using directories/files/mountpoints
 *	written by Jan Engelhardt, 2008
 *	Released in the Public Domain.
 */
#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libHX.h>
#include "pam_mount.h"
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

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

	if (isdigit(*str)) {
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
	bool ret = false;

	if (HX_getopt(options_table, &argc, &argv, HXOPT_USAGEONERR) < 0)
		return EXIT_FAILURE + 1;
	if (argc == 1) {
		fprintf(stderr, "You need to supply at least a path\n");
		return EXIT_FAILURE + 1;
	}

	if (signum_str != NULL)
		signum = parse_signal(signum_str);
	while (*++argv != NULL)
		ret |= ofl(*argv, signum);
	return ret ? EXIT_SUCCESS : EXIT_FAILURE;
}
