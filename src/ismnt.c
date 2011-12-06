/*
 *	Internal diagnostic tool to debug pmt mtab.c
 *	Copyright © Jan Engelhardt, 2009
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libHX/init.h>
#include "pam_mount.h"

int main(int argc, const char **argv)
{
	int ret;

	ret = HX_init();
	if (ret <= 0) {
		fprintf(stderr, "HX_init: %s\n", strerror(errno));
		abort();
	}

	if (argc < 3) {
		fprintf(stderr, "Usage: %s dev mountpoint\n", *argv);
		return EXIT_FAILURE;
	}

	ret = pmt_cmtab_mounted(argv[1], argv[2]);
	if (ret < 0) {
		fprintf(stderr, "%s\n", strerror(-ret));
		ret = 2;
	} else if (ret == 0) {
		printf("Not mounted\n");
		ret = EXIT_FAILURE;
	} else {
		printf("Mounted\n");
		ret = EXIT_SUCCESS;
	}
	HX_exit();
	return ret;
}
