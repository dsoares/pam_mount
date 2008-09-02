#ifdef __linux__
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <libHX/defs.h>
#include <linux/loop.h>
#include "pam_mount.h"

/**
 * loop_file_name -
 * @filename:	block device to query
 * @i:		pointer to result storage
 *
 * Run the LOOP_GET_STATUS64 ioctl on @filename and store the result in @i.
 * Returns the underlying file of the loop device, or @filename if @filename
 * does not seem to be a loop device at all.
 */
const char *loop_file_name(const char *filename, struct loop_info64 *i)
{
#ifdef HAVE_STRUCT_LOOP_INFO64_LO_FILE_NAME
	int fd;
	if ((fd = open(filename, O_RDONLY)) < 0)
		return filename;

	if (ioctl(fd, LOOP_GET_STATUS64, i) != 0) {
		close(fd);
		return filename;
	}
	close(fd);
	return signed_cast(char *, i->lo_file_name);
#else
	return NULL;
#endif
}

#endif /* __linux__ */
