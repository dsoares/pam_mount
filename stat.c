#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <pwd.h>
#include <sys/types.h>

main() {
	struct stat foo;
	struct passwd *passwd_ent;

	errno = 0;
	printf("Trying ~: %d\t", stat("~", &foo));
	printf("[%s]\n", strerror(errno));

	passwd_ent = getpwuid(getuid());
	errno = 0;	
	fprintf(stderr, "Trying %s: %d\t", passwd_ent->pw_dir,
		stat(passwd_ent->pw_dir, &foo));
	printf("[%s]\n", strerror(errno));
}
