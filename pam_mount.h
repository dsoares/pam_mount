#include <sys/types.h>
#include <sys/stat.h>

#define CONFIGFILE	"/etc/pam_mount.conf"

#define MAX_PAR		127
#include <stdio.h>

#define SMBMOUNT	0
#define NCPMOUNT	1
#define UMOUNT		2
#define PMHELPER	3
#define COMMAND_MAX	PMHELPER+1

#define DEBUG_DEFAULT	0

typedef struct pm_data {
	int unmount;
	int debug;
	int type;
	char server[MAX_PAR+1];
	char user[MAX_PAR+1];
	char password[MAX_PAR+1];
	char volume[MAX_PAR+1];
	char mountpoint[FILENAME_MAX+1];
	char command[FILENAME_MAX+1];
	char ucommand[FILENAME_MAX+1];
} pm_data;

int readconfig(const char *user, const char *password, 
	       char *command[], int* volcount, pm_data **data);

int owns(const char *user, const char *file);

void w4rn(const char *mask, const char *arg);

void debugsleep(int sec);
