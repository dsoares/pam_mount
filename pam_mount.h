#include <sys/types.h>
#include <sys/stat.h>

#define CONFIGFILE	"/etc/security/pam_mount.conf"

#define MAX_PAR		127
#include <stdio.h>

#define SMBMOUNT	0
#define NCPMOUNT	1
#define UMOUNT		2
#define PMHELPER	3
#define LCLMOUNT	4
#define LSOF		5
#define COMMAND_MAX	LSOF+1

#define DEBUG_DEFAULT	0
#define GETPASS_DEFAULT	0

typedef struct pm_data {
	int unmount;
	int debug;
	int type;
	char server[MAX_PAR+1];
	char user[MAX_PAR+1];
	char password[MAX_PAR+1];
	char volume[MAX_PAR+1];
	char options[MAX_PAR+1];
	char mountpoint[FILENAME_MAX+1];
	char command[FILENAME_MAX+1];
	char ucommand[FILENAME_MAX+1];
	char lsof[FILENAME_MAX+1];
} pm_data;

int readconfig(const char *user, const char *password, 
	       char *command[], int* volcount, pm_data **data);

/* WARNING: exists is 3-state */
int exists(const char *file);

int owns(const char *user, const char *file);

void log(const char *mask, const char *arg);
void w4rn(const char *mask, const char *arg);

void debugsleep(int sec);
