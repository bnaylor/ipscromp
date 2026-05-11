#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <syslog.h>
#include <stdlib.h>

/*
 * RETIRED in 3.0. The gatekeeper expired authenticated IPs by checking
 * spool file mtimes and calling ipscromp_dynfw close. nftables set element
 * timeouts now handle expiry natively in the kernel. This file is kept for
 * reference and for use with the iptables backend (ipscromp_dynfw.iptables).
 */

#define REPO "/var/spool/ipscromp"

int main(int argc, char **argv) 
{
	DIR           *dir  = NULL;
	struct dirent *dirp = NULL;
	struct stat    statbuf;
	char           fqfname[300], dynfw[512], uid[256];
	time_t         oldest;
	struct timeval tv;


	if (argc != 2) {
		printf("usage: %s <minutes>\n", argv[0]);
		return 0;
	}


	gettimeofday(&tv, NULL);
	oldest = tv.tv_sec - (atoi(argv[1]) * 60);

	dir = opendir(REPO);
	if (!dir) {
		printf("ERROR: can't open directory %s\n", REPO);
		return 0;
	}


	openlog("ipscromp", LOG_CONS|LOG_PID, LOG_DAEMON);

	while ((dirp = readdir(dir)) != NULL) {
		if ((strcmp(dirp->d_name, ".") == 0) ||
		     strcmp(dirp->d_name, "..") == 0)
			continue;

		sprintf(fqfname, "%s/%s", REPO, dirp->d_name);

		if (lstat(fqfname, &statbuf) < 0)
			continue;

		if (statbuf.st_mtime < oldest) {
			FILE *fp = fopen(fqfname, "r");
			if (fp) {
				memset(uid, 0x0, sizeof(uid));
				fgets(uid, sizeof(uid)-1, fp);
				uid[strlen(uid)-1] = 0;
				fclose(fp);
			}
			else {
				strcpy(uid, "unknown");
			}

			printf("EXPIRING: %s (%s) \n", dirp->d_name, uid);
			syslog(LOG_NOTICE, "Expiring: %s (%s)\n", dirp->d_name, uid);
			unlink(fqfname);

			sprintf(dynfw, "/usr/local/sbin/ipscromp_dynfw close %s > /dev/null 2>&1", dirp->d_name);
			system(dynfw);
		}
	}

	closedir(dir);
	closelog();

	return 0;
}




