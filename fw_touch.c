#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "in.ipscrompd.h"

#ifndef FW_DIRECTORY
#error You must define FW_DIRECTORY for fw_touch.c
#endif

/* Helper function to make IP address safe for use as filename */
/* Replaces : with _ for IPv6 addresses */
static char *ip_to_filename(char *ip_str)
{
	char *result, *p;

	if (ip_str == NULL) {
		return NULL;
	}

	result = strdup(ip_str);
	if (result == NULL) {
		return NULL;
	}

	/* Replace colons with underscores for IPv6 */
	for (p = result; *p != '\0'; p++) {
		if (*p == ':') {
			*p = '_';
		}
	}

	return result;
}


// this routine creates a file in FW_DIRECTORY/<ip addr>
// and then runs the firewall reload script...
//
int fw_add_ip(struct sockaddr_storage *addr, socklen_t addrlen, char *user)
{
	FILE *fp;
	struct stat st;
	char path[1024], cmd[1024];
	char need_fw=0;
	char *ip_str, *filename_str;

	ip_str = sockaddr_to_string(addr, addrlen);
	if (ip_str == NULL) {
		syslog(LOG_ERR, "Unable to convert address to string");
		return -EINVAL;
	}

	filename_str = ip_to_filename(ip_str);
	if (filename_str == NULL) {
		syslog(LOG_ERR, "Unable to create filename for IP");
		free(ip_str);
		return -ENOMEM;
	}

	snprintf(path, sizeof(path), "%s/%s", FW_DIRECTORY, filename_str);

	// if IP has already been auth'd, simply touch the spool file but
	// don't invoke dynfw again...
	if (stat(path, &st) == -1) {
		need_fw = 1;
	}

	// first create the ipaddr file in /var/spool/ipscromp...
	//
	if ((fp = fopen(path, "w")) == NULL) {
		syslog(LOG_ERR, "Unable to open '%s': %m", path);
		free(filename_str);
		free(ip_str);
		return -errno;
	}

	fprintf(fp, "%s\n", user);
	fclose(fp);

	if (need_fw) {
		snprintf(cmd, sizeof(cmd), "/usr/local/sbin/ipscromp_dynfw open %s > /dev/null 2>&1", ip_str);
		system(cmd);
	}

	free(filename_str);
	free(ip_str);

	// system("/etc/rc.d/rc.fw > /dev/null 2> /dev/null");

	return 0;
}
