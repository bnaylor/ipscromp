#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>

#include "common.h"
#include "in.ipscrompd.h"

int fw_add_ip(struct sockaddr_storage *addr, socklen_t addrlen, char *user)
{
	char cmd[256];
	char *ip_str;

	ip_str = sockaddr_to_string(addr);
	if (ip_str == NULL) {
		syslog(LOG_ERR, "Unable to convert address to string");
		return -EINVAL;
	}

	snprintf(cmd, sizeof(cmd),
	         "/usr/local/sbin/ipscromp_dynfw open %s > /dev/null 2>&1",
	         ip_str);
	system(cmd);

	free(ip_str);
	return 0;
}
