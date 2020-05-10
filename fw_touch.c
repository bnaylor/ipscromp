#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "in.ipscrompd.h"

#ifndef FW_DIRECTORY
#error You must define FW_DIRECTORY for fw_touch.c
#endif


// this routine creates a file in FW_DIRECTORY/<ip addr>
// and then runs the firewall reload script...
//
int fw_add_ip(struct in_addr ip, char *user)
{ 
	FILE *fp;
	char path[512];
  
	sprintf(path, "%s/%s", FW_DIRECTORY, inet_ntoa(ip));

	// first create the ipaddr file in /var/spool/ipscromp...
	//
	if ((fp = fopen(path, "w")) == NULL) { 
		syslog(LOG_ERR, "Unable to open '%s': %m", path); 
		return -errno; 
	}
  
	fprintf(fp, "%s\n", user); 
	fclose(fp); 

	system("/etc/rc.fw > /dev/null 2> /dev/null");
  
	return 0;
}
