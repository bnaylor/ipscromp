
/*
 * Authentication module for ipscromp protocols 1 & 2
 *
 * Originally extracted from in.ipscrompd.c by ian@sackheads.org
 * Further work and tidying by cheesy
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "in.ipscrompd.h"

/* Must easily fit in BUFFSIZE from common.h */
/* Increased from 30 because the IP is no longer part of the hash */
#define CHALLENGE_LENGTH 40

#define PASS_BUFFSIZE 127

#ifndef PASS_FILE
#define PASS_FILE "/usr/local/etc/ipscromp_pass"
#endif

char *pass_for(char *user)
{ 
	FILE *passfile; 
	char *pass = NULL, buffer[PASS_BUFFSIZE];
  
	if ((passfile = fopen(PASS_FILE, "r")) == NULL) { 
		syslog(LOG_ERR, "Couldn't open password file file '%s': %m", PASS_FILE); 
		return NULL; 
	}
  
	while(pass == NULL && !feof(passfile)) {
		char *colon;
		if (fgets(buffer, PASS_BUFFSIZE, passfile) != NULL
		   && (colon = strchr(buffer, ':')) != NULL) {
			*colon = '\0';
			if (strcmp(buffer, user) == 0) {
				chomp(colon + 1);
				pass = strdup(colon + 1);
			}
		}
	} 

	fclose(passfile); 
	return pass;
}

errorcode auth_proto_v2(authrequest *req)
{ 
	int auth_len; 
	char challenge[CHALLENGE_LENGTH + 1], 
	     *response, *command, *user_hash = NULL, 
	     *alt_ip = NULL, *pass, *auth_str;
  
	/* Send AUTH challenge */ 
	random_string(challenge, CHALLENGE_LENGTH + 1); 
	send_sock(STDOUT_FILENO, "AUTH %s\n", challenge);
  
	response = recv_sock(STDIN_FILENO); 
	command  = strtok(response, " ");
  
	if (strcmp(command, "PERMIT") == 0) { 
		user_hash = strtok(NULL, " "); 
	} 
	else if (strcmp(command, "IPERMIT") == 0) { 
		alt_ip    = strtok(NULL, " "); 
		user_hash = strtok(NULL, " "); 
	} 
	else { 
		syslog(LOG_ERR, "Expecting PERMIT or IPERMIT, got '%s'", response); 
		return ERROR_PROTOCOL; 
	}
  
	/* Check for protocol sanity */ 
	if (user_hash == NULL || 
	   (strcmp(command, "IPERMIT") == 0 && alt_ip == NULL)) { 
		syslog(LOG_ERR, "Invalid PERMIT/IPERMIT. Received '%s'", response); 
		return ERROR_PROTOCOL; 
	}
  
	/* Get password for this user */ 
	pass = pass_for(req->user); 
	if (pass == NULL) { 
		syslog(LOG_ERR, "No pass found for user '%s'", req->user); 
		return ERROR_CREDENTIALS; 
	}
  
	auth_len = strlen(req->user) + strlen(challenge) + strlen(pass) + 3;
	if (alt_ip != NULL) {
		if (string_to_sockaddr(alt_ip, &req->ip_to_add, &req->ip_to_add_len) < 0) {
			syslog(LOG_ERR, "Invalid IP specified with IPERMIT, got '%s'", response);
			return ERROR_IP_INVALID;
		}
		auth_len += strlen(alt_ip) + 1;
	}
  
	if ((auth_str = malloc(auth_len)) == NULL) { 
		syslog(LOG_ERR, "malloc() failed for auth string (user = %s)!", req->user); 
		return ERROR_AMENDING; 
	}
 
	if (alt_ip == NULL) { 
        	/* PERMIT */	
		snprintf(auth_str, auth_len, "%s:%s:%s", req->user, challenge, pass); 
	} 
	else {
		/* IPERMIT */ 
		snprintf(auth_str, auth_len, "%s:%s:%s:%s", req->user, alt_ip, challenge, pass); 
	} 
	
	if (strcmp(user_hash, hash(req->proto_version_num, auth_str)) != 0) { 
		syslog(LOG_ERR, "User '%s' failed hashed authentication.", req->user); 
		return ERROR_CREDENTIALS; 
	}
  
	free(auth_str); 
	return 0;
}
