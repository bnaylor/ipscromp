
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdarg.h>
#include <syslog.h>

#ifdef USE_MD
#include <md5.h>
#include <sha.h>

#define MD5_Init   MD5Init
#define MD5_Update MD5Update
#define MD5_Final  MD5Final

#define SHA1_Init   SHAInit
#define SHA1_Update SHAUpdate
#define SHA1_Final  SHAFinal

#define MD5_DIGEST_LENGTH MD5_HASHBYTES
#define SHA_DIGEST_LENGTH SHA_HASHBYTES

#else
#include <openssl/md5.h>
#include <openssl/sha.h>
#endif

#include "common.h"

int debug = 0;
int debug_to_syslog = 0;

#define BUFFSIZE 256

/* This used to be needed on older versions of cygwin */
#if 0
#warning Defining snprintf() to sprintf() for Cygnus. This has security implications.
#define snprintf(str, n, fmt, args...) sprintf(str, fmt, ## args)
#define vsnprintf(str, n, fmt, args...) vsprintf(str, fmt, ## args)
#endif

void random_string(char *buffer, size_t bufflen)
{ 
	char *buffptr = buffer + bufflen - 1; 
	*buffptr = '\0';
  
	while(--buffptr >= buffer) { 
		/* Random character code lifted from salt generation stuff   */ 
		/* Using random because of historical problems with low bits */ 
		/* in rand()                                                 */ 
		*buffptr = (char) (random() & 077);
    
		*buffptr += 46;                   /* . character */ 
		if (*buffptr > 57) *buffptr += 7; /* 9 character */ 
		if (*buffptr > 90) *buffptr += 6; /* Z character */ 
	}
}



/* Not really /common/ but all this sorta junk is going in common.c */
char *ask_user(char *question)
{ 
	char buffer[BUFFSIZE]; 
	char *result = NULL;
  
	printf(question); 
	fflush(stdout);
  
	if (fgets(buffer, BUFFSIZE, stdin) != NULL) { 
		chomp(buffer); 
		result = strdup(buffer); 
	}
  
	return result;
}


char *recv_sock(int fd)
{ 
	int nread; 
	char buffer[BUFFSIZE]; 

	memset(&buffer, 0, BUFFSIZE);
  
	if ((nread = read(fd, &buffer, BUFFSIZE - 1)) < 0) { 
		perror("read()"); 
		return NULL; 
	}
  
	if (nread == 0) { 
		syslog(LOG_INFO, "read(): EOF on socket.\n"); 
		return NULL; 
	}
  
	chomp(buffer);
  
	dbg("Received: '%s'\n", buffer);
  
	return strdup(buffer);
}


void send_sock(int fd, char *fmt, ...)
{ 
	char buffer[BUFFSIZE]; 
	va_list args;
  
	va_start(args, fmt); 
	vsnprintf(buffer, BUFFSIZE, fmt, args); 
	va_end(args);
  
	dbg("Sending '%s'\n", buffer);
  
	write(fd, buffer, strlen(buffer));
}


void chomp(char *string)
{ 
	char *c;
  
	if ((c = index(string, '\n')) != NULL) { 
		*c = '\0'; 
	}
  
	if ((c = index(string, '\r')) != NULL) { 
		*c = '\0'; 
	}
}


int do_sha(char *string, unsigned char **digest)
{ 
	SHA_CTX context;
  
	if ((*digest = (unsigned char *) malloc(SHA_DIGEST_LENGTH)) == NULL) { 
		return 0; 
	}
  
	SHA1_Init(&context); 
	SHA1_Update(&context, string, strlen(string)); 
	SHA1_Final(*digest, &context);
  
	return SHA_DIGEST_LENGTH;
}


int do_md5(char *string, unsigned char **digest)
{ 
	MD5_CTX context;
  
	if ((*digest = (unsigned char *) malloc(MD5_DIGEST_LENGTH)) == NULL) { 
		return 0; 
	}
  
	MD5_Init(&context); 
	MD5_Update(&context, string, strlen(string)); 
	MD5_Final(*digest, &context);
  
	return MD5_DIGEST_LENGTH;
}


char *hash(int version, char *fmt, ...)
{ 
	char *result, *tmp, string[BUFFSIZE]; 
	unsigned char *hash; 
	int         i, hashsize = 0; 
	va_list args;
  
	va_start(args, fmt); 
	vsnprintf(string, BUFFSIZE, fmt, args); 
	va_end(args);
  
	switch (version) { 
		case 1: hashsize = do_md5(string, &hash); 
			break;
    
		case 2: hashsize = do_sha(string, &hash); 
			break; 
	}
  
	if (hashsize == 0 || (result = (char *)malloc(hashsize * 2 + 1)) == NULL) { 
		return NULL; 
	}
  
	tmp = result;
  
	for(i = 0; i < hashsize; i++) { 
		snprintf(tmp, 3, "%02x", hash[i]); 
		tmp += 2; 
	}
  
	*tmp = '\0';
  
	return result;
}


char *progname(char *progpath)
{ 
	char *progname = rindex(progpath, '/');
  
	if (progname == NULL) { 
		progname = progpath; 
	} 
	else { 
		progname++; 
	} 
	
	return progname;
}

void dbg(char *fmt, ...)
{ 
	va_list args; 
	
	if (debug) { 
		char buffer[BUFFSIZE]; 
		
		memset(buffer, 0, BUFFSIZE); 
		strcat(buffer, "DEBUG: "); 
		va_start(args, fmt); 
		vsnprintf(buffer, BUFFSIZE, fmt, args); 
		va_end(args);
    
		if (debug_to_syslog) { 
			syslog(LOG_DEBUG, buffer); 
		}
		else { 
			printf(buffer); 
		} 
	}
}



