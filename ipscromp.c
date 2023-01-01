
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdarg.h>
#include <termios.h>
#include <netdb.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"

#define DEFAULT_HOST "labrat.lexington.ibm.com"
#define DEFAULT_PORT 2002
#define DEFAULT_SERVICE "ipscromp"

char *ip_string(char *data)
{
	struct hostent *he;

	if (inet_aton(data, NULL) == 1) {
		return data;
	}

	if ((he = gethostbyname(data)) == NULL) {
		return NULL;
	}
	return strdup(inet_ntoa(*(struct in_addr *)he->h_addr));
}


int connect_host(char *host, int port)
{
	int fd;
	struct protoent *proto;
	struct hostent *he;
	struct sockaddr_in s;

	memset(&s, 0, sizeof(s));

	if (inet_aton(host, &s.sin_addr) != 0) {
		/* Do nothing */
	}
	else if ((he = gethostbyname(host)) != NULL) {
		memcpy(&s.sin_addr, he->h_addr, he->h_length);
	}
	else {
		fprintf(stderr, "Unable to determine address of '%s'\n", host);
		return -1;
	}

	if ((proto = getprotobyname("tcp")) == NULL) {
		fprintf(stderr, "getprotobyname(\"tcp\") failed!\n");
		return -2;
	}

	if ((fd = socket(PF_INET, SOCK_STREAM, proto->p_proto)) < 0) {
		perror("socket()");
		return -3;
	}

	s.sin_family = PF_INET;
	s.sin_port = htons(port);

	if (debug > 1) {
		dbg("connect_host() connecting to %s:%d\n",
				inet_ntoa(s.sin_addr),
				ntohs(s.sin_port));
	}

	if (connect(fd, (struct sockaddr *)&s, sizeof(s)) < 0) {
		perror("connect()");
		close(fd);
		return -4;
	}

	return fd;
}


int find_port(char *host, char *default_service, int default_port)
{
	struct servent *se;
	int port = -1;
	char *preferred = NULL;

	if (host != NULL && (preferred = rindex(host, ':')) != NULL) {
		*preferred = '\0';
		preferred++;
	}

	if (preferred != NULL && (se = getservbyname(preferred, "tcp")) != NULL) {
		port = ntohs(se->s_port);
	}
	else if (preferred != NULL && (port = atoi(preferred)) > 0) {
		/* Do nothing */
	}
	else if (   default_service != NULL
		&& (se = getservbyname(default_service, "tcp")) != NULL) {
		port = ntohs(se->s_port);
	}
	else {
		port = default_port;
	}
	return port;
}


int set_echo(int enable)
{
	struct termios t;

	if (tcgetattr(fileno(stdin), &t) < 0) {
		perror("tcgetattr()");
		return -1;
	}

	if (enable) {
		t.c_lflag |= ECHO;
	} else {
		t.c_lflag &= (~ECHO);
	}

	if (tcsetattr(fileno(stdin), TCSANOW, &t) < 0) {
		perror("tcsetattr()");
		return -1;
	}

	return 0;
}


void usage(char *progpath)
{
	printf("Usage: %s [options] [[<user>@]host[:<port>]] [..]\n"
	       "  Options:\n"
	       "    -1     : switch to version 1 (MD5) protocol\n"
	       "    -d     : enable debug messages\n"
	       "    -l user: specify user name if different from current\n"
	       "    -p pass: specify passphrase\n"
	       "    -i ip  : specity alternate hostname or IP to open\n"
	       "\n",
	       progname(progpath));
}


int connect_ipscrompd(char *host, char *dflt_user, char *password,
                      int version, char *alt_ip)
{
	char *challenge, *response,
	     *auth_str,  *at_symbol, *user = dflt_user;

	int port, auth_len, fd;

	if ((at_symbol = index(host, '@')) != NULL) {
		user = malloc(at_symbol - host + 1);
		if (user == NULL) {
			fprintf(stderr, "Unable to malloc() space for user string.\n");
			return 1;
		}

		strncpy(user, host, at_symbol - host);
		user[at_symbol - host] = '\0';
		host = at_symbol + 1;
	}

#ifdef __CYGWIN__
	if (user == NULL) {
		user = cuserid(NULL);
	}
#endif
	if (user == NULL) {
		fprintf(stderr, "Cannot determine username; please use -l\n");
		if (user != dflt_user) free(user);
		return 2;
	}

	port = find_port(host, DEFAULT_SERVICE, DEFAULT_PORT);

	dbg("Connecting to %s:%d\n", host, port);

	if ((fd = connect_host(host, port)) < 0) {
		if (user != dflt_user) free(user);
		return 1;
	}

	send_sock(fd, "USER %s %d\n", user, version);

	response = recv_sock(fd);

	if (response == NULL) {
		printf("Server closed connection instead of responding\n");
		if (user != dflt_user) free(user);
		close(fd);
		return 1;
	}

	if (strncmp(response, "AUTH ", 5) != 0) {
		printf("Server responded incorrectly: '%s'\n", response);
		if (user != dflt_user) free(user);
		close(fd);
		return 1;
	}

	challenge = &response[5];

	auth_len = strlen(user) + strlen(challenge) + strlen(password) + 3;
	if (alt_ip != NULL) {
		auth_len += strlen(alt_ip) + 1;
	}

	if ((auth_str = malloc(auth_len)) == NULL) {
		fprintf(stderr, "Unable to malloc() space for auth string.\n");
		if (user != dflt_user) free(user);
		close(fd);
		return 1;
	}

	if (alt_ip == NULL) {
		snprintf(auth_str, auth_len, "%s:%s:%s", user, challenge, password);
	}
	else {
		snprintf(auth_str, auth_len, "%s:%s:%s:%s", user, alt_ip, challenge, password);
	}

	if (debug > 1) {
		dbg("Auth string is: '%s'\n", auth_str);
	}

	if (alt_ip == NULL) {
		send_sock(fd, "PERMIT %s\n", hash(version, auth_str));
	}
	else {
		send_sock(fd, "IPERMIT %s %s\n", alt_ip, hash(version, auth_str));
	}

	response = recv_sock(fd);
	close(fd);

	if (user != dflt_user) free(user);

	if (strncmp(response, "OK ", 3) != 0) {
		printf("Server reports an error: '%s'\n", response);
		return 1;
	}

	printf("%s\n", response);
	return 0;
}


int main(int argc, char *argv[])
{
	int opt, version = 2, rc;
	char *user = getlogin(),
	     *pass = NULL,
	     *alt_ip = NULL, *tmp;

	while ((opt = getopt(argc, argv, "1dh:i:l:p:u:")) != EOF) {
		switch(opt) {
			case '1': version = 1;
				  break;

			case 'd': debug++;
				  break;

			case 'i': alt_ip = optarg;
				  break;

			case 'l': user = optarg;
				  break;

			case 'p': pass = optarg;
				  break;

			case '?': usage(argv[0]);
				  return 1;
				  break;

			default: fprintf(stderr, "INTERNAL ERRROR: Untrapped getopt() char '%c'\n", opt);
		}
	}

	if (alt_ip != NULL && version < 2) {
		fprintf(stderr, "WARNING: Alternative IP unsupported with old protocol\n");
	}

	if (alt_ip != NULL) {
		tmp = ip_string(alt_ip);
		if (tmp == NULL) {
			fprintf(stderr, "Cannot resolve '%s' to an IP address\n", alt_ip);
			exit(1);
		}
		alt_ip = tmp;
	}

	if (!pass) {
		if (set_echo(0) < 0) {
			return 3;
		}

		pass = ask_user("Your password: ");
		printf("\n");

		/* Do we really care if this fails? What can we do? */
		set_echo(1);
	}

	rc = 0;

	if (argc - optind == 0) {
		rc += connect_ipscrompd(DEFAULT_HOST, user, pass, version, alt_ip);
	}
	else {
		for (; optind < argc; optind++) {
			rc += connect_ipscrompd(argv[optind], user, pass, version, alt_ip);
		}
	}
	return rc;
}

