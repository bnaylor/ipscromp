
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
	struct sockaddr_storage ss;
	socklen_t sslen;

	if (string_to_sockaddr(data, &ss, &sslen) < 0) {
		return NULL;
	}

	return sockaddr_to_string(&ss, sslen);
}


int connect_host(char *host, int port)
{
	int fd;
	struct addrinfo hints, *res, *rp;
	char port_str[16];
	int rc;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;

	snprintf(port_str, sizeof(port_str), "%d", port);

	rc = getaddrinfo(host, port_str, &hints, &res);
	if (rc != 0) {
		fprintf(stderr, "Unable to determine address of '%s': %s\n",
				host, gai_strerror(rc));
		return -1;
	}

	/* Try each address until we successfully connect */
	for (rp = res; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0) {
			continue;
		}

		if (debug > 1) {
			struct sockaddr_storage ss;
			memcpy(&ss, rp->ai_addr, rp->ai_addrlen);
			char *addr_str = sockaddr_to_string(&ss, rp->ai_addrlen);
			dbg("connect_host() trying %s:%d\n", addr_str ? addr_str : "unknown", port);
			free(addr_str);
		}

		if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
			/* Success */
			freeaddrinfo(res);
			return fd;
		}

		close(fd);
	}

	/* All connection attempts failed */
	freeaddrinfo(res);
	perror("connect()");
	return -4;
}


int find_port(char *host, char *default_service, int default_port)
{
	struct servent *se;
	int port = -1;
	char *preferred = NULL;

	if (host != NULL && (preferred = strrchr(host, ':')) != NULL) {
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

	if ((at_symbol = strchr(host, '@')) != NULL) {
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
		char *envpass = getenv("IPSCROMP_PASS");
		if (envpass != NULL) {
			pass = envpass;
		} else {
			if (set_echo(0) < 0) {
				return 3;
			}

			pass = ask_user("Your password: ");
			printf("\n");

			/* Do we really care if this fails? What can we do? */
			set_echo(1);
		}
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

