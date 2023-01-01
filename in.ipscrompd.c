
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "in.ipscrompd.h"
#include "common.h"

#if defined(__svr4__) && defined(__sun__) && !defined(LOG_AUTHPRIV)
#define LOG_AUTHPRIV LOG_AUTH
#endif

#ifndef PASS_FILE
#define PASS_FILE "/usr/local/etc/ipscromp_pass"
#endif

#define MIN_PROTOCOL_VERSION	1
#define MAX_PROTOCOL_VERSION	2

/* These come from errorcode in in.ipscrompd.h. */
char *errormsgs[] =
{
  "",                                                  /* ERROR_NOERROR      */
  "ERROR - Protocol error.\n",                         /* ERROR_PROTOCOL     */
  "ERROR - Protocol too old. Update your binary.\n",   /* ERROR_OLD_PROTOCOL */
  "ERROR - Protocol not supported by server\n",        /* ERROR_NEW_PROTOCOL */
  "ERROR - Refusing to add IP address\n",              /* ERROR_IP_INVALID   */
  "ERROR - Invalid credentials.\n",                    /* ERROR_CREDENTIALS  */
  "ERROR - Couldn't amend rules, an error occurred\n", /* ERROR_AMENDING     */
};

#define PERMIT_OK		"OK - Firewall opened for '%s'."
#define PERMIT_OK_TIMED		"OK - %s permitted for at least %d hours."

#define ANNOYANCE_PAUSE 10

int addable_ip(struct in_addr addr)
{
  int rc = 1;
  unsigned long ip = htonl(addr.s_addr);

  if (ip == INADDR_LOOPBACK
      || IN_MULTICAST(ip))
  {
    rc = 0;
  }

  return rc;
}

void alarm_handler(int junk)
{
  syslog(LOG_NOTICE, "Timed out reading data");
  exit(1);
}

void usage(char *progpath)
{
  printf("Usage: %s [-d]\n"
         "    -d     : enable debug messages\n"
         "\n", progname(progpath)
        );
}

int main(int argc, char *argv[])
{
  int opt, rc, proto_version_num, auth_rc;
  char *command, *response, *user, *proto_version;
  pid_t pid = getpid();
  struct sockaddr_in sa;
  socklen_t sa_size = sizeof(sa);
  authrequest authreq;

  /* Note srandom(), not srand() */
  srandom((int)time(NULL) ^ (pid + (pid <<15)));

  while ((opt = getopt(argc, argv, "d")) != EOF)
  {
    switch(opt)
    {
      case 'd':
        debug++;
        break;

      default:
        fprintf(stderr, "INTERNAL ERRROR: Untrapped getopt() char '%c'\n", opt);
    }
  }

  if (optind != argc)
  {
    usage(argv[0]);
    return 1;
  }

  openlog(progname(argv[0]), LOG_PID, LOG_AUTHPRIV);

  signal(SIGALRM, alarm_handler);
  /* Cant be less than ANNOYANCE_PAUSE or stuff will break */
  alarm(ANNOYANCE_PAUSE + 5);

  if (!isatty(STDIN_FILENO))
  {
    debug_to_syslog = 1;
  }

  if (getpeername(STDIN_FILENO, (struct sockaddr *)&sa, &sa_size) < 0
      && (!debug || !isatty(STDIN_FILENO)) )
  {
    /* This closes the connection silently. I don't think thats a problem */
    /* given that getpeername() should never fail, but is fundamental.    */
    syslog(LOG_ERR, "getpeername() failed: %m\n");
    return 1;
  }

  syslog(LOG_NOTICE, "Connect from %s\n", inet_ntoa(sa.sin_addr));

  response = recv_sock(STDIN_FILENO);

  /* strtok() inserts NULLs into a string, so we make a safe copy */
  if (response != NULL && (command = strdup(response)) != NULL)
  {
    command       = strtok(command, " ");
    user          = strtok(NULL,    " ");
    proto_version = strtok(NULL,    " ");
  }

  /* Check for protocol sanity */
  if (   response == NULL
      || command == NULL
      || user == NULL
      || proto_version == NULL
      || (proto_version_num = atoi(proto_version)) <= 0
      || strcmp(command, "USER"))
  {
    if (response == NULL)
    {
      response = "(null)";
    }

    syslog(LOG_ERR, "Received invalid USER string '%s'", response);
    send_sock(STDOUT_FILENO, errormsgs[ERROR_PROTOCOL]);
    return 1;
  }

  /*
   * Populate the authrequest struct that gets passed to
   * the auth_proto routines
   */
  authreq.user              = user;
  authreq.proto_version_num = proto_version_num;
  authreq.ip_to_add         = sa.sin_addr;

  switch (proto_version_num)
  {
    case 0:
      send_sock(STDOUT_FILENO, errormsgs[ERROR_OLD_PROTOCOL]);
      auth_rc = ERROR_OLD_PROTOCOL;
      break;
    /* Note that we ignore MIN_PROTOCOL_VERSION with this code level */
    case 1:
    case 2:
      auth_rc = auth_proto_v2(&authreq);
      break;
    default:
      send_sock(STDOUT_FILENO, errormsgs[ERROR_NEW_PROTOCOL],
                               MAX_PROTOCOL_VERSION);
      auth_rc = ERROR_NEW_PROTOCOL;
      break;
  }

  if (auth_rc != ERROR_NOERROR)
  {
    /* Authentication failed */
    syslog(LOG_ERR, "Authentication failed for user '%s' using protocol %d",
                    user, proto_version_num);

    if (auth_rc == ERROR_CREDENTIALS)
    {
      sleep(ANNOYANCE_PAUSE);
    }
    send_sock(STDOUT_FILENO, errormsgs[auth_rc]);
    return 1;
  }

  /* Check we can add this IP. Refuse to add 127.0.0.1 and some others */
  if (!addable_ip(authreq.ip_to_add))
  {
    syslog(LOG_ERR, "Refusing to add IP '%s' for user '%s'",
                    inet_ntoa(authreq.ip_to_add), user);
    send_sock(STDOUT_FILENO,
              errormsgs[ERROR_IP_INVALID], inet_ntoa(authreq.ip_to_add));
    return 1;
  }

  if((rc = fw_add_ip(authreq.ip_to_add, authreq.user)) < 0)
  {
    syslog(LOG_ERR, "User '%s' successfully authed but couldn't amend rules. "
                    "IP was '%s', rc was %d (%s)\n", user,
                    inet_ntoa(authreq.ip_to_add), rc, strerror(-rc));
    send_sock(STDOUT_FILENO, errormsgs[ERROR_AMENDING]);
  }
  else 
  {
    syslog(LOG_NOTICE, "User '%s' opened firewall for %s.\n",
           user, inet_ntoa(authreq.ip_to_add));

    if (rc == 0)
    {
      send_sock(STDOUT_FILENO, PERMIT_OK, inet_ntoa(authreq.ip_to_add));
    }
    else
    {
      send_sock(STDOUT_FILENO, PERMIT_OK_TIMED, inet_ntoa(authreq.ip_to_add), rc);
    }
  }

  return 0;
}
