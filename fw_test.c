
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "in.ipscrompd.h"

/* Simple test program for fw_add_ip().           */
/* Link with whichever fw_XXX.c you wish to test. */

int main(int argc, char *argv[])
{
  int rc;
  struct in_addr addr;

  if (argc != 3)
  {
    fprintf(stderr, "Usage: %s <ip> <user>\n", progname(argv[0]));
    return 1;
  }

  if (inet_aton(argv[1], &addr) == 0)
  {
    printf("%s is not a valid IP\n", argv[1]);
  }
  else if ((rc = fw_add_ip(addr, argv[2])) >= 0)
  {
    printf("%s added successfully. Limited to %d hours\n", argv[1], rc);
  }
  else
  {
    printf("Error adding '%s': %d (%s)\n", argv[1], rc, strerror(-rc));
  }

  return 0;
}
