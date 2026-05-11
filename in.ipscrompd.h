
#include <netinet/in.h>
#include <sys/socket.h>

typedef enum
{
	ERROR_NOERROR,
	ERROR_PROTOCOL,
	ERROR_OLD_PROTOCOL,
	ERROR_NEW_PROTOCOL,
	ERROR_IP_INVALID,
	ERROR_CREDENTIALS,
	ERROR_AMENDING
} errorcode;

typedef struct
{
  char *user;
  int  proto_version_num;
  struct sockaddr_storage ip_to_add;
  socklen_t ip_to_add_len;
} authrequest;

errorcode auth_proto_v2(authrequest *req);

/*
 * Return code:
 * <0 : Error occurred, this is -errno
 *  0 : Firewall updated, no limit.
 * >0 : Firewall updated, limit in hours
 */
int fw_add_ip(struct sockaddr_storage *addr, socklen_t addrlen, char *user);
