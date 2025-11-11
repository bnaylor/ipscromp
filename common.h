
#include <sys/socket.h>
#include <netinet/in.h>

extern int debug;
extern int debug_to_syslog;

extern void chomp(char *string);
extern char *hash(int version, char *fmt, ...);
extern char *recv_sock(int fd);
extern void send_sock(int fd, char *fmt, ...);
extern char *ask_user(char *question);
extern char *progname(char *progpath);
extern void random_string(char *buffer, size_t bufflen);
extern void dbg(char *fmt, ...);

/* New dual-stack helper functions */
extern char *sockaddr_to_string(struct sockaddr_storage *ss, socklen_t sslen);
extern int string_to_sockaddr(const char *str, struct sockaddr_storage *ss, socklen_t *sslen);

