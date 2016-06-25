#ifndef UTIL_H_
#define UTIL_H_

#include <stdlib.h>
#include <netdb.h>

#define container_of(ptr, type, field) \
  ((type *) ((char *) (ptr) - ((char *) &((type *) 0)->field)))

#define CHECK(exp) \
do { \
  if (!(exp)) { \
    fprintf(stderr, "Error occured on [%s:%d] %s()\n", __FILE__, \
        __LINE__, __FUNCTION__); \
    exit(1); \
  } \
} while (0)

void log_ipv4_and_port(void *ipv4, int port, const char *msg);
void log_ipv6_and_port(void *ipv6, int port, const char *msg);
int fill_ipaddr(struct sockaddr *addr, int port,  char *ipstr, 
    int ipstr_len, struct addrinfo *ai);
void copy_ipv4_addr(uint32_t *intip, const char *ip);
int is_ipv4_addr_any(const char *ip);
int is_ipv4_addr_local(const char *ip);
int is_ipv6_addr_any(const char *ip);
int is_ipv6_addr_local(const char *ip);
int do_setuid(const char *user);
void redirect_stderr_to_file(const char *log_file);

#endif /* end of include guard: UTIL_H_ */
