#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


int main(int argc, const char *argv[]) {
  const char *name = argv[1];
  printf(">>> %s\n", name);
  union {
    struct sockaddr addr;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
  } ipaddr;

  struct addrinfo hint, *res;
  memset(&hint, 0, sizeof(hint));
  hint.ai_family = AF_UNSPEC;
  hint.ai_socktype = SOCK_STREAM;
  hint.ai_protocol = IPPROTO_TCP;

  for (int i = 0; i < 1000; ++i) {
    getaddrinfo(name, NULL, &hint, &res);
    char ipstr[INET6_ADDRSTRLEN];
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
      if (ai->ai_family == AF_INET) {
        ipaddr.addr4 = *(struct sockaddr_in *)ai->ai_addr;
        ipaddr.addr4.sin_port = 80;
        inet_ntop(AF_INET, &ipaddr.addr4.sin_addr, ipstr, sizeof(ipstr));

      } else if (ai->ai_family == AF_INET6) {
        ipaddr.addr6 = *(struct sockaddr_in6 *)ai->ai_addr;
        ipaddr.addr6.sin6_port = 80;
        inet_ntop(AF_INET6, &ipaddr.addr6.sin6_addr, ipstr, sizeof(ipstr));

      } else {
        continue;
      }

      printf("found: %s\n", ipstr);
      break;
    }
  }
  
  return 0;
}


