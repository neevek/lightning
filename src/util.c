#include "util.h"
#include <uv.h>
#include "log/log.h"

void log_ipv4_and_port(void *ipv4, int port, const char *msg) {
  char data[INET_ADDRSTRLEN];
  uv_inet_ntop(AF_INET, ipv4, data, INET_ADDRSTRLEN);
  LOG_V("%s: %s:%d", msg, data, port);
}

void log_ipv6_and_port(void *ipv6, int port, const char *msg) {
  char data[INET6_ADDRSTRLEN];
  uv_inet_ntop(AF_INET6, ipv6, data, INET6_ADDRSTRLEN);
  LOG_V("%s: [%s]:%d", msg, data, port);
}
