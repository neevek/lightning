#ifndef DEFS_H_
#define DEFS_H_
#include <uv.h>

#define SESSION_DATA_BUFSIZ 2048

struct Socks5Ctx;

typedef enum {
  S5_METHOD_IDENTIFICATION,
  S5_REQUEST,
  S5_STREAMING,
  S5_STREAMING_END,
} SessionState;

typedef struct {
  uv_tcp_t *client_tcp;
  uv_write_t client_write_req;
  char client_buf[SESSION_DATA_BUFSIZ];

  uv_tcp_t *upstream_tcp;
  uv_write_t upstream_write_req;
  uv_getaddrinfo_t upstream_addrinfo_req;
  uv_connect_t upstream_connect_req;
  char upstream_buf[SESSION_DATA_BUFSIZ]; 
  int upstream_tcp_valid;

  SessionState state;
  Socks5Ctx s5_ctx;
} Session;


#endif /* end of include guard: DEFS_H_ */
