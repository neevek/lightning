#include <stdio.h>
#include <uv.h>
#include <sys/socket.h>
#include "log/log.h"
#include "util.h"
#include "alloc.h"

#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT 9002
#define SERVER_BACKLOG 256
#define CONNECTION_BUF_SIZE 4096

static uv_loop_t *g_loop;

typedef struct {
  const char *host;
  int port;
  int backlog;
} ServerCfg;

typedef struct {
  uv_tcp_t server_tcp;
} ServerCtx;

typedef struct {
  uv_getaddrinfo_t addrinfo_req;
  ServerCfg server_cfg;
  ServerCtx server_ctx;
} ServerState;

typedef struct {
  uv_tcp_t client_tcp;
  char buf[CONNECTION_BUF_SIZE];
} Connection;

static void start_server(const char *host, int port, int backlog);
static void do_bind_and_listen(uv_getaddrinfo_t* req, int status, struct addrinfo* res);
static void on_conn_new(uv_stream_t *server, int status);
static void on_conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void on_conn_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);

int main(int argc, const char *argv[]) {
  start_server(SERVER_HOST, SERVER_PORT, SERVER_BACKLOG);
  return 0;
}

void start_server(const char *host, int port, int backlog) {
  g_loop = uv_default_loop();

  ServerState server_state;
  server_state.server_cfg.host = host;
  server_state.server_cfg.port = port;
  server_state.server_cfg.backlog = backlog;

  struct addrinfo hint;
  memset(&hint, 0, sizeof(hint));
  hint.ai_family = AF_UNSPEC;
  hint.ai_socktype = SOCK_STREAM;
  hint.ai_protocol = IPPROTO_TCP;

  CHECK(uv_getaddrinfo(g_loop, 
                           &server_state.addrinfo_req, 
                           do_bind_and_listen, 
                           host, 
                           NULL, 
                           &hint) == 0);

  uv_run(g_loop, UV_RUN_DEFAULT);
  uv_loop_delete(g_loop);
}

void do_bind_and_listen(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
  ServerState *state = container_of(req, ServerState, addrinfo_req);
  if (status < 0) {
    LOG_E("getaddrinfo(\"%s\"): %s", state->server_cfg.host, uv_strerror(status));
    uv_freeaddrinfo(res);
    return;
  }

  // abort if failing to init uv_tcp_t
  CHECK(uv_tcp_init(g_loop, &state->server_ctx.server_tcp) == 0);

  union {
    struct sockaddr addr;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
  } ipaddr;

  char ipstr[INET6_ADDRSTRLEN];

  for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
    if (ai->ai_family == AF_INET) {
      ipaddr.addr4 = *(struct sockaddr_in *)ai->ai_addr;
      ipaddr.addr4.sin_port = htons(state->server_cfg.port);
      uv_inet_ntop(ipaddr.addr.sa_family, &ipaddr.addr4.sin_addr, ipstr, sizeof(ipstr));

    } else if (ai->ai_family == AF_INET6) {
      ipaddr.addr6 = *(struct sockaddr_in6 *)ai->ai_addr;
      ipaddr.addr6.sin6_port = htons(state->server_cfg.port);
      uv_inet_ntop(ipaddr.addr.sa_family, &ipaddr.addr6.sin6_addr, ipstr, sizeof(ipstr));

    } else {
      LOG_W("unexpected ai_family: %d", ai->ai_family);
      continue;
    }

    int err;
    if ((err = uv_tcp_bind(&state->server_ctx.server_tcp, &ipaddr.addr, 0)) != 0) {
      LOG_W("uv_tcp_bind on [%s]:%d failed: %s", 
          ipstr, state->server_cfg.port, uv_strerror(err));
      continue;
    }

    if ((err = uv_listen((uv_stream_t *)&state->server_ctx.server_tcp, 
          state->server_cfg.backlog, 
          on_conn_new)) != 0) {
      LOG_W("uv_tcp_listen on [%s]:%d failed: %s", 
          ipstr, state->server_cfg.port, uv_strerror(err));
      continue;
    }
    
    LOG_I("server listening on [%s]:%d.", ipstr, state->server_cfg.port);
    uv_freeaddrinfo(res);
    return;
  }

  LOG_E("failed to bind on port: %d", state->server_cfg.port);
  exit(1);
} 

void on_conn_new(uv_stream_t *server, int status) {
  ServerCtx *server_ctx = container_of(server, ServerCtx, server_tcp);

  Connection *conn = lmalloc(sizeof(Connection));

  int err;
  if ((err = uv_tcp_init(g_loop, &conn->client_tcp)) != 0) {
    LOG_E("uv_tcp_init failed: %s", uv_strerror(err));
    free(conn);
    return;
  }

  if ((err = uv_accept(server, (uv_stream_t *)&conn->client_tcp)) != 0) {
    LOG_E("uv_accept failed: %s", uv_strerror(err));
    free(conn);
    return;
  }

  if ((uv_read_start((uv_stream_t *)&conn->client_tcp, on_conn_alloc, on_conn_read_done)) != 0) {
    LOG_E("uv_read_start failed: %s", uv_strerror(err));
    free(conn);
    return;
  }
}

void on_conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
  Connection *conn = container_of(handle, Connection, client_tcp);
  buf->base = conn->buf;
  buf->len = sizeof(conn->buf);
}

void on_conn_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
  if (nread == buf->len) { // ignore the last byte
    --nread;
  }
  buf->base[nread-1] = '\0';
  LOG_I("read data: %s", buf->base);
}
