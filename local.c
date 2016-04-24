#include <stdio.h>
#include <uv.h>
#include "log/log.h"
#include "util.h"
#include "alloc.h"
#include "socks5.h"

#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT 9002
#define SERVER_BACKLOG 256
#define CONNECTION_BUF_SIZE 2048

struct ServerState;
static struct ServerState *g_server_state;
static uv_loop_t *g_loop;

typedef struct {
  const char *host;
  int port;
  int backlog;
} ServerCfg;

typedef enum {
  IPV4,
  IPV6
} IPVersion;

typedef struct ServerCtx {
  uv_tcp_t server_tcp;
  union {
    unsigned char ipv6[16];
    unsigned char ipv4[4];
  } bound_ip; 
  IPVersion bound_ip_ver;
} ServerCtx;

typedef struct ServerState {
  uv_getaddrinfo_t addrinfo_req;
  ServerCfg server_cfg;
  ServerCtx server_ctx;
} ServerState;

typedef enum {
  HANDSHAKE,
  REQ,
  STREAMING
} ConnectionState;

typedef struct {
  uv_tcp_t client_tcp;
  uv_write_t client_write_req;
  uv_tcp_t upstream_tcp;
  uv_write_t upstream_write_req;
  uv_getaddrinfo_t upstream_addrinfo_req;
  uv_connect_t upstream_connect;

  char buf[CONNECTION_BUF_SIZE];
  char buf2[CONNECTION_BUF_SIZE];

  ConnectionState state;
  Socks5Ctx socks5_ctx;
} Connection;

static void start_server(const char *host, int port, int backlog);
static void do_bind_and_listen(uv_getaddrinfo_t* req, int status, struct addrinfo* res);
static void on_conn_new(uv_stream_t *server, int status);

static Connection *create_connection();
static void close_connection(Connection *conn);
static void close_connection_cb(uv_handle_t *handle);

static int client_read_start(uv_stream_t *handle);
static int client_write_start(uv_stream_t *handle, const uv_buf_t *buf);
static void on_client_conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void on_client_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
static void on_client_write_done(uv_write_t *req, int status);

static void connect_upstream(uv_getaddrinfo_t* req, int status, struct addrinfo* res);
static void connect_upstream_cb(uv_connect_t* req, int status);

static int upstream_read_start(uv_stream_t *handle);
static int upstream_write_start(uv_stream_t *handle, const uv_buf_t *buf);
static void on_upstream_conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void on_upstream_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
static void on_upstream_write_done(uv_write_t *req, int status);

int main(int argc, const char *argv[]) {
  start_server(SERVER_HOST, SERVER_PORT, SERVER_BACKLOG);
  return 0;
}

void start_server(const char *host, int port, int backlog) {
  g_loop = uv_default_loop();

  ServerState server_state;
  memset(&server_state, 0, sizeof(ServerState));

  server_state.server_cfg.host = host;
  server_state.server_cfg.port = port;
  server_state.server_cfg.backlog = backlog;

  g_server_state = &server_state;

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
  if (status < 0) {
    LOG_E("getaddrinfo(\"%s\"): %s", g_server_state->server_cfg.host, uv_strerror(status));
    uv_freeaddrinfo(res);
    return;
  }

  // abort if failing to init uv_tcp_t
  CHECK(uv_tcp_init(g_loop, &g_server_state->server_ctx.server_tcp) == 0);

  union {
    struct sockaddr addr;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
  } ipaddr;

  char ipstr[INET6_ADDRSTRLEN];

  for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
    if (ai->ai_family == AF_INET) {
      ipaddr.addr4 = *(struct sockaddr_in *)ai->ai_addr;
      ipaddr.addr4.sin_port = htons(g_server_state->server_cfg.port);
      uv_inet_ntop(ipaddr.addr.sa_family, &ipaddr.addr4.sin_addr, ipstr, sizeof(ipstr));
      
      g_server_state->server_ctx.bound_ip_ver = IPV4;
      memcpy(&g_server_state->server_ctx.bound_ip, &ipaddr.addr4.sin_addr.s_addr, 
          sizeof(g_server_state->server_ctx.bound_ip.ipv4));

    } else if (ai->ai_family == AF_INET6) {
      ipaddr.addr6 = *(struct sockaddr_in6 *)ai->ai_addr;
      ipaddr.addr6.sin6_port = htons(g_server_state->server_cfg.port);
      uv_inet_ntop(ipaddr.addr.sa_family, &ipaddr.addr6.sin6_addr, ipstr, sizeof(ipstr));

      g_server_state->server_ctx.bound_ip_ver = IPV6;
      memcpy(&g_server_state->server_ctx.bound_ip, ipaddr.addr6.sin6_addr.s6_addr, 
          sizeof(g_server_state->server_ctx.bound_ip.ipv6));

    } else {
      LOG_W("unexpected ai_family: %d", ai->ai_family);
      continue;
    }

    int err;
    if ((err = uv_tcp_bind(&g_server_state->server_ctx.server_tcp, &ipaddr.addr, 0)) != 0) {
      LOG_W("uv_tcp_bind on [%s]:%d failed: %s", 
          ipstr, g_server_state->server_cfg.port, uv_strerror(err));
      continue;
    }

    if ((err = uv_listen((uv_stream_t *)&g_server_state->server_ctx.server_tcp, 
          g_server_state->server_cfg.backlog, 
          on_conn_new)) != 0) {
      LOG_W("uv_tcp_listen on [%s]:%d failed: %s", 
          ipstr, g_server_state->server_cfg.port, uv_strerror(err));
      continue;
    }
    
    printf("========================\n");
    for (int i = 0; i < sizeof(g_server_state->server_ctx.bound_ip.ipv6); ++i) {
      printf(".%d", g_server_state->server_ctx.bound_ip.ipv6[i]);
    }
    printf("\n");
    /*g_server_state->server_ctx.bound_ip = */
    LOG_I("server listening on [%s]:%d.", ipstr, g_server_state->server_cfg.port);
    uv_freeaddrinfo(res);
    return;
  }

  LOG_E("failed to bind on port: %d", g_server_state->server_cfg.port);
  exit(1);
} 

Connection *create_connection() {
  Connection *conn = lmalloc(sizeof(Connection));
  memset(conn, 0, sizeof(Connection));
  conn->state = HANDSHAKE;
  return conn;
}

void close_connection(Connection *conn) {
  uv_handle_t *handle = (uv_handle_t *)&conn->client_tcp;
  if (!uv_is_closing(handle) && uv_is_active(handle)) {
    uv_close(handle, NULL);
  }
  handle = (uv_handle_t *)&conn->upstream_tcp;;
  if (!uv_is_closing(handle) && uv_is_active(handle)) {
    uv_close(handle, NULL);
  }
  free(conn);
}

void close_connection_cb(uv_handle_t *handle) {
}

void on_conn_new(uv_stream_t *server, int status) {
  Connection *conn = create_connection();

  int err;
  if ((err = uv_tcp_init(g_loop, &conn->client_tcp)) != 0) {
    LOG_E("uv_tcp_init failed: %s", uv_strerror(err));
    close_connection(conn);
    return;
  }

  if ((err = uv_accept(server, (uv_stream_t *)&conn->client_tcp)) != 0) {
    LOG_E("uv_accept failed: %s", uv_strerror(err));
    close_connection(conn);
    return;
  }

  if (client_read_start((uv_stream_t *)&conn->client_tcp) < 0) {
    close_connection(conn);
  }
}

int client_read_start(uv_stream_t *handle) {
  Connection *conn = container_of(handle, Connection, client_tcp);
  int err;
  if ((err = uv_read_start(handle, on_client_conn_alloc, on_client_read_done)) != 0) {
    LOG_E("uv_read_start failed: %s", uv_strerror(err));
    close_connection(conn);
  }
  return err;
}

int client_write_start(uv_stream_t *handle, const uv_buf_t *buf) {
  Connection *conn = container_of(handle, Connection, client_tcp);
  int err;
  if ((err = uv_write(&conn->client_write_req, (uv_stream_t *)handle, buf, 1, on_client_write_done)) != 0) {
    LOG_E("uv_write failed: %s", uv_strerror(err));
    close_connection(conn);
  }
  return err;
}

int upstream_read_start(uv_stream_t *handle) {
  Connection *conn = container_of(handle, Connection, upstream_tcp);
  int err;
  if ((err = uv_read_start(handle, on_upstream_conn_alloc, on_upstream_read_done)) != 0) {
    LOG_E("uv_read_start failed: %s", uv_strerror(err));
    close_connection(conn);
  }
  return err;
}

int upstream_write_start(uv_stream_t *handle, const uv_buf_t *buf) {
  Connection *conn = container_of(handle, Connection, upstream_tcp);
  int err;
  if ((err = uv_write(&conn->upstream_write_req, (uv_stream_t *)handle, buf, 1, on_upstream_write_done)) != 0) {
    LOG_E("uv_write failed: %s", uv_strerror(err));
    close_connection(conn);
  }
  return err;
}

void on_client_conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
  Connection *conn = container_of(handle, Connection, client_tcp);
  buf->base = conn->buf;
  buf->len = sizeof(conn->buf);
}

void on_client_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
  Connection *conn = container_of(handle, Connection, client_tcp);
  if (conn->state == HANDSHAKE) {
    uv_read_stop(handle);

    S5Err s5_err = socks5_parse_handshake(&conn->socks5_ctx, buf->base, nread);
    if (s5_err != S5_OK) {
      LOG_E("parse handshake failed");
      close_connection(conn);
      return;
    }

    if (conn->socks5_ctx.state == S5_PARSE_STATE_FINISH) {
      buf->base[0] = SOCKS5_VERSION;
      buf->base[1] = S5_AUTH_NONE;
      ((uv_buf_t *)buf)->len = 2; // safe to cast away constness here because uv_write is synchronous

      if (client_write_start(handle, buf) < 0) {
        return;
      }

      LOG_V("handshake passed");
      conn->state = REQ;
    } 

    client_read_start((uv_stream_t *)handle);

  } else if (conn->state == REQ) {
    uv_read_stop(handle);

    S5Err s5_err = socks5_parse_req(&conn->socks5_ctx, buf->base, nread); 
    if (s5_err != S5_OK) {
      LOG_E("parsed req failed");
      close_connection(conn);
      return;
    }


    if (conn->socks5_ctx.atyp == S5_ATYP_IPV4) {

    } else if (conn->socks5_ctx.atyp == S5_ATYP_DOMAIN) {
      struct addrinfo hint;
      memset(&hint, 0, sizeof(hint));
      hint.ai_family = AF_UNSPEC;
      hint.ai_socktype = SOCK_STREAM;
      hint.ai_protocol = IPPROTO_TCP;

      int err;
      if ((err = uv_getaddrinfo(g_loop, 
            &conn->upstream_addrinfo_req, 
            connect_upstream, 
            (const char *)conn->socks5_ctx.dst_addr, 
            NULL, 
            &hint)) != 0) {
        LOG_E("connecting to upstream failed: %s", uv_strerror(err));

        // Host unreachable
        memcpy(buf->base, "\5\4\0\1\0\0\0\0\0\0", 10);
        client_write_start(handle, buf);

        close_connection(conn);
        return;
      }
    }

    LOG_V("passed req: %s:%d", conn->socks5_ctx.dst_addr, conn->socks5_ctx.dst_port);
  } else if (conn->state == STREAMING) { 
    upstream_write_start((uv_stream_t *)&conn->upstream_tcp, buf);
  }
}

void on_client_write_done(uv_write_t *req, int status) {
  Connection *conn = container_of(req, Connection, client_write_req);
  if (status < 0) {
    LOG_V("write failed: %s", uv_strerror(status));
    free(conn); // may not be the right moment to free the object here
    return;
  }

}

void on_upstream_conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
  Connection *conn = container_of(handle, Connection, upstream_tcp);
  buf->base = conn->buf2;
  buf->len = sizeof(conn->buf2);
}

void on_upstream_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
  Connection *conn = container_of(handle, Connection, upstream_tcp);
  client_write_start((uv_stream_t *)&conn->client_tcp, buf);
}

void on_upstream_write_done(uv_write_t *req, int status) {
  Connection *conn = container_of(req, Connection, upstream_write_req);
  if (status < 0) {
    LOG_V("write failed: %s", uv_strerror(status));
    free(conn); // may not be the right moment to free the object here
    return;
  }

}

void connect_upstream(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
  Connection *conn = container_of(req, Connection, upstream_addrinfo_req);
  if (status < 0) {
    LOG_E("getaddrinfo(\"%s\"): %s", conn->socks5_ctx.dst_addr, uv_strerror(status));
    uv_freeaddrinfo(res);
    return;
  }

  // abort if failing to init uv_tcp_t
  CHECK(uv_tcp_init(g_loop, &conn->upstream_tcp) == 0);

  union {
    struct sockaddr addr;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
  } ipaddr;

  char ipstr[INET6_ADDRSTRLEN];

  for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
    if (ai->ai_family == AF_INET) {
      ipaddr.addr4 = *(struct sockaddr_in *)ai->ai_addr;
      ipaddr.addr4.sin_port = htons(conn->socks5_ctx.dst_port);
      uv_inet_ntop(ipaddr.addr.sa_family, &ipaddr.addr4.sin_addr, ipstr, sizeof(ipstr));

    } else if (ai->ai_family == AF_INET6) {
      ipaddr.addr6 = *(struct sockaddr_in6 *)ai->ai_addr;
      ipaddr.addr6.sin6_port = htons(conn->socks5_ctx.dst_port);
      uv_inet_ntop(ipaddr.addr.sa_family, &ipaddr.addr6.sin6_addr, ipstr, sizeof(ipstr));

    } else {
      LOG_W("unexpected ai_family: %d", ai->ai_family);
      continue;
    }

    int err;
    if ((err = uv_tcp_connect(&conn->upstream_connect, &conn->upstream_tcp, 
            &ipaddr.addr, connect_upstream_cb)) != 0) {
      LOG_W("uv_tcp_connect failed on [%s]:%d, err: %s", 
          ipstr, conn->socks5_ctx.dst_port, uv_strerror(err));
      continue;
    }

    LOG_V("connected to [%s]:%d.", ipstr, conn->socks5_ctx.dst_port);
    uv_freeaddrinfo(res);

    return;
  }
}

void connect_upstream_cb(uv_connect_t* req, int status) {
  Connection *conn = container_of(req, Connection, upstream_connect);
  if (status < 0) {
    LOG_W("uv_tcp_connect failed on [%s]:%d, err: %s", 
        conn->socks5_ctx.dst_addr, conn->socks5_ctx.dst_port, uv_strerror(status));

    uv_buf_t buf;
    buf.base = conn->buf;
    buf.len = 10;
    // Host unreachable
    memcpy(buf.base, "\5\4\0\1\0\0\0\0\0\0", 10);
    client_write_start((uv_stream_t *)&conn->client_tcp, &buf);

    close_connection(conn);
  } else {
    conn->state = STREAMING;

    uv_buf_t buf;
    buf.base = conn->buf;

    memcpy(buf.base, "\5\0\0\1", 4);
    if (g_server_state->server_ctx.bound_ip_ver == IPV4) {
      buf.len = 10;
      memcpy(buf.base+4, &g_server_state->server_ctx.bound_ip, 4);
      memcpy(buf.base+8, &g_server_state->server_cfg.port, 2);
    } else {  // IPV6
      buf.len = 22;
      memcpy(buf.base+4, &g_server_state->server_ctx.bound_ip, 16);
      memcpy(buf.base+20, &g_server_state->server_cfg.port, 2);
    }

    client_write_start((uv_stream_t *)&conn->client_tcp, &buf);
    client_read_start((uv_stream_t *)&conn->client_tcp);
    upstream_read_start((uv_stream_t *)&conn->upstream_tcp);
  }
}
