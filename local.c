#include <stdio.h>
#include <uv.h>
#include "log/log.h"
#include "util.h"
#include "alloc.h"
#include "socks5.h"

#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT 8789
#define SERVER_BACKLOG 256
#define SESSION_DATA_BUFSIZ 2048

struct ServerContext;
static struct ServerContext *g_server_ctx;
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

typedef struct ServerContext {
  ServerCfg server_cfg;
  uv_getaddrinfo_t addrinfo_req;

  uv_tcp_t server_tcp;
  IPVersion bound_ip_ver;
  union {
    unsigned char ipv6[16];
    unsigned char ipv4[4];
  } bound_ip; 

} ServerContext;

typedef enum {
  HANDSHAKE,
  REQ,
  STREAMING,
  END
} SessionState;

typedef struct {
  uv_tcp_t client_tcp;
  uv_write_t client_write_req;
  uv_shutdown_t client_shutdown_req;
  char client_buf[SESSION_DATA_BUFSIZ];

  uv_tcp_t upstream_tcp;
  uv_write_t upstream_write_req;
  uv_shutdown_t upstream_shutdown_req;
  uv_getaddrinfo_t upstream_addrinfo_req;
  uv_connect_t upstream_connect_req;
  char upstream_buf[SESSION_DATA_BUFSIZ]; 

  SessionState state;
  Socks5Ctx socks5_ctx;

} Session;

typedef union {
  struct sockaddr addr;
  struct sockaddr_in addr4;
  struct sockaddr_in6 addr6;
} IPAddr;

static void start_server(const char *host, int port, int backlog);
static void do_bind_and_listen(uv_getaddrinfo_t* req, int status, struct addrinfo* res);
static void on_connection_new(uv_stream_t *server, int status);

static Session *create_session();
static void close_session(Session *sess);
static void client_handle_close_cb(uv_handle_t *handle);

static int client_read_start(uv_stream_t *handle);
static int client_write_start(uv_stream_t *handle, const uv_buf_t *buf);
static int client_write_string(uv_stream_t *handle, const char *data, int len);
static int client_write_error(uv_stream_t *handle, int err);
static void on_client_conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void on_client_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
static void on_client_write_done(uv_write_t *req, int status);
static void on_client_shutdown_cb(uv_shutdown_t *req, int status);

static void upstream_connect_domain(uv_getaddrinfo_t* req, int status, struct addrinfo* res);
static int upstream_connect(uv_connect_t* req, IPAddr *ipaddr);
static void upstream_connect_cb(uv_connect_t* req, int status);
static void upstream_connect_log(Session *sess, int err);

static int upstream_read_start(uv_stream_t *handle);
static int upstream_write_start(uv_stream_t *handle, const uv_buf_t *buf);
static void on_upstream_conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void on_upstream_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
static void on_upstream_write_done(uv_write_t *req, int status);
static void on_upstream_shutdown_cb(uv_shutdown_t *req, int status);

int main(int argc, const char *argv[]) {
  start_server(SERVER_HOST, SERVER_PORT, SERVER_BACKLOG);
  return 0;
}

void start_server(const char *host, int port, int backlog) {
  g_loop = uv_default_loop();

  ServerContext server_ctx;
  memset(&server_ctx, 0, sizeof(ServerContext));
  g_server_ctx = &server_ctx;

  server_ctx.server_cfg.host = host;
  server_ctx.server_cfg.port = port;
  server_ctx.server_cfg.backlog = backlog;

  struct addrinfo hint;
  memset(&hint, 0, sizeof(hint));
  hint.ai_family = AF_UNSPEC;
  hint.ai_socktype = SOCK_STREAM;
  hint.ai_protocol = IPPROTO_TCP;

  CHECK(uv_getaddrinfo(g_loop, 
                       &server_ctx.addrinfo_req, 
                       do_bind_and_listen, 
                       host, 
                       NULL, 
                       &hint) == 0);

  uv_run(g_loop, UV_RUN_DEFAULT);
  uv_loop_delete(g_loop);
}

void do_bind_and_listen(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
  if (status < 0) {
    LOG_E("getaddrinfo(\"%s\"): %s", g_server_ctx->server_cfg.host, uv_strerror(status));
    uv_freeaddrinfo(res);
    return;
  }

  // abort if failing to init uv_tcp_t
  CHECK(uv_tcp_init(g_loop, &g_server_ctx->server_tcp) == 0);

  union {
    struct sockaddr addr;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
  } ipaddr;

  char ipstr[INET6_ADDRSTRLEN];

  for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
    if (ai->ai_family == AF_INET) {
      ipaddr.addr4 = *(struct sockaddr_in *)ai->ai_addr;
      ipaddr.addr4.sin_port = htons(g_server_ctx->server_cfg.port);
      uv_inet_ntop(ipaddr.addr.sa_family, &ipaddr.addr4.sin_addr, ipstr, sizeof(ipstr));
      
      g_server_ctx->bound_ip_ver = IPV4;
      memcpy(&g_server_ctx->bound_ip, &ipaddr.addr4.sin_addr.s_addr, 
          sizeof(g_server_ctx->bound_ip.ipv4));

    } else if (ai->ai_family == AF_INET6) {
      ipaddr.addr6 = *(struct sockaddr_in6 *)ai->ai_addr;
      ipaddr.addr6.sin6_port = htons(g_server_ctx->server_cfg.port);
      uv_inet_ntop(ipaddr.addr.sa_family, &ipaddr.addr6.sin6_addr, ipstr, sizeof(ipstr));

      g_server_ctx->bound_ip_ver = IPV6;
      memcpy(&g_server_ctx->bound_ip, ipaddr.addr6.sin6_addr.s6_addr, 
          sizeof(g_server_ctx->bound_ip.ipv6));

    } else {
      LOG_W("unexpected ai_family: %d", ai->ai_family);
      continue;
    }

    int err;
    if ((err = uv_tcp_bind(&g_server_ctx->server_tcp, &ipaddr.addr, 0)) != 0) {
      LOG_W("uv_tcp_bind on [%s]:%d failed: %s", 
          ipstr, g_server_ctx->server_cfg.port, uv_strerror(err));
      continue;
    }

    if ((err = uv_listen((uv_stream_t *)&g_server_ctx->server_tcp, 
          g_server_ctx->server_cfg.backlog, 
          on_connection_new)) != 0) {
      LOG_W("uv_tcp_listen on [%s]:%d failed: %s", 
          ipstr, g_server_ctx->server_cfg.port, uv_strerror(err));
      continue;
    }
    
    LOG_I("server listening on [%s]:%d.", ipstr, g_server_ctx->server_cfg.port);
    uv_freeaddrinfo(res);
    return;
  }

  LOG_E("failed to bind on port: %d", g_server_ctx->server_cfg.port);
  exit(1);
} 

Session *create_session() {
  Session *sess = lmalloc(sizeof(Session));
  sess->state = HANDSHAKE;
  return sess;
}

void close_session(Session *sess) {
  uv_handle_t *handle = (uv_handle_t *)&sess->upstream_tcp;
  uv_read_stop((uv_stream_t *)handle);
  uv_shutdown(&sess->upstream_shutdown_req, (uv_stream_t *)handle, NULL);
  if (!uv_is_closing(handle) && uv_is_active(handle)) {
    uv_close(handle, NULL);
  }

  handle = (uv_handle_t *)&sess->client_tcp;
  uv_read_stop((uv_stream_t *)handle);
  uv_shutdown(&sess->client_shutdown_req, (uv_stream_t *)handle, NULL);
  if (!uv_is_closing(handle) && uv_is_active(handle)) {
    uv_close(handle, client_handle_close_cb);
  } else {
    // closing of upstream_tcp may still be pending, so this line may cause problem
    free(sess);
  }
}

void client_handle_close_cb(uv_handle_t *handle) {
  Session *sess = container_of(handle, Session, client_tcp);
  free(sess);
}

void on_client_shutdown_cb(uv_shutdown_t *req, int status) {

}

void on_upstream_shutdown_cb(uv_shutdown_t *req, int status) {

}

void on_connection_new(uv_stream_t *server, int status) {
  Session *sess = create_session();

  int err;
  if ((err = uv_tcp_init(g_loop, &sess->client_tcp)) != 0) {
    LOG_E("uv_tcp_init failed: %s", uv_strerror(err));
    close_session(sess);
    return;
  }

  if ((err = uv_tcp_init(g_loop, &sess->upstream_tcp)) != 0) {
    LOG_E("uv_tcp_init failed: %s", uv_strerror(err));
    close_session(sess);
    return;
  }

  if ((err = uv_accept(server, (uv_stream_t *)&sess->client_tcp)) != 0) {
    LOG_E("uv_accept failed: %s", uv_strerror(err));
    close_session(sess);
    return;
  }

  client_read_start((uv_stream_t *)&sess->client_tcp);
}

int client_read_start(uv_stream_t *handle) {
  Session *sess = container_of(handle, Session, client_tcp);
  int err;
  if ((err = uv_read_start(handle, on_client_conn_alloc, on_client_read_done)) != 0) {
    LOG_E("uv_read_start failed: %s", uv_strerror(err));
    // safe to close directly
    close_session(sess);
  }
  return err;
}

int client_write_error(uv_stream_t *handle, int err) {
  Session *sess = container_of(handle, Session, client_tcp);

  char buf[] = { 5, 1, 0, 1, 0, 0, 0, 0, 0, 0 };
  sess->state = END; // cause the session be closed in on_write_done_cb

  switch(err) {
    case UV_ENETUNREACH:
      buf[1] = 3; // from the RFC: 3 = Network unreachable
      break;
    case UV_EHOSTUNREACH:
      buf[1] = 4; // from the RFC: 4 = Host unreachable
      sess->state = END;
      break;
    case UV_ECONNREFUSED:
      buf[1] = 5;
      sess->state = END;
      break;

    case S5_UNSUPPORTED_CMD:
      buf[1] = 7;
      sess->state = END;
      break;
    case S5_BAD_ATYP:
      buf[1] = 8;
      sess->state = END;
      break;
    default:
      buf[1] = 1; // general SOCKS server failure
      sess->state = END;
      break;
  }

  uv_read_stop(handle);
  uv_read_stop((uv_stream_t *)&sess->upstream_tcp);
  return client_write_string(handle, buf, 10);
}

int client_write_string(uv_stream_t *handle, const char *data, int len) {
  uv_buf_t buf;
  buf.base = (char *)data;
  buf.len = len;
  return client_write_start(handle, &buf);
}

int client_write_start(uv_stream_t *handle, const uv_buf_t *buf) {
  Session *sess = container_of(handle, Session, client_tcp);
  int err;
  if ((err = uv_write(&sess->client_write_req, (uv_stream_t *)handle, buf, 1, on_client_write_done)) != 0) {
    LOG_E("uv_write failed: %s", uv_strerror(err));
    // safe to close directly
    close_session(sess);
  }
  return err;
}

void on_client_write_done(uv_write_t *req, int status) {
  Session *sess = container_of(req, Session, client_write_req);
  if (status < 0 || sess->state == END) {
    LOG_D("status=%d, now will close session", status);
    close_session(sess);
  } else {
    client_read_start((uv_stream_t *)&sess->client_tcp);
    if (sess->state == STREAMING) {
      upstream_read_start((uv_stream_t *)&sess->upstream_tcp);
    }
  }
}

void on_client_conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
  Session *sess = container_of(handle, Session, client_tcp);
  buf->base = sess->client_buf;
  buf->len = sizeof(sess->client_buf);
}

void on_client_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
  // stop reading before processing the data
  uv_read_stop(handle);

  Session *sess = container_of(handle, Session, client_tcp);
  if (nread < 0) {
    LOG_I("client read done: %s", uv_strerror(nread));
    close_session(sess);
    return;
  }

  if (sess->state == HANDSHAKE) {
    S5Err s5_err = socks5_parse_handshake(&sess->socks5_ctx, buf->base, nread);
    if (s5_err != S5_OK) {
      LOG_E("parse handshake failed");
      // not an understandable socks handshake message, close the session directly
      close_session(sess);
      return;
    }

    if (sess->socks5_ctx.state == S5_PARSE_STATE_FINISH) {
      // we only support AUTH_NONE at the moment
      if (sess->socks5_ctx.methods & S5_AUTH_NONE) { 
        sess->state = REQ;
        client_write_string(handle, "\5\0", 2);
      } else {
        sess->state = END;  // cause the session be closed in on_write_done_cb
        client_write_string(handle, "\5\xff", 2);
      }

      LOG_V("handshake passed");
    } else {
      // need more data
      client_read_start((uv_stream_t *)handle);
    }

  } else if (sess->state == REQ) {
    S5Err s5_err = socks5_parse_req(&sess->socks5_ctx, buf->base, nread); 
    if (s5_err != S5_OK) {
      LOG_E("parsed req failed");
      client_write_error(handle, s5_err);
      return;
    }

    if (sess->socks5_ctx.atyp == S5_ATYP_IPV4) {
      struct sockaddr_in addr4;
      addr4.sin_family = AF_INET;
      addr4.sin_port = htons(sess->socks5_ctx.dst_port);
      memcpy(&addr4.sin_addr.s_addr, sess->socks5_ctx.dst_addr, 4);

      int err;
      if ((err = upstream_connect(&sess->upstream_connect_req, 
              (IPAddr *)&addr4)) != 0) {
        log_ipv4_and_port(sess->socks5_ctx.dst_addr, sess->socks5_ctx.dst_port, 
            "upstream connect failed");
      }

    } else if (sess->socks5_ctx.atyp == S5_ATYP_DOMAIN) {
      struct addrinfo hint;
      memset(&hint, 0, sizeof(hint));
      hint.ai_family = AF_UNSPEC;
      hint.ai_socktype = SOCK_STREAM;
      hint.ai_protocol = IPPROTO_TCP;

      int err;
      if ((err = uv_getaddrinfo(g_loop, 
            &sess->upstream_addrinfo_req, 
            upstream_connect_domain, 
            (const char *)sess->socks5_ctx.dst_addr, 
            NULL, 
            &hint)) != 0) {

        LOG_E("upstream connect failed: %s, err: %s", 
            sess->socks5_ctx.dst_addr, uv_strerror(err));
        client_write_error(handle, err);
        return;
      }

      LOG_V("passed req: %s:%d", sess->socks5_ctx.dst_addr, sess->socks5_ctx.dst_port);

    } else if (sess->socks5_ctx.atyp == S5_ATYP_IPV6) {
      struct sockaddr_in6 addr6;
      addr6.sin6_family = AF_INET6;
      addr6.sin6_port = htons(sess->socks5_ctx.dst_port);
      memcpy(&addr6.sin6_addr.s6_addr, sess->socks5_ctx.dst_addr, 16);

      int err;
      if ((err = upstream_connect(&sess->upstream_connect_req, 
              (IPAddr *)&addr6)) != 0) {
        log_ipv6_and_port(sess->socks5_ctx.dst_addr, sess->socks5_ctx.dst_port, 
            "upstream connect failed");
      }

    } else {
      LOG_E("unknown ATYP: %d", sess->socks5_ctx.atyp);
      client_write_error(handle, 20000);  // the error code is chosen at random
    }

  } else if (sess->state == STREAMING) { 
    ((uv_buf_t *)buf)->len = nread;
    upstream_write_start((uv_stream_t *)&sess->upstream_tcp, buf);

  } else {
    // unreachable code
    LOG_W("unepxected state: %d", sess->state);
  }
}

int upstream_read_start(uv_stream_t *handle) {
  Session *sess = container_of(handle, Session, upstream_tcp);
  int err;
  if ((err = uv_read_start(handle, on_upstream_conn_alloc, on_upstream_read_done)) != 0) {
    LOG_E("uv_read_start failed: %s", uv_strerror(err));
    close_session(sess);
  }
  return err;
}

void on_upstream_conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
  Session *sess = container_of(handle, Session, upstream_tcp);
  buf->base = sess->upstream_buf;
  buf->len = sizeof(sess->upstream_buf);
}

void on_upstream_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
  uv_read_stop(handle);

  Session *sess = container_of(handle, Session, upstream_tcp);
  if (nread < 0 || sess->state == END) {
    LOG_V("upstream read failed: %s", uv_strerror(nread));
    close_session(sess);
    return;
  }

  ((uv_buf_t *)buf)->len = nread;
  client_write_start((uv_stream_t *)&sess->client_tcp, buf);
}

int upstream_write_start(uv_stream_t *handle, const uv_buf_t *buf) {
  Session *sess = container_of(handle, Session, upstream_tcp);
  int err;
  if ((err = uv_write(&sess->upstream_write_req, (uv_stream_t *)handle, buf, 1, on_upstream_write_done)) != 0) {
    LOG_E("uv_write failed: %s", uv_strerror(err));
    close_session(sess);
  }
  return err;
}

void on_upstream_write_done(uv_write_t *req, int status) {
  Session *sess = container_of(req, Session, upstream_write_req);
  if (status < 0 || sess->state == END) {
    LOG_V("upstream write failed: %s", uv_strerror(status));
    close_session(sess);
  } else {
    client_read_start((uv_stream_t *)&sess->client_tcp);
  }
}

void upstream_connect_domain(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
  Session *sess = container_of(req, Session, upstream_addrinfo_req);
  if (status < 0) {
    LOG_E("getaddrinfo(\"%s\"): %s", sess->socks5_ctx.dst_addr, uv_strerror(status));
    uv_freeaddrinfo(res);
    client_write_error((uv_stream_t *)&sess->client_tcp, status);
    return;
  }

  char ipstr[INET6_ADDRSTRLEN];
  IPAddr ipaddr;

  int err;
  for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
    if (ai->ai_family == AF_INET) {
      ipaddr.addr4 = *(struct sockaddr_in *)ai->ai_addr;
      ipaddr.addr4.sin_port = htons(sess->socks5_ctx.dst_port);
      uv_inet_ntop(ipaddr.addr.sa_family, &ipaddr.addr4.sin_addr, ipstr, sizeof(ipstr));

    } else if (ai->ai_family == AF_INET6) {
      ipaddr.addr6 = *(struct sockaddr_in6 *)ai->ai_addr;
      ipaddr.addr6.sin6_port = htons(sess->socks5_ctx.dst_port);
      uv_inet_ntop(ipaddr.addr.sa_family, &ipaddr.addr6.sin6_addr, ipstr, sizeof(ipstr));

    } else {
      LOG_W("unexpected ai_family: %d", ai->ai_family);
      continue;
    }

    // TODO - upstream_connect may close the session, which may not be desired
    // here, because there might be more ip_addrs to try before giving up
    if ((err = upstream_connect(&sess->upstream_connect_req, &ipaddr)) != 0) {
      LOG_W("upstream_connect failed on [%s]:%d, err: %s",
          ipstr, sess->socks5_ctx.dst_port, uv_strerror(err));
      continue;
    }

    LOG_V("connected to %s:%d", ipstr, sess->socks5_ctx.dst_port);
    uv_freeaddrinfo(res);

    return;
  }

  uv_freeaddrinfo(res);
  client_write_error((uv_stream_t *)&sess->client_tcp, err);
}

void upstream_connect_cb(uv_connect_t* req, int status) {
  Session *sess = container_of(req, Session, upstream_connect_req);
  upstream_connect_log(sess, status);

  if (status < 0) {
    client_write_error((uv_stream_t *)&sess->client_tcp, status); 

  } else {
    sess->state = STREAMING;

    uv_buf_t buf = {
      .base = sess->client_buf
    };
    memcpy(buf.base, "\5\0\0\1", 4);
    if (g_server_ctx->bound_ip_ver == IPV4) {
      buf.len = 10;
      memcpy(buf.base+4, &g_server_ctx->bound_ip, 4);
      memcpy(buf.base+8, &g_server_ctx->server_cfg.port, 2);
    } else {  // IPV6
      buf.len = 22;
      memcpy(buf.base+4, &g_server_ctx->bound_ip, 16);
      memcpy(buf.base+20, &g_server_ctx->server_cfg.port, 2);
    }

    client_write_start((uv_stream_t *)&sess->client_tcp, &buf);
  }
}

void upstream_connect_log(Session *sess, int status) {
  if (sess->socks5_ctx.atyp == S5_ATYP_IPV4) {
    char data[INET_ADDRSTRLEN];
    uv_inet_ntop(AF_INET, sess->socks5_ctx.dst_addr, data, 4);
    LOG_I("uv_tcp_connect: %s:%d, status: %s", 
        data, sess->socks5_ctx.dst_port, 
        status ? uv_strerror(status) : "CONNECTED");

  } else if (sess->socks5_ctx.atyp == S5_ATYP_IPV6) {
    char data[INET6_ADDRSTRLEN];
    uv_inet_ntop(AF_INET6, sess->socks5_ctx.dst_addr, data, 16);
    LOG_I("uv_tcp_connect: [%s]:%d, status: %s", 
        data, sess->socks5_ctx.dst_port, 
        status ? uv_strerror(status) : "CONNECTED");

  } else {
    LOG_I("uv_tcp_connect: %s:%d, status: %s", 
        sess->socks5_ctx.dst_addr, sess->socks5_ctx.dst_port, 
        status ? uv_strerror(status) : "CONNECTED");
  }
}

int upstream_connect(uv_connect_t* req, IPAddr *ipaddr) {
  Session *sess = container_of(req, Session, upstream_connect_req);

  /*int err;*/
  /*if ((err = uv_tcp_init(g_loop, &sess->upstream_tcp)) < 0) {*/
    /*LOG_E("uv_tcp_init failed: %s", uv_strerror(err));*/
    /*client_write_error((uv_stream_t *)&sess->client_tcp, err); */
    /*return err;*/
  /*}*/

  int err;
  if ((err = uv_tcp_connect(req, &sess->upstream_tcp, &ipaddr->addr, upstream_connect_cb)) != 0) {
    LOG_W("uv_tcp_connect failed: %s", uv_strerror(err));

    // in this case, upstream_connect_cb will not be called, so we should write
    // the error response to the client here
    client_write_error((uv_stream_t *)&sess->client_tcp, err); 
  }
  return err;
}
