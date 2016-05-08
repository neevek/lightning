#include <stdio.h>
#include <uv.h>
#include "log/log.h"
#include "util.h"
#include "alloc.h"
#include "socks5.h"
#include "defs.h"

#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT 8789
#define SERVER_BACKLOG 256
#define SESSION_DATA_BUFSIZ 2048
#define KEEPALIVE 60

struct ServerContext;
static struct ServerContext *g_server_ctx;
static uv_loop_t *g_loop;

typedef struct {
  const char *host;
  int local_port;
  int backlog;
} ServerCfg;

typedef enum {
  IPV4,
  IPV6
} IPVersion;

typedef struct ServerContext {
  uv_getaddrinfo_t addrinfo_req;
  uv_tcp_t server_tcp;
  ServerCfg server_cfg;
} ServerContext;

typedef union {
  struct sockaddr addr;
  struct sockaddr_in addr4;
  struct sockaddr_in6 addr6;
} IPAddr;

static void start_server(const char *host, int local_port, int backlog);
static void do_bind_and_listen(uv_getaddrinfo_t* req, int status, struct addrinfo* res);
static void on_connection_new(uv_stream_t *server, int status);

static Session *create_session();
static int init_tcp_handle(Session *sess, uv_tcp_t **tcp_handle);
static void close_session(Session *sess);
static void tcp_handle_close_cb(uv_handle_t *handle);
static void finish_socks5_handshake(Session *sess);

static int client_read_start(uv_stream_t *handle);
static int client_write_start(uv_stream_t *handle, const uv_buf_t *buf);
static int client_write_string(uv_stream_t *handle, const char *data, int len);
static int client_write_error(uv_stream_t *handle, int err);
static void on_client_conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void on_client_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
static void on_client_write_done(uv_write_t *req, int status);

static void upstream_connect_domain(uv_getaddrinfo_t* req, int status, struct addrinfo* res);
static int upstream_connect(uv_connect_t* req, IPAddr *ipaddr);
static void upstream_connect_cb(uv_connect_t* req, int status);
static void upstream_connect_log(Session *sess, int err);

static int upstream_read_start(uv_stream_t *handle);
static int upstream_write_start(uv_stream_t *handle, const uv_buf_t *buf);
static void on_upstream_conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void on_upstream_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
static void on_upstream_write_done(uv_write_t *req, int status);

int main(int argc, const char *argv[]) {
  start_server(SERVER_HOST, SERVER_PORT, SERVER_BACKLOG);
  return 0;
}

void start_server(const char *host, int local_port, int backlog) {
  g_loop = uv_default_loop();

  ServerContext server_ctx;
  memset(&server_ctx, 0, sizeof(ServerContext));
  g_server_ctx = &server_ctx;

  server_ctx.server_cfg.host = host;
  server_ctx.server_cfg.local_port = local_port;
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
  uv_loop_close(g_loop);
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

  IPAddr ipaddr;
  char ipstr[INET6_ADDRSTRLEN];

  for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
    if (ai->ai_family == AF_INET) {
      ipaddr.addr4 = *(struct sockaddr_in *)ai->ai_addr;
      ipaddr.addr4.sin_port = htons(g_server_ctx->server_cfg.local_port);
      uv_inet_ntop(ipaddr.addr.sa_family, &ipaddr.addr4.sin_addr, ipstr, sizeof(ipstr));

    } else if (ai->ai_family == AF_INET6) {
      ipaddr.addr6 = *(struct sockaddr_in6 *)ai->ai_addr;
      ipaddr.addr6.sin6_port = htons(g_server_ctx->server_cfg.local_port);
      uv_inet_ntop(ipaddr.addr.sa_family, &ipaddr.addr6.sin6_addr, ipstr, sizeof(ipstr));

    } else {
      LOG_W("unexpected ai_family: %d", ai->ai_family);
      continue;
    }

    int err;
    if ((err = uv_tcp_bind(&g_server_ctx->server_tcp, &ipaddr.addr, 0)) != 0) {
      LOG_W("uv_tcp_bind on %s:%d failed: %s", 
          ipstr, g_server_ctx->server_cfg.local_port, uv_strerror(err));
      continue;
    }

    if ((err = uv_listen((uv_stream_t *)&g_server_ctx->server_tcp, 
          g_server_ctx->server_cfg.backlog, 
          on_connection_new)) != 0) {
      LOG_W("uv_tcp_listen on %s:%d failed: %s", 
          ipstr, g_server_ctx->server_cfg.local_port, uv_strerror(err));
      continue;
    }
    
    LOG_I("server listening on %s:%d", ipstr, g_server_ctx->server_cfg.local_port);
    uv_freeaddrinfo(res);
    return;
  }

  LOG_E("failed to bind on local_port: %d", g_server_ctx->server_cfg.local_port);
  exit(1);
} 

Session *create_session() {
  Session *sess = lmalloc(sizeof(Session));
  sess->state = S5_METHOD_IDENTIFICATION;
  sess->type = SESSION_TYPE_UNKNOWN;
  return sess;
}

int init_tcp_handle(Session *sess, uv_tcp_t **tcp_handle) {
  *tcp_handle = lmalloc(sizeof(uv_tcp_t));
  (*tcp_handle)->data = sess;

  int err;
  if ((err = uv_tcp_init(g_loop, *tcp_handle)) != 0) {
    LOG_E("uv_tcp_init failed: %s", uv_strerror(err));
    close_session(sess);
    return err;
  }

  if ((err = uv_tcp_keepalive(*tcp_handle, 1, KEEPALIVE)) != 0) {
    LOG_E("uv_tcp_keepalive failed: %s", uv_strerror(err));
    close_session(sess);
    return err;
  }

  return 0;
}

void close_session(Session *sess) {
  LOG_V("now will close session");
  if (sess->type == SESSION_TYPE_TCP) {
    TCPSession *tcp_sess = (TCPSession *)sess;
    if (tcp_sess->upstream_tcp) {
      uv_handle_t *handle = (uv_handle_t *)tcp_sess->upstream_tcp;
      uv_read_stop((uv_stream_t *)handle);

      if (!uv_is_closing(handle)) {
        uv_close(handle, tcp_handle_close_cb);
      }
    }
  }

  if (sess->client_tcp) {
    uv_handle_t *handle = (uv_handle_t *)sess->client_tcp;
    uv_read_stop((uv_stream_t *)handle);
    if (!uv_is_closing(handle)) {
      uv_close(handle, tcp_handle_close_cb);
    }
  }

  free(sess);
}

void tcp_handle_close_cb(uv_handle_t *handle) {
  free(handle);
}

void on_connection_new(uv_stream_t *server, int status) {
  if (status < 0) {
    LOG_E("uv_accept failed: %s", uv_strerror(status));
    return;
  }

  LOG_V(">>>> accepted new connection");
  Session *sess = create_session();

  if (init_tcp_handle(sess, &sess->client_tcp) < 0) {
    return;
  }

  int err;
  if ((err = uv_accept(server, (uv_stream_t *)sess->client_tcp)) != 0) {
    LOG_E("uv_accept failed: %s", uv_strerror(err));
    close_session(sess);
    return;
  }

  client_read_start((uv_stream_t *)sess->client_tcp);
}

int client_read_start(uv_stream_t *handle) {
  Session *sess = (Session *)handle->data;
  int err;
  if ((err = uv_read_start(handle, on_client_conn_alloc, on_client_read_done)) != 0) {
    LOG_E("uv_read_start failed: %s", uv_strerror(err));
    // safe to close directly
    close_session(sess);
  }
  return err;
}

int client_write_error(uv_stream_t *handle, int err) {
  Session *sess = (Session *)handle->data;

  char buf[] = { 5, 1, 0, 1, 0, 0, 0, 0, 0, 0 };
  sess->state = S5_SESSION_END; // cause the session be closed in on_write_done_cb

  switch(err) {
    case UV_ENETUNREACH: buf[1] = 3; break; // from the RFC: 3 = Network unreachable
    case UV_EHOSTUNREACH: buf[1] = 4; break; // from the RFC: 4 = Host unreachable
    case UV_ECONNREFUSED: buf[1] = 5; break;
    case S5_UNSUPPORTED_CMD: buf[1] = 7; break;
    case S5_BAD_ATYP: buf[1] = 8; break;
    default: buf[1] = 1; break; // general SOCKS server failure
  }

  return client_write_string(handle, buf, 10);
}

int client_write_string(uv_stream_t *handle, const char *data, int len) {
  uv_buf_t buf;
  buf.base = (char *)data;
  buf.len = len;
  return client_write_start(handle, &buf);
}

int client_write_start(uv_stream_t *handle, const uv_buf_t *buf) {
  Session *sess = (Session *)handle->data;
  int err;
  if ((err = uv_write(&sess->client_write_req, 
          (uv_stream_t *)handle, buf, 1, on_client_write_done)) != 0) {
    LOG_E("uv_write failed: %s", uv_strerror(err));
    close_session(sess);
  }
  return err;
}

void on_client_write_done(uv_write_t *req, int status) {
  Session *sess = container_of(req, Session, client_write_req);
  if (status < 0 || sess->state == S5_SESSION_END) {
    LOG_V("status=%d, now will close session", status);
    close_session(sess);
  } else {
    client_read_start((uv_stream_t *)sess->client_tcp);
    if (sess->type == SESSION_TYPE_TCP && sess->state == S5_STREAMING) {
      upstream_read_start((uv_stream_t *)((TCPSession *)sess)->upstream_tcp);
    }
  }
}

void on_client_conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
  Session *sess = (Session *)handle->data;
  buf->base = sess->client_buf;
  buf->len = sizeof(sess->client_buf);
}

void on_client_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
  if (nread == 0) { // EAGAIN || EWOULDBLOCK
    LOG_I("nread is 0, may reuse the connection");
    return;
  }

  // stop reading so the buf can be reused and not overrun
  uv_read_stop(handle);

  Session *sess = (Session *)handle->data;
  if (nread < 0) {
    LOG_I("client read done: %s", uv_strerror(nread));
    close_session(sess);
    return;
  }

  if (sess->state == S5_METHOD_IDENTIFICATION) {
    Socks5Ctx *s5_ctx = &sess->s5_ctx;

    S5Err s5_err = socks5_parse_method_identification(s5_ctx, buf->base, nread);
    if (s5_err != S5_OK) {
      LOG_E("socks5_parse_method_identification failed");
      close_session(sess);
      return;
    }

    if (s5_ctx->state == S5_PARSE_STATE_FINISH) {
      // we only support AUTH_NONE at the moment
      if (s5_ctx->methods & S5_AUTH_NONE) { 
        sess->state = S5_REQUEST;
        client_write_string(handle, "\5\0", 2);

        LOG_V("socks5 method identification passed");
      } else {
        // this state causes the session be closed in on_write_done_cb
        sess->state = S5_SESSION_END;  
        client_write_string(handle, "\5\xff", 2);
        LOG_V("socks5 method not supported");
      }

    } else {
      // need more data
      client_read_start((uv_stream_t *)handle);
    }

  } else if (sess->state == S5_REQUEST) {
    Socks5Ctx *s5_ctx = &sess->s5_ctx;

    S5Err s5_err = socks5_parse_request(s5_ctx, buf->base, nread); 
    if (s5_err != S5_OK) {
      LOG_E("socks5_parse_request failed");
      client_write_error(handle, s5_err);
      return;
    }

    // finished parsing the SOCKS request, now we know it is a 
    // CONNECT or UDP ASSOCIATE request
    sess->type = (s5_ctx->cmd == S5_CMD_UDP_ASSOCIATE ? 
        SESSION_TYPE_UDP : SESSION_TYPE_TCP);

    if (sess->type == SESSION_TYPE_UDP) {
      sess = lrealloc(sess, sizeof(UDPSession));
      // reset the session object to client_tcp, because the memory address
      // may be changed after realloc
      handle->data = sess;  
      // TODO replay to the UDP ASSOCIATE request
      return;
    }

    sess = lrealloc(sess, sizeof(TCPSession));
    // reset the session object to client_tcp, because the memory address
    // may be changed after realloc
    handle->data = sess;

    int err;
    if ((err = init_tcp_handle(sess, &((TCPSession *)sess)->upstream_tcp)) < 0) {
      client_write_error(handle, err);
      return;
    }

    if (s5_ctx->atyp == S5_ATYP_IPV4) {
      struct sockaddr_in addr4;
      addr4.sin_family = AF_INET;
      addr4.sin_port = htons(s5_ctx->dst_port);
      memcpy(&addr4.sin_addr.s_addr, s5_ctx->dst_addr, 4);

      int err;
      if ((err = upstream_connect(&((TCPSession *)sess)->upstream_connect_req, 
              (IPAddr *)&addr4)) != 0) {
        log_ipv4_and_port(s5_ctx->dst_addr, s5_ctx->dst_port, 
            "upstream connect failed");
        client_write_error((uv_stream_t *)sess->client_tcp, err); 
      }

    } else if (s5_ctx->atyp == S5_ATYP_DOMAIN) {
      struct addrinfo hint;
      memset(&hint, 0, sizeof(hint));
      hint.ai_family = AF_UNSPEC;
      hint.ai_socktype = SOCK_STREAM;
      hint.ai_protocol = IPPROTO_TCP;

      int err;
      if ((err = uv_getaddrinfo(g_loop, 
            &((TCPSession *)sess)->upstream_addrinfo_req, 
            upstream_connect_domain, 
            (const char *)s5_ctx->dst_addr, 
            NULL, 
            &hint)) != 0) {

        LOG_E("upstream connect failed: %s, err: %s", 
            s5_ctx->dst_addr, uv_strerror(err));
        client_write_error(handle, err);
        return;
      }

    } else if (s5_ctx->atyp == S5_ATYP_IPV6) {
      struct sockaddr_in6 addr6;
      addr6.sin6_family = AF_INET6;
      addr6.sin6_port = htons(s5_ctx->dst_port);
      memcpy(&addr6.sin6_addr.s6_addr, s5_ctx->dst_addr, 16);

      int err;
      if ((err = upstream_connect(&((TCPSession *)sess)->upstream_connect_req, 
              (IPAddr *)&addr6)) != 0) {
        log_ipv6_and_port(s5_ctx->dst_addr, s5_ctx->dst_port, 
            "upstream connect failed");
        client_write_error((uv_stream_t *)sess->client_tcp, err); 
      }

    } else {
      LOG_E("unknown ATYP: %d", s5_ctx->atyp);
      client_write_error(handle, 20000);  // the error code is chosen at random
    }

  } else if (sess->state == S5_STREAMING) { 
    ((uv_buf_t *)buf)->len = nread;
    upstream_write_start((uv_stream_t *)((TCPSession *)sess)->upstream_tcp, buf);

  } else {
    // unreachable code
    LOG_W("unepxected state: %d", sess->state);
    close_session(sess);
  }
}

int upstream_read_start(uv_stream_t *handle) {
  Session *sess = (Session *)handle->data;
  int err;
  if ((err = uv_read_start(handle, on_upstream_conn_alloc, 
          on_upstream_read_done)) != 0) {
    LOG_E("uv_read_start failed: %s", uv_strerror(err));
    close_session(sess);
  }
  return err;
}

void on_upstream_conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
  TCPSession *sess = (TCPSession *)handle->data;
  buf->base = sess->upstream_buf;
  buf->len = sizeof(sess->upstream_buf);
}

void on_upstream_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
  if (nread == 0) { // EAGAIN || EWOULDBLOCK
    return;
  }

  // stop reading so the buf can be reused and not overrun
  uv_read_stop(handle);

  Session *sess = (Session *)handle->data;
  if (nread < 0 || sess->state == S5_SESSION_END) {
    LOG_V("upstream read failed: %s", uv_strerror(nread));
    close_session(sess);
    return;
  }

  ((uv_buf_t *)buf)->len = nread;
  client_write_start((uv_stream_t *)sess->client_tcp, buf);
}

int upstream_write_start(uv_stream_t *handle, const uv_buf_t *buf) {
  TCPSession *sess = (TCPSession *)handle->data;
  int err;
  if ((err = uv_write(&sess->upstream_write_req, (uv_stream_t *)handle, 
          buf, 1, on_upstream_write_done)) != 0) {
    LOG_E("uv_write failed: %s", uv_strerror(err));
    close_session((Session *)sess);
  }
  return err;
}

void on_upstream_write_done(uv_write_t *req, int status) {
  TCPSession *sess = container_of(req, TCPSession, upstream_write_req);
  if (status < 0 || sess->state == S5_SESSION_END) {
    LOG_V("upstream write failed: %s", uv_strerror(status));
    close_session((Session *)sess);
  } else {
    client_read_start((uv_stream_t *)sess->client_tcp);
  }
}

void upstream_connect_domain(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
  TCPSession *sess = container_of(req, TCPSession, upstream_addrinfo_req);
  if (status < 0) {
    LOG_E("getaddrinfo(\"%s\"): %s", sess->s5_ctx.dst_addr, uv_strerror(status));
    uv_freeaddrinfo(res);
    client_write_error((uv_stream_t *)sess->client_tcp, status);
    return;
  }

  char ipstr[INET6_ADDRSTRLEN];
  IPAddr ipaddr;

  int err;
  for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
    if (ai->ai_family == AF_INET) {
      ipaddr.addr4 = *(struct sockaddr_in *)ai->ai_addr;
      ipaddr.addr4.sin_port = htons(sess->s5_ctx.dst_port);
      uv_inet_ntop(ipaddr.addr.sa_family, &ipaddr.addr4.sin_addr, ipstr, sizeof(ipstr));

    } else if (ai->ai_family == AF_INET6) {
      ipaddr.addr6 = *(struct sockaddr_in6 *)ai->ai_addr;
      ipaddr.addr6.sin6_port = htons(sess->s5_ctx.dst_port);
      uv_inet_ntop(ipaddr.addr.sa_family, &ipaddr.addr6.sin6_addr, ipstr, sizeof(ipstr));

    } else {
      LOG_W("unexpected ai_family: %d", ai->ai_family);
      continue;
    }

    if ((err = upstream_connect(&sess->upstream_connect_req, &ipaddr)) != 0) {
      LOG_W("upstream_connect failed on %s:%d, err: %s",
          ipstr, sess->s5_ctx.dst_port, uv_strerror(err));
      continue;
    }

    LOG_I("connected to %s:%d", ipstr, sess->s5_ctx.dst_port);
    uv_freeaddrinfo(res);

    return;
  }

  uv_freeaddrinfo(res);
  client_write_error((uv_stream_t *)sess->client_tcp, err);
}

void upstream_connect_cb(uv_connect_t* req, int status) {
  TCPSession *sess = container_of(req, TCPSession, upstream_connect_req);

  upstream_connect_log((Session *)sess, status);
  if (status < 0) {
    if ((intptr_t)req->data) {
      client_write_error((uv_stream_t *)sess->client_tcp, status); 
    }
  } else {
    finish_socks5_handshake((Session *)sess);
  }
}

void finish_socks5_handshake(Session *sess) {
  IPAddr ipaddr;
  int err;
  if ((err = uv_tcp_getsockname(((TCPSession *)sess)->upstream_tcp, 
          &ipaddr.addr, (int []){ sizeof(ipaddr) })) < 0) {
    LOG_W("uv_tcp_getsockname failed: %s", uv_strerror(err));
    client_write_error((uv_stream_t *)sess->client_tcp, err);
    return;
  }

  sess->state = S5_STREAMING;

  uv_buf_t buf = {
    .base = sess->client_buf
  };
  memcpy(buf.base, "\5\0\0\1", 4);
  uint16_t local_port = 0;
  if (ipaddr.addr.sa_family == AF_INET) {
    local_port = ipaddr.addr4.sin_port;

    buf.len = 10;
    memcpy(buf.base+4, &ipaddr.addr4.sin_addr.s_addr, 4);
    memcpy(buf.base+8, &local_port, 2);

  } else {  // IPV6
    local_port = ipaddr.addr6.sin6_port;

    buf.len = 22;
    memcpy(buf.base+4, &ipaddr.addr6.sin6_addr.s6_addr, 16);
    memcpy(buf.base+20, &local_port, 2);
  }

  LOG_I("new connection bound to local local_port: %d", ntohs(local_port));
  client_write_start((uv_stream_t *)sess->client_tcp, &buf);
}

void upstream_connect_log(Session *sess, int status) {
  if (sess->s5_ctx.atyp == S5_ATYP_IPV4) {
    char ipstr[INET_ADDRSTRLEN];
    uv_inet_ntop(AF_INET, sess->s5_ctx.dst_addr, ipstr, INET_ADDRSTRLEN);
    LOG_I("uv_tcp_connect: %s:%d, status: %s", 
        ipstr, sess->s5_ctx.dst_port, 
        status ? uv_strerror(status) : "CONNECTED");

  } else if (sess->s5_ctx.atyp == S5_ATYP_IPV6) {
    char ipstr[INET6_ADDRSTRLEN];
    uv_inet_ntop(AF_INET6, sess->s5_ctx.dst_addr, ipstr, INET6_ADDRSTRLEN);
    LOG_I("uv_tcp_connect: [%s]:%d, status: %s", 
        ipstr, sess->s5_ctx.dst_port, 
        status ? uv_strerror(status) : "CONNECTED");

  } else {
    LOG_I("uv_tcp_connect: %s:%d, status: %s", 
        sess->s5_ctx.dst_addr, sess->s5_ctx.dst_port, 
        status ? uv_strerror(status) : "CONNECTED");
  }
}

int upstream_connect(uv_connect_t* req, IPAddr *ipaddr) {
  TCPSession *sess = container_of(req, TCPSession, upstream_connect_req);

  int err;
  if ((err = uv_tcp_connect(req, sess->upstream_tcp, &ipaddr->addr, upstream_connect_cb)) != 0) {
    LOG_W("uv_tcp_connect failed: %s", uv_strerror(err));
  }
  return err;
}
