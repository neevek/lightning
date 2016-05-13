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

  IPVersion bound_ip_version;
  uint8_t bound_ip[16];
} ServerContext;

static void start_server(const char *host, int local_port, int backlog);
static void do_bind_and_listen(uv_getaddrinfo_t* req, int status, struct addrinfo* res);
static void on_connection_new(uv_stream_t *server, int status);

static int init_tcp_handle(Session *sess, uv_tcp_t **tcp_handle);
static int init_udp_handle(Session *sess, uv_udp_t **udp_handle);

static Session *create_session();
static int init_tcp_handle(Session *sess, uv_tcp_t **tcp_handle);
static void close_session(Session *sess);
static void close_handle(uv_handle_t *handle);
static void handle_close_cb(uv_handle_t *handle);
static void finish_socks5_tcp_handshake(Session *sess);
static void finish_socks5_udp_handshake(Session *sess);
static void finish_socks5_handshake(Session *sess, IPAddr *ipaddr);

static int client_tcp_read_start(uv_stream_t *handle);
static int client_tcp_write_start(uv_stream_t *handle, const uv_buf_t *buf);
static int client_tcp_write_string(uv_stream_t *handle, const char *data, int len);
static int client_tcp_write_error(uv_stream_t *handle, int err);
static void on_client_tcp_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void on_client_tcp_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
static void on_client_tcp_write_done(uv_write_t *req, int status);
static void handle_socks5_method_identification(uv_stream_t *handle, 
    ssize_t nread, const uv_buf_t *buf, Session *sess);
static void handle_socks5_request(uv_stream_t *handle, 
    ssize_t nread, const uv_buf_t *buf, Session *sess);

static void upstream_tcp_connect_domain(uv_getaddrinfo_t* req, int status, 
    struct addrinfo* res);
static int upstream_tcp_connect(uv_connect_t* req, IPAddr *ipaddr);
static void upstream_tcp_connect_cb(uv_connect_t* req, int status);
static void upstream_tcp_connect_log(Session *sess, int err);
static int upstream_tcp_read_start(uv_stream_t *handle);
static int upstream_tcp_write_start(uv_stream_t *handle, const uv_buf_t *buf);
static void on_upstream_tcp_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void on_upstream_tcp_read_done(uv_stream_t *handle, ssize_t nread, 
    const uv_buf_t *buf);
static void on_upstream_tcp_write_done(uv_write_t *req, int status);

static void on_client_udp_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void on_client_udp_recv_done(uv_udp_t* handle, ssize_t nread, 
    const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags);
static void on_upstream_udp_send_done(uv_udp_send_t* req, int status);
static void on_upstream_udp_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void on_upstream_udp_recv_done(uv_udp_t* handle, ssize_t nread, 
    const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags);
static void on_client_udp_send_done(uv_udp_send_t* req, int status);
static int client_udp_recv_start(UDPSession *sess);
static void upstream_udp_send(uv_getaddrinfo_t* req, int status, 
    struct addrinfo* res);
static void init_client_udp_send_if_needed(UDPSession *sess);
static void client_udp_send_domain_resolved(uv_getaddrinfo_t* req, int status, 
    struct addrinfo* res);

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
    if (fill_ipaddr(&ipaddr, htons(g_server_ctx->server_cfg.local_port), 
          ipstr, sizeof(ipstr), ai) != 0) {
      continue;
    }

    if (ai->ai_family == AF_INET) {
      g_server_ctx->bound_ip_version = IPV4;
      memcpy(g_server_ctx->bound_ip, &ipaddr.addr4.sin_addr.s_addr, 4);

    } else if (ai->ai_family == AF_INET6) {
      g_server_ctx->bound_ip_version = IPV6;
      memcpy(g_server_ctx->bound_ip, ipaddr.addr6.sin6_addr.s6_addr, 16);
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

int init_udp_handle(Session *sess, uv_udp_t **udp_handle) {
  *udp_handle = lmalloc(sizeof(uv_udp_t));
  (*udp_handle)->data = sess;

  int err;
  if ((err = uv_udp_init(g_loop, *udp_handle)) != 0) {
    LOG_E("uv_udp_init failed: %s", uv_strerror(err));
    close_session(sess);
    return err;
  }

  return 0;
}

void close_session(Session *sess) {
  LOG_V("now will close session");
  if (sess->type == SESSION_TYPE_TCP) {
    TCPSession *tcp_sess = (TCPSession *)sess;
    close_handle((uv_handle_t *)tcp_sess->upstream_tcp);

  } else if (sess->type == SESSION_TYPE_UDP) {
    UDPSession *udp_sess = (UDPSession *)sess;
    close_handle((uv_handle_t *)udp_sess->client_udp_recv);
    close_handle((uv_handle_t *)udp_sess->upstream_udp);
    close_handle((uv_handle_t *)udp_sess->client_udp_recv);
    close_handle((uv_handle_t *)udp_sess->client_udp_send);
  }

  close_handle((uv_handle_t *)sess->client_tcp);

  free(sess);
}

void close_handle(uv_handle_t *handle) {
  if (handle == NULL) {
    return;
  }

  if (handle->type == UV_TCP) {
    uv_read_stop((uv_stream_t *)handle);
  } else if (handle->type == UV_UDP) {
    uv_udp_recv_stop((uv_udp_t *)handle);
  }

  if (!uv_is_closing(handle)) {
    uv_close(handle, handle_close_cb);
  }
}

void handle_close_cb(uv_handle_t *handle) {
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

  client_tcp_read_start((uv_stream_t *)sess->client_tcp);
}

int client_tcp_read_start(uv_stream_t *handle) {
  Session *sess = (Session *)handle->data;
  int err;
  if ((err = uv_read_start(handle, on_client_tcp_alloc, on_client_tcp_read_done)) != 0) {
    LOG_E("uv_read_start failed: %s", uv_strerror(err));
    // safe to close directly
    close_session(sess);
  }
  return err;
}

int client_tcp_write_error(uv_stream_t *handle, int err) {
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

  return client_tcp_write_string(handle, buf, 10);
}

int client_tcp_write_string(uv_stream_t *handle, const char *data, int len) {
  uv_buf_t buf;
  buf.base = (char *)data;
  buf.len = len;
  return client_tcp_write_start(handle, &buf);
}

int client_tcp_write_start(uv_stream_t *handle, const uv_buf_t *buf) {
  Session *sess = (Session *)handle->data;
  int err;
  if ((err = uv_write(&sess->client_write_req, 
          (uv_stream_t *)handle, buf, 1, on_client_tcp_write_done)) != 0) {
    LOG_E("uv_write failed: %s", uv_strerror(err));
    close_session(sess);
  }
  return err;
}

void on_client_tcp_write_done(uv_write_t *req, int status) {
  Session *sess = container_of(req, Session, client_write_req);
  if (status < 0 || sess->state == S5_SESSION_END) {
    LOG_V("status=%d, now will close session", status);
    close_session(sess);
  } else {
    client_tcp_read_start((uv_stream_t *)sess->client_tcp);
    if (sess->type == SESSION_TYPE_TCP && sess->state == S5_STREAMING) {
      upstream_tcp_read_start((uv_stream_t *)((TCPSession *)sess)->upstream_tcp);
    }
  }
}

void on_client_tcp_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
  Session *sess = (Session *)handle->data;
  buf->base = sess->client_buf;
  buf->len = sizeof(sess->client_buf);
}

void on_client_tcp_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
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
    handle_socks5_method_identification(handle, nread, buf, sess);

  } else if (sess->state == S5_REQUEST) {
    handle_socks5_request(handle, nread, buf, sess);

  } else if (sess->state == S5_STREAMING) { 
    ((uv_buf_t *)buf)->len = nread;
    upstream_tcp_write_start((uv_stream_t *)((TCPSession *)sess)->upstream_tcp, buf);

  } else {
    // unreachable code
    LOG_W("unepxected state: %d", sess->state);
    close_session(sess);
  }
}

void handle_socks5_method_identification(uv_stream_t *handle, ssize_t nread, 
    const uv_buf_t *buf, Session *sess) {
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
        client_tcp_write_string(handle, "\5\0", 2);

        LOG_V("socks5 method identification passed");
      } else {
        // this state causes the session be closed in on_write_done_cb
        sess->state = S5_SESSION_END;  
        client_tcp_write_string(handle, "\5\xff", 2);
        LOG_V("socks5 method not supported");
      }

    } else {
      // need more data
      client_tcp_read_start((uv_stream_t *)handle);
    }
}

void handle_socks5_request(uv_stream_t *handle, ssize_t nread, 
    const uv_buf_t *buf, Session *sess) {
  Socks5Ctx *s5_ctx = &sess->s5_ctx;

  S5Err s5_err = socks5_parse_request(s5_ctx, buf->base, nread); 
  if (s5_err != S5_OK) {
    LOG_E("socks5_parse_request failed");
    client_tcp_write_error(handle, s5_err);
    return;
  }

  // finished parsing the SOCKS request, now we know it is a 
  // CONNECT or UDP ASSOCIATE request
  sess->type = (s5_ctx->cmd == S5_CMD_UDP_ASSOCIATE ? 
      SESSION_TYPE_UDP : SESSION_TYPE_TCP);

  if (sess->type == SESSION_TYPE_UDP) {
    LOG_V("received a UDP request");

    sess = lrealloc(sess, sizeof(UDPSession));
    memset(((char *)sess)+sizeof(Session), 0, sizeof(UDPSession)-sizeof(Session));
    // re-assign the session object for client_tcp, because the memory address
    // may have been changed after realloc
    handle->data = sess;  

    finish_socks5_udp_handshake(sess);
    return;
  }

  // alright, it is a CONNECT request
  sess = lrealloc(sess, sizeof(TCPSession));
  memset(((char *)sess)+sizeof(Session), 0, sizeof(TCPSession)-sizeof(Session));
  // re-assign the session object for client_tcp, because the memory address
  // may have been changed after realloc
  handle->data = sess;

  int err;
  if ((err = init_tcp_handle(sess, &((TCPSession *)sess)->upstream_tcp)) < 0) {
    client_tcp_write_error(handle, err);
    return;
  }

  if (s5_ctx->atyp == S5_ATYP_IPV4) {
    struct sockaddr_in addr4;
    addr4.sin_family = AF_INET;
    addr4.sin_port = htons(s5_ctx->dst_port);
    memcpy(&addr4.sin_addr.s_addr, s5_ctx->dst_addr, 4);

    int err;
    if ((err = upstream_tcp_connect(&((TCPSession *)sess)->upstream_connect_req, 
            (IPAddr *)&addr4)) != 0) {
      log_ipv4_and_port(s5_ctx->dst_addr, s5_ctx->dst_port, 
          "upstream connect failed");
      client_tcp_write_error((uv_stream_t *)sess->client_tcp, err); 
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
            upstream_tcp_connect_domain, 
            (const char *)s5_ctx->dst_addr, 
            NULL, 
            &hint)) < 0) {

      LOG_E("uv_getaddrinfo failed: %s, err: %s", 
          s5_ctx->dst_addr, uv_strerror(err));
      client_tcp_write_error(handle, err);
      return;
    }

  } else if (s5_ctx->atyp == S5_ATYP_IPV6) {
    struct sockaddr_in6 addr6;
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(s5_ctx->dst_port);
    memcpy(addr6.sin6_addr.s6_addr, s5_ctx->dst_addr, 16);

    int err;
    if ((err = upstream_tcp_connect(&((TCPSession *)sess)->upstream_connect_req, 
            (IPAddr *)&addr6)) != 0) {
      log_ipv6_and_port(s5_ctx->dst_addr, s5_ctx->dst_port, 
          "upstream connect failed");
      client_tcp_write_error((uv_stream_t *)sess->client_tcp, err); 
    }

  } else {
    LOG_E("unknown ATYP: %d", s5_ctx->atyp);
    client_tcp_write_error(handle, 20000);  // the error code is chosen at random
  }
}

int upstream_tcp_read_start(uv_stream_t *handle) {
  Session *sess = (Session *)handle->data;
  int err;
  if ((err = uv_read_start(handle, on_upstream_tcp_alloc, 
          on_upstream_tcp_read_done)) != 0) {
    LOG_E("uv_read_start failed: %s", uv_strerror(err));
    close_session(sess);
  }
  return err;
}

void on_upstream_tcp_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
  TCPSession *sess = (TCPSession *)handle->data;
  buf->base = sess->upstream_buf;
  buf->len = sizeof(sess->upstream_buf);
}

void on_upstream_tcp_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
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
  client_tcp_write_start((uv_stream_t *)sess->client_tcp, buf);
}

int upstream_tcp_write_start(uv_stream_t *handle, const uv_buf_t *buf) {
  TCPSession *sess = (TCPSession *)handle->data;
  int err;
  if ((err = uv_write(&sess->upstream_write_req, (uv_stream_t *)handle, 
          buf, 1, on_upstream_tcp_write_done)) != 0) {
    LOG_E("uv_write failed: %s", uv_strerror(err));
    close_session((Session *)sess);
  }
  return err;
}

void on_upstream_tcp_write_done(uv_write_t *req, int status) {
  TCPSession *sess = container_of(req, TCPSession, upstream_write_req);
  if (status < 0 || sess->state == S5_SESSION_END) {
    LOG_V("upstream write failed: %s", uv_strerror(status));
    close_session((Session *)sess);
  } else {
    client_tcp_read_start((uv_stream_t *)sess->client_tcp);
  }
}

void upstream_tcp_connect_domain(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
  TCPSession *sess = container_of(req, TCPSession, upstream_addrinfo_req);
  if (status < 0) {
    LOG_E("getaddrinfo(\"%s\"): %s", sess->s5_ctx.dst_addr, uv_strerror(status));
    uv_freeaddrinfo(res);
    client_tcp_write_error((uv_stream_t *)sess->client_tcp, status);
    return;
  }

  char ipstr[INET6_ADDRSTRLEN];
  IPAddr ipaddr;

  int err;
  for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
    if (fill_ipaddr(&ipaddr, htons(sess->s5_ctx.dst_port), ipstr, sizeof(ipstr), ai) != 0) {
      continue;
    }

    if ((err = upstream_tcp_connect(&sess->upstream_connect_req, &ipaddr)) != 0) {
      LOG_W("upstream_tcp_connect failed on %s:%d, err: %s",
          ipstr, sess->s5_ctx.dst_port, uv_strerror(err));
      continue;
    }

    LOG_I("connected to %s:%d", ipstr, sess->s5_ctx.dst_port);
    uv_freeaddrinfo(res);

    return;
  }

  uv_freeaddrinfo(res);
  client_tcp_write_error((uv_stream_t *)sess->client_tcp, err);
}

void upstream_tcp_connect_cb(uv_connect_t* req, int status) {
  TCPSession *sess = container_of(req, TCPSession, upstream_connect_req);

  upstream_tcp_connect_log((Session *)sess, status);
  if (status < 0) {
    if ((intptr_t)req->data) {
      client_tcp_write_error((uv_stream_t *)sess->client_tcp, status); 
    }
  } else {
    finish_socks5_tcp_handshake((Session *)sess);
  }
}

void finish_socks5_tcp_handshake(Session *sess) {
  IPAddr ipaddr;
  int err;

  if ((err = uv_tcp_getsockname(((TCPSession *)sess)->upstream_tcp, &ipaddr.addr, 
          (int []){ sizeof(IPAddr) })) < 0) {
    LOG_W("uv_tcp_getsockname failed: %s", uv_strerror(err));
    client_tcp_write_error((uv_stream_t *)sess->client_tcp, err);
    return;
  }
  sess->state = S5_STREAMING;

  finish_socks5_handshake(sess, &ipaddr);
}

void finish_socks5_udp_handshake(Session *sess) {
  IPAddr ipaddr;
  int err;

  if (g_server_ctx->bound_ip_version == IPV4) {
    ipaddr.addr4.sin_family = AF_INET;
    memcpy(&ipaddr.addr4.sin_addr.s_addr, g_server_ctx->bound_ip, 4);
    ipaddr.addr4.sin_port = 0;
  } else {
    ipaddr.addr6.sin6_family = AF_INET6;
    memcpy(ipaddr.addr6.sin6_addr.s6_addr, g_server_ctx->bound_ip, 16);
    ipaddr.addr6.sin6_port = 0;
  }

  UDPSession *udp_sess = (UDPSession *)sess;
  init_udp_handle(sess, &udp_sess->upstream_udp);
  init_udp_handle(sess, &udp_sess->client_udp_recv);
  uv_udp_bind(udp_sess->client_udp_recv, &ipaddr.addr, UV_UDP_REUSEADDR);

  init_client_udp_send_if_needed(udp_sess);

  // get the bound port and send it to the client, so the client
  // can send us UDP packets on this port
  if ((err = uv_udp_getsockname(udp_sess->client_udp_recv, &ipaddr.addr, 
          (int []){ sizeof(ipaddr) })) < 0) {
    LOG_W("uv_udp_getsockname failed: %s", uv_strerror(err));
    client_tcp_write_error((uv_stream_t *)sess->client_tcp, err);
    return;
  }

  uv_udp_recv_start(udp_sess->client_udp_recv, on_client_udp_alloc, on_client_udp_recv_done);

  finish_socks5_handshake(sess, &ipaddr);
}

void init_client_udp_send_if_needed(UDPSession *sess) {
  Socks5Ctx *s5_ctx = &sess->s5_ctx;
  if (s5_ctx->dst_port == 0) {
    return;
  }

  if (s5_ctx->atyp == S5_ATYP_DOMAIN) {
    struct addrinfo hint;
    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_DGRAM;
    hint.ai_protocol = IPPROTO_UDP;

    int err;
    if ((err = uv_getaddrinfo(g_loop, 
            &((UDPSession *)sess)->client_udp_addrinfo_req, 
            client_udp_send_domain_resolved,
            (const char *)s5_ctx->dst_addr, 
            NULL, 
            &hint)) < 0) {

      LOG_E("uv_getaddrinfo failed: %s, err: %s", 
          s5_ctx->dst_addr, uv_strerror(err));
    }
    return;
  } 

  if (s5_ctx->atyp == S5_ATYP_IPV4) {
    if (is_ipv4_addr_any((const char *)s5_ctx->dst_addr)) {
      return;
    }
#ifdef IGNORE_LOCAL_UDP_RELAY
    if (is_ipv4_addr_local((const char *)s5_ctx->dst_addr)) {
      return;
    }
#endif

  } else if (s5_ctx->atyp == S5_ATYP_IPV6) {
    if (is_ipv6_addr_any((const char *)s5_ctx->dst_addr)) {
      return;
    }
#ifdef IGNORE_LOCAL_UDP_RELAY
    if (is_ipv6_addr_local((const char *)s5_ctx->dst_addr))) {
      return;
    }
#endif
  } else 

  init_udp_handle((Session *)sess, &sess->client_udp_send);
}

void finish_socks5_handshake(Session *sess, IPAddr *ipaddr) {
  uv_buf_t buf = {
    .base = sess->client_buf
  };
  memcpy(buf.base, "\5\0\0\1", 4);
  uint16_t local_port = 0;
  if (ipaddr->addr.sa_family == AF_INET) {
    local_port = ipaddr->addr4.sin_port;

    buf.len = 10;
    memcpy(buf.base+4, &ipaddr->addr4.sin_addr.s_addr, 4);
    memcpy(buf.base+8, &local_port, 2);

  } else {  // IPV6
    local_port = ipaddr->addr6.sin6_port;

    buf.len = 22;
    memcpy(buf.base+4, &ipaddr->addr6.sin6_addr.s6_addr, 16);
    memcpy(buf.base+20, &local_port, 2);
  }

  LOG_I("new connection bound to local port: %d", ntohs(local_port));
  client_tcp_write_start((uv_stream_t *)sess->client_tcp, &buf);
}

void upstream_tcp_connect_log(Session *sess, int status) {
  if (sess->s5_ctx.atyp == S5_ATYP_IPV4) {
    char ipstr[INET_ADDRSTRLEN];
    uv_inet_ntop(AF_INET, sess->s5_ctx.dst_addr, ipstr, INET_ADDRSTRLEN);
    LOG_I("uv_tcp_connect: %s:%d, status: %s", 
        ipstr, sess->s5_ctx.dst_port, 
        status ? uv_strerror(status) : "CONNECTED");

  } else if (sess->s5_ctx.atyp == S5_ATYP_IPV6) {
    char ipstr[INET6_ADDRSTRLEN];
    uv_inet_ntop(AF_INET6, sess->s5_ctx.dst_addr, ipstr, INET6_ADDRSTRLEN);
    LOG_I("uv_tcp_connect: %s:%d, status: %s", 
        ipstr, sess->s5_ctx.dst_port, 
        status ? uv_strerror(status) : "CONNECTED");

  } else {
    LOG_I("uv_tcp_connect: %s:%d, status: %s", 
        sess->s5_ctx.dst_addr, sess->s5_ctx.dst_port, 
        status ? uv_strerror(status) : "CONNECTED");
  }

}

int upstream_tcp_connect(uv_connect_t* req, IPAddr *ipaddr) {
  TCPSession *sess = container_of(req, TCPSession, upstream_connect_req);

  int err;
  if ((err = uv_tcp_connect(req, sess->upstream_tcp, &ipaddr->addr, 
          upstream_tcp_connect_cb)) != 0) {
    LOG_W("uv_tcp_connect failed: %s", uv_strerror(err));
  }
  return err;
}

void on_client_udp_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
  UDPSession *sess = (UDPSession *)handle->data;
  buf->base = sess->clinet_udp_recv_buf;
  buf->len = sizeof(sess->clinet_udp_recv_buf);
}

void on_client_udp_recv_done(uv_udp_t* handle, ssize_t nread, 
    const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags) {
  if (nread < 0) {
    LOG_V("received udp packet failed: %s", uv_strerror(nread));
    return;
  }

  if (nread == 0 && addr == NULL) {
    return;
  }

  LOG_V("received udp packet: %lu", nread);
  UDPSession *sess = (UDPSession *)handle->data;
  int err;
  if ((err = socks5_parse_udp_request(&sess->s5_ctx, buf->base, buf->len)) != S5_OK) {
      LOG_E("socks5_parse_udp_request failed, ignored the dgram, err: %d", err);
      return;
  }

  uv_udp_recv_stop(handle);

  ((uv_buf_t *)buf)->len = nread;

  Socks5Ctx *s5_ctx = &sess->s5_ctx;
  if (s5_ctx->atyp == S5_ATYP_IPV4) {
    struct sockaddr_in addr4;
    addr4.sin_family = AF_INET;
    addr4.sin_port = htons(s5_ctx->dst_port);
    memcpy(&addr4.sin_addr.s_addr, s5_ctx->dst_addr, 4);

    err = uv_udp_send(&sess->upstream_udp_send_req, sess->upstream_udp, 
        buf, 1, (struct sockaddr *)&addr4, on_upstream_udp_send_done);
    if (err < 0) {
      LOG_E("uv_udp_send failed: %s", uv_strerror(err));
      log_ipv6_and_port(s5_ctx->dst_addr, s5_ctx->dst_port, 
          "uv_udp_send failed");
      client_udp_recv_start(sess);
    }

  } else if (s5_ctx->atyp == S5_ATYP_DOMAIN) {
    struct addrinfo hint;
    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_DGRAM;
    hint.ai_protocol = IPPROTO_UDP;

    ((UDPSession *)sess)->upstream_udp_addrinfo_req.data = (void *)buf;

    LOG_V("now will send udp packet to: %s", (const char *)s5_ctx->dst_addr);
    int err;
    if ((err = uv_getaddrinfo(g_loop, 
            &((UDPSession *)sess)->upstream_udp_addrinfo_req, 
            upstream_udp_send,
            (const char *)s5_ctx->dst_addr, 
            NULL, 
            &hint)) < 0) {

      LOG_E("uv_getaddrinfo failed: %s, err: %s", 
          s5_ctx->dst_addr, uv_strerror(err));
      client_udp_recv_start(sess);
    }

  } else if (s5_ctx->atyp == S5_ATYP_IPV6) {
    struct sockaddr_in6 addr6;
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(s5_ctx->dst_port);
    memcpy(addr6.sin6_addr.s6_addr, s5_ctx->dst_addr, 16);

    err = uv_udp_send(&sess->upstream_udp_send_req, sess->upstream_udp, 
        buf, 1, (struct sockaddr *)&addr6, on_upstream_udp_send_done);
    if (err < 0) {
      LOG_E("uv_udp_send failed: %s", uv_strerror(err));
      log_ipv6_and_port(s5_ctx->dst_addr, s5_ctx->dst_port, 
          "uv_udp_send failed");

      client_udp_recv_start(sess);
    }

  } else {
    LOG_E("unknown ATYP: %d", s5_ctx->atyp);
    client_udp_recv_start(sess);
  }
}

void on_upstream_udp_send_done(uv_udp_send_t* req, int status) {
  LOG_I("udp package sent: %s", status == 0 ? "SUCCEEDED" : uv_strerror(status));
  UDPSession *sess = container_of(req, UDPSession, upstream_udp_send_req);
  client_udp_recv_start(sess);
}

int client_udp_recv_start(UDPSession *sess) {
  int err = uv_udp_recv_start(sess->client_udp_recv, on_client_udp_alloc, 
      on_client_udp_recv_done);
  if (err < 0) {
    LOG_E("uv_udp_recv_start failed: %s", uv_strerror(err));
    return err;
  }
  // if client_udp_send is bound, then we should start listening for UDP packets 
  // sent from the upstream_udp port which we initially relayed the packets to.
  if (sess->client_udp_send != NULL) {
    LOG_I("now will listen for UDP packets from remote");
    err = uv_udp_recv_start(sess->upstream_udp, on_upstream_udp_alloc, 
        on_upstream_udp_recv_done);
    if (err < 0) {
      LOG_E("uv_udp_recv_start failed: %s", uv_strerror(err));
    }
  }
  return err;
}

void upstream_udp_send(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
  UDPSession *sess = container_of(req, UDPSession, upstream_udp_addrinfo_req);
  if (status < 0) {
    LOG_E("getaddrinfo(\"%s\"): %s", sess->s5_ctx.dst_addr, uv_strerror(status));
    uv_freeaddrinfo(res);
    client_udp_recv_start(sess);
    return;
  }

  char ipstr[INET6_ADDRSTRLEN];
  IPAddr ipaddr;

  int err = -1;
  for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
    if (fill_ipaddr(&ipaddr, htons(sess->s5_ctx.dst_port), ipstr, sizeof(ipstr), ai) != 0) {
      continue;
    }

    err = uv_udp_send(&sess->upstream_udp_send_req, sess->upstream_udp, 
        (uv_buf_t *)req->data, 1, (struct sockaddr *)&ipaddr.addr,
        on_upstream_udp_send_done);

    if (err < 0) {
      LOG_E("uv_udp_send to %s:%d failed: %s", ipstr, sess->s5_ctx.dst_port, 
          uv_strerror(err));
      continue;
    }

    break;
  }

  uv_freeaddrinfo(res);

  if (err == -1) {
    // if we havn't successfully sent out the packets, 
    // on_upstream_udp_send_done will not be called, so we have to call the 
    // following function right here
    client_udp_recv_start(sess);
  }
}

void on_upstream_udp_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
  UDPSession *sess = (UDPSession *)handle->data;
  // 22 to encapsulate the header, see on_upstream_udp_recv_done
  buf->base = sess->upstream_udp_buf + 22;
  buf->len = sizeof(sess->upstream_udp_buf) - 22; 
}

void on_upstream_udp_recv_done(uv_udp_t* handle, ssize_t nread, 
    const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags) {
  if (nread < 0) {
    LOG_V("received udp packet failed: %s", uv_strerror(nread));
    return;
  }

  if (nread == 0 && addr == NULL) {
    return;
  }

  LOG_V("received udp packet: %lu", nread);

  uv_udp_recv_stop(handle);

  UDPSession *sess = (UDPSession *)handle->data;

  if (addr->sa_family == AF_INET) {
    ((uv_buf_t *)buf)->base -= 10;
    ((uv_buf_t *)buf)->len = nread + 10;
    char *data = buf->base;
    data[0] = 0; // RSV
    data[1] = 0; // RSV
    data[2] = 0; // FRAG
    data[3] = 1; // IPv4
    memcpy(&data[4], (char *)&((struct sockaddr_in *)addr)->sin_addr.s_addr, 4);
    data[8] = (unsigned char)(((struct sockaddr_in *)addr)->sin_port >> 8);
    data[9] = (unsigned char)(((struct sockaddr_in *)addr)->sin_port);
  } else if (addr->sa_family == AF_INET6) {
    ((uv_buf_t *)buf)->base -= 22;
    ((uv_buf_t *)buf)->len = nread + 22;
    char *data = buf->base;
    data[0] = 0; // RSV
    data[1] = 0; // RSV
    data[2] = 0; // FRAG
    data[3] = 1; // IPv4
    memcpy(&data[4], ((struct sockaddr_in6 *)addr)->sin6_addr.s6_addr, 16);
    data[20] = (unsigned char)(((struct sockaddr_in6 *)addr)->sin6_port >> 8);
    data[21] = (unsigned char)(((struct sockaddr_in6 *)addr)->sin6_port);
  } else {
    // unreachable code
    LOG_W("unepxected sa_family: %d", addr->sa_family);
    return;
  }

  Socks5Ctx *s5_ctx = &sess->s5_ctx;
  IPAddr ipaddr;

  if (s5_ctx->atyp == S5_ATYP_IPV4) {
    copy_ipv4_addr(&ipaddr.addr4.sin_addr.s_addr, (char *)s5_ctx->dst_addr);
    ipaddr.addr4.sin_family = AF_INET;
    ipaddr.addr4.sin_port = s5_ctx->dst_port;;

  } else if (s5_ctx->atyp == S5_ATYP_IPV6) {
    memcpy(ipaddr.addr6.sin6_addr.s6_addr, s5_ctx->dst_addr, 16);
    ipaddr.addr6.sin6_family = AF_INET6;
    ipaddr.addr6.sin6_port = s5_ctx->dst_port;;

  } else {
    // unreachable code
    LOG_W("unepxected atyp: %d", s5_ctx->atyp);
    return;
  }

  int err = uv_udp_send(&sess->client_udp_send_req, sess->client_udp_send, 
      buf, 1, (struct sockaddr *)&ipaddr.addr,
      on_client_udp_send_done);

  if (err < 0) {
    LOG_E("uv_udp_send to %d failed: %s", s5_ctx->dst_port, uv_strerror(err));
  }
}

void on_client_udp_send_done(uv_udp_send_t* req, int status) {
  LOG_I("client_udp_send status: %s", status == 0 ? 
      "SUCCEEDED" : uv_strerror(status));
}

void client_udp_send_domain_resolved(uv_getaddrinfo_t* req, int status, 
    struct addrinfo* res) {
  UDPSession *sess = container_of(req, UDPSession, client_udp_addrinfo_req);

  if (status < 0) {
    LOG_E("getaddrinfo(\"%s\"): %s", sess->s5_ctx.dst_addr, uv_strerror(status));
    uv_freeaddrinfo(res);
    return;
  }
  
  for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
    LOG_V("domain [%s] resolved", sess->s5_ctx.dst_addr);

    if (ai->ai_family == AF_INET) {
      struct sockaddr_in *sai = (struct sockaddr_in *)ai->ai_addr;
      sess->s5_ctx.atyp = S5_ATYP_IPV4;
      sess->s5_ctx.dst_addr[0] = (sai->sin_addr.s_addr >> 24) & 0xff;
      sess->s5_ctx.dst_addr[1] = (sai->sin_addr.s_addr >> 16) & 0xff;
      sess->s5_ctx.dst_addr[2] = (sai->sin_addr.s_addr >> 8) & 0xff;
      sess->s5_ctx.dst_addr[3] = sai->sin_addr.s_addr & 0xff;

    } else if (ai->ai_family == AF_INET6) {
      struct sockaddr_in6 *sai6 = (struct sockaddr_in6 *)ai->ai_addr;
      sess->s5_ctx.atyp = S5_ATYP_IPV6;
      memcpy(sess->s5_ctx.dst_addr, sai6->sin6_addr.s6_addr, 16);
    }

    init_udp_handle((Session *)sess, &sess->client_udp_send);
    break;
  }

  uv_freeaddrinfo(res);
}
