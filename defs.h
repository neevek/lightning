#ifndef DEFS_H_
#define DEFS_H_
#include <uv.h>
#include "encrypt.h"
#include "socks5.h"

#define SESSION_TCP_BUFSIZ 8192
#define SESSION_UDP_BUFSIZ 4096
#define DEFAULT_CIPHER_NAME "aes-256-cfb"

typedef enum {
  S5_METHOD_IDENTIFICATION,
  S5_REQUEST,
  S5_START_PROXY,           // only used in local.c
  S5_FINISHING_HANDSHAKE,   // only used in local.c
  S5_STREAMING,
  S5_STREAMING_END,
  S5_CLOSING,
} SessionState;

typedef enum {
  SESSION_TYPE_UNKNOWN,
  SESSION_TYPE_TCP,
  SESSION_TYPE_UDP
} SessionType;

 // 'socks5_req_data' is NULL if it is a DIRECT connection(no proxy)
#define SESSION_FIELDS \
  uv_tcp_t *client_tcp; \
  uv_write_t client_write_req; \
  char client_buf[SESSION_TCP_BUFSIZ + MAX_IV_LEN]; \
  SessionState state; \
  Socks5Ctx s5_ctx; \
  CipherCtx e_ctx; \
  CipherCtx d_ctx; \
  char *socks5_req_data;  \
  int socks5_req_data_len; \
  SessionType type; \
  int8_t heap_obj_count;

typedef struct {
  SESSION_FIELDS
} Session;

typedef struct {
  SESSION_FIELDS

  uv_tcp_t *upstream_tcp;
  uv_write_t upstream_write_req;
  uv_getaddrinfo_t upstream_addrinfo_req;
  uv_connect_t upstream_connect_req;
  char upstream_buf[SESSION_TCP_BUFSIZ + MAX_IV_LEN]; 
} TCPSession;

typedef struct {
  SESSION_FIELDS

  uv_udp_t *client_udp_recv;
  char clinet_udp_recv_buf[SESSION_UDP_BUFSIZ + MAX_IV_LEN]; 

  uv_udp_t *upstream_udp;
  uv_udp_send_t upstream_udp_send_req;
  uv_getaddrinfo_t upstream_udp_addrinfo_req;
  char upstream_udp_buf[SESSION_UDP_BUFSIZ + MAX_IV_LEN]; 

  uv_udp_t *client_udp_send;
  uv_udp_send_t client_udp_send_req;
  uv_getaddrinfo_t client_udp_addrinfo_req;
} UDPSession;

typedef struct {
  char *local_host;
  int local_port;
  char *cipher_name;
  char *cipher_secret;
  char *user;
  char *log_file;
  int window_size;
  int daemon_flag;
} RemoteServerCliCfg;

typedef struct {
  char *local_host;
  int local_port;
  char *remote_host;
  int remote_port;
  char *cipher_name;
  char *cipher_secret;
  char *user;
  char *log_file;
  int window_size;
  int daemon_flag;
  int set_global_proxy; 
  // if pac_file_url is not NULL, it will be used and
  // use_global_proxy will be ignored 
  char *pac_file_url; 
} LocalServerCliCfg;

#endif /* end of include guard: DEFS_H_ */
