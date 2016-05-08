#ifndef SOCKS5_H_
#define SOCKS5_H_
#include <stdint.h>

#define SOCKS5_VERSION 5

typedef enum {
  S5_PARSE_STATE_VERSION,
  S5_PARSE_STATE_NMETHODS,
  S5_PARSE_STATE_METHODS,
  S5_PARSE_STATE_REQ_VERSION,
  S5_PARSE_STATE_REQ_CMD,
  S5_PARSE_STATE_REQ_RSV,
  S5_PARSE_STATE_REQ_ATYP,
  S5_PARSE_STATE_REQ_DST_ADDR_LEN,
  S5_PARSE_STATE_REQ_DST_ADDR,
  S5_PARSE_STATE_REQ_DST_PORT,
  S5_PARSE_STATE_FINISH,
} Socks5State;

typedef enum {
  S5_ATYP_IPV4 = 1,
  S5_ATYP_DOMAIN = 3,
  S5_ATYP_IPV6 = 4
} Socks5Atyp;

typedef enum {
  S5_CMD_CONNECT = 1,
  S5_CMD_BIND = 2,
  S5_CMD_UDP_ASSOCIATE = 3,
} S5Command;

typedef enum {
  S5_AUTH_NONE =   1 << 0,
  S5_AUTH_GSSAPI = 1 << 1,
  S5_AUTH_PASSWD = 1 << 2
} Socks5AuthMethod;

typedef enum {
  S5_OK = 0,
  S5_BAD_VERSION = 1,
  S5_JUNK_DATA_IN_HANDSHAKE = 2,
  S5_JUN_DATA_IN_REQUEST = 3,
  S5_UNSUPPORTED_CMD = 4,
  S5_BAD_ATYP = 5,
  S5_BAD_UDP_REQUEST = 6,
} S5Err;

typedef struct {
  Socks5State state;
  uint8_t arg_index;
  uint8_t arg_count;
  uint8_t methods;
  uint8_t cmd;
  uint8_t atyp;
  uint8_t dst_addr[257];  // max=0xFF, one more byte for the terminating null
  uint16_t dst_port;
} Socks5Ctx;

S5Err socks5_parse_method_identification(Socks5Ctx *socks5_ctx, const char *data, int size);
S5Err socks5_parse_request(Socks5Ctx *socks5_ctx, const char *data, int size);
S5Err socks5_parse_udp_request(Socks5Ctx *socks5_ctx, const char *data, int size);

#endif /* end of include guard: SOCKS5_H_ */
