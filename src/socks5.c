#include "socks5.h"
#include "log/log.h"

static S5Err socks5_parse_addr_and_port(Socks5Ctx *socks5_ctx, 
    const char *data, int size, int is_udp_req);

S5Err socks5_parse_method_identification(Socks5Ctx *socks5_ctx, const char *data, int size) {
  socks5_ctx->state = S5_PARSE_STATE_VERSION;

  int i = 0;
  while (i < size) {
    unsigned char c = data[i];
    switch(socks5_ctx->state) {
      case S5_PARSE_STATE_VERSION:
        if (c != SOCKS5_VERSION) {
          LOG_E("bad version: %d", c);
          return S5_BAD_VERSION;
        }
        socks5_ctx->state = S5_PARSE_STATE_NMETHODS;
        break;

      case S5_PARSE_STATE_NMETHODS:
        socks5_ctx->arg_index = 0;
        socks5_ctx->arg_count = c;
        socks5_ctx->state = S5_PARSE_STATE_METHODS;
        break;

      case S5_PARSE_STATE_METHODS:
        switch(c) {
          case 0:
            socks5_ctx->methods |= S5_AUTH_NONE;
            break;
          case 1:
            socks5_ctx->methods |= S5_AUTH_GSSAPI;
            break;
          case 2:
            socks5_ctx->methods |= S5_AUTH_PASSWD;
            break;
          default:
            break;
        }
        if (++socks5_ctx->arg_index == socks5_ctx->arg_count) {
          socks5_ctx->state = S5_PARSE_STATE_FINISH;
        }
        break;

      case S5_PARSE_STATE_FINISH:
        LOG_E("junk in handshake: %d - %d", i + 1, size);
        return S5_JUNK_DATA_IN_HANDSHAKE;
        break;

      default:
        break;
    }

    ++i;
  }

  return S5_OK;
}

S5Err socks5_parse_request(Socks5Ctx *socks5_ctx, const char *data, int size) {
  socks5_ctx->state = S5_PARSE_STATE_REQ_VERSION;

  int i = 0;
  while (i < size) {
    unsigned char c = data[i];
    ++i;

    switch(socks5_ctx->state) {
      case S5_PARSE_STATE_REQ_VERSION:
        if (c != SOCKS5_VERSION) {
          LOG_E("bad version: %d", c);
          return S5_BAD_VERSION;
        }
        socks5_ctx->state = S5_PARSE_STATE_REQ_CMD;
        break;

      case S5_PARSE_STATE_REQ_CMD:
        if (c != S5_CMD_CONNECT && c != S5_CMD_UDP_ASSOCIATE) {
          LOG_E("unsupported cmd: %d", c);
          return S5_UNSUPPORTED_CMD;
        }

        socks5_ctx->cmd = c;
        socks5_ctx->state = S5_PARSE_STATE_REQ_RSV;
        break;

      case S5_PARSE_STATE_REQ_RSV:
        return socks5_parse_addr_and_port(socks5_ctx, data + i, size - i, 0);

      default:
        break;
    }

  }

  return S5_OK;
}

S5Err socks5_parse_udp_request(Socks5Ctx *socks5_ctx, const char *data, int size) {
  if (size < 3) {
    return S5_BAD_UDP_REQUEST;
  }

  // the first 2 bytes is RSV, ignored, 3rd byte is FRAG
  // FRAG is not 0, while fragmentation is not supported, 
  if (data[2] != 0) { 
    return S5_BAD_UDP_REQUEST;
  }
  
  return socks5_parse_addr_and_port(socks5_ctx, data + 3, size - 3, 1);
}

S5Err socks5_parse_addr_and_port(Socks5Ctx *socks5_ctx, 
    const char *data, int size, int is_udp_req) {
  socks5_ctx->state = S5_PARSE_STATE_REQ_ATYP;

  int i = 0;
  while (i < size) {
    unsigned char c = data[i];
    ++i;

    switch(socks5_ctx->state) {
      case S5_PARSE_STATE_REQ_ATYP:
        socks5_ctx->atyp = c;
        socks5_ctx->arg_index = 0;

        if (c == S5_ATYP_IPV4) {
          socks5_ctx->arg_count = 4;
          socks5_ctx->state = S5_PARSE_STATE_REQ_DST_ADDR;

        } else if (c == S5_ATYP_DOMAIN) {
          socks5_ctx->state = S5_PARSE_STATE_REQ_DST_ADDR_LEN;

        } else if (c == S5_ATYP_IPV6) {
          socks5_ctx->arg_count = 16;
          socks5_ctx->state = S5_PARSE_STATE_REQ_DST_ADDR;

        } else {
          LOG_E("bad atyp: %d", c);
          return S5_BAD_ATYP;
        }
        break;

      case S5_PARSE_STATE_REQ_DST_ADDR_LEN:
        socks5_ctx->arg_index = 0;
        socks5_ctx->arg_count = c;
        socks5_ctx->state = S5_PARSE_STATE_REQ_DST_ADDR;
        break;

      case S5_PARSE_STATE_REQ_DST_ADDR:
        socks5_ctx->dst_addr[socks5_ctx->arg_index] = c;

        if (++socks5_ctx->arg_index == socks5_ctx->arg_count) {
          socks5_ctx->dst_addr[socks5_ctx->arg_index] = '\0';

          socks5_ctx->state = S5_PARSE_STATE_REQ_DST_PORT;
          socks5_ctx->arg_index = 0;
          socks5_ctx->arg_count = 2;  // 2 bytes for the port
        } 
        break;

      case S5_PARSE_STATE_REQ_DST_PORT:
        if (socks5_ctx->arg_index == 0) {
          socks5_ctx->dst_port = c << 8;
          ++socks5_ctx->arg_index;

        } else {
          socks5_ctx->dst_port |= c;

          if (is_udp_req) {
            return S5_OK;
          }

          socks5_ctx->state = S5_PARSE_STATE_FINISH;
        }
        break;

      case S5_PARSE_STATE_FINISH:
        LOG_E("junk in handshake: %d - %d", i + 1, size);
        return S5_JUN_DATA_IN_REQUEST;
        break;

      default:
        break;
    }
  }

  return S5_OK;
}
