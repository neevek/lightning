#include "socks5.h"
#include "log/log.h"

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
        LOG_E("junk in handshake: %d, - %d", i + 1, size);
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
    switch(socks5_ctx->state) {
      case S5_PARSE_STATE_REQ_VERSION:
        if (c != SOCKS5_VERSION) {
          LOG_E("bad version: %d", c);
          return S5_BAD_VERSION;
        }
        socks5_ctx->state = S5_PARSE_STATE_REQ_CMD;
        break;

      case S5_PARSE_STATE_REQ_CMD:
        if (c != 1) { // we only support CONNECT
          LOG_E("unsupported cmd: %d", c);
          return S5_UNSUPPORTED_CMD;
        }

        socks5_ctx->cmd = c;
        socks5_ctx->state = S5_PARSE_STATE_REQ_RSV;
        break;

      case S5_PARSE_STATE_REQ_RSV:
        socks5_ctx->state = S5_PARSE_STATE_REQ_ATYP;
        break;

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
          socks5_ctx->state = S5_PARSE_STATE_FINISH;
        }
        break;

      case S5_PARSE_STATE_FINISH:
        LOG_E("junk in handshake: %d, - %d", i + 1, size);
        return S5_JUN_DATA_IN_REQUEST;
        break;

      default:
        break;
    }

    ++i;
  }

  return S5_OK;
}
