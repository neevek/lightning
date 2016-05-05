#ifndef POOL_H_
#define POOL_H_
#include "socks5.h"
#include "hashmap.h"
#include <uv.h>

typedef struct {
  HashMap hashmap_;
  void (*destroy_cb_)(uv_tcp_t *);
} ConnectionPool;

void connection_pool_init(ConnectionPool *pool, void (*destroy_cb)(uv_tcp_t *));
void connection_pool_destroy(ConnectionPool *pool);
uv_tcp_t *connection_pool_take(ConnectionPool *pool, Socks5Ctx *s5_ctx);
void connection_pool_cache(ConnectionPool *pool, Socks5Ctx *s5_ctx, uv_tcp_t *conn);
void connection_pool_remove(ConnectionPool *pool, Socks5Ctx *s5_ctx);

#endif /* end of include guard: POOL_H_ */
