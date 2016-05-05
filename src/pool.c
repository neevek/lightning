#include "pool.h"
#include <assert.h>
#include <stdlib.h>
#include "list.h"

#define MAX_KEY 256

void connection_pool_init(ConnectionPool *pool, void (*destroy_cb)(uv_tcp_t *)) {
  assert(pool);
  hashmap_init(&pool->hashmap_, NULL);
  pool->destroy_cb_ = destroy_cb;
}

void connection_pool_destroy(ConnectionPool *pool) {
  assert(pool);

  KeyIterator it = hashmap_key_iterator(&pool->hashmap_); 
  char *key;
  while ((key = (char *)hashmap_next_key(&pool->hashmap_, &it))) {
    List *list = (List *)hashmap_get(&pool->hashmap_, key);
    ListIterator list_it = list_iterator(list);
    uv_tcp_t *tcp_handle;
    while ((tcp_handle = list_next(&list_it))) {
      pool->destroy_cb_(tcp_handle);
    }

    hashmap_remove(&pool->hashmap_, key);
    list_destroy(list);
    free(list);
  }

  hashmap_destroy(&pool->hashmap_);
}

int init_key(Socks5Ctx *s5_ctx, char *key) {
  assert(s5_ctx);
  assert(key);

  char *s = (char *)s5_ctx->dst_addr;
  if (s5_ctx->atyp == S5_ATYP_DOMAIN) {
    sprintf(key, "%s:%d", s, s5_ctx->dst_port);

  } else if (s5_ctx->atyp == S5_ATYP_IPV4) {
    sprintf(key, "%d.%d.%d.%d:%d", s[0], s[1], s[2], s[3], s5_ctx->dst_port);

  } else if (s5_ctx->atyp == S5_ATYP_IPV4) {
    sprintf(key, "[%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d]:%d", 
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 
        s[8], s[9], s[10], s[11],s[12], s[13], s[14], s[15],
        s5_ctx->dst_port);

  } else {
    return 0;
  }

  return 1;
}

uv_tcp_t *connection_pool_take(ConnectionPool *pool, Socks5Ctx *s5_ctx) {
  char key[MAX_KEY];
  if (!init_key(s5_ctx, key)) {
    return NULL;
  }

  List *list = hashmap_get(&pool->hashmap_, key);
  return list ? list_remove_head(list) : NULL;
}

void connection_pool_cache(ConnectionPool *pool, Socks5Ctx *s5_ctx, uv_tcp_t *conn) {
  char key[MAX_KEY];
  if (!init_key(s5_ctx, key)) {
    return;
  }

  List *list = hashmap_get(&pool->hashmap_, key);
  if (list == NULL) {
    list = malloc(sizeof(List));
    list_init(list, NULL);
    hashmap_put(&pool->hashmap_, key, list);
  }

  list_add_tail(list, conn);
}

void connection_pool_remove(ConnectionPool *pool, Socks5Ctx *s5_ctx) {
  char key[MAX_KEY];
  if (!init_key(s5_ctx, key)) {
    return;
  }

  hashmap_remove(&pool->hashmap_, key);
}
